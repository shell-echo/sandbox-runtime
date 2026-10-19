package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/artifactscanner"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const engineExecutable = "/usr/sbin/clamd"
const engineSocket = phase6security.ScannerRuntimeDirectoryV2 + "/clamd.sock"
const engineConfigPath = phase6security.ScannerRuntimeDirectoryV2 + "/clamd.conf"

func engineConfiguration() []byte {
	return []byte(strings.Join([]string{
		"Foreground yes", "DatabaseDirectory /var/lib/clamav", "TemporaryDirectory " + phase6security.ScannerRuntimeDirectoryV2, "OfficialDatabaseOnly yes", "LocalSocket " + engineSocket, "LocalSocketMode 600", "FixStaleSocket no",
		"MaxThreads 1", "MaxQueue 2", "MaxFileSize 64M", "MaxScanSize 64M", "StreamMaxLength 64M",
		"ReadTimeout 30", "CommandReadTimeout 5", "MaxScanTime 30000", "SelfCheck 0", "ConcurrentDatabaseReload no", "DisableCache yes", "AlertExceedsMax yes", "AlertEncrypted yes", ""}, "\n"))
}

type engineProcess struct {
	command                *exec.Cmd
	done                   chan struct{}
	adapter                *artifactscanner.Clamd
	configPath, socketPath string
	configInfo, socketInfo os.FileInfo
	once                   sync.Once
}

// Only the fixed executable is selected in production. No caller-provided
// command, environment, socket or working directory reaches exec.
func startEngine(ctx context.Context, uid, gid uint32) (*engineProcess, error) {
	if ctx == nil || ctx.Err() != nil || uid == 0 || gid == 0 || uint32(os.Getuid()) != uid || uint32(os.Getgid()) != gid {
		return nil, errScanner
	}
	return startEngineCommand(ctx, uid, gid, engineSocket, engineConfigPath, engineConfiguration(), exec.Command(engineExecutable, "--config-file="+engineConfigPath))
}

// Tests use this private lifecycle core with a child test process. Production
// supplies only the constants above and a Profile-validated exact tmpfs.
func startEngineCommand(ctx context.Context, uid, gid uint32, socket, config string, payload []byte, command *exec.Cmd) (*engineProcess, error) {
	layout := restrictedunix.Layout{DirectoryMode: 0700, SocketMode: 0600, OwnerUID: uid, DirectoryGID: gid}
	if ctx == nil || ctx.Err() != nil || command == nil || filepath.Dir(socket) != filepath.Dir(config) || !restrictedunix.ValidateParent(socket, layout) {
		return nil, errScanner
	}
	parent, err := os.Lstat(filepath.Dir(socket))
	if err != nil {
		return nil, errScanner
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		return nil, errScanner
	}
	f, err := os.OpenFile(config, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, errScanner
	}
	process := &engineProcess{command: command, done: make(chan struct{}), configPath: config, socketPath: socket}
	process.configInfo, err = f.Stat()
	if err == nil {
		_, err = f.Write(payload)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		restrictedunix.RemoveIfSame(config, process.configInfo)
		return nil, errScanner
	}
	actual, err := secretfile.Read(config, 16<<10)
	if err != nil || !bytes.Equal(actual, payload) {
		restrictedunix.RemoveIfSame(config, process.configInfo)
		return nil, errScanner
	}
	after, err := os.Lstat(config)
	if err != nil || !os.SameFile(process.configInfo, after) {
		restrictedunix.RemoveIfSame(config, process.configInfo)
		return nil, errScanner
	}
	parentAfter, parentErr := os.Lstat(filepath.Dir(socket))
	if parentErr != nil || !os.SameFile(parent, parentAfter) || !restrictedunix.ValidateParent(socket, layout) {
		restrictedunix.RemoveIfSame(config, process.configInfo)
		return nil, errScanner
	}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "LANG=C", "HOME=/nonexistent"}
	command.Dir = filepath.Dir(config)
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		restrictedunix.RemoveIfSame(config, process.configInfo)
		return nil, errScanner
	}
	go func() { _ = command.Wait(); close(process.done) }()
	adapter, err := artifactscanner.NewClamd(socket, layout)
	if err != nil {
		process.Close()
		return nil, errScanner
	}
	process.adapter = adapter
	startup, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-process.done:
			process.Close()
			return nil, errScanner
		case <-startup.Done():
			process.Close()
			return nil, errScanner
		case <-ticker.C:
			observed, statErr := os.Lstat(socket)
			if statErr != nil || !restrictedunix.ValidateSocket(socket, layout) {
				continue
			}
			if process.socketInfo == nil {
				process.socketInfo = observed
			} else if !os.SameFile(process.socketInfo, observed) {
				process.Close()
				return nil, errScanner
			}
			probe, stop := context.WithTimeout(startup, time.Second)
			err := adapter.Ready(probe)
			stop()
			after, statErr := os.Lstat(socket)
			if statErr != nil || !restrictedunix.ValidateSocket(socket, layout) || !os.SameFile(process.socketInfo, after) {
				process.Close()
				return nil, errScanner
			}
			if err == nil && startup.Err() == nil {
				select {
				case <-process.done:
					process.Close()
					return nil, errScanner
				default:
				}
				return process, nil
			}
		}
	}
}
func (p *engineProcess) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		select {
		case <-p.done:
		default:
			_ = p.command.Process.Signal(syscall.SIGTERM)
			select {
			case <-p.done:
			case <-time.After(5 * time.Second):
				_ = p.command.Process.Kill()
				<-p.done
			}
		}
		// A socket never observed before child exit has no owned inode receipt.
		// Preserve it and fail closed on restart; never unlink an unknown path.
		restrictedunix.RemoveIfSame(p.socketPath, p.socketInfo)
		restrictedunix.RemoveIfSame(p.configPath, p.configInfo)
	})
}
