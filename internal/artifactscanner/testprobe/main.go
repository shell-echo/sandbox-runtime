//go:build integration

// This executable is built from the current source only by the opt-in ClamD
// adapter integration test. It is not a runtime role or release artifact.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/artifactscanner"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
)

const (
	probeUID    = 1000
	probeGID    = 1000
	probeSocket = "/run/sandbox/clamd.sock"
	probeConfig = "/run/sandbox/clamd.conf"
)

var clamdConfig = []byte(strings.Join([]string{
	"Foreground yes", "DatabaseDirectory /var/lib/clamav",
	"LocalSocket /run/sandbox/clamd.sock", "LocalSocketMode 600",
	"MaxThreads 1", "MaxQueue 2", "MaxFileSize 64M", "MaxScanSize 64M",
	"StreamMaxLength 64M", "ReadTimeout 30", "CommandReadTimeout 5", ""}, "\n"))

type result struct {
	Protocol     string            `json:"protocol"`
	UID          int               `json:"uid"`
	GID          int               `json:"gid"`
	ConfigDigest string            `json:"config_digest"`
	RuleDigests  map[string]string `json:"rule_digests"`
	Benign       string            `json:"benign"`
	EICAR        string            `json:"eicar"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "private ClamD adapter probe failed:", err)
		os.Exit(1)
	}
}

func run(parent context.Context) error {
	if os.Getuid() != probeUID || os.Getgid() != probeGID {
		return errors.New("unexpected non-root scanner identity")
	}
	ctx, cancel := context.WithTimeout(parent, 75*time.Second)
	defer cancel()
	rules, err := inspectRules(ctx)
	if err != nil {
		return err
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o700, SocketMode: 0o600,
		OwnerUID: probeUID, DirectoryGID: probeGID}
	if !restrictedunix.ValidateParent(probeSocket, layout) {
		return errors.New("private socket tmpfs layout invalid")
	}
	if err := os.WriteFile(probeConfig, clamdConfig, 0o600); err != nil {
		return errors.New("write private non-secret ClamD configuration")
	}
	child := exec.Command("/usr/sbin/clamd", "--config-file="+probeConfig)
	logs := &boundedLog{limit: 2048}
	child.Stdout, child.Stderr = logs, logs
	if err := child.Start(); err != nil {
		return errors.New("start pinned ClamD")
	}
	done := make(chan struct{})
	var exitError error
	go func() { exitError = child.Wait(); close(done) }()
	defer func() {
		select {
		case <-done:
		default:
			_ = child.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = child.Process.Kill()
				<-done
			}
		}
	}()
	engine, err := artifactscanner.NewClamd(probeSocket, layout)
	if err != nil {
		return err
	}
	startup, stopStartup := context.WithTimeout(ctx, 60*time.Second)
	defer stopStartup()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	ready := false
	for !ready {
		select {
		case <-done:
			return fmt.Errorf("ClamD exited before readiness: %v; %s", exitError, logs.String())
		case <-startup.Done():
			return fmt.Errorf("ClamD readiness timed out: %w; %s", startup.Err(), logs.String())
		case <-ticker.C:
			probe, stopProbe := context.WithTimeout(startup, 2*time.Second)
			ready = engine.Ready(probe) == nil
			stopProbe()
		}
	}
	scans, stopScans := context.WithTimeout(ctx, 10*time.Second)
	defer stopScans()
	benign, err := engine.Scan(scans, []byte("benign scanner integration payload"))
	if err != nil || benign != artifactscanner.MalwareClean {
		return fmt.Errorf("benign scan failed: verdict=%q err=%v; %s", benign, err, logs.String())
	}
	// EICAR's harmless, published 68-byte test string is not malware.
	eicar := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	if len(eicar) != 68 {
		return errors.New("invalid EICAR test-string length")
	}
	infected, err := engine.Scan(scans, eicar)
	if err != nil || infected != artifactscanner.MalwareInfected {
		return fmt.Errorf("EICAR scan failed: verdict=%q err=%v; %s", infected, err, logs.String())
	}
	return json.NewEncoder(os.Stdout).Encode(result{Protocol: "sandbox-runtime.clamd-adapter-probe.v1",
		UID: os.Getuid(), GID: os.Getgid(), ConfigDigest: digest(clamdConfig),
		RuleDigests: rules, Benign: string(benign), EICAR: string(infected)})
}

func inspectRules(ctx context.Context) (map[string]string, error) {
	directory, err := os.Lstat("/var/lib/clamav")
	if err != nil || !directory.IsDir() || directory.Mode().Perm() != 0o700 || !ownedByScanner(directory) {
		return nil, errors.New("pinned database directory identity invalid")
	}
	digests := make(map[string]string, 3)
	for _, name := range []string{"bytecode.cvd", "daily.cvd", "main.cvd"} {
		path := filepath.Join("/var/lib/clamav", name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !ownedByScanner(info) || info.Size() < 1 || info.Size() > 512<<20 {
			return nil, errors.New("pinned database file identity invalid")
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, errors.New("pinned database file unreadable")
		}
		hash := sha256.New()
		buffer := make([]byte, 64<<10)
		var size int64
		for {
			if err := ctx.Err(); err != nil {
				_ = file.Close()
				return nil, err
			}
			count, readErr := file.Read(buffer)
			if count > 0 {
				size += int64(count)
				_, _ = hash.Write(buffer[:count])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || count == 0 || size > info.Size() {
				_ = file.Close()
				return nil, errors.New("pinned database file read invalid")
			}
		}
		opened, statErr := file.Stat()
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || !os.SameFile(info, opened) || size != info.Size() {
			return nil, errors.New("pinned database file changed")
		}
		digests[name] = "sha256:" + hex.EncodeToString(hash.Sum(nil))
	}
	return digests, nil
}

func ownedByScanner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == probeUID && stat.Gid == probeGID
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type boundedLog struct {
	mu    sync.Mutex
	limit int
	value []byte
}

func (b *boundedLog) Write(content []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	count := len(content)
	if len(b.value) < b.limit {
		remaining := b.limit - len(b.value)
		b.value = append(b.value, content[:min(count, remaining)]...)
	}
	return count, nil
}

func (b *boundedLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.value))
}
