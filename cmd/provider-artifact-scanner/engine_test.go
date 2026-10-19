package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This child exercises process/socket lifecycle only. It is not ClamAV or a
// proof that a real daemon loaded the signed rule snapshot.
func TestEngineChild(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "scanner-test-child" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	mode, socket := os.Args[index+1], os.Args[index+2]
	if mode == "exit" {
		os.Exit(7)
	}
	if mode == "wait" {
		select {}
	}
	if os.Getenv("HOME") != "/nonexistent" || os.Getenv("LANG") != "C" {
		os.Exit(8)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil || os.Chmod(socket, 0600) != nil {
		os.Exit(9)
	}
	if mode == "socket-exit" {
		os.Exit(11)
	}
	for {
		c, err := listener.AcceptUnix()
		if err != nil {
			os.Exit(10)
		}
		command := make([]byte, 6)
		if _, err := io.ReadFull(c, command); err == nil && bytes.Equal(command, []byte("zPING\x00")) {
			_, _ = c.Write([]byte("PONG\x00"))
		}
		_ = c.Close()
	}
}

func engineFixture(t *testing.T, mode string) (string, string, *exec.Cmd) {
	t.Helper()
	dir, err := os.MkdirTemp("", "s6-engine-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	socket, config := filepath.Join(dir, "clamd.sock"), filepath.Join(dir, "clamd.conf")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return socket, config, exec.Command(executable, "-test.run=^TestEngineChild$", "--", "scanner-test-child", mode, socket)
}

func TestEngineProcessLifecycle(t *testing.T) {
	socket, config, command := engineFixture(t, "ping")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	process, err := startEngineCommand(ctx, uint32(os.Getuid()), uint32(os.Getgid()), socket, config, engineConfiguration(), command)
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	actual, err := os.ReadFile(config)
	if err != nil || !bytes.Equal(actual, engineConfiguration()) {
		t.Fatal("fixed configuration not retained", err)
	}
	if err := process.adapter.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	process.Close()
	process.Close()
	select {
	case <-process.done:
	default:
		t.Fatal("child still running after close")
	}
	for _, path := range []string{socket, config} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("owned file retained %s: %v", filepath.Base(path), err)
		}
	}
}

func TestEngineRefusesExistingOrUnsafeInputsBeforeStartingChild(t *testing.T) {
	for _, mode := range []string{"config", "socket", "directory", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			socket, config, command := engineFixture(t, "ping")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "config":
				if err := os.WriteFile(config, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "socket":
				if err := os.WriteFile(socket, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Chmod(filepath.Dir(socket), 0750); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			p, err := startEngineCommand(ctx, uint32(os.Getuid()), uint32(os.Getgid()), socket, config, engineConfiguration(), command)
			if err == nil || p != nil || command.Process != nil {
				t.Fatal("unsafe input started a child")
			}
			if mode == "config" || mode == "socket" {
				path := config
				if mode == "socket" {
					path = socket
				}
				body, err := os.ReadFile(path)
				if err != nil || string(body) != "preserve" {
					t.Fatal("existing input altered")
				}
			}
		})
	}
}

func TestEngineStartupFailureReapsChild(t *testing.T) {
	for _, mode := range []string{"exit", "wait"} {
		t.Run(mode, func(t *testing.T) {
			socket, config, command := engineFixture(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			p, err := startEngineCommand(ctx, uint32(os.Getuid()), uint32(os.Getgid()), socket, config, engineConfiguration(), command)
			if err == nil || p != nil || command.Process == nil || command.ProcessState == nil {
				t.Fatal("failed startup not reaped")
			}
			if _, err := os.Lstat(config); !os.IsNotExist(err) {
				t.Fatal("failed startup left owned config")
			}
		})
	}
}

func TestEngineCleanupPreservesReplacementFiles(t *testing.T) {
	socket, config, command := engineFixture(t, "ping")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := startEngineCommand(ctx, uint32(os.Getuid()), uint32(os.Getgid()), socket, config, engineConfiguration(), command)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, path := range []string{socket, config} {
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p.Close()
	for _, path := range []string{socket, config} {
		body, err := os.ReadFile(path)
		if err != nil || string(body) != "replacement" {
			t.Fatal("replacement removed", err)
		}
	}
}

func TestFixedEngineConfigurationBoundsIOAndUsesPrivateRuntime(t *testing.T) {
	config := string(engineConfiguration())
	for _, line := range []string{"TemporaryDirectory /run/phase6-scanner\n", "OfficialDatabaseOnly yes\n", "FixStaleSocket no\n", "MaxThreads 1\n", "StreamMaxLength 64M\n", "MaxScanTime 30000\n", "ConcurrentDatabaseReload no\n", "DisableCache yes\n", "AlertExceedsMax yes\n", "AlertEncrypted yes\n"} {
		if !strings.Contains(config, line) {
			t.Fatalf("missing bound %q", line)
		}
	}
	for _, key := range []string{"TCPSocket ", "User ", "VirusEvent ", "OnAccess"} {
		if strings.Contains(config, key) {
			t.Fatal("unexpected engine authority", key)
		}
	}
}

func TestEngineEarlySocketExitFailsClosedAndPreservesUnknownInode(t *testing.T) {
	socket, config, command := engineFixture(t, "socket-exit")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := startEngineCommand(ctx, uint32(os.Getuid()), uint32(os.Getgid()), socket, config, engineConfiguration(), command)
	if err == nil || p != nil || command.ProcessState == nil {
		t.Fatal("early child exit reported ready")
	}
	if _, err := os.Lstat(config); !os.IsNotExist(err) {
		t.Fatal("owned config retained")
	}
	// Depending on scheduling, the ticker may have captured the socket before
	// exit. Only a captured inode may be removed. An uncaptured path is kept.
	if _, err := os.Lstat(socket); err == nil {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		next := exec.Command(executable, "-test.run=^TestEngineChild$", "--", "scanner-test-child", "ping", socket)
		if p, err := startEngineCommand(ctx, uint32(os.Getuid()), uint32(os.Getgid()), socket, config, engineConfiguration(), next); err == nil || p != nil || next.Process != nil {
			t.Fatal("unobserved stale socket recovered without authority")
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
