package dockercontrol

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type codingUnixFileInfo struct {
	mode os.FileMode
	uid  uint32
	gid  uint32
}

func (i codingUnixFileInfo) Name() string       { return "socket" }
func (i codingUnixFileInfo) Size() int64        { return 0 }
func (i codingUnixFileInfo) Mode() os.FileMode  { return i.mode }
func (i codingUnixFileInfo) ModTime() time.Time { return time.Time{} }
func (i codingUnixFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i codingUnixFileInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid, Gid: i.gid} }

func TestCodingUnixSocketMetadataIsExact(t *testing.T) {
	ancestor := codingUnixFileInfo{mode: os.ModeDir | 0o755}
	if !validCodingUnixAncestor(ancestor) {
		t.Fatal("root-owned non-writable ancestor rejected")
	}
	for name, info := range map[string]codingUnixFileInfo{
		"untrusted owner": {mode: os.ModeDir | 0o755, uid: 501},
		"untrusted group": {mode: os.ModeDir | 0o755, gid: 20},
		"group writable":  {mode: os.ModeDir | 0o775},
		"world writable":  {mode: os.ModeDir | 0o757},
		"symlink":         {mode: os.ModeDir | os.ModeSymlink | 0o755},
		"not directory":   {mode: 0o755},
	} {
		t.Run(name, func(t *testing.T) {
			if validCodingUnixAncestor(info) {
				t.Fatal("untrusted ancestor accepted")
			}
		})
	}
	socket := codingUnixFileInfo{mode: os.ModeSocket | 0o660}
	if !validCodingUnixSocketInfo(socket) {
		t.Fatal("root:root 0660 socket rejected")
	}
	for name, info := range map[string]codingUnixFileInfo{
		"untrusted owner": {mode: os.ModeSocket | 0o660, uid: 501},
		"untrusted group": {mode: os.ModeSocket | 0o660, gid: 20},
		"world writable":  {mode: os.ModeSocket | 0o666},
		"wrong mode":      {mode: os.ModeSocket | 0o600},
		"symlink":         {mode: os.ModeSocket | os.ModeSymlink | 0o660},
		"regular file":    {mode: 0o660},
	} {
		t.Run(name, func(t *testing.T) {
			if validCodingUnixSocketInfo(info) {
				t.Fatal("untrusted socket accepted")
			}
		})
	}
}

func TestCodingUnixSocketPathFailsClosed(t *testing.T) {
	for _, path := range []string{"", "run/docker.sock", "/", "/run/../run/docker.sock", "/run//docker.sock", "/run/a\n"} {
		if !errors.Is(verifyCodingUnixSocket(path), ErrInvalidCodingUnixObserver) {
			t.Fatalf("invalid socket path accepted: %q", path)
		}
	}
	dir, err := os.MkdirTemp("", "cu-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "s")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if !errors.Is(verifyCodingUnixSocket(path), ErrInvalidCodingUnixObserver) {
		t.Fatal("user-owned or untrusted-ancestor socket accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(verifyCodingUnixSocket(link), ErrInvalidCodingUnixObserver) {
		t.Fatal("symlinked socket accepted")
	}
}

func TestCodingUnixObserverAdmissionAndCloseAreCancellable(t *testing.T) {
	// The empty gate models a first inventory holding the one SDK client.
	// A second inventory and close must not wait for that operation to finish
	// after their own caller deadlines have expired.
	observer := &codingUnixObserver{gate: make(chan struct{}, 1)}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := observer.ReadInventory(cancelled); !errors.Is(err, ErrInvalidCodingUnixObserver) ||
		time.Since(start) > time.Second {
		t.Fatalf("cancelled read blocked on active inventory: %v", err)
	}
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if _, err := observer.ReadInventory(short); !errors.Is(err, ErrInvalidCodingUnixObserver) {
		t.Fatalf("second read did not respect deadline: %v", err)
	}
	queueStart := time.Now()
	if _, err := observer.readInventoryWithBudget(context.Background(), 20*time.Millisecond); !errors.Is(err, ErrInvalidCodingUnixObserver) ||
		time.Since(queueStart) > time.Second {
		t.Fatalf("absolute inventory budget did not include queue time: %v", err)
	}
	shortClose, stopClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stopClose()
	if err := observer.CloseContext(shortClose); !errors.Is(err, ErrInvalidCodingUnixObserver) {
		t.Fatalf("timed-out close was marked drained: %v", err)
	}
	observer.gate <- struct{}{}
	if err := observer.CloseContext(context.Background()); err != nil {
		t.Fatalf("idle close rejected: %v", err)
	}
}
