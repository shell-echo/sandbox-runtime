package artifactscanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

func fakeClamd(t *testing.T, reply []byte, hold <-chan struct{}) (*Clamd, <-chan []byte) {
	t.Helper()
	temporary, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp(temporary, "sr-cl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(directory) })
	socketPath := filepath.Join(directory, "clamd.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o700, SocketMode: 0o600,
		OwnerUID: uint32(os.Getuid()), DirectoryGID: uint32(os.Getgid())}
	engine, err := NewClamd(socketPath, layout)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan []byte, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
		command := make([]byte, len("zINSTREAM\x00"))
		if _, err := io.ReadFull(connection, command); err != nil || string(command) != "zINSTREAM\x00" {
			return
		}
		var content bytes.Buffer
		for {
			var length [4]byte
			if _, err := io.ReadFull(connection, length[:]); err != nil {
				return
			}
			count := binary.BigEndian.Uint32(length[:])
			if count == 0 {
				break
			}
			if count > clamdChunkBytes {
				return
			}
			chunk := make([]byte, count)
			if _, err := io.ReadFull(connection, chunk); err != nil {
				return
			}
			_, _ = content.Write(chunk)
		}
		observed <- content.Bytes()
		if hold != nil {
			<-hold
		}
		_, _ = connection.Write(reply)
	}()
	return engine, observed
}

func TestClamdINSTREAMExactVerdicts(t *testing.T) {
	for _, test := range []struct {
		name    string
		reply   []byte
		verdict MalwareVerdict
		wantErr bool
	}{
		{"clean", []byte("stream: OK\x00"), MalwareClean, false},
		{"EICAR verdict", []byte("stream: Eicar-Signature FOUND\x00"), MalwareInfected, false},
		{"stream limit", []byte("INSTREAM size limit exceeded. ERROR\x00"), "", true},
		{"missing terminator", []byte("stream: OK"), "", true},
		{"extra reply", []byte("stream: OK\x00stream: OK\x00"), "", true},
		{"empty reply", nil, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, observed := fakeClamd(t, test.reply, nil)
			verdict, err := engine.Scan(context.Background(), []byte("benign payload"))
			if verdict != test.verdict || (err != nil) != test.wantErr ||
				test.wantErr && !errors.Is(err, ErrClamdUnavailable) {
				t.Fatalf("Scan = %q, %v", verdict, err)
			}
			select {
			case content := <-observed:
				if string(content) != "benign payload" {
					t.Fatalf("stream content = %q", content)
				}
			case <-time.After(time.Second):
				t.Fatal("INSTREAM was not completed")
			}
		})
	}
}

func TestClamdCancellationAndSizeDenial(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	engine, observed := fakeClamd(t, []byte("stream: OK\x00"), hold)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := engine.Scan(ctx, []byte("held scan")); result <- err }()
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("held scan did not reach clamd")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Scan = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled scan did not close")
	}
	if _, err := engine.Scan(context.Background(), make([]byte, artifact.MaxArtifactBytes+1)); !errors.Is(err, ErrClamdUnavailable) {
		t.Fatalf("oversized Scan = %v", err)
	}
}
