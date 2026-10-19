//go:build linux

package phase6fdloader

import (
	"bytes"
	"context"
	"golang.org/x/sys/unix"
	"testing"
	"time"
)

func TestDeliveryKernelPipeAndSingleReply(t *testing.T) {
	for _, kind := range []string{"one", "two", "truncated", "open", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			var fds [2]int
			if unix.Pipe2(fds[:], unix.O_NONBLOCK) != nil {
				t.Fatal("pipe")
			}
			defer func() {
				if fds[1] >= 0 {
					unix.Close(fds[1])
				}
			}()
			if CheckReplyPipe(fds[0]) != nil {
				t.Fatal("real pipe")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 140*time.Millisecond)
			defer cancel()
			var wire bytes.Buffer
			WriteFrame(&wire, []byte(`{"signature":"fixture"}`), 128)
			if kind == "two" {
				WriteFrame(&wire, []byte(`{}`), 128)
			}
			data := wire.Bytes()
			if kind == "truncated" {
				data = data[:len(data)-1]
			}
			if _, e := unix.Write(fds[1], data); e != nil {
				t.Fatal(e)
			}
			if kind != "open" && kind != "cancel" {
				unix.Close(fds[1])
				fds[1] = -1
			}
			if kind == "cancel" {
				cancel()
			}
			start := time.Now()
			got, e := readReply(ctx, fds[0], 128)
			if kind == "one" {
				if e != nil || !bytes.Equal(got, []byte(`{"signature":"fixture"}`)) {
					t.Fatal("single reply", e)
				}
			} else if e == nil {
				t.Fatal("unsafe reply accepted")
			}
			if time.Since(start) > 600*time.Millisecond {
				t.Fatal("deadline")
			}
			if _, e := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); e == nil {
				t.Fatal("owned fd leaked")
			}
		})
	}
}
func TestDeliverySealedMetadataKernelRequirements(t *testing.T) {
	for _, kind := range []string{"valid", "size", "offset", "mode", "readonly", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			fd, e := sealedPrivateMemFD("binding", []byte(`{"binding":"fixture"}`))
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(fd)
			if _, e := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			max := 2048
			switch kind {
			case "size":
				max = 3
			case "offset":
				unix.Seek(fd, 1, 0)
			case "mode":
				unix.Fchmod(fd, 0644)
			case "readonly":
				// A plain pipe is also invalid as a sealed-metadata substitute.
				var pipes [2]int
				unix.Pipe(pipes[:])
				defer unix.Close(pipes[0])
				defer unix.Close(pipes[1])
				fd = pipes[0]
			case "cancel":
				cancel()
			}
			b, e := ReadSealedPrivate(ctx, fd, 1, max)
			if kind == "valid" {
				if e != nil || string(b) != `{"binding":"fixture"}` {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}
