package phase6fdloader

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDeadlineInputRequiresActualEOFAndBoundsOpenStreams(t *testing.T) {
	for _, test := range []struct {
		name   string
		prefix []byte
		slow   bool
	}{
		{name: "open empty"},
		{name: "open prefix", prefix: []byte(`{"protocol":`)},
		{name: "slow continuous input", slow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			if err := unix.SetNonblock(int(reader.Fd()), true); err != nil {
				t.Fatal(err)
			}
			if len(test.prefix) != 0 {
				if _, err := writer.Write(test.prefix); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 130*time.Millisecond)
			defer cancel()
			if test.slow {
				go func() {
					for ctx.Err() == nil {
						_, _ = writer.Write([]byte{'x'})
						time.Sleep(20 * time.Millisecond)
					}
				}()
			}
			started := time.Now()
			content, err := io.ReadAll(deadlineInput{ctx: ctx, fd: int(reader.Fd())})
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 600*time.Millisecond ||
				!bytes.HasPrefix(content, test.prefix) {
				t.Fatalf("open stream did not obey the original deadline: length=%d error=%v", len(content), err)
			}
		})
	}
}

func TestDeadlineInputReadsHUPTailAndCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := unix.SetNonblock(int(reader.Fd()), true); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("final-data"), 100)
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	content, err := io.ReadAll(deadlineInput{ctx: ctx, fd: int(reader.Fd())})
	if err != nil || !bytes.Equal(content, payload) {
		t.Fatalf("HUP discarded pending input: length=%d error=%v", len(content), err)
	}
	cancelled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := (deadlineInput{ctx: cancelled, fd: int(reader.Fd())}).Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled input remained readable: %v", err)
	}
}

func TestDeadlineInputPreservesClosedEnvelopeValidation(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	expected := Expected{RunID: strings.Repeat("b", 32), Target: "workload-tls-agent",
		Nonce: strings.Repeat("c", 32), ContainerHostname: containerID[:12]}
	valid, err := json.Marshal(Envelope{Protocol: ProtocolID, RunID: expected.RunID,
		Target: expected.Target, ContainerID: containerID, Nonce: expected.Nonce,
		Config: []byte(`{"protocol":"test"}`), Files: []PrivateFile{{FD: 3, Data: bytes.Repeat([]byte{1}, 64)}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		value    []byte
		accepted bool
	}{
		{name: "valid final bytes with HUP", value: valid, accepted: true},
		{name: "truncated final bytes with HUP", value: valid[:len(valid)-1]},
		{name: "oversized closed input", value: bytes.Repeat([]byte{'x'}, MaxEnvelopeBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if err := unix.SetNonblock(int(reader.Fd()), true); err != nil {
				t.Fatal(err)
			}
			writerDone := make(chan struct{})
			go func() {
				_, _ = writer.Write(test.value)
				_ = writer.Close()
				close(writerDone)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			value, err := Decode(deadlineInput{ctx: ctx, fd: int(reader.Fd())}, expected)
			value.Destroy()
			_ = reader.Close()
			<-writerDone
			if (err == nil) != test.accepted {
				t.Fatalf("closed envelope acceptance = %v, want %v", err == nil, test.accepted)
			}
		})
	}
}
