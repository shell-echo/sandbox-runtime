package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"golang.org/x/sys/unix"
)

func main() {
	digest := "sha256:" + strings.Repeat("a", 64)
	if os.Getenv("PHASE6_RECEIPT_PROBE_FULL") == "1" {
		if !saturateUnreadStdout() {
			os.Exit(4)
		}
	}
	recorder, err := phase6guestreceipt.New(os.Stdout, "guest", digest, digest)
	if err != nil {
		os.Exit(2)
	}
	if os.Getenv("PHASE6_RECEIPT_PROBE_ABORT") == "1" {
		recorder.Emit(guestagent.ObservationGuestHelloWritten, digest, 1, "")
		recorder.Abort()
		recorder.Emit(guestagent.ObservationGuestWelcomeAccepted, digest, 1, "")
		if recorder.Seal(context.Background()) == nil {
			os.Exit(5)
		}
		return
	}
	for index := range 16 {
		sum := sha256.Sum256([]byte(strconv.Itoa(index)))
		recorder.Emit(guestagent.ObservationGuestHelloWritten, "sha256:"+hex.EncodeToString(sum[:]), 1, "")
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if recorder.Seal(ctx) != nil {
		writeStatus("writer_joined_invalid")
		os.Exit(3)
	}
	writeStatus("writer_joined_valid")
}

func writeStatus(value string) {
	if os.Getenv("PHASE6_RECEIPT_PROBE_FULL") != "1" {
		return
	}
	file, err := os.OpenFile("/status/terminal", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = file.WriteString(value + "\n")
	_ = file.Close()
}

func saturateUnreadStdout() bool {
	fd, err := unix.Open("/proc/self/fd/1", unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	block := make([]byte, 4096)
	for index := range block {
		block[index] = 'x'
	}
	deadline := time.Now().Add(2 * time.Second)
	var blockedSince time.Time
	for total := 0; total < 32<<20 && time.Now().Before(deadline); {
		count, err := unix.Write(fd, block)
		total += count
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			if blockedSince.IsZero() {
				blockedSince = time.Now()
			}
			if time.Since(blockedSince) >= 300*time.Millisecond {
				return true
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil || count == 0 {
			return false
		}
		blockedSince = time.Time{}
	}
	return false
}
