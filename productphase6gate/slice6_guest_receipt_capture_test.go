//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

// This collector is an E-only attached Docker stdout consumer. The container
// must have log-driver=none, no TTY, and its exact image/config/profile must be
// independently inspected by the caller. No runtime mount or wire endpoint is
// added. Unexpected output is retained only in a private bounded file and is
// never included in diagnostics.
type slice6GuestReceiptCapture struct {
	cmd      *exec.Cmd
	cancel   context.CancelFunc
	file     *os.File
	output   *slice6ReceiptBoundedFile
	done     chan struct{}
	waitErr  error
	path     string
	role     string
	profile  string
	config   string
	finalize sync.Once
}

type slice6GuestReceiptPair struct {
	Product []phase6guestreceipt.Record
	Guest   []phase6guestreceipt.Record
}

// The joined PG mutation fixture independently proves the row was revoked.
// These independently captured PID1 streams prove the original accepted
// connection was closed and a fresh signed retry was rejected as revoked.
func (pair slice6GuestReceiptPair) verifyRevoke(generation int64) error {
	if generation < 1 || len(pair.Product) < 2 || len(pair.Guest) < 2 {
		return phase6guestreceipt.ErrUnavailable
	}
	product := make(map[string]map[string]phase6guestreceipt.Record)
	guest := make(map[string]map[string]phase6guestreceipt.Record)
	for _, item := range pair.Product[1 : len(pair.Product)-1] {
		if item.BindingGeneration != generation {
			return phase6guestreceipt.ErrUnavailable
		}
		if product[item.AttemptDigest] == nil {
			product[item.AttemptDigest] = make(map[string]phase6guestreceipt.Record)
		}
		product[item.AttemptDigest][item.Event] = item
	}
	for _, item := range pair.Guest[1 : len(pair.Guest)-1] {
		if item.BindingGeneration != generation {
			return phase6guestreceipt.ErrUnavailable
		}
		if guest[item.AttemptDigest] == nil {
			guest[item.AttemptDigest] = make(map[string]phase6guestreceipt.Record)
		}
		guest[item.AttemptDigest][item.Event] = item
	}
	acceptedDigest := ""
	for digest, events := range product {
		if len(events) != 5 {
			continue
		}
		if _, ok := events["product_auth_accepted"]; !ok {
			continue
		}
		if _, ok := events["product_welcome_written"]; !ok {
			continue
		}
		if _, ok := events["product_peer_installed"]; !ok {
			continue
		}
		if _, ok := events["product_authority_stale"]; !ok {
			continue
		}
		if close, ok := events["product_close_completed"]; !ok || close.Reason != "authority_stale" ||
			events["product_authority_stale"].Sequence >= close.Sequence {
			continue
		}
		if len(guest[digest]) != 3 {
			continue
		}
		if _, ok := guest[digest]["guest_hello_written"]; !ok {
			continue
		}
		if _, ok := guest[digest]["guest_welcome_accepted"]; !ok {
			continue
		}
		if _, ok := guest[digest]["guest_read_terminated"]; !ok {
			continue
		}
		if acceptedDigest != "" {
			return phase6guestreceipt.ErrUnavailable
		}
		acceptedDigest = digest
	}
	if acceptedDigest == "" || len(product) != 2 || len(guest) != 2 {
		return phase6guestreceipt.ErrUnavailable
	}
	rejected := false
	for digest, events := range product {
		if digest == acceptedDigest {
			continue
		}
		if _, ok := events["product_validated_revoked"]; !ok {
			continue
		}
		if len(events) != 1 || len(guest[digest]) != 1 {
			return phase6guestreceipt.ErrUnavailable
		}
		if hello, ok := guest[digest]["guest_hello_written"]; !ok ||
			hello.Sequence <= guest[acceptedDigest]["guest_read_terminated"].Sequence ||
			events["product_validated_revoked"].Sequence <= product[acceptedDigest]["product_close_completed"].Sequence {
			return phase6guestreceipt.ErrUnavailable
		}
		if rejected {
			return phase6guestreceipt.ErrUnavailable
		}
		rejected = true
	}
	if !rejected {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

type slice6ReceiptBoundedFile struct {
	mu       sync.Mutex
	file     *os.File
	written  int
	overflow bool
}

func (output *slice6ReceiptBoundedFile) Write(value []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.overflow || output.written+len(value) > phase6guestreceipt.MaxTotalBytes {
		output.overflow = true
		return 0, phase6guestreceipt.ErrUnavailable
	}
	n, err := output.file.Write(value)
	output.written += n
	return n, err
}

func slice6ReceiptConfigDigest(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func slice6StartGuestReceiptCapture(t *testing.T, parent context.Context, id, role,
	profileDigest, configDigest string) (*slice6GuestReceiptCapture, error) {
	t.Helper()
	if parent == nil || parent.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) ||
		(role != "product" && role != "guest") ||
		!guestRevokeFixtureDigestGate(profileDigest) || !guestRevokeFixtureDigestGate(configDigest) {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	privateDir, err := os.MkdirTemp(t.TempDir(), "receipt-")
	if err != nil {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	info, err := os.Lstat(privateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	path := filepath.Join(privateDir, role+"-pid1.stdout")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	output := &slice6ReceiptBoundedFile{file: file}
	command := exec.CommandContext(ctx, "docker", "start", "-a", id)
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		cancel()
		file.Close()
		return nil, phase6guestreceipt.ErrUnavailable
	}
	capture := &slice6GuestReceiptCapture{cmd: command, cancel: cancel, file: file,
		output: output, done: make(chan struct{}), path: path, role: role,
		profile: profileDigest, config: configDigest}
	go func() {
		capture.waitErr = command.Wait()
		close(capture.done)
	}()
	return capture, nil
}

func (capture *slice6GuestReceiptCapture) abort() {
	if capture == nil {
		return
	}
	capture.cancel()
	<-capture.done
	capture.finalize.Do(func() { _ = capture.file.Close() })
}

func (capture *slice6GuestReceiptCapture) verifyStopped(ctx context.Context, run slice6DockerRun,
	id string, expectedExit int) ([]phase6guestreceipt.Record, error) {
	if capture == nil || ctx == nil || ctx.Err() != nil || expectedExit < 0 || expectedExit > 255 {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	select {
	case <-capture.done:
	case <-ctx.Done():
		capture.abort()
		return nil, phase6guestreceipt.ErrUnavailable
	}
	capture.finalize.Do(func() { _ = capture.file.Close() })
	defer capture.cancel()
	if capture.output.overflow || capture.output.written == 0 ||
		capture.output.written > phase6guestreceipt.MaxTotalBytes {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	if expectedExit == 0 && capture.waitErr != nil {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	if expectedExit != 0 {
		var exit *exec.ExitError
		if !errors.As(capture.waitErr, &exit) || exit.ExitCode() != expectedExit {
			return nil, phase6guestreceipt.ErrUnavailable
		}
	}
	state, err, overflow := slice6DockerBounded(ctx, 128, nil, "inspect", "--format",
		"{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}", id)
	defer clear(state)
	if err != nil || overflow || string(state) != "false "+strconv.Itoa(expectedExit)+" false\n" {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	document, err := os.ReadFile(capture.path)
	if err != nil || len(document) != capture.output.written {
		clear(document)
		return nil, phase6guestreceipt.ErrUnavailable
	}
	defer clear(document)
	return phase6guestreceipt.Verify(document, capture.role, capture.profile, capture.config)
}

func slice6StopReceiptContainer(ctx context.Context, run slice6DockerRun, id string) error {
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return phase6guestreceipt.ErrUnavailable
	}
	output, err, overflow := slice6DockerBounded(ctx, 128, nil, "stop", "--time", "10", id)
	defer clear(output)
	if err != nil || overflow || strings.TrimSpace(string(output)) != id {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}
