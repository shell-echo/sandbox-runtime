package phase6guestreceipt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"golang.org/x/sys/unix"
)

var testDigest = "sha256:" + strings.Repeat("a", 64)

func TestSealedReceiptIsBoundedAndContiguous(t *testing.T) {
	requireLinuxReceiptPipe(t)
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	readResult := make(chan []byte, 1)
	go func() { document, _ := io.ReadAll(reader); readResult <- document }()
	recorder, err := New(writer, "product", testDigest, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	recorder.Sink(guestagent.Observation{Event: guestagent.ObservationProductAuthAccepted,
		AttemptDigest: testDigest, BindingGeneration: 2})
	recorder.Sink(guestagent.Observation{Event: guestagent.ObservationProductWelcomeWritten,
		AttemptDigest: testDigest, BindingGeneration: 2})
	recorder.Sink(guestagent.Observation{Event: guestagent.ObservationProductPeerInstalled,
		AttemptDigest: testDigest, BindingGeneration: 2})
	revokedDigest := "sha256:" + strings.Repeat("b", 64)
	recorder.Emit("product_validated_revoked", revokedDigest, 2, "")
	recorder.Sink(guestagent.Observation{Event: guestagent.ObservationProductCloseCompleted,
		AttemptDigest: testDigest, BindingGeneration: 2, Reason: "authority_stale"})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := recorder.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	document := <-readResult
	lines := bytes.Split(bytes.TrimSuffix(document, []byte{'\n'}), []byte{'\n'})
	if len(lines) != 7 {
		t.Fatalf("receipt line count = %d", len(lines))
	}
	for i, line := range lines {
		if len(line) > MaxRecordBytes {
			t.Fatal("oversized receipt")
		}
		var record Record
		if err := json.Unmarshal(line, &record); err != nil || record.Sequence != uint64(i+1) || record.Protocol != Protocol {
			t.Fatalf("record %d invalid: %v", i, err)
		}
		if i == 0 && (record.Event != "begin" || record.ProfileDigest != testDigest || record.ConfigDigest != testDigest) {
			t.Fatal("begin identity missing")
		}
		if i == len(lines)-1 && (record.Event != "seal" || record.EventCount != 5 || record.Dropped != 0) {
			t.Fatalf("terminal record invalid: %+v", record)
		}
	}
	if records, err := Verify(document, "product", testDigest, testDigest); err != nil || len(records) != len(lines) {
		t.Fatalf("complete closed receipt rejected: records=%d err=%v", len(records), err)
	}
	for name, candidate := range map[string][]byte{
		"truncated seal":   document[:len(document)-1],
		"missing seal":     document[:bytes.LastIndex(document[:len(document)-1], []byte{'\n'})+1],
		"duplicate member": bytes.Replace(document, []byte(`"protocol":`), []byte(`"protocol":"duplicate","protocol":`), 1),
		"unknown member":   bytes.Replace(document, []byte(`"role":`), []byte(`"unknown":true,"role":`), 1),
		"wrong config":     bytes.Replace(document, []byte(testDigest), []byte(revokedDigest), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(candidate, "product", testDigest, testDigest); err == nil {
				t.Fatal("incomplete or altered receipt accepted")
			}
		})
	}
}

func TestReceiptOverflowAndBlockedPipeCannotSealAsComplete(t *testing.T) {
	requireLinuxReceiptPipe(t)
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	recorder, err := New(writer, "guest", testDigest, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for range MaxEvents + MaxQueued + 10 {
		recorder.Emit(guestagent.ObservationGuestHelloWritten, testDigest, 1, "")
	}
	if time.Since(start) > time.Second {
		t.Fatal("callback blocked on unread stdout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := recorder.Seal(ctx); err == nil {
		t.Fatal("dropped/blocked stdout produced a complete seal")
	}
	select {
	case <-recorder.done:
	case <-time.After(time.Second):
		t.Fatal("blocked writer did not join")
	}
}

func TestReceiptBlockedWriterJoinsWithinDeadline(t *testing.T) {
	requireLinuxReceiptPipe(t)
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	fillReceiptPipe(t, writer)
	recorder, err := New(writer, "guest", testDigest, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if err := recorder.Seal(ctx); err == nil {
		t.Fatal("unread stdout was accepted as complete evidence")
	}
	if time.Since(start) > time.Second {
		t.Fatal("blocked writer exceeded bounded join")
	}
	select {
	case <-recorder.done:
	default:
		t.Fatal("blocked writer remained live")
	}
}

func TestReceiptCancellationJoinsBlockedWriter(t *testing.T) {
	requireLinuxReceiptPipe(t)
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	fillReceiptPipe(t, writer)
	recorder, err := New(writer, "guest", testDigest, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := recorder.Seal(ctx); err == nil || time.Since(start) > time.Second {
		t.Fatal("cancelled writer was not joined within the shutdown budget")
	}
	select {
	case <-recorder.done:
	default:
		t.Fatal("writer goroutine remained live after cancellation")
	}
}

func TestReceiptRejectsInvalidRoleDigestEventAndTTY(t *testing.T) {
	requireLinuxReceiptPipe(t)
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	if _, err := New(writer, "provider", testDigest, testDigest); err == nil {
		t.Fatal("wrong role admitted")
	}
	if _, err := New(writer, "guest", "sha256:bad", testDigest); err == nil {
		t.Fatal("invalid profile digest admitted")
	}
	regular, err := os.CreateTemp(t.TempDir(), "regular-output-")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if _, err := New(regular, "guest", testDigest, testDigest); err == nil {
		t.Fatal("regular output admitted")
	}
	recorder, err := New(writer, "guest", testDigest, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	recorder.Emit("free-form-error-message", testDigest, 1, "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := recorder.Seal(ctx); err == nil {
		t.Fatal("unknown event was not sticky-invalid")
	}
}

func requireLinuxReceiptPipe(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("private receipt writer is Linux-local-candidate only; real Docker gate runs Linux probe")
	}
}

func receiptTestPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	return os.NewFile(uintptr(fds[0]), "receipt-test-reader"), os.NewFile(uintptr(fds[1]), "receipt-test-writer")
}

func fillReceiptPipe(t *testing.T, writer *os.File) {
	t.Helper()
	raw, err := writer.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var source int
	if err := raw.Control(func(fd uintptr) { source = int(fd) }); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(source), unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	block := make([]byte, 4096)
	for total := 0; total < 1<<20; {
		count, err := unix.Write(fd, block)
		total += count
		if errors.Is(err, unix.EAGAIN) {
			return
		}
		if err != nil || count == 0 {
			t.Fatal("test pipe could not be filled without blocking")
		}
	}
	t.Fatal("test pipe did not reach backpressure")
}
