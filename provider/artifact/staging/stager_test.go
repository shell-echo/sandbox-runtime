package staging

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

var stagerTestTime = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

type testOutputReader struct {
	content []byte
	err     error
}

func (r testOutputReader) OpenOutput(context.Context, string, int64, string) (artifact.Output, error) {
	if r.err != nil {
		return artifact.Output{}, r.err
	}
	return artifact.Output{Content: io.NopCloser(bytes.NewReader(r.content)), SizeBytes: int64(len(r.content))}, nil
}

type testTenantChecker struct{ status artifact.CheckStatus }

func (c testTenantChecker) CheckTenantBinding(context.Context, artifact.Request) (artifact.CheckStatus, error) {
	return c.status, nil
}

type testContentChecker struct {
	status artifact.CheckStatus
	err    error
	calls  int
	after  func()
}

func (c *testContentChecker) CheckContent(context.Context, artifact.Request, []byte) (artifact.CheckStatus, error) {
	c.calls++
	if c.after != nil {
		c.after()
	}
	return c.status, c.err
}

func TestStagerStagesCheckedBytesUnderOpaqueReference(t *testing.T) {
	content := []byte("hello\n")
	active := &testContentChecker{status: artifact.CheckPassed}
	malware := &testContentChecker{status: artifact.CheckPassed}
	root := t.TempDir()
	stager, err := New(testOutputReader{content: content}, testTenantChecker{status: artifact.CheckPassed}, active, malware, root, ClockFunc(func() time.Time { return stagerTestTime }))
	if err != nil {
		t.Fatal(err)
	}
	request := stagingRequest(content)
	evidence, err := stager.Stage(context.Background(), request, stagerTestTime)
	if err != nil || evidence.Status != artifact.StatusStaged || !strings.HasPrefix(evidence.StagingReference, "ref:staging/") || strings.Contains(evidence.StagingReference, root) {
		t.Fatalf("Stage() = %#v, %v", evidence, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatalf("staging entries = %#v, %v", entries, err)
	}
	staged, err := os.ReadFile(filepath.Join(root, entries[0].Name()))
	if err != nil || !bytes.Equal(staged, content) || active.calls != 1 || malware.calls != 1 {
		t.Fatalf("staged bytes/checks = %q, %v, %d/%d", staged, err, active.calls, malware.calls)
	}
}

func TestStagerRetainsActualMismatchWithoutRunningScanners(t *testing.T) {
	content := []byte("hello")
	active := &testContentChecker{status: artifact.CheckPassed}
	malware := &testContentChecker{status: artifact.CheckPassed}
	stager, _ := New(testOutputReader{content: content}, testTenantChecker{status: artifact.CheckPassed}, active, malware, t.TempDir(), ClockFunc(func() time.Time { return stagerTestTime }))
	request := stagingRequest(content)
	request.MaxBytes = 2
	evidence, err := stager.Stage(context.Background(), request, stagerTestTime)
	if err != nil || evidence.Status != artifact.StatusRejected || evidence.SizeBytes != int64(len(content)) || evidence.ContentDigest != digest(content) || active.calls != 0 || malware.calls != 0 {
		t.Fatalf("mismatch Stage() = %#v, %v; calls=%d/%d", evidence, err, active.calls, malware.calls)
	}
}

func TestStagerRejectsChecksAndPreservesUnknownScannerFailure(t *testing.T) {
	content := []byte("hello")
	request := stagingRequest(content)
	for _, test := range []struct {
		name      string
		active    *testContentChecker
		wantState artifact.Status
		wantErr   bool
	}{
		{name: "rejected", active: &testContentChecker{status: artifact.CheckFailed}, wantState: artifact.StatusRejected},
		{name: "unavailable", active: &testContentChecker{status: artifact.CheckNotRun, err: errors.New("scanner unavailable")}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			stager, _ := New(testOutputReader{content: content}, testTenantChecker{status: artifact.CheckPassed}, test.active, &testContentChecker{status: artifact.CheckPassed}, t.TempDir(), ClockFunc(func() time.Time { return stagerTestTime }))
			evidence, err := stager.Stage(context.Background(), request, stagerTestTime)
			if (err != nil) != test.wantErr || !test.wantErr && evidence.Status != test.wantState {
				t.Fatalf("Stage() = %#v, %v", evidence, err)
			}
		})
	}
}

func TestStagerStopsWhenRetentionExpiresDuringChecks(t *testing.T) {
	now := stagerTestTime
	content := []byte("hello")
	request := stagingRequest(content)
	request.Retention = time.Second
	active := &testContentChecker{status: artifact.CheckPassed, after: func() { now = stagerTestTime.Add(time.Second) }}
	malware := &testContentChecker{status: artifact.CheckPassed}
	root := t.TempDir()
	stager, err := New(testOutputReader{content: content}, testTenantChecker{status: artifact.CheckPassed}, active, malware, root, ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Stage(context.Background(), request, stagerTestTime); !errors.Is(err, artifact.ErrDeadlineExpired) {
		t.Fatalf("Stage() error = %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 || malware.calls != 0 {
		t.Fatalf("expired staging entries=%d malware_calls=%d error=%v", len(entries), malware.calls, err)
	}
}

func TestCommandCheckerUsesExitStatus(t *testing.T) {
	request := stagingRequest([]byte("hello"))
	passing, err := NewCommandChecker([]string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if status, err := passing.CheckContent(context.Background(), request, []byte("hello")); err != nil || status != artifact.CheckPassed {
		t.Fatalf("passing checker = %s, %v", status, err)
	}
	rejecting, err := NewCommandChecker([]string{"false"})
	if err != nil {
		t.Fatal(err)
	}
	if status, err := rejecting.CheckContent(context.Background(), request, []byte("hello")); err != nil || status != artifact.CheckFailed {
		t.Fatalf("rejecting checker = %s, %v", status, err)
	}
}

func stagingRequest(content []byte) artifact.Request {
	return artifact.Request{
		SandboxID: "sandbox-1", TenantID: "tenant-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 2, ExpectedGeneration: 1, IdempotencyKey: "key-1",
		RequestDigest: "sha256:" + strings.Repeat("a", 64), Deadline: stagerTestTime.Add(time.Hour),
		ArtifactReference: "artifact-ref:platform/artifact-1", SourcePath: "/outputs/report.txt",
		ExpectedDigest: digest(content), ExpectedMediaType: "text/plain", MaxBytes: 1024, Retention: 30 * time.Minute,
	}
}
