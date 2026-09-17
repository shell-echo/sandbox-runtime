package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

func TestRunVerifiesEvidenceAndPrintsSanitizedResult(t *testing.T) {
	originalVerify := verifyQualificationReport
	t.Cleanup(func() { verifyQualificationReport = originalVerify })

	verifyQualificationReport = func(ctx context.Context, evidenceRoot, sourceRoot string) (qualificationreport.Result, error) {
		if err := ctx.Err(); err != nil {
			t.Fatalf("verification context is already canceled: %v", err)
		}
		if got, want := evidenceRoot, "/evidence"; got != want {
			t.Fatalf("evidence root = %q, want %q", got, want)
		}
		if got, want := sourceRoot, "/source"; got != want {
			t.Fatalf("source root = %q, want %q", got, want)
		}
		return qualificationreport.Result{
			ReportID:          "report-123",
			ReportDigest:      "sha256:report",
			PayloadInventory:  "sha256:inventory",
			ReceiptFile:       "receipt.json",
			RunOutcome:        "passed",
			ValidationOutcome: "accepted",
			FileCount:         4,
			TotalBytes:        1024,
		}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if got := run([]string{"-source-root", "/source", "-evidence-root", "/evidence"}, &stdout, &stderr); got != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", got, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	for _, expected := range []string{
		"report-123",
		"sha256:report",
		"sha256:inventory",
		"run passed",
		"4 files",
		"1024 bytes",
		"validation accepted",
		"receipt.json",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("stdout %q does not contain %q", stdout.String(), expected)
		}
	}
}

func TestRunReadOnlyVerifiesRetainedReceipt(t *testing.T) {
	original := verifyRetainedQualificationReport
	t.Cleanup(func() { verifyRetainedQualificationReport = original })
	called := false
	verifyRetainedQualificationReport = func(ctx context.Context, evidenceRoot, sourceRoot string) (qualificationreport.Result, error) {
		called = true
		return qualificationreport.Result{
			ReportID: "report-retained", ReportDigest: "sha256:report",
			PayloadInventory: "sha256:inventory", ReceiptFile: "receipt.json",
			RunOutcome: "passed", ValidationOutcome: "accepted", FileCount: 7, TotalBytes: 2048,
		}, nil
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if got := run([]string{"-retained", "-source-root", "/source", "-evidence-root", "/evidence"}, &stdout, &stderr); got != 0 || !called {
		t.Fatalf("run() exit=%d called=%v stderr=%q", got, called, stderr.String())
	}
}

func TestRunRequiresEvidenceRoot(t *testing.T) {
	originalVerify := verifyQualificationReport
	t.Cleanup(func() { verifyQualificationReport = originalVerify })
	verifyQualificationReport = func(context.Context, string, string) (qualificationreport.Result, error) {
		t.Fatal("Verify called without an evidence root")
		return qualificationreport.Result{}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if got := run(nil, &stdout, &stderr); got != 2 {
		t.Fatalf("run() exit code = %d, want 2", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "-evidence-root is required") {
		t.Fatalf("stderr = %q, want required-flag error", stderr.String())
	}
}

func TestRunRejectsPositionalArguments(t *testing.T) {
	originalVerify := verifyQualificationReport
	t.Cleanup(func() { verifyQualificationReport = originalVerify })
	verifyQualificationReport = func(context.Context, string, string) (qualificationreport.Result, error) {
		t.Fatal("Verify called with a positional argument")
		return qualificationreport.Result{}, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if got := run([]string{"-evidence-root", "/evidence", "unexpected"}, &stdout, &stderr); got != 2 {
		t.Fatalf("run() exit code = %d, want 2", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "positional arguments are not supported") {
		t.Fatalf("stderr = %q, want positional-argument error", stderr.String())
	}
}

func TestRunWritesVerificationErrorsOnlyToStderr(t *testing.T) {
	originalVerify := verifyQualificationReport
	t.Cleanup(func() { verifyQualificationReport = originalVerify })
	verifyQualificationReport = func(context.Context, string, string) (qualificationreport.Result, error) {
		return qualificationreport.Result{}, errors.New("rejected evidence marker")
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if got := run([]string{"-evidence-root", "/evidence"}, &stdout, &stderr); got != 1 {
		t.Fatalf("run() exit code = %d, want 1", got)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "verify-qualification-report: rejected evidence marker") {
		t.Fatalf("stderr = %q, want verification error", stderr.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestRunReturnsFailureWhenResultCannotBeWritten(t *testing.T) {
	originalVerify := verifyQualificationReport
	t.Cleanup(func() { verifyQualificationReport = originalVerify })
	verifyQualificationReport = func(context.Context, string, string) (qualificationreport.Result, error) {
		return qualificationreport.Result{ValidationOutcome: "accepted"}, nil
	}

	var stderr bytes.Buffer
	if got := run([]string{"-evidence-root", "/evidence"}, failingWriter{}, &stderr); got != 1 {
		t.Fatalf("run() exit code = %d, want 1", got)
	}
	if !strings.Contains(stderr.String(), "result_write_failed") {
		t.Fatalf("stderr = %q, want output error", stderr.String())
	}
}
