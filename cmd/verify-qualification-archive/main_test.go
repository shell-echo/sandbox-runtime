package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationarchive"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

func TestRunVerifiesClosedBundle(t *testing.T) {
	original := verifyQualificationBundle
	t.Cleanup(func() { verifyQualificationBundle = original })
	verifyQualificationBundle = func(ctx context.Context, source, checkpoint, archive, envelope string) (qualificationarchive.BundleResult, error) {
		if ctx.Err() != nil || source != "/source" || checkpoint != "/result/execution-checkpoint.json" || archive != "/result/qualification-evidence.tar" || envelope != "/result/qualification-result.json" {
			t.Fatalf("unexpected verification call: %q %q %q %q", source, checkpoint, archive, envelope)
		}
		return qualificationarchive.BundleResult{
			EnvelopeDigest: "sha256:envelope", ArchiveDigest: "sha256:archive",
			Evidence: qualificationreport.Result{ReportDigest: "sha256:report", RunOutcome: "passed", ValidationOutcome: "accepted", FileCount: 7, TotalBytes: 4096},
		}, nil
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"-source-root", "/source", "-checkpoint", "/result/execution-checkpoint.json", "-archive", "/result/qualification-evidence.tar", "-envelope", "/result/qualification-result.json"}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	for _, want := range []string{"sha256:envelope", "sha256:archive", "sha256:report", "run passed", "validation accepted", "7 files", "4096 bytes"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout %q does not contain %q", stdout.String(), want)
		}
	}
}

func TestRunRejectsMissingInputsAndVerificationFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "are required") {
		t.Fatalf("missing inputs exit=%d stderr=%q", code, stderr.String())
	}
	original := verifyQualificationBundle
	t.Cleanup(func() { verifyQualificationBundle = original })
	verifyQualificationBundle = func(context.Context, string, string, string, string) (qualificationarchive.BundleResult, error) {
		return qualificationarchive.BundleResult{}, errors.New("rejected")
	}
	stdout.Reset()
	stderr.Reset()
	code := run([]string{"-checkpoint", "/c", "-archive", "/a", "-envelope", "/e"}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "rejected") {
		t.Fatalf("failure exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
