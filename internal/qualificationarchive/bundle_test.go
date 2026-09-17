package qualificationarchive

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

func TestWriteEnvelopeIsCanonicalBoundAndNonOverwriting(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "qualification-result.json")
	input := testEnvelopeInput(t)
	digest, err := WriteEnvelope(destination, input)
	if err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(destination)
	if err != nil || digest != rawDigest(document) || document[len(document)-1] != '\n' {
		t.Fatalf("envelope digest=%q read=%v", digest, err)
	}
	if _, err := WriteEnvelope(destination, input); err == nil {
		t.Fatal("existing envelope was overwritten")
	}
	retained, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(retained, document) {
		t.Fatalf("existing envelope changed: %v", err)
	}
}

func TestWriteEnvelopeRejectsUnboundTrustedRevision(t *testing.T) {
	input := testEnvelopeInput(t)
	input.TrustedInputs[0].Statement["source_revision"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	// Keep the subject internally valid: envelope validation must still reject
	// the mismatch against ExternalRevision.
	input.TrustedInputs[0].SubjectDigest = statementDigest(t, input.TrustedInputs[0].Statement)
	destination := filepath.Join(t.TempDir(), "qualification-result.json")
	if _, err := WriteEnvelope(destination, input); err == nil {
		t.Fatal("unbound trusted revision was accepted")
	}
}

func testEnvelopeInput(t *testing.T) EnvelopeInput {
	t.Helper()
	external := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	provider := "cccccccccccccccccccccccccccccccccccccccc"
	statements := []TrustedInputSubject{
		{InputID: "external-caller-ownership", Source: "external_caller_owner", Statement: map[string]any{"source_revision": external}},
		{InputID: "source-hosting", Source: "external_caller_owner", Statement: map[string]any{"source_revision": external}},
		{InputID: "build-system", Source: "external_caller_owner", Statement: map[string]any{"build": "exact"}},
		{InputID: "operating-system", Source: "qualification_operator", Statement: map[string]any{"provider_source_revision": provider}},
		{InputID: "network-path", Source: "qualification_operator", Statement: map[string]any{"network": "observed"}},
	}
	for index := range statements {
		statements[index].SubjectDigest = statementDigest(t, statements[index].Statement)
	}
	return EnvelopeInput{
		ProfileID: "sandbox-runtime-external-caller-coding-shell-v1", ProfileVersion: "1.0.0",
		ProfileDigest:    "sha256:ec113d31612dbb7cc0e9461925170f74f33722bb2efb237dbc68aa89f2d60231",
		ProviderRevision: provider, ExternalRevision: external,
		CheckpointPath: "/result/execution-checkpoint.json", CheckpointDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Archive:       Result{Path: "/result/qualification-evidence.tar", Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Bytes: 1024, Files: 7},
		Evidence:      qualificationreport.Result{ReportID: "report", ReportDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", PayloadInventory: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", ReceiptFile: "receipt.json", RunOutcome: "passed", ValidationOutcome: "accepted", FileCount: 7, TotalBytes: 512},
		TrustedInputs: statements, CompletedAt: time.Date(2026, 9, 17, 1, 2, 3, 0, time.UTC),
	}
}

func statementDigest(t *testing.T, statement map[string]any) string {
	t.Helper()
	document, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		t.Fatal(err)
	}
	return rawDigest(canonical)
}
