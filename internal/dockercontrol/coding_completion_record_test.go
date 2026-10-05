package dockercontrol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

const codingPrivateProofSchema = "sandbox-runtime.test-only-coding-physical-proof.v1"
const codingRawOCIFixtureReference = "internal/dockercontrol/testdata/coding-oci-arm64-v8"

type codingDiagnosticTraceItem struct {
	Seq      int    `json:"seq"`
	Category string `json:"category"`
	Status   int    `json:"status"`
	Error    bool   `json:"error"`
}

type codingPrivateProofRecord struct {
	Schema                string                      `json:"schema"`
	Source                string                      `json:"source"`
	EffectID              string                      `json:"effect_id"`
	ReceiptRevision       uint64                      `json:"receipt_revision"`
	CapturedAt            time.Time                   `json:"captured_at"`
	RawOCIReference       string                      `json:"raw_oci_reference"`
	RawOCIIndexDigest     string                      `json:"raw_oci_index_digest"`
	RawOCIManifestDigest  string                      `json:"raw_oci_manifest_digest"`
	RawOCIConfigDigest    string                      `json:"raw_oci_config_digest"`
	PreviousFailureStage  string                      `json:"previous_failure_stage"`
	PreviousReadOnlyProof string                      `json:"previous_read_only_proof"`
	Trace                 []codingDiagnosticTraceItem `json:"trace"`
	Proof                 codingCompletionObservation `json:"proof"`
}

func newCodingPrivateProofRecord(proof codingCompletionObservation,
	trace []codingDiagnosticTraceItem, capturedAt time.Time) codingPrivateProofRecord {
	return codingPrivateProofRecord{Schema: codingPrivateProofSchema,
		Source:   "TestCodingExistingUnknownReadOnlyDiagnosis/test-only-fixed-Unix-effect",
		EffectID: proof.EffectID, ReceiptRevision: proof.ReceiptRevision,
		CapturedAt: capturedAt.UTC(), RawOCIReference: codingRawOCIFixtureReference,
		RawOCIIndexDigest:     codingimage.PublishedDigest,
		RawOCIManifestDigest:  codingimage.PublishedARM64V8Digest,
		RawOCIConfigDigest:    codingimage.PublishedARM64ConfigDigest,
		PreviousFailureStage:  "initial-inventory",
		PreviousReadOnlyProof: "sha256:dda5c571f7115857fb755db1c50c035a20d0250eda9a6e313ca7e1cfd005254f",
		Trace:                 append([]codingDiagnosticTraceItem(nil), trace...), Proof: proof}
}

func (r codingPrivateProofRecord) recheck(binding CodingReceiptBinding,
	authority CodingCreateAuthority, template phase6security.CodingRuntimeTemplateV2,
	documents phase6security.ImageDescriptorDocuments, policy []byte,
	current CodingReceiptState) error {
	if r.Schema != codingPrivateProofSchema ||
		r.Source != "TestCodingExistingUnknownReadOnlyDiagnosis/test-only-fixed-Unix-effect" ||
		r.EffectID != authority.EffectID || r.ReceiptRevision != current.Revision ||
		r.CapturedAt.IsZero() || r.RawOCIReference != codingRawOCIFixtureReference ||
		r.RawOCIIndexDigest != codingimage.PublishedDigest ||
		r.RawOCIManifestDigest != codingimage.PublishedARM64V8Digest ||
		r.RawOCIConfigDigest != codingimage.PublishedARM64ConfigDigest ||
		r.PreviousFailureStage != "initial-inventory" ||
		r.PreviousReadOnlyProof != "sha256:dda5c571f7115857fb755db1c50c035a20d0250eda9a6e313ca7e1cfd005254f" ||
		current.Validate(binding) != nil || len(current.Records) != 1 ||
		current.Records[0].Status != ReceiptUnknown ||
		current.Records[0].Authority != authority ||
		len(r.Trace) != 23 || r.Proof.EffectID != r.EffectID ||
		r.Proof.ReceiptRevision != r.ReceiptRevision ||
		r.Proof.recheck(binding, authority, template, documents, policy) != nil {
		return ErrInvalidCodingCompletionObservation
	}
	for index, entry := range r.Trace {
		wantStatus := 200
		if index == 1 || index == 15 {
			wantStatus = 404
		}
		if entry.Seq != index+1 || entry.Category == "" || entry.Category == "unreviewed" ||
			entry.Error || entry.Status != wantStatus {
			return ErrInvalidCodingCompletionObservation
		}
	}
	return nil
}

// File creation is exclusive, private from birth, fsynced, and followed by a
// separate readback. This is component-test evidence, not the Control ledger.
func writeAndReadCodingPrivateProof(path string, record codingPrivateProofRecord) (codingPrivateProofRecord, error) {
	readback, err := writeAndReadCodingPrivateJSON(path, record)
	if err != nil {
		return codingPrivateProofRecord{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(readback))
	decoder.DisallowUnknownFields()
	var decoded codingPrivateProofRecord
	if decoder.Decode(&decoded) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) ||
		!reflect.DeepEqual(decoded, record) {
		return codingPrivateProofRecord{}, ErrInvalidCodingCompletionObservation
	}
	return decoded, nil
}

func writeAndReadCodingPrivateJSON(path string, value any) ([]byte, error) {
	if !validReceiptPath(path) {
		return nil, ErrInvalidCodingCompletionObservation
	}
	document, err := json.Marshal(value)
	if err != nil || len(document) < 1 || len(document) > 1<<20 {
		return nil, ErrInvalidCodingCompletionObservation
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, ErrInvalidCodingCompletionObservation
	}
	written, writeErr := file.Write(document)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(document) {
		return nil, ErrInvalidCodingCompletionObservation
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, ErrInvalidCodingCompletionObservation
	}
	dirSyncErr := directory.Sync()
	dirCloseErr := directory.Close()
	if dirSyncErr != nil || dirCloseErr != nil {
		return nil, ErrInvalidCodingCompletionObservation
	}
	info, err := os.Lstat(path)
	if err != nil || !validReceiptRegular(info) {
		return nil, ErrInvalidCodingCompletionObservation
	}
	readback, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(readback, document) {
		return nil, ErrInvalidCodingCompletionObservation
	}
	return readback, nil
}

func TestCodingPrivateProofExclusiveDurableRoundTripBeforeCleanup(t *testing.T) {
	fixture := testCodingCompletionFixture(t)
	proof, err := fixture.observer.observeCompleted(t.Context(), fixture.receipt, fixture.revision)
	if err != nil {
		t.Fatal(err)
	}
	trace := make([]codingDiagnosticTraceItem, 23)
	for index := range trace {
		status := 200
		if index == 1 || index == 15 {
			status = 404
		}
		trace[index] = codingDiagnosticTraceItem{Seq: index + 1, Category: "fixture-get", Status: status}
	}
	record := newCodingPrivateProofRecord(proof, trace, time.Now())
	current, err := NewCodingReceiptState(fixture.observer.binding)
	if err != nil {
		t.Fatal(err)
	}
	current, _, _, err = current.beginUnknown(fixture.observer.binding,
		fixture.observer.authority, fixture.observer.authority.IssuedAt)
	if err != nil || current.Revision != fixture.revision {
		t.Fatal("fixture receipt revision drift")
	}
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "proof.json")
	decoded, err := writeAndReadCodingPrivateProof(path, record)
	if err != nil || decoded.recheck(fixture.observer.binding, fixture.observer.authority,
		fixture.observer.template, fixture.observer.documents, fixture.observer.policy, current) != nil {
		t.Fatalf("private proof failed write/fsync/readback/recheck: %v", err)
	}
	if _, err := writeAndReadCodingPrivateProof(path, record); err == nil {
		t.Fatal("private proof file was overwritten")
	}
}
