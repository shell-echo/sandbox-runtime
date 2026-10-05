package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

const codingCompletionEvidenceSchema = "sandbox-runtime.docker-control-coding-completion-evidence.v1"

// codingCompletionEvidence is private to the ledger owner. The receipt holds
// its digest; the deterministic per-effect file retains the full observed
// source, never a caller-supplied success boolean or Docker API response.
type codingCompletionEvidence struct {
	Schema            string                      `json:"schema"`
	EffectID          string                      `json:"effect_id"`
	AuthorityDigest   string                      `json:"authority_digest"`
	SourceRevision    uint64                      `json:"source_revision"`
	SourceStateDigest string                      `json:"source_state_digest"`
	CapturedAt        time.Time                   `json:"captured_at"`
	Proof             codingCompletionObservation `json:"proof"`
}

// CodingCompletedSnapshot is an offline, Control-owner-produced private
// value. Its unexported fields prevent a repository caller from substituting
// an arbitrary digest/receipt in process. It is not a cross-process wire
// attestation; production must fetch it over the authenticated Control edge
// and bind the returned revision again when admitting cleanup.
type CodingCompletedSnapshot struct {
	receipt     CodingReceipt
	revision    uint64
	stateDigest string
}

func (s CodingCompletedSnapshot) Receipt() CodingReceipt { return s.receipt }
func (s CodingCompletedSnapshot) Revision() uint64       { return s.revision }
func (s CodingCompletedSnapshot) StateDigest() string    { return s.stateDigest }

func (s CodingCompletedSnapshot) Validate(create CodingCreateAuthority) error {
	if s.revision == 0 || !controlDigest.MatchString(s.stateDigest) ||
		s.receipt.Status != ReceiptCompleted || s.receipt.Authority != create ||
		s.receipt.AuthorityDigest != create.Digest() ||
		s.receipt.CleanupAuthority != (CodingCleanupAuthority{}) ||
		!controlDigest.MatchString(s.receipt.CompletionDigest) ||
		!controlDigest.MatchString(s.receipt.CompletionEvidenceDigest) {
		return ErrInvalidReceiptState
	}
	return nil
}

// ReadCompletedSnapshot is read-only and checks the current disk state plus
// the full-evidence seal before returning a private transaction input.
func (l *CodingReceiptLedger) ReadCompletedSnapshot(requestID string) (CodingCompletedSnapshot, error) {
	if l == nil || !controlDigest.MatchString(requestID) {
		return CodingCompletedSnapshot{}, ErrInvalidReceiptState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.checkDiskLocked() != nil {
		return CodingCompletedSnapshot{}, ErrInvalidReceiptState
	}
	for _, receipt := range l.current.Records {
		if receipt.Authority.RequestID == requestID {
			snapshot := CodingCompletedSnapshot{receipt: receipt,
				revision: l.current.Revision, stateDigest: l.current.StateDigest}
			if snapshot.Validate(receipt.Authority) != nil {
				return CodingCompletedSnapshot{}, ErrReceiptConflict
			}
			return snapshot, nil
		}
	}
	return CodingCompletedSnapshot{}, os.ErrNotExist
}

func (e codingCompletionEvidence) digest() string {
	document, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-completion-evidence/v1\x00"), document...))
}

func (e codingCompletionEvidence) recheck(source CodingReceiptState,
	receipt CodingReceipt, observer *codingUnixObserver) error {
	if observer == nil || e.Schema != codingCompletionEvidenceSchema ||
		e.EffectID != receipt.Authority.EffectID || e.AuthorityDigest != receipt.AuthorityDigest ||
		e.SourceRevision != source.Revision || e.SourceStateDigest != source.StateDigest ||
		e.CapturedAt.IsZero() || e.Proof.ReceiptRevision != source.Revision ||
		e.Proof.recheck(observer.binding, receipt.Authority, observer.template,
			observer.documents, observer.policy) != nil {
		return ErrInvalidCodingCompletionObservation
	}
	return nil
}

func (l *CodingReceiptLedger) completionEvidencePath(effectID string) (string, error) {
	if l == nil {
		return "", ErrInvalidReceiptState
	}
	return completionEvidencePath(l.path, effectID)
}

func completionEvidencePath(ledgerPath, effectID string) (string, error) {
	if !controlDigest.MatchString(effectID) || !validReceiptPath(ledgerPath) {
		return "", ErrInvalidReceiptState
	}
	parent := filepath.Dir(ledgerPath)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return "", ErrInvalidReceiptState
	}
	return ledgerPath + ".completion-" + strings.TrimPrefix(effectID, "sha256:") + ".json", nil
}

// Active Completed evidence is checked on every ledger use. Released
// tombstones are checked only when targeted or during Open/reopen: an
// unrelated historical file cannot multiply every hot-path read by up to
// 4096. A target Released still requires both completion and release files.
func validateCommittedCompletionEvidence(ledgerPath string, state CodingReceiptState) error {
	for _, receipt := range state.Records {
		if receipt.Status != ReceiptCompleted {
			continue
		}
		if validateCompletionEvidenceForReceipt(ledgerPath, receipt, state.Revision) != nil {
			return ErrInvalidReceiptState
		}
	}
	return nil
}

func validateCompletionEvidenceForReceipt(ledgerPath string, receipt CodingReceipt,
	currentRevision uint64) error {
	path, err := completionEvidencePath(ledgerPath, receipt.Authority.EffectID)
	if err != nil {
		return ErrInvalidReceiptState
	}
	info, err := os.Lstat(path)
	if err != nil || !validReceiptRegular(info) {
		return ErrInvalidReceiptState
	}
	document, err := secretfile.Read(path, 1<<20)
	if err != nil {
		return ErrInvalidReceiptState
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var evidence codingCompletionEvidence
	if decoder.Decode(&evidence) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return ErrInvalidReceiptState
	}
	canonical, err := json.Marshal(evidence)
	copyProof := evidence.Proof
	copyProof.CompletionDigest = ""
	proofDocument, proofErr := json.Marshal(copyProof)
	if err != nil || proofErr != nil || !bytes.Equal(canonical, document) ||
		evidence.Schema != codingCompletionEvidenceSchema ||
		evidence.digest() != receipt.CompletionEvidenceDigest ||
		evidence.EffectID != receipt.Authority.EffectID ||
		evidence.AuthorityDigest != receipt.AuthorityDigest ||
		evidence.SourceRevision == 0 || evidence.SourceRevision >= currentRevision ||
		!controlDigest.MatchString(evidence.SourceStateDigest) || evidence.CapturedAt.IsZero() ||
		evidence.Proof.ReceiptRevision != evidence.SourceRevision ||
		evidence.Proof.AuthorityDigest != evidence.AuthorityDigest ||
		evidence.Proof.EffectID != evidence.EffectID ||
		evidence.Proof.CompletionDigest != receipt.CompletionDigest ||
		evidence.Proof.CompletionDigest != digest(append(
			[]byte("sandbox-runtime/docker-control-coding-completion/v1\x00"), proofDocument...)) {
		return ErrInvalidReceiptState
	}
	return nil
}

// completeCodingCreate is intentionally not an exported SetCompleted API.
// It requires the live, internally constructed Unix observer and an
// in-process, unambiguous create callback return. Reopened historical
// Unknown receipts have no such qualification and cannot be completed from
// an old proof. No ledger mutex is held during Docker I/O.
func (l *CodingReceiptLedger) completeCodingCreate(ctx context.Context, requestID string,
	observer *codingUnixObserver) (CodingReceipt, error) {
	if l == nil || ctx == nil || ctx.Err() != nil || observer == nil ||
		!controlDigest.MatchString(requestID) {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.mu.Lock()
	if l.checkDiskLocked() != nil || l.inFlight != 0 || l.completionInFlight || l.cleanupInFlight ||
		!reflect.DeepEqual(observer.binding, l.binding) {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	var receipt CodingReceipt
	for _, candidate := range l.current.Records {
		if candidate.Authority.RequestID == requestID {
			receipt = candidate
			break
		}
	}
	if receipt.Status != ReceiptUnknown || receipt.Authority != observer.authority ||
		receipt.CleanupAuthority != (CodingCleanupAuthority{}) ||
		!l.createReturned[receipt.Authority.EffectID] {
		l.mu.Unlock()
		return CodingReceipt{}, ErrReceiptConflict
	}
	if receipt.Authority.Validate(l.clock().UTC()) != nil {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidAuthority
	}
	evidencePath, err := l.completionEvidencePath(receipt.Authority.EffectID)
	if err != nil {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	if _, err := os.Lstat(evidencePath); !errors.Is(err, os.ErrNotExist) {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	source := l.current.Clone()
	l.completionInFlight = true
	l.drained = make(chan struct{})
	l.inFlight++
	l.mu.Unlock()
	completionCtx, cancel := context.WithDeadline(ctx, receipt.Authority.ExpiresAt)
	defer cancel()
	defer func() {
		l.mu.Lock()
		l.completionInFlight = false
		l.inFlight--
		if l.inFlight == 0 {
			close(l.drained)
		}
		l.mu.Unlock()
	}()

	proof, err := observer.observeCompleted(completionCtx, receipt, source.Revision)
	if err != nil || completionCtx.Err() != nil ||
		receipt.Authority.Validate(l.clock().UTC()) != nil ||
		proof.recheck(l.binding, receipt.Authority,
			observer.template, observer.documents, observer.policy) != nil {
		return CodingReceipt{}, ErrInvalidCodingCompletionObservation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if completionCtx.Err() != nil || receipt.Authority.Validate(l.clock().UTC()) != nil ||
		l.checkDiskLocked() != nil ||
		l.current.Revision != source.Revision || l.current.StateDigest != source.StateDigest ||
		!l.createReturned[receipt.Authority.EffectID] {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	// The state transition and evidence refer to exactly the revision read
	// before observation. A concurrent create on another slot cannot be
	// silently rebased onto this physical snapshot.
	now := l.clock().UTC()
	evidence := codingCompletionEvidence{Schema: codingCompletionEvidenceSchema,
		EffectID: receipt.Authority.EffectID, AuthorityDigest: receipt.AuthorityDigest,
		SourceRevision: source.Revision, SourceStateDigest: source.StateDigest,
		CapturedAt: now, Proof: proof}
	if evidence.recheck(source, receipt, observer) != nil {
		return CodingReceipt{}, ErrInvalidCodingCompletionObservation
	}
	next, completed, err := l.current.completeObserved(l.binding, requestID,
		proof, evidence.digest(), now)
	if err != nil {
		return CodingReceipt{}, err
	}
	if writeAndReadCompletionEvidence(evidencePath, evidence, source, receipt, observer) != nil {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	if l.completionStage != nil {
		l.completionStage("after-evidence")
	}
	if completionCtx.Err() != nil || receipt.Authority.Validate(l.clock().UTC()) != nil ||
		l.checkDiskLocked() != nil || l.current.Revision != source.Revision ||
		l.current.StateDigest != source.StateDigest {
		// The newly written proof is orphan evidence, not an import permit.
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	if writeReceiptStateWithFault(l.path, next, l.writeFault) != nil {
		// Rename/dirsync can be ambiguous. Never return success or rewrite a
		// possibly committed Completed receipt back to Unknown.
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.current = next
	if l.completionStage != nil {
		l.completionStage("after-commit")
	}
	if completionCtx.Err() != nil || receipt.Authority.Validate(l.clock().UTC()) != nil {
		// A lost or late response cannot undo an already durable Completed.
		// The caller must reconcile via read-only Lookup.
		return CodingReceipt{}, ErrInvalidAuthority
	}
	return completed, nil
}

func writeAndReadCompletionEvidence(path string, evidence codingCompletionEvidence,
	source CodingReceiptState, receipt CodingReceipt, observer *codingUnixObserver) error {
	if !validReceiptPath(path) || evidence.recheck(source, receipt, observer) != nil {
		return ErrInvalidCodingCompletionObservation
	}
	document, err := json.Marshal(evidence)
	if err != nil || len(document) == 0 || len(document) > 1<<20 {
		return ErrInvalidCodingCompletionObservation
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalidCodingCompletionObservation
	}
	writeErr := writeReceiptExact(file, document)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return ErrInvalidCodingCompletionObservation
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrInvalidCodingCompletionObservation
	}
	dirSyncErr := dir.Sync()
	dirCloseErr := dir.Close()
	if dirSyncErr != nil || dirCloseErr != nil {
		return ErrInvalidCodingCompletionObservation
	}
	info, err := os.Lstat(path)
	if err != nil || !validReceiptRegular(info) {
		return ErrInvalidCodingCompletionObservation
	}
	readback, err := secretfile.Read(path, 1<<20)
	if err != nil || !bytes.Equal(readback, document) {
		return ErrInvalidCodingCompletionObservation
	}
	decoder := json.NewDecoder(bytes.NewReader(readback))
	decoder.DisallowUnknownFields()
	var decoded codingCompletionEvidence
	if decoder.Decode(&decoded) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) ||
		!reflect.DeepEqual(decoded, evidence) || decoded.recheck(source, receipt, observer) != nil {
		return ErrInvalidCodingCompletionObservation
	}
	return nil
}
