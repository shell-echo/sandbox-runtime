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

const codingReleaseEvidenceSchema = "sandbox-runtime.docker-control-coding-release-evidence.v1"

// codingExactDeletion is only an in-package source seam. A production
// implementation must itself enforce an authenticated frozen Unix endpoint,
// exact typed DELETE allowlist, bounded responses, and unequivocal completion.
// A nil result after an ambiguous daemon request is forbidden.
type codingExactDeletion interface {
	ScopeDigest() string
	RemoveRuntime(context.Context, string) error
	RemoveVolume(context.Context, string) error
}

// codingReleaseEvidence excludes raw Docker endpoints, host paths, and
// credentials. Its first digest binds the full physical sequence; the second
// receipt field seals the entire canonical private envelope including capture
// time and source-state identity.
type codingReleaseEvidence struct {
	Schema                     string                          `json:"schema"`
	EffectID                   string                          `json:"effect_id"`
	OriginalAuthorityDigest    string                          `json:"original_authority_digest"`
	CleanupAuthorityDigest     string                          `json:"cleanup_authority_digest"`
	CompletionDigest           string                          `json:"completion_digest"`
	CompletionEvidenceDigest   string                          `json:"completion_evidence_digest"`
	SourceRevision             uint64                          `json:"source_revision"`
	SourceStateDigest          string                          `json:"source_state_digest"`
	DeletedRuntimeID           string                          `json:"deleted_runtime_id"`
	DeletedVolumes             [3]string                       `json:"deleted_volumes"`
	Before                     CodingResourceInventory         `json:"before"`
	BeforeRuntime              codingRuntimeSecurityProjection `json:"before_runtime"`
	RuntimeConfigurationDigest string                          `json:"runtime_configuration_digest"`
	AfterFirst                 CodingResourceInventory         `json:"after_first"`
	AfterSecond                CodingResourceInventory         `json:"after_second"`
	CapturedAt                 time.Time                       `json:"captured_at"`
	ProofDigest                string                          `json:"proof_digest"`
}

func (e codingReleaseEvidence) proofDigest() string {
	e.ProofDigest = ""
	document, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-release-proof/v1\x00"), document...))
}

func (e codingReleaseEvidence) digest() string {
	document, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	return digest(append([]byte("sandbox-runtime/docker-control-coding-release-evidence/v1\x00"), document...))
}

func (e codingReleaseEvidence) recheck(binding CodingReceiptBinding,
	receipt CodingReceipt, set CodingResourceSet) error {
	if e.Schema != codingReleaseEvidenceSchema || e.EffectID != receipt.Authority.EffectID ||
		e.OriginalAuthorityDigest != receipt.AuthorityDigest ||
		e.CleanupAuthorityDigest != receipt.CleanupAuthority.Digest() ||
		e.CompletionDigest != receipt.CompletionDigest ||
		e.CompletionEvidenceDigest != receipt.CompletionEvidenceDigest ||
		e.SourceRevision == 0 || !controlDigest.MatchString(e.SourceStateDigest) ||
		e.CapturedAt.IsZero() || e.CapturedAt.Before(receipt.CleanupAuthority.IssuedAt) ||
		e.CapturedAt.After(receipt.CleanupAuthority.ExpiresAt) ||
		!codingArchiveRuntimeID.MatchString(e.DeletedRuntimeID) ||
		!controlDigest.MatchString(e.RuntimeConfigurationDigest) ||
		e.BeforeRuntime.StateError != "" ||
		e.RuntimeConfigurationDigest != codingRuntimeConfigurationDigest(e.BeforeRuntime) ||
		e.BeforeRuntime.ID != e.DeletedRuntimeID ||
		e.ProofDigest != e.proofDigest() ||
		e.Before.Daemon.MatchBinding(binding) != nil ||
		e.AfterFirst.Daemon != e.Before.Daemon || e.AfterSecond.Daemon != e.Before.Daemon {
		return ErrInvalidReceiptState
	}
	roles := [2]CodingResourceRole{CodingPreparationRole, CodingRuntimeRole}
	for index, role := range roles {
		name, err := set.ContainerName(role)
		if err != nil || e.Before.Containers[index].Role != role ||
			e.Before.Containers[index].Name != name ||
			e.AfterFirst.Containers[index] != (CodingInventoryObject{Role: role, Name: name}) ||
			e.AfterSecond.Containers[index] != (CodingInventoryObject{Role: role, Name: name}) {
			return ErrInvalidReceiptState
		}
	}
	if e.Before.Containers[0] != (CodingInventoryObject{Role: CodingPreparationRole,
		Name: e.Before.Containers[0].Name}) ||
		!e.Before.Containers[1].Present ||
		e.Before.Containers[1].ID != e.DeletedRuntimeID ||
		!controlDigest.MatchString(e.Before.Containers[1].LabelsDigest) {
		return ErrInvalidReceiptState
	}
	runtimeName, _ := set.ContainerName(CodingRuntimeRole)
	if e.BeforeRuntime.Name != "/"+runtimeName ||
		!controlDigest.MatchString(e.BeforeRuntime.LabelsDigest) {
		return ErrInvalidReceiptState
	}
	for index, role := range [3]CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, err := set.VolumeName(role)
		before := e.Before.Volumes[index]
		if err != nil || name != e.DeletedVolumes[index] || before.Role != role ||
			before.Name != name || !before.Present || before.ID != name ||
			before.Driver != "local" || before.Scope != "local" ||
			!controlDigest.MatchString(before.LabelsDigest) || before.OptionsCount != 0 ||
			e.AfterFirst.Volumes[index] != (CodingInventoryObject{Role: role, Name: name}) ||
			e.AfterSecond.Volumes[index] != (CodingInventoryObject{Role: role, Name: name}) {
			return ErrInvalidReceiptState
		}
	}
	return nil
}

func releaseEvidencePath(ledgerPath, effectID string) (string, error) {
	if !controlDigest.MatchString(effectID) || !validReceiptPath(ledgerPath) {
		return "", ErrInvalidReceiptState
	}
	parent := filepath.Dir(ledgerPath)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		return "", ErrInvalidReceiptState
	}
	return ledgerPath + ".release-" + strings.TrimPrefix(effectID, "sha256:") + ".json", nil
}

func readReleaseEvidence(path string) (codingReleaseEvidence, error) {
	info, err := os.Lstat(path)
	if err != nil || !validReceiptRegular(info) {
		return codingReleaseEvidence{}, ErrInvalidReceiptState
	}
	document, err := secretfile.Read(path, 1<<20)
	if err != nil {
		return codingReleaseEvidence{}, ErrInvalidReceiptState
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var evidence codingReleaseEvidence
	if decoder.Decode(&evidence) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return codingReleaseEvidence{}, ErrInvalidReceiptState
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(canonical, document) {
		return codingReleaseEvidence{}, ErrInvalidReceiptState
	}
	return evidence, nil
}

func validateCommittedReleaseEvidence(ledgerPath string, state CodingReceiptState,
	binding CodingReceiptBinding) error {
	for _, receipt := range state.Records {
		if receipt.Status != ReceiptReleased {
			continue
		}
		if validateReleaseEvidenceForReceipt(ledgerPath, state.Revision, receipt, binding) != nil {
			return ErrInvalidReceiptState
		}
	}
	return nil
}

func validateReleaseEvidenceForReceipt(ledgerPath string, revision uint64,
	receipt CodingReceipt, binding CodingReceiptBinding) error {
	if receipt.Status != ReceiptReleased ||
		validateCompletionEvidenceForReceipt(ledgerPath, receipt, revision) != nil {
		return ErrInvalidReceiptState
	}
	path, err := releaseEvidencePath(ledgerPath, receipt.Authority.EffectID)
	if err != nil {
		return ErrInvalidReceiptState
	}
	evidence, err := readReleaseEvidence(path)
	if err != nil || evidence.SourceRevision >= revision ||
		evidence.ProofDigest != receipt.AbsenceDigest ||
		evidence.digest() != receipt.AbsenceEvidenceDigest {
		return ErrInvalidReceiptState
	}
	set, err := NewCodingResourceSet(binding, receipt.Authority)
	_, completedProjection, completionErr := readCompletionRuntimeID(ledgerPath, receipt)
	if err != nil || completionErr != nil || evidence.recheck(binding, receipt, set) != nil ||
		evidence.RuntimeConfigurationDigest != codingRuntimeConfigurationDigest(completedProjection) {
		return ErrInvalidReceiptState
	}
	return nil
}

func writeAndReadReleaseEvidence(path string, evidence codingReleaseEvidence,
	binding CodingReceiptBinding, receipt CodingReceipt, set CodingResourceSet) error {
	if !validReceiptPath(path) || evidence.recheck(binding, receipt, set) != nil {
		return ErrInvalidReceiptState
	}
	document, err := json.Marshal(evidence)
	if err != nil || len(document) == 0 || len(document) > 1<<20 {
		return ErrInvalidReceiptState
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalidReceiptState
	}
	writeErr := writeReceiptExact(file, document)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return ErrInvalidReceiptState
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrInvalidReceiptState
	}
	dirSyncErr := dir.Sync()
	dirCloseErr := dir.Close()
	if dirSyncErr != nil || dirCloseErr != nil {
		return ErrInvalidReceiptState
	}
	readback, err := readReleaseEvidence(path)
	if err != nil || !reflect.DeepEqual(readback, evidence) {
		return ErrInvalidReceiptState
	}
	return nil
}

func readCompletionRuntimeID(ledgerPath string, receipt CodingReceipt) (string, codingRuntimeSecurityProjection, error) {
	path, err := completionEvidencePath(ledgerPath, receipt.Authority.EffectID)
	if err != nil {
		return "", codingRuntimeSecurityProjection{}, ErrInvalidReceiptState
	}
	info, err := os.Lstat(path)
	if err != nil || !validReceiptRegular(info) {
		return "", codingRuntimeSecurityProjection{}, ErrInvalidReceiptState
	}
	document, err := secretfile.Read(path, 1<<20)
	if err != nil {
		return "", codingRuntimeSecurityProjection{}, ErrInvalidReceiptState
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var evidence codingCompletionEvidence
	if decoder.Decode(&evidence) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return "", codingRuntimeSecurityProjection{}, ErrInvalidReceiptState
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(canonical, document) ||
		evidence.Schema != codingCompletionEvidenceSchema ||
		evidence.digest() != receipt.CompletionEvidenceDigest ||
		evidence.EffectID != receipt.Authority.EffectID ||
		evidence.AuthorityDigest != receipt.AuthorityDigest ||
		evidence.Proof.CompletionDigest != receipt.CompletionDigest ||
		!codingArchiveRuntimeID.MatchString(evidence.Proof.RuntimeID) {
		return "", codingRuntimeSecurityProjection{}, ErrInvalidReceiptState
	}
	return evidence.Proof.RuntimeID, evidence.Proof.FinalRuntime, nil
}

// completeCodingCleanup is source-only normal cleanup, not a public
// SetReleased operation. The exact deletion implementation remains an
// unexported Control-owned seam; no Provider caller can supply a proof or
// directly mark Released. DispatchCodingCleanup durably commits the current
// intent before this callback, and a failed/uncertain mutation leaves the
// effect occupied. The external quiescence requirements for historical
// Unknown effects are deliberately not implemented here.
func (l *CodingReceiptLedger) completeCodingCleanup(ctx context.Context,
	createRequestID string, intent CodingCleanupAuthority,
	observer *codingUnixObserver, deletion codingExactDeletion) (CodingReceipt, error) {
	if l == nil || ctx == nil || ctx.Err() != nil || observer == nil || deletion == nil ||
		!controlDigest.MatchString(createRequestID) {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	var released CodingReceipt
	_, err := l.DispatchCodingCleanup(ctx, createRequestID, intent,
		func(physicalCtx context.Context, accepted CodingCleanupAuthority) error {
			var runErr error
			released, runErr = l.runCodingExactCleanup(physicalCtx,
				createRequestID, accepted, observer, deletion)
			return runErr
		})
	if err != nil {
		return CodingReceipt{}, err
	}
	return released, nil
}

func (l *CodingReceiptLedger) runCodingExactCleanup(ctx context.Context,
	createRequestID string, intent CodingCleanupAuthority,
	observer *codingUnixObserver, deletion codingExactDeletion) (CodingReceipt, error) {
	l.mu.Lock()
	if ctx.Err() != nil || l.checkDiskLocked() != nil ||
		!l.cleanupInFlight || l.inFlight != 1 ||
		!reflect.DeepEqual(observer.binding, l.binding) ||
		deletion.ScopeDigest() != l.binding.EndpointScopeDigest {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	var receipt CodingReceipt
	for _, item := range l.current.Records {
		if item.Authority.RequestID == createRequestID {
			receipt = item
			break
		}
	}
	if receipt.Status != ReceiptCompleted || receipt.CleanupAuthority != intent ||
		observer.authority != receipt.Authority ||
		intent.BindControl(receipt.Authority, l.binding.Plan, l.binding.ControlPolicyDigest,
			l.binding.PeerPrincipalDigest, l.binding.SpecBySlot[receipt.Authority.SlotID],
			l.clock().UTC()) != nil {
		l.mu.Unlock()
		return CodingReceipt{}, ErrReceiptConflict
	}
	set, err := NewCodingResourceSet(l.binding, receipt.Authority)
	if err != nil {
		l.mu.Unlock()
		return CodingReceipt{}, ErrInvalidAuthority
	}
	source := l.current.Clone()
	runtimeID, completedProjection, err := readCompletionRuntimeID(l.path, receipt)
	if err != nil {
		l.mu.Unlock()
		return CodingReceipt{}, err
	}
	l.mu.Unlock()

	before, beforeRuntime, err := observer.readDeletePreflight(ctx, runtimeID)
	if err != nil || before.Containers[0].Present || !before.Containers[1].Present ||
		before.Containers[1].ID != runtimeID {
		return CodingReceipt{}, ErrInvalidCodingInventory
	}
	for _, volume := range before.Volumes {
		if !volume.Present {
			return CodingReceipt{}, ErrInvalidCodingInventory
		}
	}
	if codingRuntimeConfigurationDigest(beforeRuntime) !=
		codingRuntimeConfigurationDigest(completedProjection) {
		return CodingReceipt{}, ErrInvalidCodingInventory
	}
	// State.Error is a daemon diagnostic, not cleanup authority. It may
	// contain a host path; never persist its raw text in private evidence.
	beforeRuntime.StateError = ""
	var deletedVolumes [3]string
	for index, role := range [3]CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, nameErr := set.VolumeName(role)
		if nameErr != nil || before.Volumes[index].Name != name || before.Volumes[index].ID != name {
			return CodingReceipt{}, ErrInvalidCodingInventory
		}
		deletedVolumes[index] = name
	}
	if ctx.Err() != nil || intent.Validate(time.Now().UTC()) != nil {
		return CodingReceipt{}, ErrInvalidAuthority
	}
	if err := deletion.RemoveRuntime(ctx, runtimeID); err != nil || ctx.Err() != nil {
		return CodingReceipt{}, ErrInvalidCodingInventory
	}
	for _, name := range deletedVolumes {
		if ctx.Err() != nil || intent.Validate(time.Now().UTC()) != nil {
			return CodingReceipt{}, ErrInvalidAuthority
		}
		if err := deletion.RemoveVolume(ctx, name); err != nil || ctx.Err() != nil {
			return CodingReceipt{}, ErrInvalidCodingInventory
		}
	}
	first, err := observer.ReadInventory(ctx)
	if err != nil || ctx.Err() != nil {
		return CodingReceipt{}, ErrInvalidCodingInventory
	}
	second, err := observer.ReadInventory(ctx)
	if err != nil || ctx.Err() != nil {
		return CodingReceipt{}, ErrInvalidCodingInventory
	}
	now := l.clock().UTC()
	evidence := codingReleaseEvidence{Schema: codingReleaseEvidenceSchema,
		EffectID: receipt.Authority.EffectID, OriginalAuthorityDigest: receipt.AuthorityDigest,
		CleanupAuthorityDigest: intent.Digest(), CompletionDigest: receipt.CompletionDigest,
		CompletionEvidenceDigest: receipt.CompletionEvidenceDigest,
		SourceRevision:           source.Revision, SourceStateDigest: source.StateDigest,
		DeletedRuntimeID: runtimeID, DeletedVolumes: deletedVolumes,
		Before: before, BeforeRuntime: beforeRuntime,
		RuntimeConfigurationDigest: codingRuntimeConfigurationDigest(beforeRuntime),
		AfterFirst:                 first, AfterSecond: second, CapturedAt: now}
	evidence.ProofDigest = evidence.proofDigest()
	if evidence.recheck(l.binding, receipt, set) != nil || ctx.Err() != nil ||
		intent.Validate(now) != nil {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctx.Err() != nil || intent.Validate(l.clock().UTC()) != nil ||
		l.checkDiskLocked() != nil || l.current.Revision != source.Revision ||
		l.current.StateDigest != source.StateDigest || !l.cleanupInFlight || l.inFlight != 1 {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	path, err := releaseEvidencePath(l.path, receipt.Authority.EffectID)
	if err != nil {
		return CodingReceipt{}, err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	next, released, err := l.current.releaseObserved(l.binding, createRequestID,
		intent, evidence.ProofDigest, evidence.digest(), source.Revision, now)
	if err != nil {
		return CodingReceipt{}, err
	}
	if writeAndReadReleaseEvidence(path, evidence, l.binding, receipt, set) != nil {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	if l.cleanupStage != nil {
		l.cleanupStage("after-evidence")
	}
	if ctx.Err() != nil || intent.Validate(l.clock().UTC()) != nil ||
		l.checkDiskLocked() != nil || l.current.Revision != source.Revision ||
		l.current.StateDigest != source.StateDigest {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	if writeReceiptStateWithFault(l.path, next, l.writeFault) != nil {
		return CodingReceipt{}, ErrInvalidReceiptState
	}
	l.current = next
	if l.cleanupStage != nil {
		l.cleanupStage("after-commit")
	}
	if ctx.Err() != nil || intent.Validate(l.clock().UTC()) != nil {
		return CodingReceipt{}, ErrInvalidAuthority
	}
	return released, nil
}

// CodingReleasedSnapshot is an in-process private read of a fully sealed
// tombstone. Production cannot infer a cross-process Control identity or PG
// release CAS from this value alone.
type CodingReleasedSnapshot struct {
	receipt     CodingReceipt
	revision    uint64
	stateDigest string
}

func (s CodingReleasedSnapshot) Receipt() CodingReceipt { return s.receipt }
func (s CodingReleasedSnapshot) Revision() uint64       { return s.revision }
func (s CodingReleasedSnapshot) StateDigest() string    { return s.stateDigest }

func (s CodingReleasedSnapshot) Validate(create CodingCreateAuthority,
	intent CodingCleanupAuthority) error {
	if s.revision == 0 || !controlDigest.MatchString(s.stateDigest) ||
		s.receipt.Status != ReceiptReleased || s.receipt.Authority != create ||
		s.receipt.AuthorityDigest != create.Digest() ||
		s.receipt.CleanupAuthority != intent ||
		!controlDigest.MatchString(s.receipt.AbsenceDigest) ||
		!controlDigest.MatchString(s.receipt.AbsenceEvidenceDigest) {
		return ErrInvalidReceiptState
	}
	return nil
}

func (l *CodingReceiptLedger) ReadReleasedSnapshot(requestID string) (CodingReleasedSnapshot, error) {
	if l == nil || !controlDigest.MatchString(requestID) {
		return CodingReleasedSnapshot{}, ErrInvalidReceiptState
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.checkDiskLocked() != nil {
		return CodingReleasedSnapshot{}, ErrInvalidReceiptState
	}
	for _, receipt := range l.current.Records {
		if receipt.Authority.RequestID == requestID {
			if validateReleaseEvidenceForReceipt(l.path, l.current.Revision,
				receipt, l.binding) != nil {
				return CodingReleasedSnapshot{}, ErrInvalidReceiptState
			}
			snapshot := CodingReleasedSnapshot{receipt: receipt,
				revision: l.current.Revision, stateDigest: l.current.StateDigest}
			if snapshot.Validate(receipt.Authority, receipt.CleanupAuthority) != nil {
				return CodingReleasedSnapshot{}, ErrReceiptConflict
			}
			return snapshot, nil
		}
	}
	return CodingReleasedSnapshot{}, os.ErrNotExist
}
