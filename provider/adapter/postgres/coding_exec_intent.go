package providerpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

const (
	codingExecIntentDocument  = "coding_exec_intents"
	codingExecIntentMode      = "coding-exec-intents-v1"
	maxCodingExecIntents      = 256
	maxCodingExecIntentBytes  = 8 << 20
	maxCodingExecRequestBytes = 256 << 10
)

type codingExecIntentRecord struct {
	Request       providerexec.Request                   `json:"request"`
	PayloadDigest string                                 `json:"payload_digest"`
	Snapshot      codingcontrol.RuntimeSnapshot          `json:"snapshot"`
	AllocationID  string                                 `json:"allocation_id"`
	Completion    codingidentity.CreateCompletionBinding `json:"completion"`
}

type codingExecIntentState struct {
	Version    int                      `json:"version"`
	Mode       string                   `json:"mode"`
	PlanDigest string                   `json:"plan_digest"`
	Records    []codingExecIntentRecord `json:"records"`
}

// This is an internal encoding identity, not RFC8785 Contract admission proof.
func codingExecRequest(request providerexec.Request, now time.Time) (providerexec.Request, []byte, string, error) {
	request = request.Clone()
	request.Deadline = request.Deadline.UTC()
	if now.IsZero() || request.Validate(now) != nil {
		return providerexec.Request{}, nil, "", codingcontrol.ErrExecIntent
	}
	if len(request.Environment) != 0 || len(request.SecretReferenceIDs) != 0 || request.SecretGrantID != "" || request.SecretGrantDigest != "" || request.StdinReference != "" {
		return providerexec.Request{}, nil, "", providerexec.ErrUnsupportedRequest
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > maxCodingExecRequestBytes {
		return providerexec.Request{}, nil, "", codingcontrol.ErrExecIntent
	}
	sum := sha256.Sum256(raw)
	return request, raw, "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Optional documents distinguish absent SQL NULL from a corrupt present JSON
// null. Bootstrap must never erase a present-but-damaged execution history.
func decodeCodingExecDocument(document []byte) (json.RawMessage, bool, error) {
	raw, exists, err := decodeStoredDocument(document)
	if err != nil || (len(document) != 0 && !exists) {
		return nil, false, ErrCorrupt
	}
	return raw, exists, nil
}

func importCodingExecIntents(state *codingExecIntentState, raw json.RawMessage) error {
	if len(raw) > maxCodingExecIntentBytes || decodePersisted(state, raw) != nil {
		return ErrCorrupt
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(raw, canonical) || state.Version != 1 || state.Mode != codingExecIntentMode ||
		lifecycle.ValidateDigest(state.PlanDigest) != nil || state.Records == nil || len(state.Records) > maxCodingExecIntents {
		return ErrCorrupt
	}
	return nil
}

func (s codingExecIntentState) validate(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State,
	plan codingidentity.Plan, specs map[string]string, policy string, now time.Time) error {
	digest, err := plan.Digest()
	if err != nil || now.IsZero() || !marker.matchesAtomic(digest, policy) || marker.ExecIntentMode != codingExecIntentMode ||
		s.Version != 1 || s.Mode != codingExecIntentMode || s.PlanDigest != digest || s.Records == nil || len(s.Records) > maxCodingExecIntents ||
		slots.Validate(plan) != nil || checkCodingRetirementBarrierWithMarker(marker, slots, ledger, ledger, now) != nil {
		return ErrCorrupt
	}
	if err := s.validateNamespace(marker, ledger, now); err != nil {
		return ErrCorrupt
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, record := range s.Records {
		snapshot, request := record.Snapshot, record.Request
		sb, lease := snapshot.Sandbox, snapshot.Lease
		_, _, payload, err := codingExecRequest(request, snapshot.ObservedAt)
		original, originalErr := decodeCodingOriginalCreate(slots.OriginalCreates[record.AllocationID], now)
		originalOperation := ledger.Operations[original.OperationID]
		tenant, tenantErr := codingidentity.TenantDigestForID(sb.TenantID)
		completed, exists := slots.CreateCompletions[record.AllocationID]
		if err != nil || originalErr != nil || tenantErr != nil || payload != record.PayloadDigest || snapshot.ObservedAt.After(now) ||
			snapshot.ProfileDigest != plan.ProfileDigest || snapshot.ControlPolicyDigest != policy || snapshot.ProviderPrincipalDigest != plan.OwnerPrincipalDigest ||
			sb.Validate() != nil || lease.Validate() != nil || sb.RuntimeProfile != "sandbox-runtime-coding-shell-v1" || sb.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) || sb.ID != request.SandboxID || sb.Generation != uint64(request.ExpectedGeneration) ||
			sb.DesiredState != lifecycle.DesiredReady || sb.ObservedState != lifecycle.ObservedReady || sb.ObservedGeneration != sb.Generation ||
			sb.UpdatedAt.After(snapshot.ObservedAt) || lease.SandboxID != sb.ID || lease.Generation != sb.Generation ||
			!lease.ExpiresAt.Equal(sb.LeaseExpiresAt) || !lease.ExpiresAt.After(snapshot.ObservedAt) || uint64(request.FencingToken) < lease.FencingToken || lease.FencingToken < original.Fence ||
			original.AllocationID != record.AllocationID || original.SandboxID != sb.ID || original.ProviderRevisionID != sb.ProviderRevisionID || original.TenantDigest != tenant ||
			(originalOperation.State != lifecycle.OperationSucceeded && originalOperation.State != lifecycle.OperationOutcomeUnknown) ||
			originalOperation.ObservedAt.After(snapshot.ObservedAt) ||
			original.CreationGeneration != sb.Generation || original.ControlPolicyDigest != policy || original.SpecDigest != specs[original.SlotID] ||
			validateCodingOriginalCreate(slots, ledger, plan, original, now) != nil || !exists || completed != record.Completion ||
			!validCodingCompletion(record.Completion, original, snapshot.ObservedAt) || ids[request.OperationID] || keys[request.IdempotencyKey] {
			return ErrCorrupt
		}
		ids[request.OperationID], keys[request.IdempotencyKey] = true, true
	}
	encoded, err := json.Marshal(s)
	if err != nil || len(encoded) > maxCodingExecIntentBytes {
		return ErrCorrupt
	}
	return nil
}

func reserveCodingExecIntent(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State,
	state *codingExecIntentState, plan codingidentity.Plan, specs map[string]string, policy string, request providerexec.Request, now time.Time) (codingcontrol.ExecIntentReceipt, error) {
	empty := codingcontrol.ExecIntentReceipt{}
	request, raw, digest, err := codingExecRequest(request, now)
	if err != nil {
		return empty, err
	}
	if err := state.validate(marker, slots, ledger, plan, specs, policy, now); err != nil {
		return empty, err
	}
	for _, record := range state.Records {
		if record.Request.IdempotencyKey != request.IdempotencyKey && record.Request.OperationID != request.OperationID {
			continue
		}
		stored, err := json.Marshal(record.Request)
		if err != nil || !bytes.Equal(stored, raw) {
			return empty, codingcontrol.ErrExecIntentConflict
		}
		return codingcontrol.ExecIntentReceipt{OperationID: request.OperationID, PayloadDigest: record.PayloadDigest, RecordedAt: record.Snapshot.ObservedAt, Replayed: true}, nil
	}
	snapshot, err := readCodingRuntimeSnapshot(marker, slots, ledger, plan, specs, policy, request.SandboxID, now)
	if err != nil || snapshot.Sandbox.Generation != uint64(request.ExpectedGeneration) || uint64(request.FencingToken) < snapshot.Lease.FencingToken {
		return empty, codingcontrol.ErrExecIntent
	}
	if _, exists := ledger.Operations[request.OperationID]; exists {
		return empty, codingcontrol.ErrExecIntentConflict
	}
	if len(state.Records) >= maxCodingExecIntents {
		return empty, codingcontrol.ErrExecIntentCapacity
	}
	var allocation string
	for _, reservation := range slots.Reservations {
		if reservation.Claim.SandboxID == request.SandboxID {
			allocation = reservation.Claim.AllocationID
		}
	}
	record := codingExecIntentRecord{Request: request, PayloadDigest: digest, Snapshot: snapshot, AllocationID: allocation, Completion: slots.CreateCompletions[allocation]}
	next := *state
	next.Records = append(append([]codingExecIntentRecord{}, state.Records...), record)
	raw, err = json.Marshal(next)
	if err != nil || len(raw) > maxCodingExecIntentBytes {
		return empty, codingcontrol.ErrExecIntentCapacity
	}
	if err := next.validate(marker, slots, ledger, plan, specs, policy, now); err != nil {
		return empty, err
	}
	*state = next
	return codingcontrol.ExecIntentReceipt{OperationID: request.OperationID, PayloadDigest: digest, RecordedAt: now}, nil
}

// No physical absence claim is added: the earlier atomic bootstrap remains
// authoritative, and this mode is available only before any local history.
func initializeCodingExecIntentState(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State,
	plan codingidentity.Plan, policy string, hasIntents, hasLegacy bool) (codingIdentityMarker, codingExecIntentState, error) {
	digest, err := plan.Digest()
	if err != nil || hasIntents || hasLegacy || !marker.matchesAtomic(digest, policy) || marker.ExecIntentMode != "" ||
		slots.Validate(plan) != nil || len(slots.Reservations) != 0 || len(slots.Retirements) != 0 || len(slots.OriginalCreates) != 0 || len(slots.CreateCompletions) != 0 ||
		!reflect.DeepEqual(ledger.Export(), newLifecycleState().Export()) {
		return codingIdentityMarker{}, codingExecIntentState{}, codingcontrol.ErrExecIntentConflict
	}
	marker.ExecIntentMode = codingExecIntentMode
	return marker, codingExecIntentState{Version: 1, Mode: codingExecIntentMode, PlanDigest: digest, Records: []codingExecIntentRecord{}}, nil
}

// InitializeCodingExecIntents explicitly enables only a no-permit ledger on an
// already independently bootstrapped, completely unused atomic Coding state.
// It is not called by construction/startup, never upgrades existing allocations
// or exec history, and never repairs a missing document after initialization.
func (r *CodingLifecycleRepository) InitializeCodingExecIntents(ctx context.Context) error {
	_, err := r.codingExecIntentTransaction(ctx, true, providerexec.Request{})
	return err
}

func (r *CodingLifecycleRepository) ReserveCodingExecIntent(ctx context.Context, request providerexec.Request) (codingcontrol.ExecIntentReceipt, error) {
	if ctx == nil {
		return codingcontrol.ExecIntentReceipt{}, ErrUnavailable
	}
	request, _, _, err := codingExecRequest(request, time.Now().UTC())
	if err != nil {
		return codingcontrol.ExecIntentReceipt{}, err
	}
	bounded, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	return r.codingExecIntentTransaction(bounded, false, request)
}

func (r *CodingLifecycleRepository) codingExecIntentTransaction(ctx context.Context, initialize bool, request providerexec.Request) (codingcontrol.ExecIntentReceipt, error) {
	empty := codingcontrol.ExecIntentReceipt{}
	if r == nil || r.bound == nil || r.bound.store == nil || r.bound.store.pool == nil || ctx == nil {
		return empty, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	store := r.bound.store
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	tx, err := store.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	defer rollbackBounded(tx, store.operationTimeout)
	var markerRaw, slotsRaw, ledgerRaw, intentsRaw, legacyRaw, fencesRaw []byte
	if err := tx.QueryRow(opCtx, `SELECT documents->$1,documents->$2,documents->$3,documents->$4,documents->$5,documents->$6 FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument, codingExecIntentDocument, execDocument, codingExecFenceDocument).Scan(&markerRaw, &slotsRaw, &ledgerRaw, &intentsRaw, &legacyRaw, &fencesRaw); err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	marker, slots, ledger, intents := codingIdentityMarker{}, codingidentity.State{}, newLifecycleState(), codingExecIntentState{}
	for _, item := range []struct {
		raw      []byte
		required bool
		decode   func(json.RawMessage) error
	}{
		{markerRaw, true, func(b json.RawMessage) error { return importCodingIdentityMarker(&marker, b) }},
		{slotsRaw, true, func(b json.RawMessage) error { return importCodingIdentityState(&slots, b) }},
		{ledgerRaw, !initialize, func(b json.RawMessage) error { return importLifecycleState(&ledger, b) }},
		{intentsRaw, !initialize, func(b json.RawMessage) error { return importCodingExecIntents(&intents, b) }},
	} {
		raw, exists, err := decodeCodingExecDocument(item.raw)
		if err != nil || (!exists && item.required) || (exists && item.decode(raw) != nil) {
			return empty, ErrCorrupt
		}
	}
	now := time.Now().UTC()
	if _, err := decodeCodingExecIsolation(markerRaw, intentsRaw, legacyRaw, ledgerRaw, slotsRaw, fencesRaw, now); err != nil {
		return empty, err
	}
	// Both ordinary admission and read-only recovery reject mixed execution
	// histories. A present JSON null is still a present legacy document.
	if len(legacyRaw) != 0 && marker.ExecIntentMode != "" {
		return empty, ErrCorrupt
	}
	// Recovery of a committed initialization is read-only, including after the
	// namespace starts being used. A missing/damaged initialized doc is fatal.
	if initialize && marker.ExecIntentMode == codingExecIntentMode {
		if err := intents.validate(marker, slots, ledger, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, now); err != nil {
			return empty, err
		}
		if opCtx.Err() != nil {
			return empty, stateError(ctx, opCtx, opCtx.Err())
		}
		return empty, nil
	}
	var receipt codingcontrol.ExecIntentReceipt
	if initialize {
		_, hasIntents, intentErr := decodeCodingExecDocument(intentsRaw)
		_, hasLegacy, legacyErr := decodeCodingExecDocument(legacyRaw)
		if intentErr != nil || legacyErr != nil {
			return empty, ErrCorrupt
		}
		marker, intents, err = initializeCodingExecIntentState(marker, slots, ledger, r.bound.plan, r.bound.controlPolicyDigest, hasIntents, hasLegacy)
		if err != nil {
			return empty, err
		}
	} else {
		receipt, err = reserveCodingExecIntent(marker, slots, ledger, &intents, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, request, now)
		if err != nil {
			return empty, err
		}
		if receipt.Replayed {
			// No UPDATE, no revision bump, no dispatch. Rollback only releases the lock.
			if opCtx.Err() != nil {
				return empty, stateError(ctx, opCtx, opCtx.Err())
			}
			return receipt, nil
		}
	}
	if err := intents.validate(marker, slots, ledger, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, now); err != nil {
		return empty, err
	}
	encoded, err := encodeStoredState(intents)
	if err != nil {
		return empty, err
	}
	if initialize {
		encodedMarker, err := encodeStoredState(marker)
		if err != nil {
			return empty, err
		}
		_, err = tx.Exec(opCtx, `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(jsonb_set(documents,ARRAY[$1]::text[],$3::jsonb,true),ARRAY[$2]::text[],$4::jsonb,true),revision=revision+1,updated_at=clock_timestamp() WHERE singleton`, codingIdentityMarkerDocument, codingExecIntentDocument, encodedMarker, encoded)
		if err != nil {
			return empty, stateError(ctx, opCtx, err)
		}
	} else {
		if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(documents,ARRAY[$1]::text[],$2::jsonb,true),revision=revision+1,updated_at=clock_timestamp() WHERE singleton`, codingExecIntentDocument, encoded); err != nil {
			return empty, stateError(ctx, opCtx, err)
		}
	}
	if err := tx.Commit(opCtx); err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	if opCtx.Err() != nil {
		return empty, stateError(ctx, opCtx, opCtx.Err())
	}
	return receipt, nil
}

var _ codingcontrol.ExecIntentRecorder = (*CodingLifecycleRepository)(nil)
