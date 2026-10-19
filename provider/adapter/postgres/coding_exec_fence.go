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
	codingExecFenceDocument = "coding_exec_fences"
	codingExecFenceMode     = "coding-exec-fences-v1"
	maxCodingExecFences     = 256
	maxCodingExecFenceBytes = 8 << 20
)

type codingExecFenceRecord struct {
	OperationID    string                                 `json:"operation_id"`
	PayloadDigest  string                                 `json:"payload_digest"`
	AllocationID   string                                 `json:"allocation_id"`
	OriginalDigest string                                 `json:"original_digest"`
	Snapshot       codingcontrol.RuntimeSnapshot          `json:"snapshot"`
	Completion     codingidentity.CreateCompletionBinding `json:"completion"`
}

type codingExecFenceState struct {
	Version    int                     `json:"version"`
	Mode       string                  `json:"mode"`
	PlanDigest string                  `json:"plan_digest"`
	Records    []codingExecFenceRecord `json:"records"`
}

func importCodingExecFences(state *codingExecFenceState, raw json.RawMessage) error {
	if len(raw) > maxCodingExecFenceBytes || decodePersisted(state, raw) != nil {
		return ErrCorrupt
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(raw, canonical) || state.Version != 1 || state.Mode != codingExecFenceMode ||
		lifecycle.ValidateDigest(state.PlanDigest) != nil || state.Records == nil || len(state.Records) > maxCodingExecFences {
		return ErrCorrupt
	}
	return nil
}

func sameCodingExecTuple(a, b codingcontrol.RuntimeSnapshot) bool {
	a.ObservedAt, b.ObservedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(a, b)
}

// This validation also runs in generic writers, before replay callbacks and
// after candidate mutations. Retired allocations retain their original,
// completion, sandbox, lease and monotonic fence history; slot reuse cannot
// rebind a reservation or erase its high-water mark.
func (s codingExecFenceState) validateNamespace(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State, intents codingExecIntentState, now time.Time) error {
	if marker.validate() != nil || marker.ExecFenceMode != codingExecFenceMode || now.IsZero() || s.Version != 1 || s.Mode != codingExecFenceMode ||
		s.PlanDigest != marker.PlanDigest || s.Records == nil || len(s.Records) > maxCodingExecFences || intents.validateNamespace(marker, ledger, now) != nil {
		return ErrCorrupt
	}
	byID := make(map[string]codingExecIntentRecord, len(intents.Records))
	for _, intent := range intents.Records {
		byID[intent.Request.OperationID] = intent
	}
	seen := map[string]bool{}
	for _, record := range s.Records {
		intent, exists := byID[record.OperationID]
		original, err := decodeCodingOriginalCreate(slots.OriginalCreates[record.AllocationID], now)
		at := record.Snapshot.ObservedAt
		_, _, payload, requestErr := codingExecRequest(intent.Request, at)
		lease, hasLease := ledger.Leases[intent.Request.SandboxID]
		sb, hasSandbox := ledger.Sandboxes[intent.Request.SandboxID]
		fence := uint64(intent.Request.FencingToken)
		if !exists || seen[record.OperationID] || err != nil || requestErr != nil || at.Before(intent.Snapshot.ObservedAt) || at.After(now) ||
			payload != record.PayloadDigest || record.PayloadDigest != intent.PayloadDigest || !sameCodingExecTuple(record.Snapshot, intent.Snapshot) ||
			record.AllocationID != intent.AllocationID || original.AllocationID != record.AllocationID || original.Digest() != record.OriginalDigest ||
			original.SandboxID != intent.Request.SandboxID || original.CreationGeneration != uint64(intent.Request.ExpectedGeneration) ||
			record.Completion != intent.Completion || record.Completion != slots.CreateCompletions[record.AllocationID] || !validCodingCompletion(record.Completion, original, at) ||
			!record.Snapshot.Lease.ExpiresAt.After(at) || fence < record.Snapshot.Lease.FencingToken ||
			!hasLease || !hasSandbox || lease.FencingToken < fence || ledger.Fencing[original.ProviderRevisionID+"\x00"+original.SandboxID] < fence ||
			sb.ProviderRevisionID != original.ProviderRevisionID || lease.SandboxID != original.SandboxID {
			return ErrCorrupt
		}
		seen[record.OperationID] = true
	}
	encoded, err := json.Marshal(s)
	if err != nil || len(encoded) > maxCodingExecFenceBytes {
		return ErrCorrupt
	}
	return nil
}

func (s codingExecFenceState) validate(marker codingIdentityMarker, slots codingidentity.State, ledger lifecyclerepository.State, intents codingExecIntentState,
	plan codingidentity.Plan, specs map[string]string, policy string, now time.Time) error {
	if err := intents.validate(marker, slots, ledger, plan, specs, policy, now); err != nil {
		return err
	}
	return s.validateNamespace(marker, slots, ledger, intents, now)
}

func codingFenceReceipt(record codingExecFenceRecord, fence uint64, replay bool) codingcontrol.ExecFenceReceipt {
	// An internal content identity, not a signature or Contract admission proof.
	raw, _ := json.Marshal(record)
	sum := sha256.Sum256(raw)
	return codingcontrol.ExecFenceReceipt{OperationID: record.OperationID, PayloadDigest: record.PayloadDigest,
		ReservationDigest: "sha256:" + hex.EncodeToString(sum[:]), FencingToken: fence, RecordedAt: record.Snapshot.ObservedAt, Replayed: replay}
}

func reserveCodingExecFence(marker codingIdentityMarker, slots codingidentity.State, ledger *lifecyclerepository.State, intents codingExecIntentState,
	state *codingExecFenceState, plan codingidentity.Plan, specs map[string]string, policy string, request providerexec.Request, now time.Time) (codingcontrol.ExecFenceReceipt, error) {
	empty := codingcontrol.ExecFenceReceipt{}
	request, raw, payload, err := codingExecRequest(request, now)
	if err != nil {
		return empty, err
	}
	if err := state.validate(marker, slots, *ledger, intents, plan, specs, policy, now); err != nil {
		return empty, err
	}
	var intent codingExecIntentRecord
	found := false
	for _, candidate := range intents.Records {
		if candidate.Request.OperationID != request.OperationID && candidate.Request.IdempotencyKey != request.IdempotencyKey {
			continue
		}
		stored, err := json.Marshal(candidate.Request)
		if err != nil || !bytes.Equal(raw, stored) {
			return empty, codingcontrol.ErrExecIntentConflict
		}
		intent, found = candidate, true
	}
	if !found {
		return empty, codingcontrol.ErrExecFence
	}
	for _, record := range state.Records {
		if record.OperationID == request.OperationID {
			return codingFenceReceipt(record, uint64(request.FencingToken), true), nil
		}
	}
	if len(state.Records) >= maxCodingExecFences {
		return empty, codingcontrol.ErrExecIntentCapacity
	}
	snapshot, err := readCodingRuntimeSnapshot(marker, slots, *ledger, plan, specs, policy, request.SandboxID, now)
	if err != nil || !sameCodingExecTuple(snapshot, intent.Snapshot) || snapshot.ObservedAt.Before(intent.Snapshot.ObservedAt) ||
		uint64(request.FencingToken) < snapshot.Lease.FencingToken {
		return empty, codingcontrol.ErrExecFence
	}
	currentAllocation := ""
	for _, reservation := range slots.Reservations {
		if reservation.Claim.SandboxID == request.SandboxID {
			currentAllocation = reservation.Claim.AllocationID
		}
	}
	original, err := decodeCodingOriginalCreate(slots.OriginalCreates[currentAllocation], now)
	if err != nil || currentAllocation != intent.AllocationID || slots.CreateCompletions[currentAllocation] != intent.Completion {
		return empty, codingcontrol.ErrExecFence
	}
	record := codingExecFenceRecord{OperationID: request.OperationID, PayloadDigest: payload, AllocationID: currentAllocation,
		OriginalDigest: original.Digest(), Snapshot: snapshot, Completion: intent.Completion}
	// The dedicated transaction changes exactly these two fields. It does not
	// relax the generic readiness barrier, which still rejects bare fence writes.
	nextLedger := newLifecycleState()
	if err := nextLedger.Import(ledger.Export()); err != nil {
		return empty, ErrCorrupt
	}
	lease := nextLedger.Leases[request.SandboxID]
	lease.FencingToken = uint64(request.FencingToken)
	nextLedger.Leases[request.SandboxID] = lease
	nextLedger.Fencing[snapshot.Sandbox.ProviderRevisionID+"\x00"+request.SandboxID] = uint64(request.FencingToken)
	next := *state
	next.Records = append(append([]codingExecFenceRecord{}, state.Records...), record)
	if err := next.validate(marker, slots, nextLedger, intents, plan, specs, policy, now); err != nil {
		return empty, err
	}
	*ledger, *state = nextLedger, next
	return codingFenceReceipt(record, uint64(request.FencingToken), false), nil
}

func initializeCodingExecFenceState(g *codingExecIsolation, plan codingidentity.Plan, specs map[string]string, policy string, now time.Time) (codingIdentityMarker, codingExecFenceState, error) {
	if g == nil || g.marker.ExecFenceMode != "" || g.intents.validate(g.marker, g.slots, g.ledger, plan, specs, policy, now) != nil ||
		len(g.intents.Records) != 0 || len(g.slots.Reservations) != 0 || len(g.slots.Retirements) != 0 || len(g.slots.OriginalCreates) != 0 || len(g.slots.CreateCompletions) != 0 ||
		!reflect.DeepEqual(g.ledger.Export(), newLifecycleState().Export()) {
		return codingIdentityMarker{}, codingExecFenceState{}, codingcontrol.ErrExecIntentConflict
	}
	marker := g.marker
	marker.ExecFenceMode = codingExecFenceMode
	return marker, codingExecFenceState{Version: 1, Mode: codingExecFenceMode, PlanDigest: marker.PlanDigest, Records: []codingExecFenceRecord{}}, nil
}

// InitializeCodingExecFences is an explicit, unused-state-only bootstrap. It
// never runs during construction/startup and cannot upgrade populated intents.
func (r *CodingLifecycleRepository) InitializeCodingExecFences(ctx context.Context) error {
	_, err := r.codingExecFenceTransaction(ctx, true, providerexec.Request{})
	return err
}

func (r *CodingLifecycleRepository) ReserveCodingExecFence(ctx context.Context, request providerexec.Request) (codingcontrol.ExecFenceReceipt, error) {
	if ctx == nil {
		return codingcontrol.ExecFenceReceipt{}, ErrUnavailable
	}
	request, _, _, err := codingExecRequest(request, time.Now().UTC())
	if err != nil {
		return codingcontrol.ExecFenceReceipt{}, err
	}
	bounded, cancel := context.WithDeadline(ctx, request.Deadline)
	defer cancel()
	return r.codingExecFenceTransaction(bounded, false, request)
}

func (r *CodingLifecycleRepository) codingExecFenceTransaction(ctx context.Context, initialize bool, request providerexec.Request) (codingcontrol.ExecFenceReceipt, error) {
	empty := codingcontrol.ExecFenceReceipt{}
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
	if err := tx.QueryRow(opCtx, `SELECT singleton FROM sandbox_runtime_provider.control_state WHERE singleton FOR UPDATE`).Scan(new(bool)); err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	g, err := readCodingExecIsolation(opCtx, tx)
	if err != nil {
		return empty, err
	}
	now := time.Now().UTC()
	if initialize && g.marker.ExecFenceMode == codingExecFenceMode {
		if err := g.fences.validate(g.marker, g.slots, g.ledger, g.intents, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, now); err != nil {
			return empty, err
		}
		return empty, opCtx.Err() // Read-only recovery, never document repair.
	}
	var receipt codingcontrol.ExecFenceReceipt
	writeKey := lifecycleDocument
	var writeValue any
	if initialize {
		g.marker, g.fences, err = initializeCodingExecFenceState(g, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, now)
		writeKey, writeValue = codingIdentityMarkerDocument, g.marker
	} else {
		receipt, err = reserveCodingExecFence(g.marker, g.slots, &g.ledger, g.intents, &g.fences, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, request, now)
		writeValue = g.ledger.Export()
	}
	if err != nil {
		return empty, err
	}
	if receipt.Replayed {
		if err := opCtx.Err(); err != nil {
			return empty, err
		}
		return receipt, nil
	}
	encoded, err := encodeStoredState(g.fences)
	if err != nil {
		return empty, err
	}
	other, err := encodeStoredState(writeValue)
	if err != nil {
		return empty, err
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_provider.control_state SET documents=jsonb_set(jsonb_set(documents,ARRAY[$1]::text[],$3::jsonb,true),ARRAY[$2]::text[],$4::jsonb,true),revision=revision+1,updated_at=clock_timestamp() WHERE singleton`, codingExecFenceDocument, writeKey, encoded, other); err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	if err := tx.Commit(opCtx); err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	if err := opCtx.Err(); err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	return receipt, nil
}

func (r *CodingLifecycleRepository) ReadCodingExecFence(ctx context.Context, id string) (codingcontrol.ExecFenceReceipt, error) {
	empty := codingcontrol.ExecFenceReceipt{}
	if r == nil || r.bound == nil || r.bound.store == nil || r.bound.store.pool == nil || ctx == nil || lifecycle.ValidateIdentifier(id) != nil {
		return empty, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	store := r.bound.store
	opCtx, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	g, err := readCodingExecIsolation(opCtx, store.pool)
	if err != nil {
		return empty, err
	}
	if err := g.fences.validate(g.marker, g.slots, g.ledger, g.intents, r.bound.plan, r.specBySlot, r.bound.controlPolicyDigest, time.Now().UTC()); err != nil {
		return empty, err
	}
	if err := opCtx.Err(); err != nil {
		return empty, stateError(ctx, opCtx, err)
	}
	for _, record := range g.fences.Records {
		if record.OperationID == id {
			for _, intent := range g.intents.Records {
				if intent.Request.OperationID == id {
					return codingFenceReceipt(record, uint64(intent.Request.FencingToken), true), nil
				}
			}
		}
	}
	return empty, codingcontrol.ErrExecFence
}

var _ codingcontrol.ExecFenceRecorder = (*CodingLifecycleRepository)(nil)
