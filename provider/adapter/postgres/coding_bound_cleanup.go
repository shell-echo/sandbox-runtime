package providerpostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

type codingCleanupAdmission struct {
	Create              dockercontrol.CodingCreateAuthority
	Completed           dockercontrol.CodingReceipt
	ControlRevision     uint64
	ControlStateDigest  string
	TerminationID       string
	ControlPolicyDigest string
	PeerPrincipalDigest string
	SpecBySlot          map[string]string
}

// BeginCodingCurrentCleanup is a source-only PG-row-bound admission. The
// completed snapshot must come from the authenticated Control owner outside
// the row lock; the production cross-process adapter/profile is still gated.
// It does not inspect Docker or turn a historical create outcome_unknown into
// Succeeded. All three Provider documents commit or roll back together.
func (r *CodingLifecycleRepository) BeginCodingCurrentCleanup(ctx context.Context,
	terminationID string, create dockercontrol.CodingCreateAuthority,
	completed dockercontrol.CodingCompletedSnapshot, expectedControlPolicyDigest string,
) (dockercontrol.CodingCleanupAuthority, codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error) {
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil ||
		lifecycle.ValidateDigest(expectedControlPolicyDigest) != nil {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.Reservation{},
			lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	marker, markerErr := r.bound.readCodingMarker(ctx)
	if markerErr != nil || marker.AuthorityMode != "" ||
		marker.PlanDigest != r.bound.digest || !marker.Initialized {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.Reservation{},
			lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrInvalidState
	}
	if completed.Validate(create) != nil {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.Reservation{},
			lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrConflict
	}
	input := codingCleanupAdmission{Create: create, Completed: completed.Receipt(),
		ControlRevision: completed.Revision(), ControlStateDigest: completed.StateDigest(),
		TerminationID: terminationID, ControlPolicyDigest: expectedControlPolicyDigest,
		PeerPrincipalDigest: r.bound.plan.OwnerPrincipalDigest, SpecBySlot: r.specBySlot}
	var authority dockercontrol.CodingCleanupAuthority
	var cleaning codingidentity.Reservation
	var running lifecycle.Operation
	var terminating lifecycle.Sandbox
	err := mutateStateTriple(ctx, r.bound.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			now := time.Now().UTC()
			if !marker.Initialized || marker.PlanDigest != r.bound.digest ||
				marker.AuthorityMode != "" || marker.ControlPolicyDigest != "" ||
				checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now) != nil {
				return codingidentity.ErrInvalidState
			}
			var err error
			authority, cleaning, running, terminating, err = beginCodingCurrentCleanup(
				ctx, slots, ledger, r.bound.plan, input, now)
			return err
		})
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.Reservation{},
			lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if err := ctx.Err(); err != nil {
		// The PG commit may have happened. Do not return a dispatch permit;
		// reconcile the stored retirement binding read-only.
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.Reservation{},
			lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if authority.Validate(time.Now().UTC()) != nil {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.Reservation{},
			lifecycle.Operation{}, lifecycle.Sandbox{}, dockercontrol.ErrInvalidAuthority
	}
	return authority, cleaning, running, terminating, nil
}

// beginCodingCurrentCleanup only mutates transaction-local decoded copies.
// Its caller must already have obtained Completed from a trusted current
// Control read; this structural helper alone cannot authenticate that read.
func beginCodingCurrentCleanup(ctx context.Context, slots *codingidentity.State, ledger *lifecyclerepository.State,
	plan codingidentity.Plan, input codingCleanupAdmission, now time.Time,
) (dockercontrol.CodingCleanupAuthority, codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error) {
	stage := "admission"
	fail := func() (dockercontrol.CodingCleanupAuthority, codingidentity.Reservation,
		lifecycle.Operation, lifecycle.Sandbox, error) {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.Reservation{},
			lifecycle.Operation{}, lifecycle.Sandbox{}, fmt.Errorf("coding cleanup %s: %w", stage, codingidentity.ErrConflict)
	}
	create := input.Create
	if ctx == nil || ctx.Err() != nil || slots == nil || ledger == nil ||
		now.IsZero() || slots.Validate(plan) != nil ||
		lifecycle.ValidateIdentifier(input.TerminationID) != nil ||
		len(input.SpecBySlot) != len(plan.Slots) ||
		lifecycle.ValidateDigest(input.ControlPolicyDigest) != nil ||
		input.PeerPrincipalDigest != plan.OwnerPrincipalDigest ||
		input.ControlRevision == 0 || lifecycle.ValidateDigest(input.ControlStateDigest) != nil ||
		input.Completed.Status != dockercontrol.ReceiptCompleted ||
		input.Completed.Authority != create || input.Completed.AuthorityDigest != create.Digest() ||
		input.Completed.UpdatedAt.IsZero() || input.Completed.UpdatedAt.After(now) ||
		input.Completed.CleanupAuthority != (dockercontrol.CodingCleanupAuthority{}) ||
		lifecycle.ValidateDigest(input.Completed.CompletionDigest) != nil ||
		lifecycle.ValidateDigest(input.Completed.CompletionEvidenceDigest) != nil ||
		create.ControlPolicyDigest != input.ControlPolicyDigest ||
		create.BindControl(plan, input.ControlPolicyDigest, input.PeerPrincipalDigest,
			input.SpecBySlot[create.SlotID], create.IssuedAt) != nil {
		return fail()
	}
	for _, slot := range plan.Slots {
		if lifecycle.ValidateDigest(input.SpecBySlot[slot.ID]) != nil {
			return fail()
		}
	}
	var original codingidentity.Reservation
	stage = "original-reservation"
	for _, candidate := range slots.Reservations {
		if candidate.Slot.ID == create.SlotID {
			original = candidate
			break
		}
	}
	if original.Status != codingidentity.Creating && original.Status != codingidentity.Active {
		return fail()
	}
	if original.Claim.AllocationID != create.AllocationID ||
		original.Claim.SandboxID != create.SandboxID ||
		original.Claim.OperationID != create.OperationID ||
		original.Claim.AttemptID != create.AttemptID ||
		original.Claim.RequestDigest != create.RequestDigest ||
		original.Claim.Generation != create.CreationGeneration ||
		original.Claim.Fence != create.Fence ||
		original.Claim.TenantDigest != create.TenantDigest ||
		original.SpecDigest != create.SpecDigest ||
		original.PlanDigest != create.PlanDigest {
		return fail()
	}
	if _, exists := slots.Retirements[create.SlotID]; exists {
		return fail()
	}
	stage = "original-operation"
	createOperation, err := ledger.GetOperation(create.OperationID)
	if err != nil || createOperation.Validate() != nil || createOperation.ID != create.OperationID ||
		createOperation.Type != lifecycle.OperationCreate ||
		(createOperation.State != lifecycle.OperationRunning &&
			createOperation.State != lifecycle.OperationSucceeded &&
			createOperation.State != lifecycle.OperationOutcomeUnknown) ||
		createOperation.SandboxID != create.SandboxID ||
		createOperation.AttemptID != create.AttemptID ||
		createOperation.FencingToken != create.Fence ||
		(createOperation.RequestDigest != "" && createOperation.RequestDigest != create.RequestDigest) ||
		!codingStoredIdempotencyMatches(ledger, createOperation, create.RequestDigest, create.ProviderRevisionID, false) {
		return fail()
	}
	stage = "current-sandbox"
	sandbox, err := ledger.GetSandbox(create.SandboxID)
	if err != nil || sandbox.Validate() != nil || sandbox.ProviderRevisionID != create.ProviderRevisionID ||
		sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
		sandbox.DesiredState != lifecycle.DesiredTerminated ||
		sandbox.Generation <= create.CreationGeneration {
		return fail()
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil || tenantDigest != create.TenantDigest {
		return fail()
	}
	stage = "current-termination"
	termination, err := ledger.GetOperation(input.TerminationID)
	if err != nil || termination.Validate() != nil || termination.ID != input.TerminationID ||
		termination.Type != lifecycle.OperationTerminate ||
		termination.State != lifecycle.OperationAccepted || termination.CancelRequested ||
		termination.ID == create.OperationID || termination.SandboxID != sandbox.ID ||
		termination.FencingToken < create.Fence || !termination.Deadline.After(now) ||
		termination.ObservedAt.After(now) ||
		lifecycle.ValidateDigest(termination.RequestDigest) != nil ||
		!codingStoredIdempotencyMatches(ledger, termination, termination.RequestDigest,
			sandbox.ProviderRevisionID, true) {
		return fail()
	}
	stage = "current-fence"
	scope := sandbox.ProviderRevisionID + "\x00" + sandbox.ID
	lease, err := ledger.GetLease(sandbox.ID)
	if err != nil || lease.Validate() != nil || lease.SandboxID != sandbox.ID ||
		ledger.Fencing[scope] != termination.FencingToken ||
		lease.Generation != sandbox.Generation ||
		lease.FencingToken != termination.FencingToken ||
		!lease.ExpiresAt.Equal(sandbox.LeaseExpiresAt) {
		return fail()
	}
	// A trustworthy Control Completed may close a Provider Creating slot
	// without changing the historical create operation or publishing Ready.
	stage = "transaction-transition"
	if original.Status == codingidentity.Creating {
		original, err = slots.CompleteCreate(plan, original)
		if err != nil {
			return fail()
		}
	}
	cleaning, err := slots.BeginCleanup(plan, original)
	if err != nil {
		return fail()
	}
	running, err := lifecycle.BeginOperation(termination, now)
	if err != nil {
		return fail()
	}
	terminating, err := lifecycle.ApplyObservedTransition(sandbox,
		lifecycle.ObservedTerminating, sandbox.Generation, now)
	if err != nil || ledger.UpdateSandbox(terminating, sandbox.Generation, termination.FencingToken) != nil ||
		ledger.UpdateOperation(running) != nil {
		return fail()
	}
	stage = "cleanup-authority"
	authority, err := dockercontrol.NewCodingCleanupAuthority(ctx, create,
		cleaning, running, terminating, plan, input.ControlPolicyDigest,
		input.PeerPrincipalDigest, now)
	if err != nil {
		return fail()
	}
	authorityDocument, err := dockercontrol.EncodeCodingCleanupAuthority(authority)
	if err != nil {
		return fail()
	}
	binding := codingidentity.RetirementBinding{OriginalAllocationID: create.AllocationID,
		OriginalAuthorityDigest: create.Digest(), OriginalGeneration: create.CreationGeneration,
		OriginalFence: create.Fence, OperationID: running.ID, AttemptID: running.AttemptID,
		RequestDigest: running.RequestDigest, CurrentGeneration: terminating.Generation,
		CurrentFence: running.FencingToken, ControlReceiptRevision: input.ControlRevision,
		ControlReceiptStateDigest: input.ControlStateDigest,
		ControlCompletionDigest:   input.Completed.CompletionDigest,
		ControlEvidenceDigest:     input.Completed.CompletionEvidenceDigest,
		CleanupAuthorityDocument:  string(authorityDocument),
		CleanupAuthorityDigest:    authority.Digest()}
	if slots.Retirements == nil {
		slots.Retirements = make(map[string]codingidentity.RetirementBinding)
	}
	slots.Retirements[cleaning.Slot.ID] = binding
	if slots.Validate(plan) != nil {
		return fail()
	}
	stage = "terminating-event"
	eventSum := sha256.Sum256([]byte(running.ID + "\x00" + string(running.State) + "\x00terminating"))
	_, err = ledger.AppendEvent(lifecycle.Event{ID: "event-" + hex.EncodeToString(eventSum[:]),
		SandboxID: terminating.ID, OperationID: running.ID, Generation: terminating.Generation,
		FencingToken: running.FencingToken, Kind: "terminating", OccurredAt: now})
	if err != nil {
		return fail()
	}
	if ctx.Err() != nil || authority.Validate(now) != nil {
		return fail()
	}
	return authority, cleaning, running, terminating, nil
}

func codingStoredIdempotencyMatches(state *lifecyclerepository.State,
	operation lifecycle.Operation, requestDigest, revision string, exactCurrent bool) bool {
	count := 0
	for scope, candidate := range state.Idempotency {
		if candidate.Operation.ID != operation.ID {
			continue
		}
		if scope != revision+"\x00"+candidate.Key || candidate.Scope != scope ||
			candidate.Key == "" || (exactCurrent && candidate.Key != operation.IdempotencyKey) ||
			candidate.RequestDigest != requestDigest ||
			candidate.Operation.AttemptID != operation.AttemptID ||
			candidate.Operation.FencingToken != operation.FencingToken ||
			candidate.Operation.SandboxID != operation.SandboxID ||
			candidate.Operation.Type != operation.Type ||
			!reflect.DeepEqual(candidate.Operation, operation) {
			return false
		}
		count++
	}
	return count == 1
}

// ReadCodingCleanupEnvelope returns the exact historically committed private
// envelope after an uncertain PG response. It does not renew expiry, attest
// current Control state, or grant a second physical dispatch. Production
// continuation must separately recheck current PG/Control retirement state.
func (r *CodingLifecycleRepository) ReadCodingCleanupEnvelope(ctx context.Context,
	create dockercontrol.CodingCreateAuthority, terminationID, expectedControlPolicyDigest string,
) (dockercontrol.CodingCleanupAuthority, error) {
	if r == nil || r.bound == nil || ctx == nil || ctx.Err() != nil ||
		lifecycle.ValidateDigest(expectedControlPolicyDigest) != nil {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.ErrConflict
	}
	marker, err := r.bound.readCodingMarker(ctx)
	if err != nil || !marker.Initialized || marker.PlanDigest != r.bound.digest {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.ErrConflict
	}
	// This legacy raw-authority readback is not a v3 recovery path. The v3
	// application uses ReadFinishBinding for a status observation and its
	// typed PG commit rechecks the exact persisted envelope under the lock.
	if marker.AuthorityMode != "" || r.bound.controlPolicyDigest != "" {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.ErrConflict
	}
	state, err := readState(ctx, r.bound.store, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil {
		return dockercontrol.CodingCleanupAuthority{}, err
	}
	return readCodingCleanupEnvelope(state, r.bound.plan, create, terminationID,
		expectedControlPolicyDigest, r.bound.plan.OwnerPrincipalDigest, r.specBySlot)
}

func readCodingCleanupEnvelope(state codingidentity.State, plan codingidentity.Plan,
	create dockercontrol.CodingCreateAuthority, terminationID, controlPolicyDigest,
	peerPrincipalDigest string, specBySlot map[string]string,
) (dockercontrol.CodingCleanupAuthority, error) {
	if state.Validate(plan) != nil || lifecycle.ValidateIdentifier(terminationID) != nil ||
		create.BindControl(plan, controlPolicyDigest, peerPrincipalDigest,
			specBySlot[create.SlotID], create.IssuedAt) != nil {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.ErrConflict
	}
	var reservation codingidentity.Reservation
	for _, item := range state.Reservations {
		if item.Slot.ID == create.SlotID {
			reservation = item
			break
		}
	}
	binding, ok := state.Retirements[create.SlotID]
	if !ok || binding.Validate(reservation) != nil || binding.OperationID != terminationID ||
		binding.OriginalAuthorityDigest != create.Digest() ||
		binding.OriginalAllocationID != create.AllocationID {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.ErrConflict
	}
	document := []byte(binding.CleanupAuthorityDocument)
	var raw dockercontrol.CodingCleanupAuthority
	if json.Unmarshal(document, &raw) != nil {
		return dockercontrol.CodingCleanupAuthority{}, ErrCorrupt
	}
	authority, err := dockercontrol.DecodeCodingCleanupAuthority(document, raw.IssuedAt)
	if err != nil || authority.Digest() != binding.CleanupAuthorityDigest ||
		authority.BindControl(create, plan, controlPolicyDigest,
			peerPrincipalDigest, reservation.SpecDigest, authority.IssuedAt) != nil ||
		authority.CleanupOperationID != terminationID ||
		authority.CleanupAttemptID != binding.AttemptID ||
		authority.CleanupRequestDigest != binding.RequestDigest ||
		authority.CurrentGeneration != binding.CurrentGeneration ||
		authority.CleanupFence != binding.CurrentFence ||
		authority.BirthGeneration != binding.OriginalGeneration ||
		authority.BirthFence != binding.OriginalFence {
		return dockercontrol.CodingCleanupAuthority{}, codingidentity.ErrConflict
	}
	return authority, nil
}
