package providerpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

const (
	codingIdentityMarkerDocument = "coding_identity_marker"
	codingIdentityStateDocument  = "coding_identity_state"
)

// CodingBoundCreateRepository is a PG-row-bound primitive, not a production
// coding-v3 composition. The latter still requires the complete v2 Profile,
// restricted Docker control, scanner and named release gate.
type CodingBoundCreateRepository struct {
	store               *Store
	plan                codingidentity.Plan
	digest              string
	controlPolicyDigest string
}

// NewCodingBoundCreateRepositoryWithPolicy freezes the independent Control
// policy before any original create authority is minted. The legacy
// constructor has no such authority and cannot use the atomic v3 permit.
func NewCodingBoundCreateRepositoryWithPolicy(store *Store, plan codingidentity.Plan,
	controlPolicyDigest string) (*CodingBoundCreateRepository, error) {
	if lifecycle.ValidateDigest(controlPolicyDigest) != nil {
		return nil, codingidentity.ErrInvalidPlan
	}
	repository, err := NewCodingBoundCreateRepository(store, plan)
	if err != nil {
		return nil, err
	}
	repository.controlPolicyDigest = controlPolicyDigest
	return repository, nil
}

func NewCodingBoundCreateRepository(store *Store, plan codingidentity.Plan) (*CodingBoundCreateRepository, error) {
	if store == nil || store.pool == nil {
		return nil, ErrUnavailable
	}
	if plan.Capacity != codingidentity.LocalCandidateCapacity {
		return nil, codingidentity.ErrInvalidPlan
	}
	digest, err := plan.Digest()
	if err != nil {
		return nil, err
	}
	plan.Slots = append([]codingidentity.Slot(nil), plan.Slots...)
	return &CodingBoundCreateRepository{store: store, plan: plan, digest: digest}, nil
}

func importCodingIdentityState(state *codingidentity.State, document json.RawMessage) error {
	var decoded codingidentity.State
	if decodePersisted(&decoded, document) != nil {
		return ErrCorrupt
	}
	canonical, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrCorrupt
	}
	*state = decoded
	return nil
}

// Initialize requires an independently established empty physical namespace.
// It never treats a missing document as permission to recycle an old slot.
// The callback runs before the PG row lock and is not an admission substitute.
func (r *CodingBoundCreateRepository) Initialize(ctx context.Context,
	confirmClean func(context.Context, codingidentity.Plan) error) error {
	if r == nil || ctx == nil || confirmClean == nil || r.controlPolicyDigest != "" {
		return ErrUnavailable
	}
	cleanPlan := r.plan
	cleanPlan.Slots = append([]codingidentity.Slot(nil), r.plan.Slots...)
	if err := confirmClean(ctx, cleanPlan); err != nil {
		return err
	}
	return mutateStatePair(ctx, r.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		func(marker *codingIdentityMarker, state *codingidentity.State) error {
			if *marker != (codingIdentityMarker{}) || state.Version != 0 || state.Initialized ||
				state.PlanDigest != "" || state.Reservations != nil || state.Retirements != nil ||
				state.OriginalCreates != nil {
				return codingidentity.ErrConflict
			}
			fresh, err := codingidentity.NewState(r.plan)
			if err != nil {
				return err
			}
			*marker = codingIdentityMarker{Initialized: true, PlanDigest: r.digest}
			*state = fresh
			return nil
		})
}

// InitializeAtomicOriginal is the only v3 bootstrap. It requires the same
// independent clean-namespace proof as legacy Initialize and atomically
// freezes the plan, mode and Control policy before any first permit exists.
// A legacy initialized marker, even with no live slots, cannot be upgraded.
func (r *CodingBoundCreateRepository) InitializeAtomicOriginal(ctx context.Context,
	confirmClean func(context.Context, codingidentity.Plan) error) error {
	if r == nil || ctx == nil || confirmClean == nil ||
		lifecycle.ValidateDigest(r.controlPolicyDigest) != nil {
		return ErrUnavailable
	}
	cleanPlan := r.plan
	cleanPlan.Slots = append([]codingidentity.Slot(nil), r.plan.Slots...)
	if err := confirmClean(ctx, cleanPlan); err != nil {
		return err
	}
	return mutateStatePair(ctx, r.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		func(marker *codingIdentityMarker, state *codingidentity.State) error {
			if *marker != (codingIdentityMarker{}) || state.Version != 0 || state.Initialized ||
				state.PlanDigest != "" || state.Reservations != nil || state.Retirements != nil ||
				state.OriginalCreates != nil {
				return codingidentity.ErrConflict
			}
			fresh, err := codingidentity.NewState(r.plan)
			if err != nil {
				return err
			}
			*marker = codingIdentityMarker{Initialized: true, PlanDigest: r.digest,
				AuthorityMode:       codingAtomicOriginalMode,
				ControlPolicyDigest: r.controlPolicyDigest}
			*state = fresh
			return nil
		})
}

// BeginFirstCreate is the only first Docker-create permit in this bounded
// model. It binds the original accepted Provider create, finite slot and
// lifecycle Running/Provisioning transition in one locked PG row update.
// Nothing here contacts Docker; a retry after a committed permit cannot
// obtain another first-create permit from a Running/Unknown operation. The
// deadline check uses current time inside the locked mutation, not a
// caller-supplied timestamp captured before queueing for the row lock.
func (r *CodingBoundCreateRepository) BeginFirstCreate(ctx context.Context, operationID string,
	specBySlot map[string]string) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error) {
	if r == nil || ctx == nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, ErrUnavailable
	}
	var ticket codingidentity.Reservation
	var running lifecycle.Operation
	var provisioning lifecycle.Sandbox
	err := mutateStateTriple(ctx, r.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			now := time.Now().UTC()
			if !marker.Initialized || marker.PlanDigest != r.digest || marker.AuthorityMode != "" ||
				marker.ControlPolicyDigest != "" || slots.Validate(r.plan) != nil ||
				checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now) != nil {
				return codingidentity.ErrInvalidState
			}
			var err error
			ticket, running, provisioning, err = beginCodingFirstCreate(slots, ledger, r.plan, operationID, specBySlot, now)
			return err
		})
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	return ticket, running, provisioning, nil
}

// BeginFirstCreateWithAuthority is the production-oriented atomic first
// permit. The original envelope is minted and retained inside the same PG
// transaction as Creating/Running/Provisioning and its event. An uncertain
// commit, cancellation, or expiry returns no physical dispatch permission.
// The older BeginFirstCreate remains a component primitive, not a v3 route.
func (r *CodingBoundCreateRepository) BeginFirstCreateWithAuthority(ctx context.Context,
	operationID string, specBySlot map[string]string,
) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, dockercontrol.CodingCreateAuthority, error) {
	if r == nil || ctx == nil || lifecycle.ValidateDigest(r.controlPolicyDigest) != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
			dockercontrol.CodingCreateAuthority{}, ErrUnavailable
	}
	var ticket codingidentity.Reservation
	var running lifecycle.Operation
	var provisioning lifecycle.Sandbox
	var authority dockercontrol.CodingCreateAuthority
	err := mutateStateTriple(ctx, r.store,
		codingIdentityMarkerDocument, codingIdentityStateDocument, lifecycleDocument,
		func() codingIdentityMarker { return codingIdentityMarker{} }, importCodingIdentityMarker,
		func(marker codingIdentityMarker) any { return marker },
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState,
		func(state codingidentity.State) any { return state },
		newLifecycleState, importLifecycleState, exportLifecycleState,
		func(marker *codingIdentityMarker, slots *codingidentity.State, ledger *lifecyclerepository.State) error {
			now := time.Now().UTC()
			if !marker.matchesAtomic(r.digest, r.controlPolicyDigest) ||
				checkCodingRetirementBarrierWithMarker(*marker, *slots, *ledger, *ledger, now) != nil {
				return codingidentity.ErrInvalidState
			}
			var err error
			ticket, running, provisioning, authority, err = beginCodingFirstCreateWithAuthority(
				ctx, slots, ledger, r.plan, operationID, specBySlot,
				r.controlPolicyDigest, now)
			return err
		})
	if err != nil || ctx.Err() != nil || authority.Validate(time.Now().UTC()) != nil {
		if err == nil {
			err = ctx.Err()
			if err == nil {
				err = dockercontrol.ErrInvalidAuthority
			}
		}
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
			dockercontrol.CodingCreateAuthority{}, err
	}
	return ticket, running, provisioning, authority, nil
}

// beginCodingFirstCreateWithAuthority mutates only transaction-local copies.
// A caller must discard all four results and both state copies on error.
func beginCodingFirstCreateWithAuthority(ctx context.Context, slots *codingidentity.State,
	ledger *lifecyclerepository.State, plan codingidentity.Plan, operationID string,
	specBySlot map[string]string, controlPolicyDigest string, now time.Time,
) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox,
	dockercontrol.CodingCreateAuthority, error) {
	fail := func(err error) (codingidentity.Reservation, lifecycle.Operation,
		lifecycle.Sandbox, dockercontrol.CodingCreateAuthority, error) {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
			dockercontrol.CodingCreateAuthority{}, err
	}
	if ctx == nil || ctx.Err() != nil || slots == nil || ledger == nil ||
		lifecycle.ValidateDigest(controlPolicyDigest) != nil || now.IsZero() ||
		slots.Validate(plan) != nil ||
		len(slots.OriginalCreates) >= codingidentity.MaxOriginalCreateEnvelopes {
		return fail(codingidentity.ErrInvalidState)
	}
	ticket, running, provisioning, err := beginCodingFirstCreate(slots, ledger,
		plan, operationID, specBySlot, now)
	if err != nil {
		return fail(err)
	}
	if _, exists := slots.OriginalCreates[ticket.Claim.AllocationID]; exists {
		return fail(codingidentity.ErrConflict)
	}
	authority, err := dockercontrol.NewCodingCreateAuthority(ctx, ticket, running,
		provisioning, plan, controlPolicyDigest, plan.OwnerPrincipalDigest, now)
	if err != nil {
		return fail(err)
	}
	document, err := dockercontrol.EncodeCodingCreateAuthority(authority)
	if err != nil {
		return fail(err)
	}
	if slots.OriginalCreates == nil {
		slots.OriginalCreates = make(map[string]codingidentity.OriginalCreateEnvelope)
	}
	slots.OriginalCreates[ticket.Claim.AllocationID] = codingidentity.OriginalCreateEnvelope{
		Document: string(document), Digest: authority.Digest()}
	if slots.Validate(plan) != nil ||
		validateCodingOriginalCreate(*slots, *ledger, plan, authority, now) != nil {
		return fail(codingidentity.ErrInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	return ticket, running, provisioning, authority, nil
}

// beginCodingFirstCreate must only run on freshly decoded, transaction-local
// states. A returned error discards both documents, including partial scratch
// mutations. The authorization callback is pure and never performs I/O.
func beginCodingFirstCreate(slots *codingidentity.State, ledger *lifecyclerepository.State,
	plan codingidentity.Plan, operationID string, specBySlot map[string]string, now time.Time,
) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox, error) {
	if slots == nil || ledger == nil || slots.Validate(plan) != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrInvalidState
	}
	claim, err := codingClaimFromAcceptedCreate(ledger, operationID, now)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	operation, err := ledger.GetOperation(operationID)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	sandbox, err := ledger.GetSandbox(claim.SandboxID)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	provisioning, err := lifecycle.ApplyObservedTransition(sandbox, lifecycle.ObservedProvisioning, claim.Generation, now)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	running, err := lifecycle.BeginOperation(operation, now)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	ticket, err := slots.Reserve(plan, claim, specBySlot, func(candidate codingidentity.Claim) error {
		if candidate != claim {
			return codingidentity.ErrConflict
		}
		return nil
	})
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if ticket.Status != codingidentity.Reserved {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, codingidentity.ErrInProgress
	}
	ticket, err = slots.BeginCreate(plan, ticket)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if err := ledger.UpdateSandbox(provisioning, sandbox.Generation, claim.Fence); err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	if err := ledger.UpdateOperation(running); err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	// Match the established coordinator provisioning event exactly, but
	// commit it with the first permit. No caller can receive a ticket if the
	// lifecycle event or either state document fails to persist.
	eventDigest := sha256.Sum256([]byte(running.ID + "\x00" + string(running.State) + "\x00provisioning"))
	_, err = ledger.AppendEvent(lifecycle.Event{ID: "event-" + hex.EncodeToString(eventDigest[:]),
		SandboxID: provisioning.ID, OperationID: running.ID, Generation: provisioning.Generation,
		FencingToken: running.FencingToken, Kind: "provisioning", OccurredAt: now})
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{}, err
	}
	return ticket, running, provisioning, nil
}
