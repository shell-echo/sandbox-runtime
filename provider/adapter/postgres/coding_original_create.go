package providerpostgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

// ReadOriginalCreateAuthority is read-only recovery of the exact retained
// original. It never authorizes a create retry. The read can race another PG
// commit; a later typed cleanup/release CAS must recheck under the row lock.
func (r *CodingBoundCreateRepository) ReadOriginalCreateAuthority(ctx context.Context,
	allocationID string) (dockercontrol.CodingCreateAuthority, error) {
	if r == nil || ctx == nil || lifecycle.ValidateDigest(r.controlPolicyDigest) != nil {
		return dockercontrol.CodingCreateAuthority{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return dockercontrol.CodingCreateAuthority{}, err
	}
	if err := r.readAtomicMarker(ctx); err != nil {
		return dockercontrol.CodingCreateAuthority{}, err
	}
	slots, err := readState(ctx, r.store, codingIdentityStateDocument,
		func() codingidentity.State { return codingidentity.State{} }, importCodingIdentityState)
	if err != nil {
		return dockercontrol.CodingCreateAuthority{}, err
	}
	record, exists := slots.OriginalCreates[allocationID]
	if !exists {
		return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
	}
	now := time.Now().UTC()
	authority, err := decodeCodingOriginalCreate(record, now)
	if err != nil || authority.AllocationID != allocationID ||
		authority.ControlPolicyDigest != r.controlPolicyDigest ||
		authority.PeerPrincipalDigest != r.plan.OwnerPrincipalDigest {
		return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
	}
	ledger, err := readState(ctx, r.store, lifecycleDocument,
		newLifecycleState, importLifecycleState)
	if err != nil || validateCodingOriginalCreate(slots, ledger, r.plan, authority, now) != nil {
		return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
	}
	if err := ctx.Err(); err != nil {
		return dockercontrol.CodingCreateAuthority{}, err
	}
	return authority, nil
}

// decodeCodingOriginalCreate never renews a historical authority. It checks
// canonical bytes at their original issuance time; current mutation validity
// is a separate gate. The trusted Profile/policy comparison is supplied by
// the PG repository composition, never inferred from a Control response.
func decodeCodingOriginalCreate(record codingidentity.OriginalCreateEnvelope,
	now time.Time) (dockercontrol.CodingCreateAuthority, error) {
	if record.Validate() != nil || now.IsZero() {
		return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
	}
	var raw dockercontrol.CodingCreateAuthority
	if json.Unmarshal([]byte(record.Document), &raw) != nil || raw.IssuedAt.After(now) {
		return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
	}
	authority, err := dockercontrol.DecodeCodingCreateAuthority([]byte(record.Document), raw.IssuedAt)
	if err != nil || authority.Digest() != record.Digest {
		return dockercontrol.CodingCreateAuthority{}, ErrCorrupt
	}
	return authority, nil
}

// validateCodingOriginalCreate is used under a Provider row transaction and
// on read-only recovery. It permits a released historical allocation with no
// active reservation, but any active matching reservation must bind exactly.
func validateCodingOriginalCreate(slots codingidentity.State,
	ledger lifecyclerepository.State, plan codingidentity.Plan,
	create dockercontrol.CodingCreateAuthority, now time.Time,
) error {
	record, exists := slots.OriginalCreates[create.AllocationID]
	if !exists || slots.Validate(plan) != nil {
		return ErrCorrupt
	}
	stored, err := decodeCodingOriginalCreate(record, now)
	if err != nil || stored != create ||
		create.BindControl(plan, create.ControlPolicyDigest, plan.OwnerPrincipalDigest,
			create.SpecDigest, create.IssuedAt) != nil {
		return ErrCorrupt
	}
	operation, operationExists := ledger.Operations[create.OperationID]
	sandbox, sandboxExists := ledger.Sandboxes[create.SandboxID]
	if !operationExists || !sandboxExists || operation.Validate() != nil ||
		sandbox.Validate() != nil || operation.ID != create.OperationID ||
		operation.Type != lifecycle.OperationCreate || operation.SandboxID != create.SandboxID ||
		operation.AttemptID != create.AttemptID || operation.FencingToken != create.Fence ||
		(operation.RequestDigest != "" && operation.RequestDigest != create.RequestDigest) ||
		!operation.Deadline.Equal(create.OperationDeadline) ||
		sandbox.ID != create.SandboxID || sandbox.ProviderRevisionID != create.ProviderRevisionID ||
		sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
		sandbox.Generation < create.CreationGeneration ||
		!codingStoredIdempotencyMatches(&ledger, operation, create.RequestDigest,
			create.ProviderRevisionID, false) {
		return ErrCorrupt
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil || tenantDigest != create.TenantDigest {
		return ErrCorrupt
	}
	allocationID, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID,
		sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil || allocationID != create.AllocationID {
		return ErrCorrupt
	}
	for _, reservation := range slots.Reservations {
		if reservation.Claim.AllocationID != create.AllocationID {
			continue
		}
		claim := reservation.Claim
		if reservation.PlanDigest != create.PlanDigest || reservation.SpecDigest != create.SpecDigest ||
			reservation.Slot.ID != create.SlotID || claim.SandboxID != create.SandboxID ||
			claim.OperationID != create.OperationID || claim.AttemptID != create.AttemptID ||
			claim.RequestDigest != create.RequestDigest || claim.TenantDigest != create.TenantDigest ||
			claim.Generation != create.CreationGeneration || claim.Fence != create.Fence {
			return ErrCorrupt
		}
	}
	return nil
}
