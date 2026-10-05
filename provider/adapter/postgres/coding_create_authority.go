package providerpostgres

import (
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecyclerepository "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
)

// codingClaimFromAcceptedCreate is a pure projection for use *inside* a
// future locked Provider control_state transaction. It deliberately accepts
// only the original, still-eligible Accepted create: Running/Unknown without
// an existing reservation cannot fabricate a new allocation after restart.
// This helper alone is not a PostgreSQL reservation or dispatch permit.
func codingClaimFromAcceptedCreate(state *lifecyclerepository.State, operationID string, now time.Time) (codingidentity.Claim, error) {
	if state == nil || now.IsZero() || lifecycle.ValidateIdentifier(operationID) != nil {
		return codingidentity.Claim{}, codingidentity.ErrConflict
	}
	operation, err := state.GetOperation(operationID)
	if err != nil || operation.Validate() != nil || operation.Type != lifecycle.OperationCreate ||
		operation.State != lifecycle.OperationAccepted || operation.CancelRequested ||
		!operation.Deadline.After(now) || operation.ObservedAt.After(now) {
		return codingidentity.Claim{}, codingidentity.ErrConflict
	}
	sandbox, err := state.GetSandbox(operation.SandboxID)
	if err != nil || sandbox.Validate() != nil || sandbox.RuntimeProfile != "sandbox-runtime-coding-shell-v1" ||
		sandbox.Network != (lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}) ||
		sandbox.Generation != 1 || sandbox.ObservedGeneration != 0 ||
		sandbox.ObservedState != lifecycle.ObservedRequested || sandbox.DesiredState != lifecycle.DesiredReady ||
		!sandbox.LeaseExpiresAt.After(now) {
		return codingidentity.Claim{}, codingidentity.ErrConflict
	}
	lease, err := state.GetLease(sandbox.ID)
	if err != nil || lease.Validate() != nil || lease.Generation != sandbox.Generation ||
		lease.FencingToken != operation.FencingToken || !lease.ExpiresAt.Equal(sandbox.LeaseExpiresAt) ||
		state.Fencing[sandbox.ProviderRevisionID+"\x00"+sandbox.ID] != operation.FencingToken {
		return codingidentity.Claim{}, codingidentity.ErrConflict
	}
	var record lifecyclerepository.IdempotencyRecord
	count := 0
	for key, candidate := range state.Idempotency {
		if candidate.Operation.ID != operation.ID {
			continue
		}
		if key != candidate.Scope || candidate.Key == "" ||
			candidate.Scope != sandbox.ProviderRevisionID+"\x00"+candidate.Key ||
			lifecycle.ValidateDigest(candidate.RequestDigest) != nil ||
			!reflect.DeepEqual(candidate.Operation, operation) {
			return codingidentity.Claim{}, codingidentity.ErrConflict
		}
		record = candidate
		count++
	}
	if count != 1 || (operation.RequestDigest != "" && operation.RequestDigest != record.RequestDigest) {
		return codingidentity.Claim{}, codingidentity.ErrConflict
	}
	allocationID, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID, sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		return codingidentity.Claim{}, err
	}
	tenantDigest, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil {
		return codingidentity.Claim{}, err
	}
	claim := codingidentity.Claim{TenantDigest: tenantDigest, SandboxID: sandbox.ID,
		AllocationID: allocationID, OperationID: operation.ID, AttemptID: operation.AttemptID,
		RequestDigest: record.RequestDigest, Generation: sandbox.Generation, Fence: operation.FencingToken}
	if claim.Validate() != nil {
		return codingidentity.Claim{}, codingidentity.ErrConflict
	}
	return claim, nil
}
