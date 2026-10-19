package lifecycle

import (
	"crypto/sha256"
	"fmt"
	"time"
)

// LeaseExpiryTermination is the shared deterministic provider-local expiry
// request. Its caller still checks the actual stored lease is expired. Both
// admission and the atomic Coding guard use these exact historical bytes.
func LeaseExpiryTermination(sandbox Sandbox, lease Lease, now time.Time) TerminateRequest {
	seed := sandbox.ProviderRevisionID + "\x00" + sandbox.ID + "\x00" + fmt.Sprintf("%d", sandbox.Generation) + "\x00" + sandbox.LeaseExpiresAt.UTC().Format(time.RFC3339Nano)
	digest := sha256.Sum256([]byte(seed))
	id := fmt.Sprintf("lease-expiry-%x", digest[:16])
	requestDigest := sha256.Sum256([]byte("lease-expiry-request\x00" + seed))
	return TerminateRequest{MutationRequest: MutationRequest{
		OperationID: id, AttemptID: id, FencingToken: lease.FencingToken,
		IdempotencyKey: id, RequestDigest: fmt.Sprintf("sha256:%x", requestDigest[:]),
		Deadline: now.Add(5 * time.Minute), ExpectedGeneration: sandbox.Generation,
	}, Reason: "lease_expired"}
}
