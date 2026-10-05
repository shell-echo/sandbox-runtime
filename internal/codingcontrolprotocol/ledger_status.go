package codingcontrolprotocol

import (
	"errors"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
)

// ProjectLedgerStatus is the Control-owned read-only status projection. The
// caller must supply the principal digest of the actually authenticated mTLS
// Provider peer; this helper is not a transport or a peer authenticator.
// Unknown effects remain not_found and never become completion evidence.
func ProjectLedgerStatus(ledger *dockercontrol.CodingReceiptLedger, request Request,
	authenticatedPeerDigest string, now time.Time,
) (Response, error) {
	if ledger == nil || request.Action != ActionStatus ||
		request.Validate(now, authenticatedPeerDigest) != nil {
		return Response{}, ErrInvalidWire
	}
	receipt, revision, stateDigest, err := ledger.LookupBoundProjection(
		request.Create, authenticatedPeerDigest, now)
	if errors.Is(err, os.ErrNotExist) {
		response := Response{Protocol: ProtocolID, Scope: ScopeCoding,
			Action: ActionStatus, Status: StatusNotFound,
			CreateAuthorityDigest: request.Create.Digest(), EffectID: request.Create.EffectID}
		if response.Validate(request) != nil {
			return Response{}, ErrInvalidWire
		}
		return response, nil
	}
	if err != nil {
		return Response{}, err
	}
	response, err := ProjectReceipt(request, receipt, revision, stateDigest)
	if err != nil {
		return Response{}, err
	}
	// A cleanup-bound status read must identify exactly the requested intent.
	// A create-only read can report pending/released without becoming a
	// consumable PG final-release observation.
	if request.Cleanup != nil && response.CleanupAuthorityDigest != request.Cleanup.Digest() {
		return Response{}, ErrInvalidWire
	}
	return response, nil
}
