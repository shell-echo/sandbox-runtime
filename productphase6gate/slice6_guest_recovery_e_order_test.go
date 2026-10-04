//go:build phase6slice6gate

package productphase6gate

import (
	"errors"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

var slice6GuestRecoveryEOrder = [slice6GuestRecoveryEventCount]string{
	"source_complete", "initial_sql_call", "initial_sql_observed",
	"pg_down_call", "pg_down_observed", "trigger_observed",
	"guest_off_call", "guest_off_observed", "pg_up_call", "pg_up_observed",
	"released_sql_call", "released_sql_observed",
	"guest_on_call", "guest_on_observed",
	"reconnected_sql_call", "reconnected_sql_observed",
	"guest_a_stop_call", "guest_a_exit_observed", "guest_a_sealed",
	"recovered_close_observed",
	"product_a_stop_call", "product_a_exit_observed", "product_a_sealed",
	"final_sql_call", "final_sql_observed",
	"product_b_start_call", "product_b_start_observed",
	"guest_b_start_call", "guest_b_start_observed",
}

// Check at every E action boundary. Final replay still checks references,
// time relations and raw evidence; this guard prevents a later action after
// an unexpected or missing call/observation while the process is live.
func slice6RequireGuestRecoveryEOrder(recorder *slice6GuestRecoveryERecorder,
	count int) error {
	if recorder == nil || count < 0 || count > len(slice6GuestRecoveryEOrder) {
		return phase6guestreceipt.ErrUnavailable
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.sealed || len(recorder.events) != count {
		return errors.New("Guest E action count drift")
	}
	var previous int64
	for index, event := range recorder.events {
		if event.Kind != slice6GuestRecoveryEOrder[index] ||
			event.Sequence != uint64(index+1) ||
			event.ElapsedNanos <= previous ||
			!guestRevokeFixtureDigestGate(event.ReferenceDigest) {
			return errors.New("Guest E action order drift")
		}
		previous = event.ElapsedNanos
	}
	return nil
}
