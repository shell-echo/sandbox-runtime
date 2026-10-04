//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

const slice6GuestRecoveryEventJournalFile = "guest-e-events.json"
const slice6GuestRecoveryEventCount = 29

type slice6GuestRecoveryEEvent struct {
	Kind, UTC, ReferenceDigest string
	Sequence                   uint64
	ElapsedNanos               int64
}

type slice6GuestRecoveryEJournal struct {
	Protocol, RunID string
	Events          []slice6GuestRecoveryEEvent
}

type slice6GuestRecoveryERecorder struct {
	mu     sync.Mutex
	base   time.Time // retains Go's monotonic component; never serialized
	runID  string
	events []slice6GuestRecoveryEEvent
	sealed bool
}

func newSlice6GuestRecoveryERecorder(runID string) (*slice6GuestRecoveryERecorder, error) {
	if len(runID) != 32 || !lowerHexSlice6(runID) {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	return &slice6GuestRecoveryERecorder{base: time.Now(), runID: runID}, nil
}

// Call at the actual E call-entry or completed-observation point, not when
// assembling the verifier input. An ambiguous action has no "observed" event.
func (recorder *slice6GuestRecoveryERecorder) record(kind, reference string) error {
	if recorder == nil || !guestRevokeFixtureDigestGate(reference) ||
		!slice6GuestRecoveryEventKind(kind) {
		return phase6guestreceipt.ErrUnavailable
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.sealed || len(recorder.events) >= slice6GuestRecoveryEventCount {
		return phase6guestreceipt.ErrUnavailable
	}
	observed := time.Now()
	elapsed := observed.Sub(recorder.base).Nanoseconds()
	if elapsed < 1 || (len(recorder.events) != 0 &&
		elapsed <= recorder.events[len(recorder.events)-1].ElapsedNanos) {
		return phase6guestreceipt.ErrUnavailable
	}
	recorder.events = append(recorder.events, slice6GuestRecoveryEEvent{Kind: kind,
		UTC: observed.UTC().Format(time.RFC3339Nano), ReferenceDigest: reference,
		Sequence: uint64(len(recorder.events) + 1), ElapsedNanos: elapsed})
	return nil
}

func (recorder *slice6GuestRecoveryERecorder) seal(run *slice6ReceiptEvidenceRun) (string, error) {
	if recorder == nil || run == nil || run.id != recorder.runID {
		return "", phase6guestreceipt.ErrUnavailable
	}
	recorder.mu.Lock()
	if recorder.sealed || len(recorder.events) != slice6GuestRecoveryEventCount {
		recorder.mu.Unlock()
		return "", phase6guestreceipt.ErrUnavailable
	}
	recorder.sealed = true
	events := append([]slice6GuestRecoveryEEvent(nil), recorder.events...)
	recorder.mu.Unlock()
	return run.writeGuestRecoveryEventJournal(slice6GuestRecoveryEJournal{
		Protocol: "sandbox-runtime.phase6-guest-e-events.v1", RunID: recorder.runID, Events: events})
}

func slice6GuestRecoveryEventKind(kind string) bool {
	for _, allowed := range []string{
		"source_complete", "initial_sql_call", "initial_sql_observed", "pg_down_call", "pg_down_observed",
		"trigger_observed", "guest_off_call", "guest_off_observed", "pg_up_call",
		"pg_up_observed", "released_sql_call", "released_sql_observed", "guest_on_call", "guest_on_observed",
		"reconnected_sql_call", "reconnected_sql_observed",
		"guest_a_stop_call", "guest_a_exit_observed", "guest_a_sealed",
		"recovered_close_observed",
		"product_a_stop_call", "product_a_exit_observed", "product_a_sealed",
		"final_sql_call", "final_sql_observed", "product_b_start_call", "product_b_start_observed",
		"guest_b_start_call", "guest_b_start_observed",
	} {
		if kind == allowed {
			return true
		}
	}
	return false
}

func slice6GuestRecoverySQLRef(binding slice6GuestOperatorRawBinding) string {
	return slice6ReceiptSHA256([]byte(strings.Join([]string{binding.Stage, binding.RunID,
		binding.SourceProofDigest, binding.PostgresID, binding.ReadExecID,
		binding.CheckExecID, binding.SettingsRecheckExecID, binding.RowSHA256}, "|")))
}

func slice6GuestRecoverySQLCallRef(binding slice6GuestOperatorRawBinding) string {
	return slice6ReceiptSHA256([]byte(strings.Join([]string{"sql-call.v1", binding.Stage,
		binding.RunID, binding.SourceProofDigest, binding.TargetDigest,
		binding.PostgresID, binding.OperationDigest}, "|")))
}

func slice6GuestRecoverySQLKind(stage string, observed bool) string {
	if stage == "final_released" {
		stage = "final"
	}
	if stage != "initial" && stage != "released" && stage != "reconnected" && stage != "final" {
		return ""
	}
	if observed {
		return stage + "_sql_observed"
	}
	return stage + "_sql_call"
}

func slice6GuestRecoveryActionRef(projection, utc string, snapshot slice6GuestRecoveryDockerSnapshot) string {
	parts := slice6GuestRecoveryDockerSnapshotParts(snapshot)
	return slice6ReceiptSHA256([]byte("action-observation.v2|" + projection + "|" + utc + "|" +
		slice6ReceiptSHA256(parts[0]) + "|" + slice6ReceiptSHA256(parts[1]) + "|" +
		slice6ReceiptSHA256(parts[2]) + "|" + slice6ReceiptSHA256(parts[3])))
}

func slice6GuestRecoveryStartOperation(binding slice6GuestRecoveryRawBinding) string {
	return slice6ReceiptSHA256([]byte("start-op.v1|" + binding.RunID + "|" +
		binding.Process + "|" + binding.ContainerID))
}

func slice6GuestRecoveryStartCallRef(binding slice6GuestRecoveryRawBinding) string {
	return slice6ReceiptSHA256([]byte(slice6GuestRecoveryStartOperation(binding) + "|" +
		binding.ImageID + "|" + binding.ImageRef + "|" + binding.ProfileDigest + "|" + binding.ConfigDigest))
}

func slice6GuestRecoveryStartObservedRef(binding slice6GuestRecoveryRawBinding) string {
	return slice6ReceiptSHA256([]byte(slice6GuestRecoveryStartOperation(binding) + "|" +
		binding.ContainerID + "|" + strconv.Itoa(binding.PID) + "|" + binding.StartedAt + "|" +
		binding.StartInspectSHA256))
}

func slice6GuestRecoveryStopOperation(binding slice6GuestRecoveryRawBinding) string {
	return slice6ReceiptSHA256([]byte("stop-op.v1|" + binding.RunID + "|" +
		binding.Process + "|" + binding.ContainerID))
}

func slice6GuestRecoveryStopCallRef(binding slice6GuestRecoveryRawBinding) string {
	return slice6ReceiptSHA256([]byte(slice6GuestRecoveryStopOperation(binding) + "|" +
		binding.ContainerID + "|" + strconv.Itoa(binding.PID) + "|" + binding.StartedAt))
}

func slice6GuestRecoveryExitObservedRef(binding slice6GuestRecoveryRawBinding) string {
	return slice6ReceiptSHA256([]byte(slice6GuestRecoveryStopOperation(binding) + "|" +
		binding.ContainerID + "|" + strconv.Itoa(binding.PID) + "|" + binding.FinishedAt + "|" +
		strconv.Itoa(binding.ExitCode)))
}

func slice6GuestRecoverySealRef(binding slice6GuestRecoveryRawBinding) string {
	return slice6ReceiptSHA256([]byte(slice6GuestRecoveryStopOperation(binding) + "|" +
		binding.SHA256 + "|" + strconv.Itoa(binding.Bytes) + "|" + strconv.Itoa(binding.ExitCode)))
}

func slice6GuestRecoveryTriggerRef(trigger slice6GuestRecoveryCloseTrigger) string {
	return slice6ReceiptSHA256([]byte(trigger.ProductPrefixSHA256 + "|" +
		trigger.GuestPrefixSHA256 + "|" + trigger.ObservedUTC))
}

func slice6GuestRecoveryExpectedEvents(input slice6GuestRecoveryPrecleanupInput) [slice6GuestRecoveryEventCount]struct{ kind, ref string } {
	a := input.Actions
	return [slice6GuestRecoveryEventCount]struct{ kind, ref string }{
		{"source_complete", input.Source.proofDigest()},
		{"initial_sql_call", slice6GuestRecoverySQLCallRef(input.SQL[0])},
		{"initial_sql_observed", slice6GuestRecoverySQLRef(input.SQL[0])},
		{"pg_down_call", slice6GuestRecoveryActionRef(a.PGDown.BeforeProjection, a.PGDown.StartedUTC, a.PGDown.BeforeDocker)},
		{"pg_down_observed", slice6GuestRecoveryActionRef(a.PGDown.AfterProjection, a.PGDown.FinishedUTC, a.PGDown.AfterDocker)},
		{"trigger_observed", slice6GuestRecoveryTriggerRef(input.Trigger)},
		{"guest_off_call", slice6GuestRecoveryActionRef(a.GuestOff.BeforeProjection, a.GuestOff.StartedUTC, a.GuestOff.BeforeDocker)},
		{"guest_off_observed", slice6GuestRecoveryActionRef(a.GuestOff.AfterProjection, a.GuestOff.FinishedUTC, a.GuestOff.AfterDocker)},
		{"pg_up_call", slice6GuestRecoveryActionRef(a.PGUp.BeforeProjection, a.PGUp.StartedUTC, a.PGUp.BeforeDocker)},
		{"pg_up_observed", slice6GuestRecoveryActionRef(a.PGUp.AfterProjection, a.PGUp.FinishedUTC, a.PGUp.AfterDocker)},
		{"released_sql_call", slice6GuestRecoverySQLCallRef(input.SQL[1])},
		{"released_sql_observed", slice6GuestRecoverySQLRef(input.SQL[1])},
		{"guest_on_call", slice6GuestRecoveryActionRef(a.GuestOn.BeforeProjection, a.GuestOn.StartedUTC, a.GuestOn.BeforeDocker)},
		{"guest_on_observed", slice6GuestRecoveryActionRef(a.GuestOn.AfterProjection, a.GuestOn.FinishedUTC, a.GuestOn.AfterDocker)},
		{"reconnected_sql_call", slice6GuestRecoverySQLCallRef(input.SQL[2])},
		{"reconnected_sql_observed", slice6GuestRecoverySQLRef(input.SQL[2])},
		{"guest_a_stop_call", slice6GuestRecoveryStopCallRef(input.Process[1])},
		{"guest_a_exit_observed", slice6GuestRecoveryExitObservedRef(input.Process[1])},
		{"guest_a_sealed", slice6GuestRecoverySealRef(input.Process[1])},
		{"recovered_close_observed", input.RecoveredCloseDigest},
		{"product_a_stop_call", slice6GuestRecoveryStopCallRef(input.Process[0])},
		{"product_a_exit_observed", slice6GuestRecoveryExitObservedRef(input.Process[0])},
		{"product_a_sealed", slice6GuestRecoverySealRef(input.Process[0])},
		{"final_sql_call", slice6GuestRecoverySQLCallRef(input.SQL[3])},
		{"final_sql_observed", slice6GuestRecoverySQLRef(input.SQL[3])},
		{"product_b_start_call", slice6GuestRecoveryStartCallRef(input.Process[2])},
		{"product_b_start_observed", slice6GuestRecoveryStartObservedRef(input.Process[2])},
		{"guest_b_start_call", slice6GuestRecoveryStartCallRef(input.Process[3])},
		{"guest_b_start_observed", slice6GuestRecoveryStartObservedRef(input.Process[3])},
	}
}

func (run *slice6ReceiptEvidenceRun) writeGuestRecoveryEventJournal(journal slice6GuestRecoveryEJournal) (string, error) {
	if run == nil || run.check() != nil || journal.RunID != run.id ||
		journal.Protocol != "sandbox-runtime.phase6-guest-e-events.v1" || len(journal.Events) != slice6GuestRecoveryEventCount {
		return "", phase6guestreceipt.ErrUnavailable
	}
	encoded, err := json.Marshal(journal)
	if err != nil || len(encoded) > 8192 {
		return "", phase6guestreceipt.ErrUnavailable
	}
	if err := run.writeV2BoundedPrivateFile(slice6GuestRecoveryEventJournalFile, encoded, 8192, false); err != nil {
		return "", err
	}
	return slice6ReceiptSHA256(encoded), nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryEventJournal(input slice6GuestRecoveryPrecleanupInput) error {
	if run == nil || run.check() != nil || !guestRevokeFixtureDigestGate(input.EventJournalDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := run.readFile(slice6GuestRecoveryEventJournalFile, 8192)
	if err != nil {
		return err
	}
	defer clear(raw)
	if slice6ReceiptSHA256(raw) != input.EventJournalDigest {
		return phase6guestreceipt.ErrUnavailable
	}
	var journal slice6GuestRecoveryEJournal
	if json.Unmarshal(raw, &journal) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(raw, canonical) || journal.Protocol != "sandbox-runtime.phase6-guest-e-events.v1" ||
		journal.RunID != run.id || len(journal.Events) != slice6GuestRecoveryEventCount {
		return phase6guestreceipt.ErrUnavailable
	}
	return slice6CheckGuestRecoveryEJournal(journal, input, run.id)
}

func slice6CheckGuestRecoveryEJournal(journal slice6GuestRecoveryEJournal,
	input slice6GuestRecoveryPrecleanupInput, runID string) error {
	if journal.Protocol != "sandbox-runtime.phase6-guest-e-events.v1" || journal.RunID != runID ||
		len(journal.Events) != slice6GuestRecoveryEventCount {
		return phase6guestreceipt.ErrUnavailable
	}
	expected := slice6GuestRecoveryExpectedEvents(input)
	var previous int64
	for index, event := range journal.Events {
		if event.Sequence != uint64(index+1) || event.ElapsedNanos <= previous ||
			event.Kind != expected[index].kind || event.ReferenceDigest != expected[index].ref ||
			!guestRevokeFixtureDigestGate(event.ReferenceDigest) ||
			!slice6GuestRecoveryEventKind(event.Kind) {
			return errors.New("Guest E event monotonic/action reference drift")
		}
		utc, err := time.Parse(time.RFC3339Nano, event.UTC)
		if err != nil || event.UTC != utc.UTC().Format(time.RFC3339Nano) {
			return phase6guestreceipt.ErrUnavailable
		}
		previous = event.ElapsedNanos
	}
	return nil
}
