//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

const slice6GuestRecoveryBeforeBEventCount = 25
const slice6GuestRecoveryBeforeBFile = "guest-e-before-b-admission.raw"

// A formal E caller must pass this gate while both B process bindings are
// still absent. The later four-PID1 merger is not a substitute for refusing
// to launch replacements after an uncertain A action or unproved final NULL.
func (run *slice6ReceiptEvidenceRun) admitGuestRecoveryBeforeB(ctx context.Context,
	input slice6GuestRecoveryPrecleanupInput,
	recorder *slice6GuestRecoveryERecorder) (string, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || run.check() != nil ||
		recorder == nil || recorder.runID != run.id {
		return "", phase6guestreceipt.ErrUnavailable
	}
	frozen, err := slice6FrozenProductMigrationLedger(ctx)
	if err != nil || input.Source.verifySourceSemantics(frozen) != nil {
		return "", errors.New("Guest E pre-B frozen source unavailable")
	}
	recorder.mu.Lock()
	if recorder.sealed || len(recorder.events) != slice6GuestRecoveryBeforeBEventCount {
		recorder.mu.Unlock()
		return "", errors.New("Guest E pre-B journal not at final NULL observation")
	}
	events := append([]slice6GuestRecoveryEEvent(nil), recorder.events...)
	recorder.mu.Unlock()
	digest, err := run.checkGuestRecoveryBeforeBCore(input, events)
	if err != nil {
		return "", err
	}
	if err := run.writeV2BoundedPrivateFile(slice6GuestRecoveryBeforeBFile,
		[]byte(digest+"\n"), 96, false); err != nil {
		return "", err
	}
	return digest, nil
}

func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryBeforeBAdmission(
	input slice6GuestRecoveryPrecleanupInput) error {
	if run == nil || run.check() != nil || !guestRevokeFixtureDigestGate(input.BeforeBAdmissionDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	journalRaw, err := run.readFile(slice6GuestRecoveryEventJournalFile, 8192)
	if err != nil {
		return err
	}
	defer clear(journalRaw)
	var journal slice6GuestRecoveryEJournal
	if json.Unmarshal(journalRaw, &journal) != nil ||
		len(journal.Events) != slice6GuestRecoveryEventCount {
		return phase6guestreceipt.ErrUnavailable
	}
	beforeB := input
	beforeB.Process[2], beforeB.Process[3] = slice6GuestRecoveryRawBinding{}, slice6GuestRecoveryRawBinding{}
	digest, err := run.checkGuestRecoveryBeforeBCore(beforeB,
		journal.Events[:slice6GuestRecoveryBeforeBEventCount])
	if err != nil || digest != input.BeforeBAdmissionDigest {
		return errors.New("Guest E pre-B admission does not replay")
	}
	raw, err := run.readFile(slice6GuestRecoveryBeforeBFile, 96)
	if err != nil || string(raw) != digest+"\n" {
		clear(raw)
		return errors.New("Guest E pre-B admission raw unavailable")
	}
	clear(raw)
	return nil
}

// This core is only a synthetic-testable prefix check. Production admission
// always goes through admitGuestRecoveryBeforeB and its frozen source reread.
func (run *slice6ReceiptEvidenceRun) checkGuestRecoveryBeforeBCore(
	input slice6GuestRecoveryPrecleanupInput, events []slice6GuestRecoveryEEvent) (string, error) {
	if run == nil || run.check() != nil || input.Source.evidence != run || input.Source.runID != run.id ||
		input.Process[2] != (slice6GuestRecoveryRawBinding{}) ||
		input.Process[3] != (slice6GuestRecoveryRawBinding{}) ||
		len(events) != slice6GuestRecoveryBeforeBEventCount || input.Generation < 1 ||
		!guestRevokeFixtureDigestGate(input.ProductConfigDigest) ||
		!guestRevokeFixtureDigestGate(input.GuestConfigDigest) ||
		!guestRevokeFixtureDigestGate(input.InitialAttemptDigest) ||
		!guestRevokeFixtureDigestGate(input.RecoveredAttemptDigest) ||
		input.InitialAttemptDigest == input.RecoveredAttemptDigest ||
		input.Source.verifyRawFiles() != nil {
		return "", errors.New("Guest E pre-B source or predecessor identity unavailable")
	}
	var imageID, imageRef, guestImageID, guestImageRef string
	for _, principal := range input.Source.profile.Principals {
		switch principal.Name {
		case "product-runtime":
			imageID, imageRef = principal.ImageDigest, principal.ImageReference
		case "guest-runtime":
			guestImageID, guestImageRef = principal.ImageDigest, principal.ImageReference
		}
	}
	if imageID == "" || imageRef == "" || imageID != guestImageID || imageRef != guestImageRef ||
		run.verifyV2GuestOperatorStages(input.SQL) != nil ||
		input.SQL[0].SourceProofDigest != input.Source.proofDigest() ||
		input.SQL[0].ProfileDigest != input.Source.profileDigest ||
		input.SQL[0].PGFingerprint != input.Source.pgFingerprint ||
		input.SQL[0].PostgresID != input.Source.postgresID {
		return "", errors.New("Guest E pre-B SQL/source readback unavailable")
	}
	var raw [2][]byte
	defer func() {
		clear(raw[0])
		clear(raw[1])
	}()
	for index, binding := range input.Process[:2] {
		role := "product"
		if index == 1 {
			role = "guest"
		}
		started, startErr := time.Parse(time.RFC3339Nano, binding.StartedAt)
		finished, finishErr := time.Parse(time.RFC3339Nano, binding.FinishedAt)
		if binding.Process != role+"-a" || binding.Role != role ||
			binding.File != slice6GuestRecoveryRawName(binding.Process) ||
			binding.RunID != run.id || binding.PID < 1 || binding.ContainerID == "" ||
			binding.ImageID != imageID || binding.ImageRef != imageRef ||
			binding.ProfileDigest != input.Source.profileDigest ||
			binding.ExitCode != 0 || startErr != nil || finishErr != nil || !finished.After(started) ||
			(binding.ConfigDigest != input.ProductConfigDigest && index == 0) ||
			(binding.ConfigDigest != input.GuestConfigDigest && index == 1) {
			return "", errors.New("Guest E pre-B predecessor seal identity drift")
		}
		document, err := run.readFile(binding.File, phase6guestreceipt.MaxTotalBytes)
		if err != nil || len(document) != binding.Bytes ||
			slice6ReceiptSHA256(document) != binding.SHA256 {
			clear(document)
			return "", errors.New("Guest E pre-B predecessor raw unavailable")
		}
		raw[index] = document
	}
	if input.Process[0].ContainerID == input.Process[1].ContainerID ||
		input.Process[0].PID == input.Process[1].PID ||
		run.verifyGuestRecoveryRecoveredClose(input) != nil ||
		slice6VerifyGuestRecoveryTriggerSealed(input.Trigger, input.Process[0], input.Process[1],
			raw[0], raw[1], input.InitialAttemptDigest, input.Generation) != nil ||
		phase6guestreceipt.VerifyV2RecoveryPair(raw[0], raw[1], input.Source.profileDigest,
			input.ProductConfigDigest, input.GuestConfigDigest,
			input.InitialAttemptDigest, input.RecoveredAttemptDigest, input.Generation) != nil {
		return "", errors.New("Guest E pre-B recovered close/release not sealed")
	}
	actions := input.Actions
	if !actions.PGDown.Attempted || !actions.GuestOff.Attempted ||
		!actions.PGUp.Attempted || !actions.GuestOn.Attempted ||
		actions.PGDown.OutcomeUnknown || actions.GuestOff.OutcomeUnknown ||
		actions.PGUp.OutcomeUnknown || actions.GuestOn.OutcomeUnknown ||
		!actions.PGDown.Disconnected || !actions.GuestOff.Disconnected ||
		actions.PGUp.Disconnected || actions.GuestOn.Disconnected ||
		actions.PGDown.NetworkID != actions.PGUp.NetworkID ||
		actions.GuestOff.ProductNetworkID != actions.GuestOn.ProductNetworkID ||
		actions.PGDown.PostgresPID != actions.PGUp.PostgresPID ||
		actions.PGDown.PostgresStartedAt != actions.PGUp.PostgresStartedAt ||
		actions.PGDown.AfterProjection != actions.PGUp.BeforeProjection ||
		actions.PGDown.BeforeProjection != actions.PGUp.AfterProjection ||
		actions.GuestOff.AfterProjection != actions.GuestOn.BeforeProjection ||
		actions.GuestOff.BeforeProjection != actions.GuestOn.AfterProjection ||
		actions.PGDown.ProductID != input.Process[0].ContainerID ||
		actions.GuestOff.ProductID != input.Process[0].ContainerID ||
		actions.GuestOff.GuestID != input.Process[1].ContainerID {
		return "", errors.New("Guest E pre-B edge outcome or restoration drift")
	}
	if slice6VerifyGuestRecoveryActionSourceIdentity(input.Source, input.Actions,
		input.Process, input.SQL) != nil ||
		run.verifyGuestRecoveryCreatedNetworks(input) != nil ||
		run.verifyGuestRecoveryImplicitOrigin(input.VaultOrigin) != nil ||
		run.verifyGuestRecoveryActionRaw(input.Actions) != nil ||
		slice6ReplayGuestRecoveryActionDockerRaw(input.Source, input.Actions) != nil {
		return "", errors.New("Guest E pre-B original action/source replay unavailable")
	}
	expected := slice6GuestRecoveryExpectedEvents(input)
	var previous int64
	for index, event := range events {
		if event.Sequence != uint64(index+1) || event.ElapsedNanos <= previous ||
			event.Kind != expected[index].kind || event.ReferenceDigest != expected[index].ref ||
			!guestRevokeFixtureDigestGate(event.ReferenceDigest) {
			return "", errors.New("Guest E pre-B causal event prefix drift")
		}
		utc, err := time.Parse(time.RFC3339Nano, event.UTC)
		if err != nil || event.UTC != utc.UTC().Format(time.RFC3339Nano) {
			return "", errors.New("Guest E pre-B event UTC invalid")
		}
		previous = event.ElapsedNanos
	}
	return slice6ReceiptSHA256([]byte("guest-e-before-b.v1|" + run.id + "|" +
		input.Source.proofDigest() + "|" + input.CreatedNetworksDigest + "|" +
		slice6GuestRecoveryOriginDigest(input.VaultOrigin) + "|" +
		input.Actions.RawProofDigest + "|" +
		input.RecoveredCloseDigest + "|" +
		input.Process[0].SHA256 + "|" + input.Process[1].SHA256 + "|" +
		input.SQL[3].RowSHA256 + "|" + strconv.FormatInt(previous, 10))), nil
}
