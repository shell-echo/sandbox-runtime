//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
)

// E owns this sequence after the shared bootstrap has delivered real,
// independently verified A handles and the nine-bridge PostgreSQL source.
// It does not invoke the historical Product/Guest component wrappers.
type slice6GuestRecoveryESequenceInput struct {
	Run            slice6DockerRun
	Evidence       *slice6ReceiptEvidenceRun
	Composed       slice6VaultComposedInputs
	Source         slice6GuestOperatorFormalSource
	Target         slice6GuestOperatorTarget
	ProductA       *slice6GuestRecoveryProductProcess
	GuestA         *slice6GuestRecoveryGuestProcess
	PGEdge         slice6ProductPGFaultEdge
	GuestEdge      slice6GuestRecoveryEdge
	Manifest       slice6GuestRecoveryNetworkManifest
	Prepared       slice6GuestRuntimePrepared
	ProductSockets map[string]string
	GuestSockets   map[string]string
	Anchors        map[string]string
	VaultOrigin    slice6GuestRecoveryImplicitOrigin
	Recorder       *slice6GuestRecoveryERecorder
}

func slice6RunGuestRecoveryE29(ctx context.Context,
	input slice6GuestRecoveryESequenceInput) (slice6GuestRecoveryPrecleanupInput, string, error) {
	var unavailable = errors.New("Guest E single-run sequence authority unavailable")
	run, evidence := input.Run, input.Evidence
	productA, guestA := input.ProductA, input.GuestA
	if ctx == nil || ctx.Err() != nil || evidence == nil || evidence.check() != nil ||
		evidence.id != run.id || input.Composed.GuestReceiptEvidence != evidence ||
		!input.Composed.PrivateGuestReceipt || input.Source.evidence != evidence ||
		input.Source.runID != run.id || input.Target.Run.id != run.id ||
		input.Source.postgresID != input.Target.PostgresID ||
		input.Source.profileDigest != input.Composed.Profile.ProfileDigest ||
		input.Manifest.runID != run.id || input.Prepared.RunID != run.id ||
		input.Prepared.Generation < 1 || input.Recorder == nil || input.Recorder.runID != run.id ||
		productA == nil || guestA == nil || productA.Capture == nil || guestA.Capture == nil ||
		productA.Slot != "product-a" || guestA.Slot != "guest-a" ||
		guestA.Product != productA || productA.Run.id != run.id || guestA.Run.id != run.id ||
		productA.Evidence != evidence || guestA.Evidence != evidence ||
		input.PGEdge.ProductID != productA.ID || input.PGEdge.PostgresID != input.Target.PostgresID ||
		input.GuestEdge.ProductID != productA.ID || input.GuestEdge.GuestID != guestA.ID ||
		input.GuestEdge.ProductNetworkID != guestA.ProductNetID ||
		input.GuestEdge.RuntimeNetworkID != guestA.InternalNetID ||
		!input.GuestEdge.valid() ||
		!slice6ProductPGFaultSourceMatches(input.PGEdge, input.Target, input.Source,
			input.Composed.Profile.ProfileDigest) ||
		evidence.verifyGuestRecoveryImplicitOrigin(input.VaultOrigin) != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", unavailable
	}
	input.Recorder.mu.Lock()
	initialJournalEmpty := !input.Recorder.sealed && len(input.Recorder.events) == 0
	input.Recorder.mu.Unlock()
	if !initialJournalEmpty || productA.Capture.recorder != input.Recorder ||
		guestA.Capture.recorder != input.Recorder ||
		productA.Capture.confirmStillRunning(ctx, run) != nil ||
		guestA.Capture.confirmStillRunning(ctx, run) != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", unavailable
	}
	defer productA.Capture.abort()
	defer guestA.Capture.abort()
	hba, err := input.Composed.Profile.PostgresServerAuth.RenderApprovedHBA(
		input.Composed.Profile.ProviderDatabases)
	if err != nil || len(hba) == 0 || slice6ReceiptSHA256(hba) != input.Source.hbaDigest {
		clear(hba)
		return slice6GuestRecoveryPrecleanupInput{}, "", unavailable
	}
	defer clear(hba)
	wait := func(task func(context.Context) error) error {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return task(bounded)
	}
	sharedAttempt := func(product, guest *slice6GuestRecoveryCapture,
		excluded map[string]bool) (string, error) {
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return slice6AwaitGuestRecoverySharedAttempt(bounded, run, product, guest,
			input.Prepared.Generation, excluded)
	}
	initialDigest, err := sharedAttempt(productA.Capture, guestA.Capture, nil)
	if err != nil || !guestRevokeFixtureDigestGate(initialDigest) {
		return slice6GuestRecoveryPrecleanupInput{}, "", unavailable
	}
	if err := input.Recorder.record("source_complete", input.Source.proofDigest()); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 1); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result := slice6GuestRecoveryPrecleanupInput{Source: input.Source,
		ProductConfigDigest: productA.ConfigDigest, GuestConfigDigest: guestA.ConfigDigest,
		InitialAttemptDigest: initialDigest, CreatedNetworksDigest: input.Manifest.createdDigest,
		VaultOrigin: input.VaultOrigin, Generation: input.Prepared.Generation}
	result.SQL[0], err = evidence.captureGuestOperatorStageRecorded(ctx, input.Target,
		input.Source, input.Source.profileDigest, hba,
		slice6GuestOperatorInitialConnected, 0, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 3); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	expiry := result.SQL[0].ExpiresUnixMicros
	result.Actions.PGDown, err = slice6DisconnectProductPGEdgeFormalRecorded(ctx,
		input.PGEdge, input.Target, input.Source, input.Source.profileDigest, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 5); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	var trigger slice6GuestRecoveryCloseTrigger
	err = wait(func(bounded context.Context) error {
		var observeErr error
		trigger, observeErr = slice6ObserveGuestRecoveryInitialClose(bounded, run,
			productA.Capture, guestA.Capture, initialDigest, input.Prepared.Generation)
		return observeErr
	})
	pgDownObserved, pgDownErr := slice6CheckProductPGFaultSnapshot(ctx, input.PGEdge, false)
	if err != nil || pgDownErr != nil ||
		pgDownObserved.BeforeDigest != result.Actions.PGDown.AfterDigest ||
		pgDownObserved.BeforeProjection != result.Actions.PGDown.AfterProjection {
		return slice6GuestRecoveryPrecleanupInput{}, "", unavailable
	}
	result.Trigger = trigger
	if err := input.Recorder.record("trigger_observed", slice6GuestRecoveryTriggerRef(trigger)); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 6); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.Actions.GuestOff, err = slice6DetachGuestProductEdgeWithProbeRecorded(ctx,
		input.GuestEdge, slice6GuestNetworkCommand, slice6CheckGuestEdgeSnapshot, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 8); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.Actions.PGUp, err = slice6RestoreProductPGEdgeFormalRecorded(ctx,
		input.PGEdge, input.Target, input.Source, input.Source.profileDigest,
		result.Actions.PGDown, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 10); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	err = wait(func(bounded context.Context) error {
		return slice6AwaitGuestRecoveryProductEvent(bounded, run, productA.Capture,
			initialDigest, guestagent.ObservationProductDisconnectResolved,
			string(guestagent.RetirementReleased), input.Prepared.Generation)
	})
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.SQL[1], err = evidence.captureGuestOperatorStageRecorded(ctx, input.Target,
		input.Source, input.Source.profileDigest, hba,
		slice6GuestOperatorReleased, expiry, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 12); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.Actions.GuestOn, err = slice6RestoreGuestProductEdgeWithProbeRecorded(ctx,
		input.GuestEdge, result.Actions.GuestOff, slice6GuestNetworkCommand,
		slice6CheckGuestEdgeSnapshot, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 14); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	recoveredDigest, err := sharedAttempt(productA.Capture, guestA.Capture,
		map[string]bool{initialDigest: true})
	if err != nil || !guestRevokeFixtureDigestGate(recoveredDigest) || recoveredDigest == initialDigest {
		return slice6GuestRecoveryPrecleanupInput{}, "", unavailable
	}
	result.RecoveredAttemptDigest = recoveredDigest
	result.SQL[2], err = evidence.captureGuestOperatorStageRecorded(ctx, input.Target,
		input.Source, input.Source.profileDigest, hba,
		slice6GuestOperatorRecoveredConnected, expiry, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 16); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.Process[1], _, err = slice6StopGuestRecoveryCaptureRecorded(ctx, run, guestA.Capture)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 19); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	err = wait(func(bounded context.Context) error {
		var observeErr error
		result.RecoveredCloseDigest, observeErr = slice6ObserveGuestRecoveryRecoveredClose(
			bounded, run, productA.Capture, result.Process[1],
			initialDigest, recoveredDigest, input.Prepared.Generation)
		return observeErr
	})
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 20); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.Process[0], _, err = slice6StopGuestRecoveryCaptureRecorded(ctx, run, productA.Capture)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 23); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.SQL[3], err = evidence.captureGuestOperatorStageRecorded(ctx, input.Target,
		input.Source, input.Source.profileDigest, hba,
		slice6GuestOperatorFinalReleased, expiry, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 25); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.Actions.RawProofDigest, err = evidence.writeGuestRecoveryActionRaw(result.Actions)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	beforeBDigest, err := evidence.admitGuestRecoveryBeforeB(ctx, result, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.BeforeBAdmissionDigest = beforeBDigest
	if err := slice6RemoveGuestRecoverySealedProcess(ctx, run, guestA.Capture, result.Process[1]); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	if err := slice6RemoveGuestRecoverySealedProcess(ctx, run, productA.Capture, result.Process[0]); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	productB, err := slice6CreateGuestRecoveryProductProcess(ctx, run, input.Composed,
		input.Target.PostgresID, input.ProductSockets, input.Anchors, productA.Observer,
		input.Manifest, evidence, "product-b", productA.ID, beforeBDigest, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	startErr := productB.start(ctx, input.Recorder, beforeBDigest)
	if productB.Capture != nil {
		defer productB.Capture.abort()
	}
	if startErr != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", startErr
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 27); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	guestB, err := slice6CreateGuestRecoveryGuestProcess(ctx, run, input.Composed,
		input.Prepared, input.GuestSockets, input.Anchors, input.Manifest, evidence,
		productB, "guest-b", guestA.ID, beforeBDigest, input.Recorder)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	startErr = guestB.start(ctx, input.Recorder, beforeBDigest)
	if guestB.Capture != nil {
		defer guestB.Capture.abort()
	}
	if startErr != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", startErr
	}
	if err := slice6RequireGuestRecoveryEOrder(input.Recorder, 29); err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	replacementDigest, err := sharedAttempt(productB.Capture, guestB.Capture, nil)
	if err != nil || !guestRevokeFixtureDigestGate(replacementDigest) ||
		replacementDigest == initialDigest || replacementDigest == recoveredDigest {
		return slice6GuestRecoveryPrecleanupInput{}, "", unavailable
	}
	result.ReplacementAttemptDigest = replacementDigest
	result.Process[3], _, err = slice6StopGuestRecoveryReplacementCapture(ctx, run, guestB.Capture)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.Process[2], _, err = slice6StopGuestRecoveryReplacementCapture(ctx, run, productB.Capture)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	result.EventJournalDigest, err = input.Recorder.seal(evidence)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	precleanupDigest, err := evidence.verifyGuestRecoveryPrecleanup(ctx, result)
	if err != nil {
		return slice6GuestRecoveryPrecleanupInput{}, "", err
	}
	for _, item := range []struct {
		capture *slice6GuestRecoveryCapture
		binding slice6GuestRecoveryRawBinding
	}{{guestB.Capture, result.Process[3]}, {productB.Capture, result.Process[2]}} {
		if err := slice6RemoveGuestRecoverySealedProcess(ctx, run, item.capture, item.binding); err != nil {
			return slice6GuestRecoveryPrecleanupInput{}, "", err
		}
	}
	return result, precleanupDigest, nil
}
