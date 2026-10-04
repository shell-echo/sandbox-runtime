//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

type slice6GuestRecoveryPrecleanupInput struct {
	Source                   slice6GuestOperatorFormalSource
	Process                  [4]slice6GuestRecoveryRawBinding
	SQL                      [4]slice6GuestOperatorRawBinding
	Actions                  slice6GuestRecoveryActionLedger
	Trigger                  slice6GuestRecoveryCloseTrigger
	ProductConfigDigest      string
	GuestConfigDigest        string
	InitialAttemptDigest     string
	RecoveredAttemptDigest   string
	RecoveredCloseDigest     string
	ReplacementAttemptDigest string
	EventJournalDigest       string
	BeforeBAdmissionDigest   string
	CreatedNetworksDigest    string
	VaultOrigin              slice6GuestRecoveryImplicitOrigin
	Generation               int64
}

// This merger is deliberately precleanup and cannot publish an accepted E
// binding. The final gate must additionally prove and persist every exact
// resource class at zero after cleanup, then bind the frozen E/R/F identities.
func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryPrecleanup(ctx context.Context,
	input slice6GuestRecoveryPrecleanupInput) (string, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || run.check() != nil ||
		input.Source.evidence != run || input.Source.runID != run.id ||
		input.Generation < 1 ||
		!guestRevokeFixtureDigestGate(input.ProductConfigDigest) ||
		!guestRevokeFixtureDigestGate(input.GuestConfigDigest) ||
		!guestRevokeFixtureDigestGate(input.InitialAttemptDigest) ||
		!guestRevokeFixtureDigestGate(input.RecoveredAttemptDigest) ||
		!guestRevokeFixtureDigestGate(input.ReplacementAttemptDigest) ||
		input.InitialAttemptDigest == input.RecoveredAttemptDigest ||
		input.InitialAttemptDigest == input.ReplacementAttemptDigest ||
		input.RecoveredAttemptDigest == input.ReplacementAttemptDigest {
		return "", errors.New("Guest recovery precleanup source unavailable")
	}
	frozenLedger, err := slice6FrozenProductMigrationLedger(ctx)
	if err != nil || input.Source.verifySourceSemantics(frozenLedger) != nil {
		return "", errors.New("Guest recovery precleanup frozen migration source unavailable")
	}
	return run.verifyGuestRecoveryPrecleanupCore(input)
}

// The core is pure with respect to Docker/issuer state and is exercised by a
// synthetic source fixture. Only verifyGuestRecoveryPrecleanup may call it in
// the formal run, after full frozen Profile/raw-source validation.
func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryPrecleanupCore(
	input slice6GuestRecoveryPrecleanupInput) (string, error) {
	if run == nil || run.check() != nil || input.Source.evidence != run ||
		input.Source.runID != run.id || input.Generation < 1 {
		return "", errors.New("Guest recovery precleanup run identity drift")
	}
	var productImageRef, productImageID, guestImageRef, guestImageID string
	for _, principal := range input.Source.profile.Principals {
		switch principal.Name {
		case "product-runtime":
			productImageRef, productImageID = principal.ImageReference, principal.ImageDigest
		case "guest-runtime":
			guestImageRef, guestImageID = principal.ImageReference, principal.ImageDigest
		}
	}
	// This frozen Slice 6 Profile maps both roles to the same selected core
	// image, while their startup config digests and role receipts differ.
	if productImageRef == "" || productImageID == "" ||
		productImageRef != guestImageRef || productImageID != guestImageID ||
		productImageID != input.Process[0].ImageID ||
		productImageRef != input.Process[0].ImageRef ||
		input.Process[0].ConfigDigest != input.ProductConfigDigest ||
		input.Process[2].ConfigDigest != input.ProductConfigDigest ||
		input.Process[1].ConfigDigest != input.GuestConfigDigest ||
		input.Process[3].ConfigDigest != input.GuestConfigDigest ||
		slice6VerifyGuestRecoveryProcessOrder(run.id, input.Source.profileDigest,
			productImageID, productImageRef, input.Process, [4]int{}) != nil ||
		run.verifyV2GuestOperatorStages(input.SQL) != nil ||
		input.SQL[0].SourceProofDigest != input.Source.proofDigest() ||
		input.SQL[0].PGFingerprint != input.Source.pgFingerprint ||
		input.SQL[0].PostgresID != input.Source.postgresID {
		return "", errors.New("Guest recovery precleanup process/SQL identity drift")
	}
	var raw [4][]byte
	defer func() {
		for _, document := range raw {
			clear(document)
		}
	}()
	for index, binding := range input.Process {
		document, err := run.readFile(binding.File, phase6guestreceipt.MaxTotalBytes)
		if err != nil || len(document) != binding.Bytes ||
			slice6ReceiptSHA256(document) != binding.SHA256 {
			clear(document)
			return "", errors.New("Guest recovery PID1 raw/seal unavailable")
		}
		raw[index] = document
	}
	if run.verifyGuestRecoveryStartRaw(input.Process[2]) != nil ||
		run.verifyGuestRecoveryStartRaw(input.Process[3]) != nil {
		return "", errors.New("Guest replacement live start raw unavailable")
	}
	if slice6VerifyGuestRecoveryTriggerSealed(input.Trigger, input.Process[0], input.Process[1],
		raw[0], raw[1], input.InitialAttemptDigest, input.Generation) != nil ||
		run.verifyGuestRecoveryRecoveredClose(input) != nil ||
		phase6guestreceipt.VerifyV2RecoveryPair(raw[0], raw[1], input.Source.profileDigest,
			input.ProductConfigDigest, input.GuestConfigDigest,
			input.InitialAttemptDigest, input.RecoveredAttemptDigest, input.Generation) != nil ||
		phase6guestreceipt.VerifyV2ReplacementPair(raw[2], raw[3], input.Source.profileDigest,
			input.ProductConfigDigest, input.GuestConfigDigest,
			input.ReplacementAttemptDigest, input.Generation) != nil {
		return "", errors.New("Guest recovery sealed causal pair unavailable")
	}
	if err := slice6VerifyGuestRecoveryActionSourceIdentity(input.Source, input.Actions,
		input.Process, input.SQL); err != nil {
		return "", err
	}
	if err := run.verifyGuestRecoveryCreatedNetworks(input); err != nil {
		return "", err
	}
	if err := run.verifyGuestRecoveryImplicitOrigin(input.VaultOrigin); err != nil {
		return "", err
	}
	if err := run.verifyGuestRecoveryActionRaw(input.Actions); err != nil {
		return "", err
	}
	if err := slice6ReplayGuestRecoveryActionDockerRaw(input.Source, input.Actions); err != nil {
		return "", err
	}
	if err := run.verifyGuestRecoveryEventJournal(input); err != nil {
		return "", err
	}
	if err := run.verifyGuestRecoveryBeforeBAdmission(input); err != nil {
		return "", err
	}
	ledgerDigest, err := slice6VerifyGuestRecoveryActionLedger(run.id, input.Source.proofDigest(),
		input.Actions, input.Trigger, input.SQL, input.Process)
	if err != nil {
		return "", err
	}
	return slice6ReceiptSHA256([]byte("phase6-guest-recovery-precleanup.v1|" +
		run.id + "|" + input.Source.proofDigest() + "|" + input.EventJournalDigest + "|" +
		input.BeforeBAdmissionDigest + "|" + input.CreatedNetworksDigest + "|" +
		input.RecoveredCloseDigest + "|" +
		slice6GuestRecoveryOriginDigest(input.VaultOrigin) + "|" + ledgerDigest + "|" +
		input.Process[0].SHA256 + "|" + input.Process[1].SHA256 + "|" +
		input.Process[2].SHA256 + "|" + input.Process[3].SHA256)), nil
}
