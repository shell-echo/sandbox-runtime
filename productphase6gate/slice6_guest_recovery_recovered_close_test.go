//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

const slice6GuestRecoveryRecoveredCloseFile = "guest-e-recovered-close-observed.json"

type slice6GuestRecoveryRecoveredClose struct {
	Protocol, RunID, ProfileDigest               string
	ProductID, GuestID                           string
	ProductPID, GuestPID                         int
	ProductStart, GuestStart                     string
	ProductConfigDigest, GuestConfigDigest       string
	ProductPrefixSHA256, GuestSealedSHA256       string
	GuestStopCallRef, GuestExitRef               string
	GuestSealRef                                 string
	ProductPrefixBytes, GuestSealedBytes         int
	InitialAttemptDigest, RecoveredAttemptDigest string
	Generation                                   int64
	ObservedUTC                                  string
}

func (run *slice6ReceiptEvidenceRun) writeGuestRecoveryRecoveredClose(
	observation slice6GuestRecoveryRecoveredClose) (string, error) {
	if run == nil || run.check() != nil || observation.RunID != run.id ||
		observation.Protocol != "sandbox-runtime.phase6-guest-e-recovered-close.v1" {
		return "", phase6guestreceipt.ErrUnavailable
	}
	raw, err := json.Marshal(observation)
	if err != nil || len(raw) > 2048 ||
		run.writeV2BoundedPrivateFile(slice6GuestRecoveryRecoveredCloseFile, raw, 2048, false) != nil {
		return "", phase6guestreceipt.ErrUnavailable
	}
	return slice6ReceiptSHA256(raw), nil
}

// This replay works after both PID1 files are sealed. The exact bytes observed
// before Product's stop must still be the prefix of its final original raw.
func (run *slice6ReceiptEvidenceRun) verifyGuestRecoveryRecoveredClose(
	input slice6GuestRecoveryPrecleanupInput) error {
	if run == nil || run.check() != nil || !guestRevokeFixtureDigestGate(input.RecoveredCloseDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := run.readFile(slice6GuestRecoveryRecoveredCloseFile, 2048)
	if err != nil {
		return err
	}
	defer clear(raw)
	if slice6ReceiptSHA256(raw) != input.RecoveredCloseDigest {
		return phase6guestreceipt.ErrUnavailable
	}
	var observed slice6GuestRecoveryRecoveredClose
	if json.Unmarshal(raw, &observed) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	canonical, err := json.Marshal(observed)
	if err != nil || !bytes.Equal(raw, canonical) ||
		observed.Protocol != "sandbox-runtime.phase6-guest-e-recovered-close.v1" ||
		observed.RunID != run.id || observed.ProfileDigest != input.Source.profileDigest ||
		observed.ProductConfigDigest != input.ProductConfigDigest ||
		observed.GuestConfigDigest != input.GuestConfigDigest ||
		observed.InitialAttemptDigest != input.InitialAttemptDigest ||
		observed.RecoveredAttemptDigest != input.RecoveredAttemptDigest ||
		observed.Generation != input.Generation ||
		observed.ProductID != input.Process[0].ContainerID ||
		observed.ProductPID != input.Process[0].PID ||
		observed.ProductStart != input.Process[0].StartedAt ||
		observed.GuestID != input.Process[1].ContainerID ||
		observed.GuestPID != input.Process[1].PID ||
		observed.GuestStart != input.Process[1].StartedAt ||
		observed.GuestSealedSHA256 != input.Process[1].SHA256 ||
		observed.GuestSealedBytes != input.Process[1].Bytes ||
		observed.GuestStopCallRef != slice6GuestRecoveryStopCallRef(input.Process[1]) ||
		observed.GuestExitRef != slice6GuestRecoveryExitObservedRef(input.Process[1]) ||
		observed.GuestSealRef != slice6GuestRecoverySealRef(input.Process[1]) ||
		observed.ProductPrefixBytes < 1 || observed.ProductPrefixBytes > input.Process[0].Bytes ||
		!guestRevokeFixtureDigestGate(observed.ProductPrefixSHA256) ||
		!guestRevokeFixtureDigestGate(observed.GuestSealedSHA256) {
		return errors.New("Guest E recovered-close observation identity drift")
	}
	when, err := time.Parse(time.RFC3339Nano, observed.ObservedUTC)
	if err != nil || observed.ObservedUTC != when.UTC().Format(time.RFC3339Nano) {
		return phase6guestreceipt.ErrUnavailable
	}
	product, err := run.readFile(input.Process[0].File, phase6guestreceipt.MaxTotalBytes)
	if err != nil {
		return err
	}
	defer clear(product)
	guest, err := run.readFile(input.Process[1].File, phase6guestreceipt.MaxTotalBytes)
	if err != nil {
		return err
	}
	defer clear(guest)
	if len(product) != input.Process[0].Bytes || slice6ReceiptSHA256(product) != input.Process[0].SHA256 ||
		len(guest) != observed.GuestSealedBytes || slice6ReceiptSHA256(guest) != observed.GuestSealedSHA256 ||
		slice6ReceiptSHA256(product[:observed.ProductPrefixBytes]) != observed.ProductPrefixSHA256 ||
		phase6guestreceipt.VerifyV2RecoveredClosedPrefix(product[:observed.ProductPrefixBytes], guest,
			observed.ProfileDigest, observed.ProductConfigDigest, observed.GuestConfigDigest,
			observed.InitialAttemptDigest, observed.RecoveredAttemptDigest, observed.Generation) != nil {
		return errors.New("Guest E recovered-close observed prefix not in final sealed originals")
	}
	return nil
}

// The normal Product-A stop path requires this exact live observation. Failure
// cleanup is separate and must never mark the normal stop as admitted.
func (capture *slice6GuestRecoveryCapture) checkRecoveredCloseBeforeStop(ctx context.Context) error {
	if capture == nil || capture.process != "product-a" || capture.recorder == nil ||
		capture.recoveredCloseDigest == "" || capture.run == nil || ctx == nil || ctx.Err() != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := capture.run.readFile(slice6GuestRecoveryRecoveredCloseFile, 2048)
	if err != nil {
		return err
	}
	defer clear(raw)
	capture.recorder.mu.Lock()
	defer capture.recorder.mu.Unlock()
	if capture.recorder.sealed || len(capture.recorder.events) != 20 ||
		capture.recorder.events[16].Kind != "guest_a_stop_call" ||
		capture.recorder.events[17].Kind != "guest_a_exit_observed" ||
		capture.recorder.events[18].Kind != "guest_a_sealed" ||
		capture.recorder.events[19].Kind != "recovered_close_observed" ||
		capture.recorder.events[19].ReferenceDigest != capture.recoveredCloseDigest ||
		slice6ReceiptSHA256(raw) != capture.recoveredCloseDigest {
		return phase6guestreceipt.ErrUnavailable
	}
	var observed slice6GuestRecoveryRecoveredClose
	if json.Unmarshal(raw, &observed) != nil || observed.RunID != capture.run.id ||
		observed.ProductID != capture.id || observed.ProductPID != capture.pid ||
		observed.ProductStart != capture.startedAt ||
		observed.ProfileDigest != capture.profile ||
		observed.ProductConfigDigest != capture.config ||
		observed.GuestStopCallRef != capture.recorder.events[16].ReferenceDigest ||
		observed.GuestExitRef != capture.recorder.events[17].ReferenceDigest ||
		observed.GuestSealRef != capture.recorder.events[18].ReferenceDigest ||
		observed.ProductPrefixBytes < 1 ||
		!guestRevokeFixtureDigestGate(observed.ProductPrefixSHA256) ||
		!guestRevokeFixtureDigestGate(observed.GuestSealedSHA256) {
		return phase6guestreceipt.ErrUnavailable
	}
	canonical, err := json.Marshal(observed)
	if err != nil || !bytes.Equal(raw, canonical) {
		return phase6guestreceipt.ErrUnavailable
	}
	prefix, complete, err := capture.readLivePrefix(ctx)
	if err != nil || !complete {
		clear(prefix)
		return phase6guestreceipt.ErrUnavailable
	}
	defer clear(prefix)
	guest, err := capture.run.readFile(slice6GuestRecoveryRawName("guest-a"), phase6guestreceipt.MaxTotalBytes)
	if err != nil {
		return err
	}
	defer clear(guest)
	if len(prefix) < observed.ProductPrefixBytes ||
		slice6ReceiptSHA256(prefix[:observed.ProductPrefixBytes]) != observed.ProductPrefixSHA256 ||
		len(guest) != observed.GuestSealedBytes ||
		slice6ReceiptSHA256(guest) != observed.GuestSealedSHA256 ||
		phase6guestreceipt.VerifyV2RecoveredClosedPrefix(prefix[:observed.ProductPrefixBytes], guest,
			observed.ProfileDigest, observed.ProductConfigDigest, observed.GuestConfigDigest,
			observed.InitialAttemptDigest, observed.RecoveredAttemptDigest, observed.Generation) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

func slice6ObserveGuestRecoveryRecoveredClose(ctx context.Context, dockerRun slice6DockerRun,
	product *slice6GuestRecoveryCapture, guestSealed slice6GuestRecoveryRawBinding,
	initialDigest, recoveredDigest string, generation int64) (string, error) {
	if ctx == nil || ctx.Err() != nil || product == nil || product.process != "product-a" ||
		product.recorder == nil || product.run == nil || product.run.id != dockerRun.id ||
		guestSealed.Process != "guest-a" || guestSealed.Role != "guest" ||
		guestSealed.RunID != dockerRun.id || guestSealed.ProfileDigest != product.profile ||
		guestSealed.ExitCode != 0 || guestSealed.PID < 1 ||
		!guestRevokeFixtureDigestGate(guestSealed.SHA256) {
		return "", phase6guestreceipt.ErrUnavailable
	}
	product.recorder.mu.Lock()
	ready := !product.recorder.sealed && len(product.recorder.events) == 19 &&
		product.recorder.events[16].Kind == "guest_a_stop_call" &&
		product.recorder.events[16].ReferenceDigest == slice6GuestRecoveryStopCallRef(guestSealed) &&
		product.recorder.events[17].Kind == "guest_a_exit_observed" &&
		product.recorder.events[17].ReferenceDigest == slice6GuestRecoveryExitObservedRef(guestSealed) &&
		product.recorder.events[18].Kind == "guest_a_sealed" &&
		product.recorder.events[18].ReferenceDigest == slice6GuestRecoverySealRef(guestSealed)
	product.recorder.mu.Unlock()
	if !ready {
		return "", phase6guestreceipt.ErrUnavailable
	}
	guest, err := product.run.readFile(guestSealed.File, phase6guestreceipt.MaxTotalBytes)
	if err != nil {
		return "", err
	}
	defer clear(guest)
	if len(guest) != guestSealed.Bytes || slice6ReceiptSHA256(guest) != guestSealed.SHA256 {
		return "", phase6guestreceipt.ErrUnavailable
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		prefix, complete, err := product.readLivePrefix(ctx)
		if err != nil {
			return "", err
		}
		if complete && phase6guestreceipt.VerifyV2RecoveredClosedPrefix(prefix, guest,
			product.profile, product.config, guestSealed.ConfigDigest,
			initialDigest, recoveredDigest, generation) == nil {
			if product.confirmStillRunning(ctx, dockerRun) != nil {
				clear(prefix)
				return "", phase6guestreceipt.ErrUnavailable
			}
			observed := slice6GuestRecoveryRecoveredClose{
				Protocol: "sandbox-runtime.phase6-guest-e-recovered-close.v1",
				RunID:    dockerRun.id, ProfileDigest: product.profile,
				ProductID: product.id, ProductPID: product.pid, ProductStart: product.startedAt,
				GuestID: guestSealed.ContainerID, GuestPID: guestSealed.PID,
				GuestStart: guestSealed.StartedAt, ProductConfigDigest: product.config,
				GuestConfigDigest:   guestSealed.ConfigDigest,
				ProductPrefixSHA256: slice6ReceiptSHA256(prefix), ProductPrefixBytes: len(prefix),
				GuestSealedSHA256: guestSealed.SHA256, GuestSealedBytes: guestSealed.Bytes,
				GuestStopCallRef:     slice6GuestRecoveryStopCallRef(guestSealed),
				GuestExitRef:         slice6GuestRecoveryExitObservedRef(guestSealed),
				GuestSealRef:         slice6GuestRecoverySealRef(guestSealed),
				InitialAttemptDigest: initialDigest, RecoveredAttemptDigest: recoveredDigest,
				Generation: generation, ObservedUTC: time.Now().UTC().Format(time.RFC3339Nano),
			}
			clear(prefix)
			digest, err := product.run.writeGuestRecoveryRecoveredClose(observed)
			if err != nil || product.recorder.record("recovered_close_observed", digest) != nil {
				return "", phase6guestreceipt.ErrUnavailable
			}
			product.recoveredCloseDigest = digest
			return digest, nil
		}
		clear(prefix)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return "", phase6guestreceipt.ErrUnavailable
}
