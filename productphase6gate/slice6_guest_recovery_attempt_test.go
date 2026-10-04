//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

// An attempt digest is learned from both live canonical PID1 streams, not
// supplied by the E operator or guessed from a future sealed receipt.
func slice6GuestRecoverySharedAttemptFromRecords(product, guest []phase6guestreceipt.Record,
	generation int64, excluded map[string]bool) (string, error) {
	if generation < 1 || len(product) < 1 || len(guest) < 1 ||
		product[0].Event != "begin" || guest[0].Event != "begin" {
		return "", phase6guestreceipt.ErrUnavailable
	}
	accepted := make(map[string]bool)
	installed := make(map[string]bool)
	for _, record := range product[1:] {
		if record.BindingGeneration != generation ||
			!guestRevokeFixtureDigestGate(record.AttemptDigest) {
			return "", errors.New("Guest E Product attempt generation drift")
		}
		if record.Event == guestagent.ObservationProductAuthAccepted {
			accepted[record.AttemptDigest] = true
		}
		if record.Event == guestagent.ObservationProductPeerInstalled {
			installed[record.AttemptDigest] = true
		}
	}
	var selected string
	for _, record := range guest[1:] {
		if record.BindingGeneration != generation ||
			!guestRevokeFixtureDigestGate(record.AttemptDigest) {
			return "", errors.New("Guest E Guest attempt generation drift")
		}
		if record.Event != guestagent.ObservationGuestWelcomeAccepted ||
			!accepted[record.AttemptDigest] || !installed[record.AttemptDigest] ||
			excluded[record.AttemptDigest] {
			continue
		}
		if selected != "" && selected != record.AttemptDigest {
			return "", errors.New("Guest E multiple fresh accepted attempts")
		}
		selected = record.AttemptDigest
	}
	return selected, nil
}

func slice6AwaitGuestRecoverySharedAttempt(ctx context.Context, run slice6DockerRun,
	product, guest *slice6GuestRecoveryCapture, generation int64,
	excluded map[string]bool) (string, error) {
	if ctx == nil || ctx.Err() != nil || product == nil || guest == nil ||
		product.run == nil || guest.run == nil || product.run.id != run.id ||
		guest.run.id != run.id || product.profile != guest.profile || generation < 1 {
		return "", phase6guestreceipt.ErrUnavailable
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		productRaw, productReady, productErr := product.readLivePrefix(ctx)
		guestRaw, guestReady, guestErr := guest.readLivePrefix(ctx)
		if productErr != nil || guestErr != nil {
			clear(productRaw)
			clear(guestRaw)
			return "", phase6guestreceipt.ErrUnavailable
		}
		if productReady && guestReady {
			productRecords, productErr := phase6guestreceipt.VerifyV2OpenPrefix(productRaw,
				"product", product.profile, product.config)
			guestRecords, guestErr := phase6guestreceipt.VerifyV2OpenPrefix(guestRaw,
				"guest", guest.profile, guest.config)
			clear(productRaw)
			clear(guestRaw)
			if productErr != nil || guestErr != nil {
				return "", phase6guestreceipt.ErrUnavailable
			}
			digest, err := slice6GuestRecoverySharedAttemptFromRecords(productRecords,
				guestRecords, generation, excluded)
			if err != nil {
				return "", err
			}
			if digest != "" {
				if product.confirmStillRunning(ctx, run) != nil ||
					guest.confirmStillRunning(ctx, run) != nil {
					return "", phase6guestreceipt.ErrUnavailable
				}
				return digest, nil
			}
		} else {
			clear(productRaw)
			clear(guestRaw)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return "", phase6guestreceipt.ErrUnavailable
}

func slice6AwaitGuestRecoveryProductEvent(ctx context.Context, run slice6DockerRun,
	product *slice6GuestRecoveryCapture, attemptDigest, event, reason string,
	generation int64) error {
	if ctx == nil || ctx.Err() != nil || product == nil || product.run == nil ||
		product.run.id != run.id || product.role != "product" ||
		!guestRevokeFixtureDigestGate(attemptDigest) || event == "" || generation < 1 {
		return phase6guestreceipt.ErrUnavailable
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		raw, ready, err := product.readLivePrefix(ctx)
		if err != nil {
			clear(raw)
			return err
		}
		if ready {
			records, verifyErr := phase6guestreceipt.VerifyV2OpenPrefix(raw,
				"product", product.profile, product.config)
			clear(raw)
			if verifyErr != nil {
				return verifyErr
			}
			for _, record := range records[1:] {
				if record.AttemptDigest == attemptDigest && record.Event == event &&
					record.Reason == reason && record.BindingGeneration == generation {
					return product.confirmStillRunning(ctx, run)
				}
			}
		} else {
			clear(raw)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return phase6guestreceipt.ErrUnavailable
}
