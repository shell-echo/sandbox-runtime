//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

// A live close trigger is only admissible if the same exact bytes occur at
// the start of the subsequently sealed, independently reread PID1 files.
// This proves prefix continuity, not the PostgreSQL cause or action order.
func slice6VerifyGuestRecoveryTriggerSealed(trigger slice6GuestRecoveryCloseTrigger,
	product, guest slice6GuestRecoveryRawBinding, productRaw, guestRaw []byte,
	initialDigest string, generation int64) error {
	observed, err := time.Parse(time.RFC3339Nano, trigger.ObservedUTC)
	if err != nil || observed.IsZero() || trigger.RunID == "" ||
		trigger.RunID != product.RunID || trigger.RunID != guest.RunID ||
		product.Process != "product-a" || guest.Process != "guest-a" ||
		trigger.ProductID != product.ContainerID || trigger.GuestID != guest.ContainerID ||
		trigger.ProductPID != product.PID || trigger.GuestPID != guest.PID ||
		trigger.ProductStart != product.StartedAt || trigger.GuestStart != guest.StartedAt ||
		product.ProfileDigest != guest.ProfileDigest ||
		trigger.ProductPrefixBytes < 1 || trigger.GuestPrefixBytes < 1 ||
		trigger.ProductPrefixBytes >= len(productRaw) || trigger.GuestPrefixBytes >= len(guestRaw) ||
		len(productRaw) != product.Bytes || len(guestRaw) != guest.Bytes ||
		product.SHA256 != slice6ReceiptSHA256(productRaw) ||
		guest.SHA256 != slice6ReceiptSHA256(guestRaw) ||
		trigger.ProductPrefixSHA256 != slice6ReceiptSHA256(productRaw[:trigger.ProductPrefixBytes]) ||
		trigger.GuestPrefixSHA256 != slice6ReceiptSHA256(guestRaw[:trigger.GuestPrefixBytes]) ||
		!bytes.HasSuffix(productRaw[:trigger.ProductPrefixBytes], []byte{'\n'}) ||
		!bytes.HasSuffix(guestRaw[:trigger.GuestPrefixBytes], []byte{'\n'}) {
		return phase6guestreceipt.ErrUnavailable
	}
	if phase6guestreceipt.VerifyV2InitialClosedPrefix(
		productRaw[:trigger.ProductPrefixBytes], guestRaw[:trigger.GuestPrefixBytes],
		product.ProfileDigest, product.ConfigDigest, guest.ConfigDigest,
		initialDigest, generation) != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	if _, err := phase6guestreceipt.VerifyV2(productRaw, "product", product.ProfileDigest, product.ConfigDigest); err != nil {
		return err
	}
	if _, err := phase6guestreceipt.VerifyV2(guestRaw, "guest", guest.ProfileDigest, guest.ConfigDigest); err != nil {
		return err
	}
	return nil
}
