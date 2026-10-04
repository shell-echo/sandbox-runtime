//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

func TestSlice6GuestRecoverySharedAttemptRequiresBothLiveSides(t *testing.T) {
	first := "sha256:" + strings.Repeat("a", 64)
	second := "sha256:" + strings.Repeat("b", 64)
	begin := phase6guestreceipt.Record{Event: "begin"}
	product := []phase6guestreceipt.Record{begin,
		{Event: guestagent.ObservationProductAuthAccepted, AttemptDigest: first, BindingGeneration: 1},
		{Event: guestagent.ObservationProductPeerInstalled, AttemptDigest: first, BindingGeneration: 1}}
	guest := []phase6guestreceipt.Record{begin,
		{Event: guestagent.ObservationGuestWelcomeAccepted, AttemptDigest: first, BindingGeneration: 1}}
	if got, err := slice6GuestRecoverySharedAttemptFromRecords(product, guest, 1, nil); err != nil || got != first {
		t.Fatalf("initial two-sided accepted attempt unavailable: %v", err)
	}
	if got, err := slice6GuestRecoverySharedAttemptFromRecords(product[:2], guest, 1, nil); err != nil || got != "" {
		t.Fatal("attempt returned before Product peer installation")
	}
	if got, err := slice6GuestRecoverySharedAttemptFromRecords(product, guest, 1,
		map[string]bool{first: true}); err != nil || got != "" {
		t.Fatal("excluded old attempt was returned as fresh")
	}
	guest[1].AttemptDigest = second
	if got, err := slice6GuestRecoverySharedAttemptFromRecords(product, guest, 1, nil); err != nil || got != "" {
		t.Fatal("single-sided accepted attempt was returned")
	}
	guest[1].AttemptDigest = first
	product = append(product,
		phase6guestreceipt.Record{Event: guestagent.ObservationProductAuthAccepted,
			AttemptDigest: second, BindingGeneration: 1},
		phase6guestreceipt.Record{Event: guestagent.ObservationProductPeerInstalled,
			AttemptDigest: second, BindingGeneration: 1})
	guest = append(guest, phase6guestreceipt.Record{Event: guestagent.ObservationGuestWelcomeAccepted,
		AttemptDigest: second, BindingGeneration: 1})
	if _, err := slice6GuestRecoverySharedAttemptFromRecords(product, guest, 1, nil); err == nil {
		t.Fatal("multiple fresh accepted attempts did not fail closed")
	}
	if got, err := slice6GuestRecoverySharedAttemptFromRecords(product, guest, 1,
		map[string]bool{first: true}); err != nil || got != second {
		t.Fatal("fresh recovered attempt was not isolated from the old digest")
	}
	guest[2].BindingGeneration = 2
	if _, err := slice6GuestRecoverySharedAttemptFromRecords(product, guest, 1,
		map[string]bool{first: true}); err == nil {
		t.Fatal("generation drift was accepted")
	}
}
