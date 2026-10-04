//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

func TestSlice6LiveClosePrefixBindsToFinalSealedPID1Bytes(t *testing.T) {
	profile := "sha256:" + strings.Repeat("a", 64)
	config := "sha256:" + strings.Repeat("b", 64)
	attempt := "sha256:" + strings.Repeat("c", 64)
	runID := strings.Repeat("d", 32)
	stamp := time.Now().UTC()
	makeRecords := func(role string, events []string) ([]byte, int) {
		t.Helper()
		var raw []byte
		prefixBytes := 0
		for index, event := range events {
			record := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
				Role: role, Event: event, Sequence: uint64(index + 1),
				ElapsedNanos: int64(index), UnixMillis: stamp.UnixMilli()}
			switch event {
			case "begin":
				record.ProfileDigest, record.ConfigDigest = profile, config
			case "seal":
				record.EventCount = uint64(len(events) - 2)
			default:
				record.AttemptDigest, record.BindingGeneration = attempt, 1
				if event == guestagent.ObservationProductCloseCompleted {
					record.Reason = "dependency_lost"
				}
				if event == guestagent.ObservationProductDisconnectResolved {
					record.Reason = "released"
				}
			}
			line, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, line...)
			raw = append(raw, '\n')
			if event == guestagent.ObservationProductCloseCompleted ||
				event == guestagent.ObservationGuestReadTerminated {
				prefixBytes = len(raw)
			}
		}
		return raw, prefixBytes
	}
	productRaw, productPrefix := makeRecords("product", []string{"begin",
		guestagent.ObservationProductAuthAccepted, guestagent.ObservationProductWelcomeWritten,
		guestagent.ObservationProductPeerInstalled, guestagent.ObservationProductAuthorityDependencyLost,
		guestagent.ObservationProductDisconnectPending, guestagent.ObservationProductCloseCompleted,
		guestagent.ObservationProductDisconnectResolved, "seal"})
	guestRaw, guestPrefix := makeRecords("guest", []string{"begin",
		guestagent.ObservationGuestHelloWritten, guestagent.ObservationGuestWelcomeAccepted,
		guestagent.ObservationGuestReadTerminated, "seal"})
	product := slice6GuestRecoveryRawBinding{Process: "product-a", RunID: runID,
		ContainerID: strings.Repeat("e", 64), PID: 101, StartedAt: stamp.Format(time.RFC3339Nano),
		ProfileDigest: profile, ConfigDigest: config, SHA256: slice6ReceiptSHA256(productRaw), Bytes: len(productRaw)}
	guest := slice6GuestRecoveryRawBinding{Process: "guest-a", RunID: runID,
		ContainerID: strings.Repeat("f", 64), PID: 102, StartedAt: stamp.Add(time.Millisecond).Format(time.RFC3339Nano),
		ProfileDigest: profile, ConfigDigest: config, SHA256: slice6ReceiptSHA256(guestRaw), Bytes: len(guestRaw)}
	trigger := slice6GuestRecoveryCloseTrigger{RunID: runID,
		ProductID: product.ContainerID, GuestID: guest.ContainerID,
		ProductPID: product.PID, GuestPID: guest.PID,
		ProductStart: product.StartedAt, GuestStart: guest.StartedAt,
		ProductPrefixSHA256: slice6ReceiptSHA256(productRaw[:productPrefix]),
		GuestPrefixSHA256:   slice6ReceiptSHA256(guestRaw[:guestPrefix]),
		ProductPrefixBytes:  productPrefix, GuestPrefixBytes: guestPrefix,
		ObservedUTC: stamp.Add(2 * time.Millisecond).Format(time.RFC3339Nano)}
	check := func(tr slice6GuestRecoveryCloseTrigger, p, g slice6GuestRecoveryRawBinding,
		pr, gr []byte) error {
		return slice6VerifyGuestRecoveryTriggerSealed(tr, p, g, pr, gr, attempt, 1)
	}
	if err := check(trigger, product, guest, productRaw, guestRaw); err != nil {
		t.Fatalf("same-byte live prefix/final seal rejected: %v", err)
	}
	wrong := trigger
	wrong.GuestPrefixBytes--
	if check(wrong, product, guest, productRaw, guestRaw) == nil {
		t.Fatal("partial live Guest prefix accepted")
	}
	wrong = trigger
	wrong.ProductPrefixSHA256 = slice6ReceiptSHA256([]byte("spliced"))
	if check(wrong, product, guest, productRaw, guestRaw) == nil {
		t.Fatal("spliced live Product prefix accepted")
	}
	wrong = trigger
	wrong.ProductPID++
	if check(wrong, product, guest, productRaw, guestRaw) == nil {
		t.Fatal("different Product PID1 accepted")
	}
	if check(trigger, product, guest, productRaw, bytes.TrimSuffix(guestRaw, []byte{'\n'})) == nil {
		t.Fatal("unsealed final Guest bytes accepted")
	}
}
