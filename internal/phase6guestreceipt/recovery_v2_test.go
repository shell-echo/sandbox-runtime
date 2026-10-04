package phase6guestreceipt

import (
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
)

func TestV2RecoveryPairRequiresReleasedOldNonceAndDistinctSignedReconnect(t *testing.T) {
	first := testDigest
	retry := "sha256:" + strings.Repeat("b", 64)
	fresh := "sha256:" + strings.Repeat("c", 64)
	item := func(role, event, digest, reason string) Record {
		return Record{Protocol: ProtocolV2, Role: role, Event: event,
			AttemptDigest: digest, BindingGeneration: 1, Reason: reason}
	}
	product := []Record{
		{Protocol: ProtocolV2, Role: "product", Event: "begin", ProfileDigest: testDigest, ConfigDigest: testDigest},
		item("product", guestagent.ObservationProductAuthAccepted, first, ""),
		item("product", guestagent.ObservationProductWelcomeWritten, first, ""),
		item("product", guestagent.ObservationProductPeerInstalled, first, ""),
		item("product", guestagent.ObservationProductAuthorityDependencyLost, first, ""),
		item("product", guestagent.ObservationProductDisconnectPending, first, ""),
		item("product", guestagent.ObservationProductAuthRetryable, retry, "connected_busy"),
		item("product", guestagent.ObservationProductCloseCompleted, first, "dependency_lost"),
		item("product", guestagent.ObservationProductDisconnectResolved, first, "released"),
		item("product", guestagent.ObservationProductAuthAccepted, fresh, ""),
		item("product", guestagent.ObservationProductWelcomeWritten, fresh, ""),
		item("product", guestagent.ObservationProductPeerInstalled, fresh, ""),
		item("product", guestagent.ObservationProductDisconnectPending, fresh, ""),
		item("product", guestagent.ObservationProductCloseCompleted, fresh, "handler_shutdown"),
		item("product", guestagent.ObservationProductDisconnectResolved, fresh, "released"),
		{Protocol: ProtocolV2, Role: "product", Event: "seal", EventCount: 14},
	}
	guest := []Record{
		{Protocol: ProtocolV2, Role: "guest", Event: "begin", ProfileDigest: testDigest, ConfigDigest: testDigest},
		item("guest", guestagent.ObservationGuestHelloWritten, first, ""),
		item("guest", guestagent.ObservationGuestWelcomeAccepted, first, ""),
		item("guest", guestagent.ObservationGuestReadTerminated, first, ""),
		item("guest", guestagent.ObservationGuestHelloWritten, retry, ""),
		item("guest", guestagent.ObservationGuestAuthRetry, retry, ""),
		item("guest", guestagent.ObservationGuestHelloWritten, fresh, ""),
		item("guest", guestagent.ObservationGuestWelcomeAccepted, fresh, ""),
		item("guest", guestagent.ObservationGuestReadTerminated, fresh, ""),
		{Protocol: ProtocolV2, Role: "guest", Event: "seal", EventCount: 8},
	}
	stamp := time.Now().UnixMilli()
	for i := range product {
		product[i].Sequence = uint64(i + 1)
		product[i].ElapsedNanos = int64(i)
		product[i].UnixMillis = stamp
	}
	for i := range guest {
		guest[i].Sequence = uint64(i + 1)
		guest[i].ElapsedNanos = int64(i)
		guest[i].UnixMillis = stamp
	}
	check := func(p, g []Record) error {
		return VerifyV2RecoveryPair(encodeV2Records(t, p), encodeV2Records(t, g),
			testDigest, testDigest, testDigest, first, fresh, 1)
	}
	resequence := func(records []Record) {
		for i := range records {
			records[i].Sequence = uint64(i + 1)
			records[i].ElapsedNanos = int64(i)
			records[i].UnixMillis = stamp
		}
		records[len(records)-1].EventCount = uint64(len(records) - 2)
	}
	if err := check(product, guest); err != nil {
		t.Fatal(err)
	}
	openProduct := append([]Record(nil), product[:len(product)-1]...)
	checkObserved := func(p []Record, g []Record, recoveredDigest string, generation int64) error {
		return VerifyV2RecoveredClosedPrefix(encodeV2Records(t, p), encodeV2Records(t, g),
			testDigest, testDigest, testDigest, first, recoveredDigest, generation)
	}
	if err := checkObserved(openProduct, guest, fresh, 1); err != nil {
		t.Fatalf("live recovered close and sealed Guest rejected: %v", err)
	}
	for _, drift := range []struct {
		name  string
		alter func([]Record, []Record) ([]Record, []Record)
	}{
		{"initial release only", func(p, g []Record) ([]Record, []Record) { return p[:9], g }},
		{"pending only", func(p, g []Record) ([]Record, []Record) { return p[:len(p)-2], g }},
		{"close only", func(p, g []Record) ([]Record, []Record) { return p[:len(p)-1], g }},
		{"nonreleased", func(p, g []Record) ([]Record, []Record) {
			p[len(p)-1].Reason = "already_inactive"
			return p, g
		}},
		{"wrong generation", func(p, g []Record) ([]Record, []Record) { return p, g }},
		{"Guest unsealed", func(p, g []Record) ([]Record, []Record) { return p, g[:len(g)-1] }},
	} {
		t.Run("observed "+drift.name, func(t *testing.T) {
			p := append([]Record(nil), openProduct...)
			g := append([]Record(nil), guest...)
			p, g = drift.alter(p, g)
			generation := int64(1)
			if drift.name == "wrong generation" {
				generation = 2
			}
			if err := checkObserved(p, g, fresh, generation); err == nil {
				t.Fatal("invalid recovered live observation accepted")
			}
		})
	}
	if err := checkObserved(openProduct, guest, retry, 1); err == nil {
		t.Fatal("retry attempt substituted for recovered release")
	}
	// During an installed connection's PostgreSQL loss, the capacity gate can
	// reject pre-Accept with HTTP 503. That produces no signed hello/1013
	// receipt; only the initial and recovered signed attempts are mandatory.
	twoProduct := append(append([]Record(nil), product[:6]...), product[7:]...)
	twoGuest := append(append([]Record(nil), guest[:4]...), guest[6:]...)
	resequence(twoProduct)
	resequence(twoGuest)
	if err := check(twoProduct, twoGuest); err != nil {
		t.Fatalf("two real signed attempts rejected: %v", err)
	}
	retry2 := "sha256:" + strings.Repeat("d", 64)
	multipleProduct := append(append([]Record(nil), product[:7]...), item("product", guestagent.ObservationProductAuthRetryable, retry2, "dependency_unavailable"))
	multipleProduct = append(multipleProduct, product[7:]...)
	multipleGuest := append(append([]Record(nil), guest[:6]...),
		item("guest", guestagent.ObservationGuestHelloWritten, retry2, ""),
		item("guest", guestagent.ObservationGuestAuthRetry, retry2, ""))
	multipleGuest = append(multipleGuest, guest[6:]...)
	resequence(multipleProduct)
	resequence(multipleGuest)
	if err := check(multipleProduct, multipleGuest); err != nil {
		t.Fatalf("two complete optional 1013 attempts rejected: %v", err)
	}
	for _, drift := range []struct {
		name  string
		alter func([]Record, []Record)
	}{
		{"single-sided retry", func(_, g []Record) { g[7].AttemptDigest = "sha256:" + strings.Repeat("e", 64) }},
		{"duplicate retry", func(p, _ []Record) { p[7].AttemptDigest = retry }},
		{"wrong retry generation", func(_, g []Record) { g[7].BindingGeneration = 2 }},
		{"welcome after retry", func(_, g []Record) { g[7].Event = guestagent.ObservationGuestWelcomeAccepted }},
	} {
		t.Run(drift.name, func(t *testing.T) {
			p := append([]Record(nil), multipleProduct...)
			g := append([]Record(nil), multipleGuest...)
			drift.alter(p, g)
			if err := check(p, g); err == nil {
				t.Fatal("drifted optional signed retry was accepted")
			}
		})
	}
	replacementProduct := append([]Record{product[0]}, product[9:15]...)
	replacementProduct = append(replacementProduct, product[len(product)-1])
	replacementGuest := append([]Record{guest[0]}, guest[6:9]...)
	replacementGuest = append(replacementGuest, guest[len(guest)-1])
	for i := range replacementProduct {
		replacementProduct[i].Sequence = uint64(i + 1)
		replacementProduct[i].ElapsedNanos = int64(i)
	}
	replacementProduct[len(replacementProduct)-1].EventCount = uint64(len(replacementProduct) - 2)
	for i := range replacementGuest {
		replacementGuest[i].Sequence = uint64(i + 1)
		replacementGuest[i].ElapsedNanos = int64(i)
	}
	replacementGuest[len(replacementGuest)-1].EventCount = uint64(len(replacementGuest) - 2)
	if err := VerifyV2ReplacementPair(encodeV2Records(t, replacementProduct),
		encodeV2Records(t, replacementGuest), testDigest, testDigest, testDigest, fresh, 1); err != nil {
		t.Fatalf("clean successor PID1 pair rejected: %v", err)
	}
	replacementProduct[6].Reason = "already_inactive"
	if err := VerifyV2ReplacementPair(encodeV2Records(t, replacementProduct),
		encodeV2Records(t, replacementGuest), testDigest, testDigest, testDigest, fresh, 1); err == nil {
		t.Fatal("replacement accepted without exact old nonce release")
	}
	for _, change := range []struct {
		name  string
		alter func([]Record, []Record)
	}{
		{"old nonce not released", func(p, _ []Record) { p[8].Reason = "already_inactive" }},
		{"missing Guest actual 1013", func(_, g []Record) { g[5].Event = guestagent.ObservationGuestWelcomeAccepted }},
		{"fresh Product before release", func(p, _ []Record) { p[8], p[9] = p[9], p[8]; p[8].Sequence, p[9].Sequence = 9, 10 }},
		{"extra Product attempt", func(p, _ []Record) { p[6].AttemptDigest = "sha256:" + strings.Repeat("d", 64) }},
		{"wrong generation", func(_, g []Record) { g[7].BindingGeneration = 2 }},
		{"legacy Product protocol", func(p, _ []Record) { p[0].Protocol = Protocol }},
	} {
		t.Run(change.name, func(t *testing.T) {
			p := append([]Record(nil), product...)
			g := append([]Record(nil), guest...)
			change.alter(p, g)
			if err := check(p, g); err == nil {
				t.Fatal("drifted pair was accepted")
			}
		})
	}
}
