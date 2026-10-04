package phase6guestreceipt

import (
	"bytes"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
)

func TestV2InitialClosedPrefixIsOnlyACompleteLineTrigger(t *testing.T) {
	item := func(role, event, reason string) Record {
		return Record{Protocol: ProtocolV2, Role: role, Event: event,
			AttemptDigest: testDigest, BindingGeneration: 1, Reason: reason}
	}
	product := []Record{
		{Protocol: ProtocolV2, Role: "product", Event: "begin", ProfileDigest: testDigest, ConfigDigest: testDigest},
		item("product", guestagent.ObservationProductAuthAccepted, ""),
		item("product", guestagent.ObservationProductWelcomeWritten, ""),
		item("product", guestagent.ObservationProductPeerInstalled, ""),
		item("product", guestagent.ObservationProductAuthorityDependencyLost, ""),
		item("product", guestagent.ObservationProductDisconnectPending, ""),
		item("product", guestagent.ObservationProductCloseCompleted, "dependency_lost"),
	}
	guest := []Record{
		{Protocol: ProtocolV2, Role: "guest", Event: "begin", ProfileDigest: testDigest, ConfigDigest: testDigest},
		item("guest", guestagent.ObservationGuestHelloWritten, ""),
		item("guest", guestagent.ObservationGuestWelcomeAccepted, ""),
		item("guest", guestagent.ObservationGuestReadTerminated, ""),
	}
	stamp := time.Now().UnixMilli()
	for i := range product {
		product[i].Sequence, product[i].ElapsedNanos, product[i].UnixMillis = uint64(i+1), int64(i), stamp
	}
	for i := range guest {
		guest[i].Sequence, guest[i].ElapsedNanos, guest[i].UnixMillis = uint64(i+1), int64(i), stamp
	}
	check := func(p, g []Record) error {
		return VerifyV2InitialClosedPrefix(encodeV2Records(t, p), encodeV2Records(t, g),
			testDigest, testDigest, testDigest, testDigest, 1)
	}
	if err := check(product, guest); err != nil {
		t.Fatal(err)
	}
	if err := check(product[:len(product)-1], guest); err == nil {
		t.Fatal("prefix triggered before actual Product transport close")
	}
	if err := check(product, guest[:len(guest)-1]); err == nil {
		t.Fatal("prefix triggered before Guest read termination")
	}
	wrongReason := append([]Record(nil), product...)
	wrongReason[len(wrongReason)-1].Reason = "handler_shutdown"
	if err := check(wrongReason, guest); err == nil {
		t.Fatal("prefix attributed non-dependency close to PostgreSQL loss")
	}
	wrongGeneration := append([]Record(nil), guest...)
	wrongGeneration[1].BindingGeneration = 2
	if err := check(product, wrongGeneration); err == nil {
		t.Fatal("prefix accepted generation drift")
	}
	sealed := append(append([]Record(nil), product...), Record{Protocol: ProtocolV2, Role: "product",
		Event: "seal", Sequence: uint64(len(product) + 1), ElapsedNanos: int64(len(product)),
		UnixMillis: stamp, EventCount: uint64(len(product) - 1)})
	if err := check(sealed, guest); err == nil {
		t.Fatal("open prefix accepted a final seal")
	}
	raw := encodeV2Records(t, product)
	if _, err := VerifyV2OpenPrefix(bytes.TrimSuffix(raw, []byte{'\n'}), "product", testDigest, testDigest); err == nil {
		t.Fatal("open prefix accepted an incomplete last line")
	}
	if _, err := VerifyV2OpenPrefix(raw, "product", testDigest, "sha256:"+string(bytes.Repeat([]byte{'f'}, 64))); err == nil {
		t.Fatal("open prefix accepted a different source config")
	}
}
