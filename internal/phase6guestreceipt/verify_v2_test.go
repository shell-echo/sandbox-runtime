package phase6guestreceipt

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
)

func TestV2ReceiptStrictDependencyLossAndInterleavedRetry(t *testing.T) {
	requireLinuxReceiptPipe(t)
	reader, writer := receiptTestPipe(t)
	defer reader.Close()
	defer writer.Close()
	readResult := make(chan []byte, 1)
	go func() { document, _ := io.ReadAll(reader); readResult <- document }()
	recorder, err := NewV2(writer, "product", testDigest, testDigest)
	if err != nil {
		t.Fatal(err)
	}
	other := "sha256:" + strings.Repeat("b", 64)
	for _, observation := range []guestagent.Observation{
		{Event: guestagent.ObservationProductAuthAccepted, AttemptDigest: testDigest, BindingGeneration: 1},
		{Event: guestagent.ObservationProductWelcomeWritten, AttemptDigest: testDigest, BindingGeneration: 1},
		{Event: guestagent.ObservationProductPeerInstalled, AttemptDigest: testDigest, BindingGeneration: 1},
		{Event: guestagent.ObservationProductAuthorityDependencyLost, AttemptDigest: testDigest, BindingGeneration: 1},
		{Event: guestagent.ObservationProductDisconnectPending, AttemptDigest: testDigest, BindingGeneration: 1},
		{Event: guestagent.ObservationProductAuthRetryable, AttemptDigest: other, BindingGeneration: 1, Reason: "dependency_unavailable"},
		{Event: guestagent.ObservationProductCloseCompleted, AttemptDigest: testDigest, BindingGeneration: 1, Reason: "dependency_lost"},
		{Event: guestagent.ObservationProductDisconnectResolved, AttemptDigest: testDigest, BindingGeneration: 1, Reason: "released"},
	} {
		recorder.Sink(observation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := recorder.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	document := <-readResult
	records, err := VerifyV2(document, "product", testDigest, testDigest)
	if err != nil || len(records) != 10 {
		t.Fatalf("v2 product stream = %d records, %v", len(records), err)
	}
	if _, err := Verify(document, "product", testDigest, testDigest); err == nil {
		t.Fatal("historical v1 verifier accepted v2 runtime stream")
	}
	for name, change := range map[string]func([]Record){
		"missing pending":      func(values []Record) { values[5].Event = "unknown_event" },
		"wrong close cause":    func(values []Record) { values[7].Reason = "authority_stale" },
		"wrong resolved cause": func(values []Record) { values[8].Reason = "connected_busy" },
		"wrong generation":     func(values []Record) { values[8].BindingGeneration = 2 },
		"old protocol":         func(values []Record) { values[0].Protocol = Protocol },
		"dual authority cause": func(values []Record) {
			values[6].Event = guestagent.ObservationProductAuthorityStale
			values[6].AttemptDigest = testDigest
			values[6].Reason = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			altered := append([]Record(nil), records...)
			change(altered)
			if _, err := VerifyV2(encodeV2Records(t, altered), "product", testDigest, testDigest); err == nil {
				t.Fatal("invalid v2 stream accepted")
			}
		})
	}
}

func TestV2GuestRetryCannotBecomeWelcomeOrReadTermination(t *testing.T) {
	records := []Record{
		{Protocol: ProtocolV2, Role: "guest", Event: "begin", Sequence: 1, ProfileDigest: testDigest, ConfigDigest: testDigest},
		{Protocol: ProtocolV2, Role: "guest", Event: guestagent.ObservationGuestHelloWritten, Sequence: 2, AttemptDigest: testDigest, BindingGeneration: 1},
		{Protocol: ProtocolV2, Role: "guest", Event: guestagent.ObservationGuestAuthRetry, Sequence: 3, AttemptDigest: testDigest, BindingGeneration: 1},
		{Protocol: ProtocolV2, Role: "guest", Event: "seal", Sequence: 4, EventCount: 2},
	}
	now := time.Now().UnixMilli()
	for i := range records {
		records[i].UnixMillis = now
		records[i].ElapsedNanos = int64(i)
	}
	if _, err := VerifyV2(encodeV2Records(t, records), "guest", testDigest, testDigest); err != nil {
		t.Fatal(err)
	}
	for _, event := range []string{guestagent.ObservationGuestWelcomeAccepted, guestagent.ObservationGuestReadTerminated} {
		altered := append([]Record(nil), records...)
		altered[3].Sequence = 4
		altered[3].Event = event
		altered[3].AttemptDigest = testDigest
		altered[3].BindingGeneration = 1
		altered[3].EventCount = 0
		altered = append(altered, Record{Protocol: ProtocolV2, Role: "guest", Event: "seal", Sequence: 5,
			ElapsedNanos: 4, UnixMillis: now, EventCount: 3})
		if _, err := VerifyV2(encodeV2Records(t, altered), "guest", testDigest, testDigest); err == nil {
			t.Fatalf("retry attempt accepted subsequent %s", event)
		}
	}
}

func encodeV2Records(t *testing.T, values []Record) []byte {
	t.Helper()
	var result []byte
	for _, value := range values {
		line, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, line...)
		result = append(result, '\n')
	}
	return result
}
