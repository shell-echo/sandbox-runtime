package terminalgateway

import (
	"testing"
	"time"
)

func TestReplayClaimRejectsDuplicateUntilExpiry(t *testing.T) {
	handler := &Handler{replayed: make(map[string]time.Time)}
	now := time.Now().UTC()
	if !handler.claim("request-1", now, now.Add(time.Minute)) {
		t.Fatal("first handoff request was rejected")
	}
	if handler.claim("request-1", now, now.Add(time.Minute)) {
		t.Fatal("replayed handoff request was accepted")
	}
	if !handler.claim("request-2", now.Add(2*time.Minute), now.Add(3*time.Minute)) {
		t.Fatal("expired replay entry blocked a fresh request")
	}
}
