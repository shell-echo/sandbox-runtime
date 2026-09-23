package egresspolicystate

import (
	"context"
	"errors"
	"testing"
	"time"
)

type currentSourceFunc func(context.Context) (CurrentResponse, error)

func (f currentSourceFunc) Current(ctx context.Context) (CurrentResponse, error) { return f(ctx) }

func TestCurrentTrackerRejectsRollbackMutationAndRevocation(t *testing.T) {
	start := time.Now().UTC()
	response := func(generation uint64, digest, status string, issued time.Time) CurrentResponse {
		return CurrentResponse{Protocol: CurrentProtocolID, Generation: generation, SnapshotDigest: digest,
			Status: status, IssuedAt: issued.Format(time.RFC3339Nano)}
	}
	firstDigest, secondDigest := "sha256:"+repeatHex("a"), "sha256:"+repeatHex("b")
	for name, sequence := range map[string][]CurrentResponse{
		"generation rollback":   {response(2, secondDigest, "active", start), response(1, firstDigest, "active", start.Add(time.Millisecond))},
		"same generation drift": {response(1, firstDigest, "active", start), response(1, secondDigest, "active", start.Add(time.Millisecond))},
		"issued time rollback":  {response(1, firstDigest, "active", start), response(1, firstDigest, "active", start.Add(-time.Millisecond))},
		"terminal revoke":       {response(1, firstDigest, "active", start), response(2, secondDigest, "revoked", start.Add(time.Millisecond))},
	} {
		t.Run(name, func(t *testing.T) {
			tracker := new(CurrentTracker)
			if err := tracker.Accept(sequence[0], start); err != nil {
				t.Fatal(err)
			}
			if err := tracker.Accept(sequence[1], start.Add(2*time.Millisecond)); err == nil {
				t.Fatal("authority state drift accepted")
			}
			if err := tracker.Accept(sequence[0], start.Add(3*time.Millisecond)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("terminated tracker revived: %v", err)
			}
		})
	}
}

func TestCurrentPollStopsOnFirstAuthorityOutage(t *testing.T) {
	tracker := new(CurrentTracker)
	start := time.Now().UTC()
	response := CurrentResponse{Protocol: CurrentProtocolID, Generation: 1, Status: "active",
		SnapshotDigest: "sha256:" + repeatHex("a"), IssuedAt: start.Format(time.RFC3339Nano)}
	if err := tracker.Accept(response, start); err != nil {
		t.Fatal(err)
	}
	calls := 0
	source := currentSourceFunc(func(context.Context) (CurrentResponse, error) {
		calls++
		if calls == 1 {
			return response, nil
		}
		return CurrentResponse{}, ErrInvalid
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := PollCurrent(ctx, source, tracker, 50*time.Millisecond, time.Now); !errors.Is(err, ErrInvalid) || calls != 2 {
		t.Fatalf("poll outage = %v after %d calls", err, calls)
	}
	if err := tracker.Accept(response, time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tracker revived after outage: %v", err)
	}
}

func repeatHex(char string) string {
	result := ""
	for range 64 {
		result += char
	}
	return result
}
