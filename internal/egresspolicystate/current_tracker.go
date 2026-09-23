package egresspolicystate

import (
	"context"
	"time"
)

// CurrentTracker is terminal on any drift. Responses passed to Accept must
// first have been verified by AuthorityClient.Current against a fresh nonce.
type CurrentTracker struct {
	lastNow        time.Time
	lastIssued     time.Time
	lastGeneration uint64
	lastDigest     string
	terminated     bool
}

type CurrentSource interface {
	Current(context.Context) (CurrentResponse, error)
}

func PollCurrent(ctx context.Context, source CurrentSource, tracker *CurrentTracker, interval time.Duration, now func() time.Time) error {
	if ctx == nil || source == nil || tracker == nil || now == nil || interval < 50*time.Millisecond || interval > time.Second {
		return ErrInvalid
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			response, err := source.Current(ctx)
			if err != nil {
				tracker.terminated = true
				return ErrInvalid
			}
			if err := tracker.Accept(response, now().UTC()); err != nil {
				return err
			}
		}
	}
}

func (t *CurrentTracker) Accept(response CurrentResponse, now time.Time) error {
	if t == nil || t.terminated || now.IsZero() ||
		(!t.lastNow.IsZero() && now.Before(t.lastNow)) {
		if t != nil {
			t.terminated = true
		}
		return ErrInvalid
	}
	issued, err := canonicalTime(response.IssuedAt)
	if err != nil || response.Protocol != CurrentProtocolID || response.Generation < 1 ||
		!digestRegex.MatchString(response.SnapshotDigest) ||
		(response.Status != "active" && response.Status != "revoked") ||
		response.Generation < t.lastGeneration ||
		(response.Generation == t.lastGeneration && response.SnapshotDigest != t.lastDigest) ||
		(!t.lastIssued.IsZero() && issued.Before(t.lastIssued)) {
		t.terminated = true
		return ErrInvalid
	}
	t.lastNow, t.lastIssued = now, issued
	t.lastGeneration, t.lastDigest = response.Generation, response.SnapshotDigest
	if response.Status == "revoked" {
		t.terminated = true
		return ErrRevoked
	}
	return nil
}
