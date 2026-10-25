package phase6tls

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type completionGuardClient struct {
	PeerCRLClient
	operation context.Context
}

func (c *completionGuardClient) PeerCRL(ctx context.Context, binding workloadtlsagent.PeerCRLBinding, issuer []byte) (workloadtlsagent.PeerCRLResponse, error) {
	c.operation = ctx
	return c.PeerCRLClient.PeerCRL(ctx, binding, issuer)
}

func (c *completionGuardClient) BootstrapPeerCRL(ctx context.Context, binding workloadtlsagent.PeerCRLBinding, issuer string) (workloadtlsagent.PeerCRLResponse, error) {
	c.operation = ctx
	return c.PeerCRLClient.BootstrapPeerCRL(ctx, binding, issuer)
}

func TestPeerCRLGuardRejectsExpiredCompletion(t *testing.T) {
	for _, stage := range []string{"verification", "commit"} {
		for _, cause := range []string{"parent_cancel", "parent_deadline", "operation_deadline"} {
			for _, mode := range []string{"bootstrap", "handshake_good", "handshake_revoked"} {
				t.Run(stage+"/"+cause+"/"+mode, func(t *testing.T) {
					f := newGuardFixture(t)
					f.client.response = f.response(t, 1, false, "fixed-source")
					if err := f.guard.Bootstrap(t.Context()); err != nil {
						t.Fatal(err)
					}
					local, peer := net.Pipe()
					defer local.Close()
					defer peer.Close()
					if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					if err := f.guard.Track(local, f.state); err != nil {
						t.Fatal(err)
					}
					oldDigest := f.guard.current.CRLDigest()
					oldExpirySequence := f.guard.expirySequence
					f.client.response = f.response(t, 2, mode == "handshake_revoked", "fixed-source")
					client := &completionGuardClient{PeerCRLClient: f.client}
					f.guard.client = client
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					wantClass, wantContext := PeerCRLParentCanceledFailure, context.Canceled
					if cause == "parent_deadline" {
						var stop context.CancelFunc
						ctx, stop = context.WithTimeout(t.Context(), 500*time.Millisecond)
						defer stop()
						wantClass, wantContext = PeerCRLParentDeadlineFailure, context.DeadlineExceeded
					} else if cause == "operation_deadline" {
						f.guard.timeout = 500 * time.Millisecond
						wantClass, wantContext = PeerCRLInternalDeadlineFailure, context.DeadlineExceeded
					}
					// The first clock read starts the pull. The second follows the
					// agent-return context check; the third holds the commit lock.
					// Expire at the selected boundary, without changing CRL wall time.
					reads, expired := 0, false
					f.guard.now = func() time.Time {
						reads++
						target := 2
						if stage == "commit" {
							target = 3
						}
						if reads == target {
							if client.operation == nil || client.operation.Err() != nil {
								t.Fatal("pull did not reach the post-agent boundary within its original budget")
							}
							if cause == "parent_cancel" {
								cancel()
							} else {
								select {
								case <-client.operation.Done():
								case <-time.After(2 * time.Second):
									t.Fatal("original context deadline did not fire")
								}
							}
							expired = true
						}
						return f.now
					}
					var err error
					if mode == "bootstrap" {
						err = f.guard.Bootstrap(ctx)
					} else {
						err = f.guard.CheckHandshake(ctx, f.state)
					}
					if !expired {
						t.Fatal("test did not expire after the agent-return context check")
					}
					if !errors.Is(err, ErrPeerCRLUnavailable) || !errors.Is(err, wantContext) || PeerCRLFailureOf(err) != wantClass {
						t.Errorf("late completion = %v, class %q; want %q with %v", err, PeerCRLFailureOf(err), wantClass, wantContext)
					}
					if f.guard.Ready() || !f.guard.unavailable || f.guard.failed {
						t.Errorf("late completion readiness = unavailable %v, failed %v", f.guard.unavailable, f.guard.failed)
					}
					if f.guard.current.CRLDigest() != oldDigest || f.guard.number.Cmp(big.NewInt(1)) != 0 ||
						len(f.guard.observedRevoked) != 0 || f.guard.expirySequence != oldExpirySequence+1 {
						t.Error("late completion published a CRL, revocation observation or expiry timer")
					}
					if len(f.guard.active) != 0 || len(f.guard.closing) != 0 || f.guard.draining != nil || len(f.guard.pullPermit) != 0 {
						t.Error("late completion retained an active peer, unfinished drain or pull permit")
					}
					var one [1]byte
					if _, err := peer.Read(one[:]); !errors.Is(err, io.EOF) {
						t.Errorf("old peer was not closed: %v", err)
					}
					// A new pull, with a fresh caller and operation budget, may recover.
					f.guard.now = func() time.Time { return f.now }
					f.guard.timeout = time.Second
					f.client.response = f.response(t, 3, mode == "handshake_revoked", "fixed-source")
					if err := f.guard.Bootstrap(t.Context()); err != nil || !f.guard.Ready() || f.guard.number.Cmp(big.NewInt(3)) != 0 {
						t.Fatalf("fresh pull did not recover: %v", err)
					}
					if len(f.guard.active) != 0 || f.client.calls.Load() != 3 {
						t.Error("recovery revived an old peer or retried the expired pull")
					}
				})
			}
		}
	}
}

func TestPeerCRLGuardPublicationChargesVerificationTimeToExpiry(t *testing.T) {
	f := newGuardFixture(t)
	f.client.response = f.response(t, 1, false, "fixed-source")
	if err := f.guard.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := f.guard.Track(local, f.state); err != nil {
		t.Fatal(err)
	}
	f.guard.mu.Lock()
	// The fixed wall clock still sees fresh CRL data. Verification, however,
	// has already spent the entire relative freshness budget before scheduling.
	f.guard.maxStaleness = time.Second
	f.guard.scheduleEvidenceExpiryLocked(f.now, time.Now().Add(-2*time.Second))
	f.guard.mu.Unlock()
	var one [1]byte
	if _, err := peer.Read(one[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("verification time extended evidence expiry: %v", err)
	}
	if f.guard.Ready() {
		t.Fatal("expired publication retained readiness")
	}
}

func TestPeerCRLGuardInvalidPeerRetainsVerifiedCRLWatermark(t *testing.T) {
	f := newGuardFixture(t)
	first := f.response(t, 1, false, "fixed-source")
	f.client.response = first
	if err := f.guard.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	// This peer is valid at handshake start but expires while the fixed agent
	// returns a newer, authentic CRL. Peer failure must not erase that watermark.
	template := *f.leaf
	template.NotAfter = f.now.Add(time.Second)
	der, err := x509.CreateCertificate(rand.Reader, &template, f.issuer, &f.leafKey.PublicKey, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	state := f.state
	state.PeerCertificates = []*x509.Certificate{leaf, f.issuer}
	state.VerifiedChains = [][]*x509.Certificate{{leaf, f.issuer}}
	second := f.response(t, 2, false, "fixed-source")
	f.client.responseForCall = func(int32) workloadtlsagent.PeerCRLResponse {
		*f.clock = f.now.Add(2 * time.Second)
		return second
	}
	if err := f.guard.CheckHandshake(t.Context(), state); !errors.Is(err, ErrPeerCRLUnavailable) || PeerCRLFailureOf(err) != PeerCRLSemanticFailure {
		t.Fatalf("expired peer did not reach the semantic rejection: %v", err)
	}
	if f.guard.number.Cmp(big.NewInt(2)) != 0 || f.guard.current.CRLDigest() != second.CRLDigest ||
		!f.guard.unavailable || f.guard.failed || f.guard.Ready() {
		t.Fatal("invalid peer erased the newer verified CRL watermark")
	}
	f.client.responseForCall = nil
	f.client.response = first
	if err := f.guard.Bootstrap(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) || PeerCRLFailureOf(err) != PeerCRLSemanticFailure {
		t.Fatalf("lower CRL after peer rejection escaped rollback refusal: %v", err)
	}
	if !f.guard.failed || f.guard.Ready() || f.guard.number.Cmp(big.NewInt(2)) != 0 || f.client.calls.Load() != 3 {
		t.Fatal("rollback did not retain the verified watermark and closed state")
	}
}

var _ PeerCRLClient = (*completionGuardClient)(nil)
