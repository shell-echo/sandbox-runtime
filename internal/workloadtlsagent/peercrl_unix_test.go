package workloadtlsagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testPeerCRLProvider struct {
	issuerDER []byte
	crlDER    []byte
	calls     atomic.Int32
	blocked   chan struct{}
	ended     chan struct{}
}

func (p *testPeerCRLProvider) ReadPeerCRL(ctx context.Context, request PeerCRLRequest) (string, []byte, []byte, time.Time, error) {
	p.calls.Add(1)
	if p.blocked != nil {
		close(p.blocked)
		<-ctx.Done()
		if p.ended != nil {
			close(p.ended)
		}
		return "", nil, nil, time.Time{}, ctx.Err()
	}
	if request.EdgeID != "product-provider-contract" || request.Direction != "outbound" ||
		request.PeerAnchorID != "internal-server-ca" || request.LocalPrincipalDigest != peerCRLTestDigest("product") ||
		request.SourceMappingDigest != peerCRLTestDigest("mapping") {
		return "", nil, nil, time.Time{}, ErrUnavailable
	}
	return "vault-peer-source", append([]byte(nil), p.issuerDER...), append([]byte(nil), p.crlDER...), time.Now().UTC(), nil
}

func TestPeerCRLV2UnixRoundTripReplayAndV1Separation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, crlDER := peerCRLTestDER(t, now)
	provider := &testPeerCRLProvider{issuerDER: issuerDER, crlDER: crlDER}
	fixture := newUnixFixtureWithPeer(t, 4, provider)
	defer fixture.close(t)
	binding := PeerCRLBinding{ProfileDigest: peerCRLTestDigest("profile"), SourceMappingDigest: peerCRLTestDigest("mapping"), EdgeID: "product-provider-contract",
		LocalPrincipalDigest: peerCRLTestDigest("product"), Direction: "outbound", PeerAnchorID: "internal-server-ca"}
	response, err := fixture.client.PeerCRL(context.Background(), binding, issuerDER)
	if err != nil || response.SourceID != "vault-peer-source" || provider.calls.Load() != 1 {
		t.Fatalf("v2 Unix CRL round trip failed: %v calls=%d", err, provider.calls.Load())
	}
	clear(response.CRLDER)
	// The v1 signer and snapshot path still work over the same restricted socket.
	snapshot, err := fixture.client.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Destroy()
	issuerHash := sha256.Sum256(issuerDER)
	request := peerCRLTestRequest(t, now, "sha256:"+hex.EncodeToString(issuerHash[:]))
	request.Nonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	request.RequestDigest = peerCRLRequestDigest(request)
	first, err := fixture.client.executePeerCRL(context.Background(), request, issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	clear(first.CRLDER)
	if _, err := fixture.client.executePeerCRL(context.Background(), request, issuerDER); !errors.Is(err, ErrUnavailable) || provider.calls.Load() != 2 {
		t.Fatalf("v2 replay admitted or reached provider: %v calls=%d", err, provider.calls.Load())
	}
	binding.EdgeID = "gateway-provider-private"
	if _, err := fixture.client.PeerCRL(context.Background(), binding, issuerDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong edge admitted by configured provider: %v", err)
	}
	binding.EdgeID = "product-provider-contract"
	binding.SourceMappingDigest = peerCRLTestDigest("other-mapping")
	if _, err := fixture.client.PeerCRL(context.Background(), binding, issuerDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong source mapping admitted by configured provider: %v", err)
	}
}

func TestPeerCRLV2RequiresExplicitProviderAndHonorsCancellation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, crlDER := peerCRLTestDER(t, now)
	binding := PeerCRLBinding{ProfileDigest: peerCRLTestDigest("profile"), SourceMappingDigest: peerCRLTestDigest("mapping"), EdgeID: "product-provider-contract",
		LocalPrincipalDigest: peerCRLTestDigest("product"), Direction: "outbound", PeerAnchorID: "internal-server-ca"}
	legacy := newUnixFixture(t, 2)
	if _, err := legacy.client.PeerCRL(context.Background(), binding, issuerDER); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("v1-only server silently accepted v2: %v", err)
	}
	legacy.close(t)
	blocked, ended := make(chan struct{}), make(chan struct{})
	provider := &testPeerCRLProvider{issuerDER: issuerDER, crlDER: crlDER, blocked: blocked, ended: ended}
	fixture := newUnixFixtureWithPeer(t, 1, provider)
	defer fixture.close(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		response, err := fixture.client.PeerCRL(ctx, binding, issuerDER)
		clear(response.CRLDER)
		done <- err
	}()
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("v2 provider did not receive request")
	}
	secondContext, secondCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer secondCancel()
	if _, err := fixture.client.PeerCRL(secondContext, binding, issuerDER); err == nil || provider.calls.Load() != 1 {
		t.Fatalf("v2 capacity did not reject second provider call: %v calls=%d", err, provider.calls.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled v2 read succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("v2 cancellation did not terminate read")
	}
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("v2 upstream read was not canceled")
	}
}

func TestPeerCRLV2BootstrapUsesPinnedIssuerDigest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, crlDER := peerCRLTestDER(t, now)
	provider := &testPeerCRLProvider{issuerDER: issuerDER, crlDER: crlDER}
	fixture := newUnixFixtureWithPeer(t, 2, provider)
	defer fixture.close(t)
	binding := PeerCRLBinding{ProfileDigest: peerCRLTestDigest("profile"), SourceMappingDigest: peerCRLTestDigest("mapping"), EdgeID: "product-provider-contract",
		LocalPrincipalDigest: peerCRLTestDigest("product"), Direction: "outbound", PeerAnchorID: "internal-server-ca"}
	hash := sha256.Sum256(issuerDER)
	response, err := fixture.client.BootstrapPeerCRL(t.Context(), binding, "sha256:"+hex.EncodeToString(hash[:]))
	if err != nil || !bytes.Equal(response.IssuerDER, issuerDER) || provider.calls.Load() != 1 {
		t.Fatalf("bootstrap issuer did not match fixed digest: %v", err)
	}
	clear(response.IssuerDER)
	clear(response.CRLDER)
	if _, err := fixture.client.BootstrapPeerCRL(t.Context(), binding, peerCRLTestDigest("other")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong fixed issuer digest admitted: %v", err)
	}
}

func TestPeerCRLClientFailureClassesDoNotExposeLocalDetails(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	issuerDER, crlDER := peerCRLTestDER(t, now)
	issuerHash := sha256.Sum256(issuerDER)
	binding := PeerCRLBinding{ProfileDigest: peerCRLTestDigest("profile"),
		SourceMappingDigest: peerCRLTestDigest("mapping"), EdgeID: "product-provider-contract",
		LocalPrincipalDigest: peerCRLTestDigest("product"), Direction: "outbound", PeerAnchorID: "internal-server-ca"}
	legacy := newUnixFixtureWithPeer(t, 2, &testPeerCRLProvider{issuerDER: issuerDER, crlDER: crlDER})
	if _, err := legacy.client.BootstrapPeerCRL(t.Context(), binding, "invalid"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("malformed pinned issuer was accepted")
	} else if class, ok := PeerCRLClientFailureOf(err); !ok || class != PeerCRLRequestBuildFailure || err.Error() != ErrUnavailable.Error() {
		t.Fatalf("request failure class: %q %v", class, err)
	}
	binding.EdgeID = "wrong-edge"
	if _, err := legacy.client.BootstrapPeerCRL(t.Context(), binding, "sha256:"+hex.EncodeToString(issuerHash[:])); !errors.Is(err, ErrUnavailable) {
		t.Fatal("agent error frame accepted")
	} else if class, ok := PeerCRLClientFailureOf(err); !ok || class != PeerCRLResponseFailure || err.Error() != ErrUnavailable.Error() {
		t.Fatalf("agent response failure class: %q %v", class, err)
	}
	binding.EdgeID = "product-provider-contract"
	legacy.close(t)
	if _, err := legacy.client.BootstrapPeerCRL(t.Context(), binding, "sha256:"+hex.EncodeToString(issuerHash[:])); !errors.Is(err, ErrUnavailable) {
		t.Fatal("removed agent socket accepted request")
	} else if class, ok := PeerCRLClientFailureOf(err); !ok || class != PeerCRLSocketPeerFailure || err.Error() != ErrUnavailable.Error() {
		t.Fatalf("socket failure class: %q %v", class, err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(legacy.dir, "agent.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(filepath.Join(legacy.dir, "agent.sock"), 0o666); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			_ = connection.Close()
		}
		close(ended)
	}()
	if _, err := legacy.client.BootstrapPeerCRL(t.Context(), binding, "sha256:"+hex.EncodeToString(issuerHash[:])); !errors.Is(err, ErrUnavailable) {
		t.Fatal("truncated agent frame accepted")
	} else if class, ok := PeerCRLClientFailureOf(err); !ok || class != PeerCRLTransportFailure || err.Error() != ErrUnavailable.Error() {
		t.Fatalf("transport failure class: %q %v", class, err)
	}
	<-ended
}
