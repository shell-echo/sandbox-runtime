package phase6tls

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func TestV2GuardRejectsBeforeAgentIO(t *testing.T) {
	client := &testGuardClient{}
	profile, role := phase6security.ProfileV2{}, phase6security.PeerCRLRoleDocument{}
	guard, err := NewPeerCRLGuardV2(profile, role, role.SourceMappingDigest, role.Digest(), "edge", "unbound", "inbound", client, time.Second, time.Now)
	if err == nil || guard != nil {
		t.Fatal("invalid v2 profile produced ordinary guard")
	}
	guard, err = NewPostgresPeerCRLGuardV2(profile, role, role.SourceMappingDigest, role.Digest(), "product-runtime", "unbound", client, time.Second, time.Now)
	if err == nil || guard != nil {
		t.Fatal("invalid v2 profile produced PostgreSQL guard")
	}
	if client.calls.Load() != 0 {
		t.Fatal("rejected admission called agent")
	}
}

// This exercises only the private post-admission construction and shared CRL
// runtime. It intentionally cannot pass the public Profile-v2 admission gate.
func TestV2BoundGuardUsesSharedVerifiedCRLRuntime(t *testing.T) {
	f := newGuardFixture(t)
	binding := f.guard.binding
	profile := phase6security.ProfileV2{ProfileDigest: binding.ProfileDigest,
		TrustEdges: []phase6security.TrustEdge{{ID: binding.EdgeID, Authentication: "mtls",
			To: "local", ToPrincipalDigest: binding.LocalPrincipalDigest, ClientAnchorID: binding.PeerAnchorID}},
		Principals: []phase6security.Principal{{Name: "local", PrincipalDigest: binding.LocalPrincipalDigest,
			TLS: &phase6security.TLSIdentity{RevocationMaxStalenessSeconds: 30, ConnectionDrainSeconds: 30}}}}
	role := phase6security.PeerCRLRoleDocument{SecurityProfileDigest: binding.ProfileDigest,
		SourceMappingDigest: binding.SourceMappingDigest, LocalPrincipalDigest: binding.LocalPrincipalDigest,
		Edges: []phase6security.PeerCRLRoleEdgeBinding{{EdgeID: binding.EdgeID, Direction: binding.Direction,
			PeerAnchorID: binding.PeerAnchorID, IssuerDigest: f.guard.expectedIssuerDigest}}}
	guard, err := newPeerCRLGuardV2Bound(profile, role, binding.EdgeID, binding.LocalPrincipalDigest,
		binding.Direction, f.client, time.Second, f.guard.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(guard.Close)
	if guard.binding != binding || guard.maxStaleness != 30*time.Second || guard.closeBudget != 3*time.Second {
		t.Fatal("bound identity or drain budget lost")
	}
	f.client.response = f.response(t, 1, false, "fixed-source")
	if err := guard.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := guard.CheckHandshake(t.Context(), f.state); err != nil {
		t.Fatal(err)
	}
	f.client.response = f.response(t, 2, true, "fixed-source")
	if err := guard.CheckHandshake(t.Context(), f.state); !errors.Is(err, workloadpki.ErrPeerRevoked) {
		t.Fatalf("revoked peer admitted: %v", err)
	}
	if value, err := NewPeerCRLGuardV2(profile, role, binding.SourceMappingDigest, role.Digest(), binding.EdgeID,
		binding.LocalPrincipalDigest, binding.Direction, f.client, time.Second, f.guard.now); err == nil || value != nil {
		t.Fatal("field fixture became publicly admissible")
	}
}
