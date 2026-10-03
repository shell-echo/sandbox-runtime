//go:build phase6slice6gate

package productphase6gate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This is run-owned controller input derived from two Vault-observed issuer
// certificates and the complete Profile. It is not an observed CRL read by a
// running controller or a released per-role material receipt.
func slice6VaultComposePeerCRLSources(t *testing.T, directory string,
	profile phase6security.Profile, general, broker slice6VaultRoot) (string, phase6security.PeerCRLSources) {
	t.Helper()
	if profile.Validate() != nil || general.Certificate == nil || broker.Certificate == nil ||
		general.ID == broker.ID || general.Certificate.Equal(broker.Certificate) {
		t.Fatal("two independent supplied issuer sources are unavailable")
	}
	issuerDigest := func(root slice6VaultRoot) string {
		sum := sha256.Sum256(root.Certificate.Raw)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	value := phase6security.PeerCRLSources{Protocol: phase6security.PeerCRLSourcesProtocolID,
		SecurityProfileDigest: profile.ProfileDigest,
		Sources: []phase6security.PeerCRLSource{
			{ID: "broker-only", Mount: "pki", IssuerID: broker.ID, IssuerDigest: issuerDigest(broker)},
			{ID: "general", Mount: "pki", IssuerID: general.ID, IssuerDigest: issuerDigest(general)},
		}}
	for _, service := range profile.External {
		if service.Name == "vault" {
			value.VaultExternalIdentityDigest = service.IdentityDigest
		}
	}
	subjects := make(map[string]string, len(profile.TLSAgentBindings))
	for _, agent := range profile.TLSAgentBindings {
		if subjects[agent.SubjectDeployment] != "" {
			t.Fatal("duplicate TLS subject in peer-source derivation")
		}
		subjects[agent.SubjectDeployment] = agent.SubjectPrincipalDigest
	}
	sourceFor := func(peer string) string {
		switch peer {
		case "egress-broker-product", "egress-broker-gateway", "egress-broker-browser-action-ingress",
			"egress-broker-provider-browser", "egress-broker-provider-desktop":
			return "broker-only"
		default:
			return "general"
		}
	}
	for _, edge := range profile.TrustEdges {
		if edge.Authentication != "mtls" {
			continue
		}
		postgresPeer := profile.IsSlice6FinalPostgresPeerEdge(edge.ID, edge.FromPrincipalDigest)
		dnsPeer := profile.IsSlice6DNSPeerEdge(edge.ID, edge.FromPrincipalDigest, "outbound")
		if edge.ClientAnchorID == "" && !postgresPeer && !dnsPeer {
			continue
		}
		if subjects[edge.From] == edge.FromPrincipalDigest || postgresPeer {
			value.Edges = append(value.Edges, phase6security.PeerCRLEdgeBinding{EdgeID: edge.ID,
				LocalPrincipalDigest: edge.FromPrincipalDigest, Direction: "outbound",
				PeerAnchorID: edge.ServerAnchorID, SourceID: sourceFor(edge.To)})
		}
		if edge.ClientAnchorID != "" && subjects[edge.To] == edge.ToPrincipalDigest {
			value.Edges = append(value.Edges, phase6security.PeerCRLEdgeBinding{EdgeID: edge.ID,
				LocalPrincipalDigest: edge.ToPrincipalDigest, Direction: "inbound",
				PeerAnchorID: edge.ClientAnchorID, SourceID: sourceFor(edge.From)})
		}
	}
	slices.SortFunc(value.Edges, func(a, b phase6security.PeerCRLEdgeBinding) int {
		left := a.EdgeID + "/" + a.LocalPrincipalDigest + "/" + a.Direction
		right := b.EdgeID + "/" + b.LocalPrincipalDigest + "/" + b.Direction
		switch {
		case left < right:
			return -1
		case left > right:
			return 1
		default:
			return 0
		}
	})
	if value.Validate(profile) != nil {
		t.Fatal("same-run two-issuer peer-CRL mapping does not cover the complete Profile")
	}
	ordinaryRoles := 0
	for _, agent := range profile.TLSAgentBindings {
		if !slice6SubjectHasPeerCRLEdge(profile, agent.SubjectDeployment, agent.SubjectPrincipalDigest) {
			continue
		}
		if _, err := phase6security.DerivePeerCRLRoleDocument(profile, value, agent.SubjectPrincipalDigest); err != nil {
			t.Fatalf("ordinary TLS peer source missing for %s: %v", agent.SubjectDeployment, err)
		}
		ordinaryRoles++
	}
	for _, target := range phase6security.Slice6DesiredFinalPostgresSignerTargets() {
		if _, err := phase6security.DerivePostgresPeerCRLRoleDocument(profile, value, target.SubjectDeployment); err != nil {
			t.Fatalf("PostgreSQL-purpose peer source missing for %s: %v", target.SubjectDeployment, err)
		}
	}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode canonical same-run peer-CRL mapping")
	}
	path := filepath.Join(directory, "peer-crl-sources.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal("write run-owned peer-CRL source mapping")
	}
	reopened, err := phase6security.VerifyPeerCRLSourcesFile(path, profile)
	if err != nil || reopened.Digest() != value.Digest() {
		t.Fatal("reopen run-owned canonical peer-CRL source mapping")
	}
	t.Logf("same-run controller peer-CRL sources=%d edge_bindings=%d ordinary_peer_roles=%d postgres_purpose_roles=%d; no live controller read",
		len(reopened.Sources), len(reopened.Edges), ordinaryRoles, len(phase6security.Slice6DesiredFinalPostgresSignerTargets()))
	return path, reopened
}

func slice6SubjectHasPeerCRLEdge(profile phase6security.Profile, name, digest string) bool {
	for _, edge := range profile.TrustEdges {
		if edge.Authentication != "mtls" ||
			(edge.ClientAnchorID == "" && !profile.IsSlice6DNSPeerEdge(edge.ID, digest, "outbound")) {
			continue
		}
		if edge.From == name && edge.FromPrincipalDigest == digest ||
			edge.ClientAnchorID != "" && edge.To == name && edge.ToPrincipalDigest == digest {
			return true
		}
	}
	return false
}

func TestSlice6SubjectHasPeerCRLEdge(t *testing.T) {
	profile := phase6security.Profile{TrustEdges: []phase6security.TrustEdge{{ID: "role-server",
		From: "role", FromPrincipalDigest: "role-digest", To: "server", ToPrincipalDigest: "server-digest",
		Authentication: "mtls", ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca"},
		{ID: "material-unix", From: "material-agent", FromPrincipalDigest: "material-digest",
			To: "controller", Authentication: "unix_peer_credentials"}}}
	if !slice6SubjectHasPeerCRLEdge(profile, "role", "role-digest") ||
		!slice6SubjectHasPeerCRLEdge(profile, "server", "server-digest") ||
		slice6SubjectHasPeerCRLEdge(profile, "material-agent", "material-digest") ||
		slice6SubjectHasPeerCRLEdge(profile, "role", "wrong-digest") {
		t.Fatal("peer-CRL role was not limited to a real bound mTLS edge")
	}
}
