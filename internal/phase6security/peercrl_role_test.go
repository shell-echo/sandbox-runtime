package phase6security

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func completePeerCRLSources(t *testing.T, profile Profile) PeerCRLSources {
	t.Helper()
	vaultDigest := ""
	for _, external := range profile.External {
		if external.Name == "vault" {
			vaultDigest = external.IdentityDigest
		}
	}
	sources := PeerCRLSources{Protocol: PeerCRLSourcesProtocolID,
		SecurityProfileDigest: profile.ProfileDigest, VaultExternalIdentityDigest: vaultDigest,
		Sources: []PeerCRLSource{{ID: "fixed-peer-ca", Mount: "pki",
			IssuerID: "3d24b01e-81e2-42ac-a6d6-6203166d15ad", IssuerDigest: testDigest("issuer")}}}
	for _, edge := range profile.TrustEdges {
		if edge.Authentication != "mtls" || edge.ClientAnchorID == "" {
			continue
		}
		if localAgentOwnsEdge(profile, edge.From, edge.FromPrincipalDigest) {
			sources.Edges = append(sources.Edges, PeerCRLEdgeBinding{EdgeID: edge.ID,
				LocalPrincipalDigest: edge.FromPrincipalDigest, Direction: "outbound",
				PeerAnchorID: edge.ServerAnchorID, SourceID: "fixed-peer-ca"})
		}
		if localAgentOwnsEdge(profile, edge.To, edge.ToPrincipalDigest) {
			sources.Edges = append(sources.Edges, PeerCRLEdgeBinding{EdgeID: edge.ID,
				LocalPrincipalDigest: edge.ToPrincipalDigest, Direction: "inbound",
				PeerAnchorID: edge.ClientAnchorID, SourceID: "fixed-peer-ca"})
		}
	}
	slices.SortFunc(sources.Edges, func(a, b PeerCRLEdgeBinding) int {
		first := a.EdgeID + "/" + a.LocalPrincipalDigest + "/" + a.Direction
		second := b.EdgeID + "/" + b.LocalPrincipalDigest + "/" + b.Direction
		if first < second {
			return -1
		}
		if first > second {
			return 1
		}
		return 0
	})
	if err := sources.Validate(profile); err != nil {
		t.Fatal(err)
	}
	return sources
}

func TestPeerCRLRoleDocumentDerivesCompleteMinimalBindings(t *testing.T) {
	profile := validProfile()
	sources := completePeerCRLSources(t, profile)
	for _, binding := range profile.TLSAgentBindings {
		required, err := peerCRLRoleRequiredEdges(profile, binding.SubjectPrincipalDigest)
		if err != nil {
			continue
		}
		document, err := DerivePeerCRLRoleDocument(profile, sources, binding.SubjectPrincipalDigest)
		if err != nil || len(document.Edges) != len(required) {
			t.Fatalf("role %s did not receive exact required edges: %v", binding.SubjectDeployment, err)
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodePeerCRLRoleDocument(encoded, profile, sources.Digest(), document.Digest())
		if err != nil || decoded.LocalPrincipalDigest != binding.SubjectPrincipalDigest ||
			!bytes.Equal(encoded, mustPeerRoleJSON(t, decoded)) {
			t.Fatalf("role %s canonical binding rejected: %v", binding.SubjectDeployment, err)
		}
		if _, err := decoded.Binding(required[0].EdgeID, required[0].Direction); err != nil {
			t.Fatal(err)
		}
		if _, err := decoded.Binding("wrong-edge", "outbound"); err == nil {
			t.Fatal("role accepted undeclared edge")
		}
		changed := document
		changed.Edges = slices.Clone(document.Edges[:len(document.Edges)-1])
		if changed.Validate(profile, sources.Digest()) == nil {
			t.Fatal("missing required edge admitted")
		}
		changed = document
		changed.Edges = slices.Clone(document.Edges)
		changed.Edges[0].IssuerDigest = testDigest("other-issuer")
		changedDocument, _ := json.Marshal(changed)
		if _, err := DecodePeerCRLRoleDocument(changedDocument, profile, sources.Digest(), document.Digest()); err == nil {
			t.Fatal("issuer changed without the pinned role-document digest")
		}
		if changed.Validate(profile, testDigest("other-mapping")) == nil {
			t.Fatal("wrong source mapping digest accepted")
		}
		path := filepath.Join(t.TempDir(), "role-peer-crl.json")
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyPeerCRLRoleFile(path, profile, sources.Digest(), document.Digest()); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyPeerCRLRoleFile(path, profile, sources.Digest(), testDigest("other-role-document")); err == nil {
			t.Fatal("correctly formatted but wrong pinned role digest admitted")
		}
		changedSources := sources
		changedSources.Sources = slices.Clone(sources.Sources)
		changedSources.Sources[0].IssuerDigest = testDigest("different-issuer")
		if changedSources.Validate(profile) != nil {
			t.Fatal("changed source fixture is invalid")
		}
		if _, err := VerifyPeerCRLRoleFile(path, profile, changedSources.Digest(), document.Digest()); err == nil {
			t.Fatal("role document admitted under different source mapping")
		}
		for _, other := range profile.TLSAgentBindings {
			if other.SubjectPrincipalDigest != binding.SubjectPrincipalDigest {
				if document.ValidateForPrincipal(profile, sources.Digest(), other.SubjectPrincipalDigest) == nil {
					t.Fatal("cross-role document admitted")
				}
				break
			}
		}
	}
}

func mustPeerRoleJSON(t *testing.T, value PeerCRLRoleDocument) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestDerivePeerCRLRoleCommandWritesPrivateCanonicalArtifact(t *testing.T) {
	profile := validProfile()
	sources := completePeerCRLSources(t, profile)
	var principal string
	for _, binding := range profile.TLSAgentBindings {
		if _, err := peerCRLRoleRequiredEdges(profile, binding.SubjectPrincipalDigest); err == nil {
			principal = binding.SubjectPrincipalDigest
			break
		}
	}
	if principal == "" {
		t.Fatal("fixture lacks a role with peer CRL edges")
	}
	directory := t.TempDir()
	profilePath, sourcesPath, outputPath := filepath.Join(directory, "profile.json"),
		filepath.Join(directory, "sources.json"), filepath.Join(directory, "role.json")
	for path, value := range map[string]any{profilePath: profile, sourcesPath: sources} {
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, document, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	arguments := []string{"run", "../../cmd/derive-phase6-peer-crl-role", "-profile", profilePath,
		"-profile-digest", profile.ProfileDigest, "-sources", sourcesPath,
		"-sources-digest", sources.Digest(), "-principal-digest", principal, "-output", outputPath}
	output, err := exec.Command("go", arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("derive command failed: %v: %s", err, output)
	}
	info, err := os.Lstat(outputPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("derived role file privacy: %v %v", info, err)
	}
	role, err := VerifyPeerCRLRoleFile(outputPath, profile, sources.Digest(),
		deriveTestRoleDigest(t, profile, sources, principal))
	if err != nil || !bytes.Contains(output, []byte(role.Digest())) {
		t.Fatalf("derived canonical role binding invalid: %v: %s", err, output)
	}
	rawRole, err := os.ReadFile(outputPath)
	if err != nil || bytes.Contains(rawRole, []byte(sources.Sources[0].Mount)) ||
		bytes.Contains(rawRole, []byte(sources.Sources[0].IssuerID)) {
		t.Fatal("derived role file contains a Vault locator")
	}
	if second, err := exec.Command("go", arguments...).CombinedOutput(); err == nil {
		t.Fatalf("derive command overwrote existing role file: %s", second)
	}
}

func deriveTestRoleDigest(t *testing.T, profile Profile, sources PeerCRLSources, principal string) string {
	t.Helper()
	role, err := DerivePeerCRLRoleDocument(profile, sources, principal)
	if err != nil {
		t.Fatal(err)
	}
	return role.Digest()
}
