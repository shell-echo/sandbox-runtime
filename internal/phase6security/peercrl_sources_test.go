package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func testPeerCRLSources(t *testing.T, profile Profile) (PeerCRLSources, []byte) {
	t.Helper()
	issuerDER := []byte("test actual peer issuer DER")
	hash := sha256.Sum256(issuerDER)
	var vaultDigest, productDigest, providerDigest string
	for _, external := range profile.External {
		if external.Name == "vault" {
			vaultDigest = external.IdentityDigest
		}
	}
	for _, principal := range profile.Principals {
		switch principal.Name {
		case "product-runtime":
			productDigest = principal.PrincipalDigest
		case "provider-runtime":
			providerDigest = principal.PrincipalDigest
		}
	}
	value := PeerCRLSources{Protocol: PeerCRLSourcesProtocolID, SecurityProfileDigest: profile.ProfileDigest,
		VaultExternalIdentityDigest: vaultDigest,
		Sources: []PeerCRLSource{{ID: "provider-peer-ca", Mount: "pki", IssuerID: "3d24b01e-81e2-42ac-a6d6-6203166d15ad",
			IssuerDigest: "sha256:" + hex.EncodeToString(hash[:])}},
		Edges: []PeerCRLEdgeBinding{
			{EdgeID: ProductProviderContractEdgeID, LocalPrincipalDigest: productDigest, Direction: "outbound",
				PeerAnchorID: "internal-server-ca", SourceID: "provider-peer-ca"},
			{EdgeID: ProductProviderContractEdgeID, LocalPrincipalDigest: providerDigest, Direction: "inbound",
				PeerAnchorID: "internal-client-ca", SourceID: "provider-peer-ca"},
		}}
	slices.SortFunc(value.Edges, func(a, b PeerCRLEdgeBinding) int {
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
	return value, issuerDER
}

func TestPeerCRLSourcesBindExactProfileEdgeAndIssuer(t *testing.T) {
	profile := validProfile()
	value, issuerDER := testPeerCRLSources(t, profile)
	if err := value.Validate(profile); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePeerCRLSources(document, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range decoded.Edges {
		issuerHash := sha256.Sum256(issuerDER)
		sourceID, err := decoded.AuthorizedSourceID(profile, binding.EdgeID, binding.LocalPrincipalDigest,
			binding.Direction, binding.PeerAnchorID, "sha256:"+hex.EncodeToString(issuerHash[:]))
		if err != nil || sourceID != "provider-peer-ca" {
			t.Fatalf("agent did not receive exact authorized source ID: %v", err)
		}
		source, err := decoded.Resolve(profile, binding.EdgeID, binding.LocalPrincipalDigest,
			binding.Direction, binding.PeerAnchorID, issuerDER)
		if err != nil || source.ID != "provider-peer-ca" {
			t.Fatalf("same actual issuer source did not resolve under exact edge: %v", err)
		}
		if _, err := decoded.Resolve(profile, binding.EdgeID, binding.LocalPrincipalDigest,
			binding.Direction, binding.PeerAnchorID, []byte("other issuer")); err == nil {
			t.Fatal("wrong issuer DER selected source")
		}
		if _, err := decoded.AuthorizedSourceID(profile, binding.EdgeID, binding.LocalPrincipalDigest,
			binding.Direction, binding.PeerAnchorID, testDigest("other issuer")); err == nil {
			t.Fatal("wrong issuer digest selected source ID")
		}
	}
	first := decoded.Edges[0]
	for name, selector := range map[string]PeerCRLEdgeBinding{
		"wrong edge": {EdgeID: "gateway-provider-private", LocalPrincipalDigest: first.LocalPrincipalDigest,
			Direction: first.Direction, PeerAnchorID: first.PeerAnchorID},
		"wrong role": {EdgeID: first.EdgeID, LocalPrincipalDigest: testDigest("other-role"),
			Direction: first.Direction, PeerAnchorID: first.PeerAnchorID},
		"wrong direction": {EdgeID: first.EdgeID, LocalPrincipalDigest: first.LocalPrincipalDigest,
			Direction: "sideways", PeerAnchorID: first.PeerAnchorID},
		"wrong anchor": {EdgeID: first.EdgeID, LocalPrincipalDigest: first.LocalPrincipalDigest,
			Direction: first.Direction, PeerAnchorID: "external-server-ca"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decoded.Resolve(profile, selector.EdgeID, selector.LocalPrincipalDigest,
				selector.Direction, selector.PeerAnchorID, issuerDER); err == nil {
				t.Fatal("cross-edge source selected")
			}
		})
	}
	unknown := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"extra":true}`)...)
	duplicate := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"protocol":"`+PeerCRLSourcesProtocolID+`"}`)...)
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "trailing": append(append([]byte(nil), document...), '\n'),
		"noncanonical": bytes.Replace(document, []byte(`"protocol"`), []byte(`"protocol" `), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePeerCRLSources(candidate, profile); err == nil {
				t.Fatal("noncanonical or open source document admitted")
			}
		})
	}
}

func TestPeerCRLSourcesFileRequiresPrivateCanonicalDocument(t *testing.T) {
	profile := validProfile()
	sources, _ := testPeerCRLSources(t, profile)
	document, err := json.Marshal(sources)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "peer-crl-sources.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyPeerCRLSourcesFile(path, profile); err != nil || got.SecurityProfileDigest != profile.ProfileDigest {
		t.Fatalf("private source document: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPeerCRLSourcesFile(path, profile); err == nil {
		t.Fatal("world-readable operator source mapping accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "source-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPeerCRLSourcesFile(link, profile); err == nil {
		t.Fatal("symlinked operator source mapping accepted")
	}
}

func TestPeerCRLSourcesRejectUnsafeMappingAndAuthorization(t *testing.T) {
	profile := validProfile()
	valid, _ := testPeerCRLSources(t, profile)
	for name, mutate := range map[string]func(*PeerCRLSources){
		"wrong profile":         func(value *PeerCRLSources) { value.SecurityProfileDigest = testDigest("other-profile") },
		"wrong Vault":           func(value *PeerCRLSources) { value.VaultExternalIdentityDigest = testDigest("other-vault") },
		"default issuer":        func(value *PeerCRLSources) { value.Sources[0].IssuerID = "default" },
		"issuer path injection": func(value *PeerCRLSources) { value.Sources[0].IssuerID = "../default" },
		"mount injection":       func(value *PeerCRLSources) { value.Sources[0].Mount = "pki/other" },
		"wrong anchor":          func(value *PeerCRLSources) { value.Edges[0].PeerAnchorID = "external-server-ca" },
		"cross-role":            func(value *PeerCRLSources) { value.Edges[0].LocalPrincipalDigest = testDigest("gateway") },
		"unused source": func(value *PeerCRLSources) {
			value.Sources = append(value.Sources, PeerCRLSource{ID: "unused", Mount: "other", IssuerID: "3d24b01e-81e2-42ac-a6d6-6203166d15ad",
				IssuerDigest: testDigest("unused")})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Sources = slices.Clone(valid.Sources)
			candidate.Edges = slices.Clone(valid.Edges)
			mutate(&candidate)
			if candidate.Validate(profile) == nil {
				t.Fatal("unsafe source mapping or authorization accepted")
			}
		})
	}
}
