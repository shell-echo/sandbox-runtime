package phase6security

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func testPeerCRLSourcesV2(t *testing.T, profile ProfileV2) PeerCRLSources {
	t.Helper()
	required, err := requiredPeerCRLV2(profile)
	if err != nil {
		t.Fatal(err)
	}
	vaultDigest := ""
	var brokerCA DNSClientCA
	for _, service := range profile.External {
		if service.Name == "vault" {
			vaultDigest = service.IdentityDigest
		}
		if service.Name == "dns" && service.DNSClientCA != nil {
			brokerCA = *service.DNSClientCA
		}
	}
	sources := PeerCRLSources{Protocol: PeerCRLSourcesProtocolID,
		SecurityProfileDigest: profile.ProfileDigest, VaultExternalIdentityDigest: vaultDigest,
		Sources: []PeerCRLSource{
			{ID: "broker-peer", Mount: "pki", IssuerID: brokerCA.IssuerID,
				IssuerDigest: brokerCA.IssuerDigest},
			{ID: "general-peer", Mount: "pki",
				IssuerID:     "3d24b01e-81e2-42ac-a6d6-6203166d15ad",
				IssuerDigest: testDigest("v2-general-issuer")}}}
	edges := make(map[string]TrustEdge)
	for _, edge := range profile.TrustEdges {
		edges[edge.ID] = edge
	}
	for _, bound := range required {
		peer := edges[bound.EdgeID].To
		if bound.Direction == "inbound" {
			peer = edges[bound.EdgeID].From
		}
		sourceID := "general-peer"
		if slices.Contains(slice6DNSBrokerSubjects, peer) {
			sourceID = "broker-peer"
		}
		sources.Edges = append(sources.Edges, PeerCRLEdgeBinding{
			EdgeID: bound.EdgeID, LocalPrincipalDigest: bound.LocalPrincipalDigest,
			Direction: bound.Direction, PeerAnchorID: bound.PeerAnchorID, SourceID: sourceID})
	}
	slices.SortFunc(sources.Edges, func(a, b PeerCRLEdgeBinding) int {
		return strings.Compare(peerCRLRequiredV2Key(a.EdgeID, a.LocalPrincipalDigest, a.Direction),
			peerCRLRequiredV2Key(b.EdgeID, b.LocalPrincipalDigest, b.Direction))
	})
	if err := sources.validateV2Fields(profile); err != nil {
		t.Fatalf("synthetic complete v2 mapping rejected: %v", err)
	}
	return sources
}

func TestV2PeerCRLCompleteMappingAndRoleMinimumRemainHeld(t *testing.T) {
	profile := testCompleteV2Fields(t)
	sources := testPeerCRLSourcesV2(t, profile)
	edges := make(map[string]TrustEdge)
	for _, edge := range profile.TrustEdges {
		edges[edge.ID] = edge
	}
	sourceDocument, err := json.Marshal(sources)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodePeerCRLSourcesV2Fields(sourceDocument, profile, sources.Digest()); err != nil || decoded.Digest() != sources.Digest() {
		t.Fatalf("complete canonical source decode: %v", err)
	}
	if _, err := DecodePeerCRLSourcesV2(sourceDocument, profile, sources.Digest()); err == nil {
		t.Fatal("public source decoder bypassed Profile-v2 hold")
	}
	for name, bad := range map[string][]byte{
		"whitespace": append([]byte(" "), sourceDocument...),
		"duplicate": append(append([]byte{}, sourceDocument[:len(sourceDocument)-1]...),
			[]byte(`,"protocol":"sandbox-runtime.phase6-peer-crl-sources.v1"}`)...),
		"unknown": append(append([]byte{}, sourceDocument[:len(sourceDocument)-1]...),
			[]byte(`,"backend_id":"forbidden"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodePeerCRLSourcesV2Fields(bad, profile, sources.Digest()); err == nil {
				t.Fatal("noncanonical v2 source admitted")
			}
		})
	}
	if _, err := decodePeerCRLSourcesV2Fields(sourceDocument, profile,
		testDigest("not-the-externally-pinned-source")); err == nil {
		t.Fatal("source self-digest replaced external expected digest")
	}
	if sources.ValidateV2(profile) == nil {
		t.Fatal("source mapping bypassed public Profile-v2 hold")
	}
	index, err := compilePeerCRLAuthorizerV2Fields(profile, sources)
	if err != nil || index.MappingDigest() != sources.Digest() {
		t.Fatalf("v2 source index: %v", err)
	}
	if _, err := CompilePeerCRLAuthorizerV2(profile, sources, sources.Digest()); err == nil {
		t.Fatal("public source compiler bypassed Profile-v2 hold")
	}
	required, err := requiredPeerCRLV2(profile)
	if err != nil {
		t.Fatal(err)
	}
	issuerBySource := make(map[string]string)
	for _, source := range sources.Sources {
		issuerBySource[source.ID] = source.IssuerDigest
	}
	for _, binding := range sources.Edges {
		owner := required[peerCRLRequiredV2Key(binding.EdgeID,
			binding.LocalPrincipalDigest, binding.Direction)].PostgresOwner
		issuer := issuerBySource[binding.SourceID]
		got, err := index.AuthorizedSourceID(profile.ProfileDigest, sources.Digest(),
			binding.EdgeID, binding.LocalPrincipalDigest, binding.Direction,
			binding.PeerAnchorID, issuer, owner)
		if err != nil || got != binding.SourceID {
			t.Fatalf("bound source lookup = %q, %v", got, err)
		}
		wrongOwner := "provider-runtime"
		if owner == wrongOwner {
			wrongOwner = ""
		}
		if _, err := index.AuthorizedSourceID(profile.ProfileDigest, sources.Digest(),
			binding.EdgeID, binding.LocalPrincipalDigest, binding.Direction,
			binding.PeerAnchorID, issuer, wrongOwner); err == nil {
			t.Fatal("ordinary/PostgreSQL purpose crossed")
		}
	}
	for _, name := range []string{"provider-docker-control", "provider-artifact-scanner"} {
		var principal Principal
		for _, candidate := range profile.Principals {
			if candidate.Name == name {
				principal = candidate
			}
		}
		if principal.Name == "" {
			t.Fatal("missing control or scanner")
		}
		role, err := derivePeerCRLRoleDocumentV2Fields(profile, sources, principal.PrincipalDigest)
		if err != nil || role.validateV2Fields(profile, sources.Digest()) != nil {
			t.Fatalf("%s minimal source document: %v", name, err)
		}
		want := 3
		if name == "provider-artifact-scanner" {
			want = 1
		}
		if len(role.Edges) != want {
			t.Fatalf("%s received %d edges, want %d", name, len(role.Edges), want)
		}
		for _, bound := range role.Edges {
			if bound.Direction != "inbound" {
				t.Fatal("Control/Scanner gained outbound CRL source")
			}
		}
		roleDocument, err := json.Marshal(role)
		if err != nil {
			t.Fatal(err)
		}
		if decoded, err := decodePeerCRLRoleDocumentV2Fields(roleDocument, profile,
			sources.Digest(), role.Digest(), principal.PrincipalDigest); err != nil ||
			!bytes.Equal(roleDocument, mustPeerRoleJSON(t, decoded)) {
			t.Fatalf("%s canonical role decode: %v", name, err)
		}
		if _, err := decodePeerCRLRoleDocumentV2Fields(roleDocument, profile,
			sources.Digest(), testDigest("not-the-externally-pinned-role"),
			principal.PrincipalDigest); err == nil {
			t.Fatal("role self-digest replaced external expected digest")
		}
		if _, err := decodePeerCRLRoleDocumentV2Fields(roleDocument, profile,
			sources.Digest(), role.Digest(), testDigest("wrong-subject")); err == nil {
			t.Fatal("role principal swapped despite pinned digest")
		}
		if _, err := DecodePeerCRLRoleDocumentV2(roleDocument, profile,
			sources.Digest(), role.Digest(), principal.PrincipalDigest); err == nil {
			t.Fatal("public role decoder bypassed Profile-v2 hold")
		}
		if role.ValidateV2(profile, sources.Digest(), principal.PrincipalDigest) == nil {
			t.Fatal("role document bypassed public Profile-v2 hold")
		}
		if _, err := DerivePeerCRLRoleDocumentV2(profile, sources,
			sources.Digest(), principal.PrincipalDigest); err == nil {
			t.Fatal("production derivation bypassed Profile-v2 hold")
		}
	}
	for name, mutate := range map[string]func(*PeerCRLSources){
		"cross profile": func(s *PeerCRLSources) { s.SecurityProfileDigest = testDigest("v1-profile") },
		"missing edge":  func(s *PeerCRLSources) { s.Edges = s.Edges[:len(s.Edges)-1] },
		"extra edge": func(s *PeerCRLSources) {
			s.Edges = append(s.Edges, PeerCRLEdgeBinding{EdgeID: "unreviewed",
				LocalPrincipalDigest: testDigest("other"), Direction: "outbound",
				PeerAnchorID: "internal-server-ca", SourceID: "general-peer"})
		},
		"wrong anchor": func(s *PeerCRLSources) { s.Edges[0].PeerAnchorID = "other-ca" },
		"wrong direction": func(s *PeerCRLSources) {
			if s.Edges[0].Direction == "inbound" {
				s.Edges[0].Direction = "outbound"
			} else {
				s.Edges[0].Direction = "inbound"
			}
		},
		"wrong subject":     func(s *PeerCRLSources) { s.Edges[0].LocalPrincipalDigest = testDigest("other") },
		"unapproved source": func(s *PeerCRLSources) { s.Edges[0].SourceID = "unreviewed" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := sources
			bad.Edges = slices.Clone(sources.Edges)
			mutate(&bad)
			if bad.validateV2Fields(profile) == nil {
				t.Fatal("incomplete or cross-authorized v2 mapping accepted")
			}
		})
	}
	firstBroker, firstControl, firstPostgres := -1, -1, -1
	for index, bound := range sources.Edges {
		peer := edges[bound.EdgeID].To
		if bound.Direction == "inbound" {
			peer = edges[bound.EdgeID].From
		}
		if firstBroker < 0 && slices.Contains(slice6DNSBrokerSubjects, peer) {
			firstBroker = index
		}
		if firstControl < 0 && bound.EdgeID == "provider-coding-control" {
			firstControl = index
		}
		if firstPostgres < 0 && required[peerCRLRequiredV2Key(bound.EdgeID,
			bound.LocalPrincipalDigest, bound.Direction)].PostgresOwner != "" {
			firstPostgres = index
		}
	}
	if firstBroker < 0 || firstControl < 0 || firstPostgres < 0 {
		t.Fatal("synthetic mapping omitted broker, Control or PostgreSQL exercise")
	}
	for name, mutate := range map[string]func(*PeerCRLSources){
		"missing broker source": func(s *PeerCRLSources) { s.Sources = s.Sources[1:] },
		"broker peer gets general": func(s *PeerCRLSources) {
			s.Edges[firstBroker].SourceID = "general-peer"
		},
		"Control peer gets broker": func(s *PeerCRLSources) {
			s.Edges[firstControl].SourceID = "broker-peer"
		},
		"DNS broker UUID drift": func(s *PeerCRLSources) {
			s.Sources[0].IssuerID = "b26eab8a-482b-4fb1-a232-24235775b5fb"
		},
		"DNS broker DER drift": func(s *PeerCRLSources) {
			s.Sources[0].IssuerDigest = testDigest("changed-broker-DER")
		},
		"shared issuer DER": func(s *PeerCRLSources) {
			s.Sources[1].IssuerDigest = s.Sources[0].IssuerDigest
		},
		"third PostgreSQL issuer": func(s *PeerCRLSources) {
			s.Sources = append(s.Sources, PeerCRLSource{ID: "third-peer", Mount: "pki",
				IssuerID:     "b26eab8a-482b-4fb1-a232-24235775b5fb",
				IssuerDigest: testDigest("unapproved-postgres-issuer")})
			s.Edges[firstPostgres].SourceID = "third-peer"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := sources
			bad.Edges = slices.Clone(sources.Edges)
			bad.Sources = slices.Clone(sources.Sources)
			mutate(&bad)
			if bad.validateV2Fields(profile) == nil {
				t.Fatal("two-issuer peer partition drift accepted after recomputing source digest")
			}
		})
	}
}
