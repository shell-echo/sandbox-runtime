package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"reflect"
	"testing"
)

func TestPeerCRLV2ValidatedRequiredGraphRejectsInvalidInput(t *testing.T) {
	profile := testCompleteV2Fields(t)
	sources := testPeerCRLSourcesV2(t, profile)
	cases := []struct {
		name   string
		mutate func(*ProfileV2, *PeerCRLSources)
	}{
		{"profile_fields", func(p *ProfileV2, s *PeerCRLSources) {
			for i := range p.Principals {
				if p.Principals[i].TLS != nil {
					p.Principals[i].TLS.TTLSeconds = 0
					break
				}
			}
			p.ProfileDigest = p.Digest()
			s.SecurityProfileDigest = p.ProfileDigest
		}},
		{"protocol", func(_ *ProfileV2, s *PeerCRLSources) { s.Protocol = "unapproved" }},
		{"profile_binding", func(_ *ProfileV2, s *PeerCRLSources) { s.SecurityProfileDigest = testDigest("other") }},
		{"vault_binding", func(_ *ProfileV2, s *PeerCRLSources) { s.VaultExternalIdentityDigest = testDigest("other") }},
		{"missing_source", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources = s.Sources[:1] }},
		{"third_source", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources = append(s.Sources, s.Sources[1]) }},
		{"source_order", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources[0], s.Sources[1] = s.Sources[1], s.Sources[0] }},
		{"mount", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources[0].Mount = "other" }},
		{"issuer_id", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources[1].IssuerID = "unapproved" }},
		{"issuer_digest", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources[1].IssuerDigest = "" }},
		{"duplicate_location", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources[1].IssuerID = s.Sources[0].IssuerID }},
		{"shared_issuer", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources[1].IssuerDigest = s.Sources[0].IssuerDigest }},
		{"broker_substitution", func(_ *ProfileV2, s *PeerCRLSources) { s.Sources[0].IssuerDigest = testDigest("other") }},
		{"missing_edge", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges = s.Edges[:len(s.Edges)-1] }},
		{"extra_edge", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges = append(s.Edges, s.Edges[0]) }},
		{"duplicate_edge", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges[1] = s.Edges[0] }},
		{"edge_order", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges[0], s.Edges[1] = s.Edges[1], s.Edges[0] }},
		{"edge_id", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges[0].EdgeID = "unapproved" }},
		{"local", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges[0].LocalPrincipalDigest = testDigest("other") }},
		{"direction", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges[0].Direction = "sideways" }},
		{"anchor", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges[0].PeerAnchorID = "other-ca" }},
		{"source_selection", func(_ *ProfileV2, s *PeerCRLSources) { s.Edges[0].SourceID = "unapproved" }},
		{"postgres_broker", func(_ *ProfileV2, s *PeerCRLSources) {
			for i := range s.Edges {
				if s.Edges[i].EdgeID == "product-postgres" {
					s.Edges[i].SourceID = "broker-peer"
					break
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, s, err := copyPeerCRLSnapshotV2(profile, sources)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&p, &s)
			graph, err := s.validateV2FieldsAndRequired(p)
			if err != ErrInvalidProfile || graph != nil {
				t.Fatalf("invalid source returned authority: graph=%v, error=%v", graph != nil, err)
			}
			role, err := derivePostgresPeerCRLRoleDocumentV2Fields(p, s, "product-runtime")
			if err != ErrInvalidProfile || !reflect.DeepEqual(role, PeerCRLRoleDocument{}) {
				t.Fatalf("invalid source returned a role: %+v, %v", role, err)
			}
		})
	}
}

func TestPeerCRLV2ValidatedRequiredGraphIsCallLocal(t *testing.T) {
	profile := testCompleteV2Fields(t)
	sources := testPeerCRLSourcesV2(t, profile)
	inputJSON := func() []byte {
		t.Helper()
		data, err := json.Marshal([]any{profile, sources})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := inputJSON()
	graph, err := sources.validateV2FieldsAndRequired(profile)
	if err != nil || len(graph) == 0 {
		t.Fatalf("complete source graph: %v", err)
	}
	expected := maps.Clone(graph)
	for key := range graph {
		delete(graph, key)
		break
	}
	fresh, err := sources.validateV2FieldsAndRequired(profile)
	if err != nil || !reflect.DeepEqual(fresh, expected) {
		t.Fatal("returned graph aliases another invocation")
	}
	if !bytes.Equal(before, inputJSON()) {
		t.Fatal("source validation changed caller inputs")
	}

	// A successful earlier call grants no authority after caller mutation.
	originalSourceID := sources.Edges[0].SourceID
	sources.Edges[0].SourceID = "unapproved"
	if graph, err := sources.validateV2FieldsAndRequired(profile); err != ErrInvalidProfile || graph != nil {
		t.Fatal("earlier graph reused after source mutation")
	}
	if role, err := derivePostgresPeerCRLRoleDocumentV2Fields(profile, sources, "product-runtime"); err != ErrInvalidProfile || !reflect.DeepEqual(role, PeerCRLRoleDocument{}) {
		t.Fatal("earlier success reused after source mutation")
	}
	sources.Edges[0].SourceID = originalSourceID
	for i := range profile.Principals {
		if profile.Principals[i].TLS != nil {
			profile.Principals[i].TLS.TTLSeconds = 0
			break
		}
	}
	profile.ProfileDigest = profile.Digest()
	sources.SecurityProfileDigest = profile.ProfileDigest
	if graph, err := sources.validateV2FieldsAndRequired(profile); err != ErrInvalidProfile || graph != nil {
		t.Fatal("earlier graph reused after profile mutation")
	}
	if role, err := derivePostgresPeerCRLRoleDocumentV2Fields(profile, sources, "product-runtime"); err != ErrInvalidProfile || !reflect.DeepEqual(role, PeerCRLRoleDocument{}) {
		t.Fatal("earlier success reused after profile mutation")
	}
}

func TestPostgresPeerCRLV2DerivedCanonicalOwnerTuples(t *testing.T) {
	profile := testCompleteV2Fields(t)
	sources := testPeerCRLSourcesV2(t, profile)
	before, err := json.Marshal([]any{profile, sources})
	if err != nil {
		t.Fatal(err)
	}
	// Fixed reviewed tuples are independent of requiredPeerCRLV2 and its callers.
	expected := map[string]string{
		"gateway-runtime":                "gateway-postgres",
		"product-migration-job":          "product-migration-postgres",
		"product-runtime":                "product-postgres",
		"provider-browser-migration-job": "provider-browser-migration-postgres",
		"provider-browser-runtime":       "provider-browser-postgres",
		"provider-desktop-migration-job": "provider-desktop-migration-postgres",
		"provider-desktop-runtime":       "provider-desktop-postgres",
		"provider-migration-job":         "provider-migration-postgres",
		"provider-runtime":               "provider-coding-postgres",
	}
	for owner, edgeID := range expected {
		t.Run(owner, func(t *testing.T) {
			local := ""
			for _, principal := range profile.Principals {
				if principal.Name == owner {
					local = principal.PrincipalDigest
				}
			}
			if local == "" {
				t.Fatal("missing expected owner")
			}
			want := PeerCRLRoleDocument{Protocol: PeerCRLRoleProtocolID,
				SecurityProfileDigest: profile.ProfileDigest, SourceMappingDigest: sources.Digest(),
				LocalPrincipalDigest: local, Edges: []PeerCRLRoleEdgeBinding{{
					EdgeID: edgeID, Direction: "outbound", PeerAnchorID: "external-server-ca",
					IssuerDigest: testDigest("v2-general-issuer"),
				}}}
			wantJSON := mustPeerRoleJSON(t, want)
			hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-peer-crl-role/v1\x00"), wantJSON...))
			wantDigest := "sha256:" + hex.EncodeToString(hash[:])
			got, err := derivePostgresPeerCRLRoleDocumentV2Fields(profile, sources, owner)
			if err != nil || !bytes.Equal(mustPeerRoleJSON(t, got), wantJSON) || got.Digest() != wantDigest {
				t.Fatalf("canonical owner role changed: %+v, %v", got, err)
			}
		})
	}
	for name, owner := range map[string]string{"empty_owner": "", "unknown_owner": "unapproved", "ordinary_owner": "provider-docker-control"} {
		t.Run(name, func(t *testing.T) {
			role, err := derivePostgresPeerCRLRoleDocumentV2Fields(profile, sources, owner)
			if err != ErrInvalidProfile || !reflect.DeepEqual(role, PeerCRLRoleDocument{}) {
				t.Fatalf("unbound owner returned a role: %+v, %v", role, err)
			}
		})
	}
	after, err := json.Marshal([]any{profile, sources})
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("derive changed caller inputs")
	}
}
