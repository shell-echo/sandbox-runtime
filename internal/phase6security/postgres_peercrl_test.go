package phase6security

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestFinalPostgresPeerCRLSourceAndRoleArePurposeBound(t *testing.T) {
	profile, err := BuildSlice6FinalExternalProfileTarget(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	sources := completePeerCRLSources(t, profile)
	sources.Sources = append(sources.Sources, PeerCRLSource{ID: "postgres-server-peer",
		Mount: "postgres-server-pki", IssuerID: "b26eab8a-482b-4fb1-a232-24235775b5fb",
		IssuerDigest: testDigest("postgres-server-issuer")})
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		authority, err := profile.ResolveSlice6FinalPostgresAuthority(target.SubjectDeployment)
		if err != nil {
			t.Fatal(err)
		}
		var subject Principal
		for _, principal := range profile.Principals {
			if principal.Name == target.SubjectDeployment {
				subject = principal
			}
		}
		sources.Edges = append(sources.Edges, PeerCRLEdgeBinding{EdgeID: authority.PeerEdgeID,
			LocalPrincipalDigest: subject.PrincipalDigest, Direction: "outbound",
			PeerAnchorID: authority.ServerAnchor.ID, SourceID: "postgres-server-peer"})
	}
	slices.SortFunc(sources.Edges, func(left, right PeerCRLEdgeBinding) int {
		first := left.EdgeID + "/" + left.LocalPrincipalDigest + "/" + left.Direction
		second := right.EdgeID + "/" + right.LocalPrincipalDigest + "/" + right.Direction
		if first < second {
			return -1
		}
		if first > second {
			return 1
		}
		return 0
	})
	if err := sources.Validate(profile); err != nil {
		t.Fatalf("closed PostgreSQL source mapping: %v", err)
	}
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		t.Run(target.SubjectDeployment, func(t *testing.T) {
			authority, err := profile.ResolveSlice6FinalPostgresAuthority(target.SubjectDeployment)
			if err != nil {
				t.Fatal(err)
			}
			role, err := DerivePostgresPeerCRLRoleDocument(profile, sources, target.SubjectDeployment)
			if err != nil || len(role.Edges) != 1 || role.Edges[0].EdgeID != authority.PeerEdgeID ||
				role.Edges[0].PeerAnchorID != "external-server-ca" {
				t.Fatalf("wrong PostgreSQL-purpose role: %+v, %v", role, err)
			}
			encoded, err := json.Marshal(role)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodePeerCRLRoleDocument(encoded, profile, sources.Digest(), role.Digest()); err != nil {
				t.Fatalf("canonical PostgreSQL role rejected: %v", err)
			}
			wrong := role
			wrong.Edges = slices.Clone(role.Edges)
			wrong.Edges[0].PeerAnchorID = "internal-server-ca"
			if wrong.Validate(profile, sources.Digest()) == nil {
				t.Fatal("wrong PostgreSQL server anchor admitted")
			}
		})
	}
	bad := sources
	bad.Edges = slices.Clone(sources.Edges)
	for index := range bad.Edges {
		if bad.Edges[index].SourceID == "postgres-server-peer" {
			bad.Edges[index].Direction = "inbound"
			break
		}
	}
	if bad.Validate(profile) == nil {
		t.Fatal("external PostgreSQL client-authority direction admitted")
	}
}
