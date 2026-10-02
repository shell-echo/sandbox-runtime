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

func TestFinalPostgresPeerCRLFastPathPreservesClosedAuthority(t *testing.T) {
	profile, err := BuildSlice6FinalExternalProfileTarget(validProfile())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("product-runtime")
	if err != nil {
		t.Fatal(err)
	}
	var product Principal
	for _, principal := range profile.Principals {
		if principal.Name == "product-runtime" {
			product = principal
		}
	}
	sources := completePeerCRLSources(t, profile)
	sources.Sources = append(sources.Sources, PeerCRLSource{ID: "postgres-server-peer",
		Mount: "postgres-server-pki", IssuerID: "b26eab8a-482b-4fb1-a232-24235775b5fb",
		IssuerDigest: testDigest("postgres-server-issuer")})
	sources.Edges = append(sources.Edges, PeerCRLEdgeBinding{EdgeID: authority.PeerEdgeID,
		LocalPrincipalDigest: product.PrincipalDigest, Direction: "outbound",
		PeerAnchorID: authority.ServerAnchor.ID, SourceID: "postgres-server-peer"})
	sortPeerCRLTestEdges(sources.Edges)
	if !profile.IsSlice6FinalPostgresPeerEdge(authority.PeerEdgeID, product.PrincipalDigest) ||
		sources.Validate(profile) != nil {
		t.Fatal("valid logical PostgreSQL peer no longer admitted")
	}

	for _, test := range []struct {
		name   string
		mutate func(*Profile)
	}{
		{"shared HBA drift", func(p *Profile) {
			p.PostgresServerAuth.HBADigest = testDigest("unapproved-hba")
		}},
		{"network drift", func(p *Profile) {
			for i := range p.Networks {
				if p.Networks[i].Name == authority.Network {
					p.Networks[i].IPv4Subnet = "172.31.250.0/24"
				}
			}
		}},
		{"issuer anchor purpose drift", func(p *Profile) {
			for i := range p.TrustAnchors {
				if p.TrustAnchors[i].ID == "external-server-ca" {
					p.TrustAnchors[i].Purpose = "client_verification"
				}
			}
		}},
		{"cross-owner edge", func(p *Profile) {
			for i := range p.TrustEdges {
				if p.TrustEdges[i].ID == authority.PeerEdgeID {
					p.TrustEdges[i].From = "gateway-runtime"
				}
			}
		}},
		{"wrong PostgreSQL signer purpose", func(p *Profile) {
			for i := range p.PostgresClientAgents {
				if p.PostgresClientAgents[i].SubjectDeployment == "product-runtime" {
					p.PostgresClientAgents[i].CommonName = "wrong_role"
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			var changed Profile
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			test.mutate(&changed)
			changed.ProfileDigest = changed.Digest()
			if test.name == "network drift" && changed.Validate() != nil {
				t.Fatal("network regression no longer isolates the stronger final-profile verifier")
			}
			bound := sources
			bound.SecurityProfileDigest = changed.ProfileDigest
			if changed.IsSlice6FinalPostgresPeerEdge(authority.PeerEdgeID, product.PrincipalDigest) ||
				bound.Validate(changed) == nil {
				t.Fatal("recomputed profile digest admitted unreviewed PostgreSQL authority")
			}
		})
	}

	broker, err := profile.ResolveSlice6FinalPostgresAuthority("provider-browser-runtime")
	if err != nil {
		t.Fatal(err)
	}
	var physicalDigest string
	for _, edge := range profile.TrustEdges {
		if edge.ID == broker.EdgeID {
			physicalDigest = edge.FromPrincipalDigest
		}
	}
	physical := sources
	physical.Edges = slices.Clone(sources.Edges)
	physical.Edges = append(physical.Edges, PeerCRLEdgeBinding{EdgeID: broker.EdgeID,
		LocalPrincipalDigest: physicalDigest, Direction: "outbound",
		PeerAnchorID: broker.ServerAnchor.ID, SourceID: "postgres-server-peer"})
	sortPeerCRLTestEdges(physical.Edges)
	if profile.IsSlice6FinalPostgresPeerEdge(broker.EdgeID, physicalDigest) ||
		physical.Validate(profile) == nil {
		t.Fatal("broker physical dial edge admitted as logical PostgreSQL peer")
	}
}

func sortPeerCRLTestEdges(edges []PeerCRLEdgeBinding) {
	slices.SortFunc(edges, func(left, right PeerCRLEdgeBinding) int {
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
}
