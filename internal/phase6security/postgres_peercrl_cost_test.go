package phase6security

import (
	"slices"
	"testing"
)

// A bounded synthetic final-Profile cost sample for the Product migration
// owner. It uses the complete reviewed source inventory, not the one-edge
// role derivative. No issuer, CRL, Unix socket or historical run secret is
// involved. These calls are only the authorization portion of first pull.
func BenchmarkProductMigrationPeerCRLAuthorization(b *testing.B) {
	profile, err := BuildSlice6FinalExternalProfileTarget(validProfile())
	if err != nil {
		b.Fatal(err)
	}
	const owner = "product-migration-job"
	authority, err := profile.ResolveSlice6FinalPostgresAuthority(owner)
	if err != nil {
		b.Fatal(err)
	}
	var subjectDigest string
	for _, principal := range profile.Principals {
		if principal.Name == owner {
			subjectDigest = principal.PrincipalDigest
		}
	}
	if subjectDigest == "" {
		b.Fatal("migration subject unavailable")
	}
	sources := completePeerCRLSources(b, profile)
	const sourceID = "postgres-server-peer"
	issuerDigest := testDigest("postgres-server-issuer")
	sources.Sources = append(sources.Sources, PeerCRLSource{ID: sourceID,
		Mount: "postgres-server-pki", IssuerID: "b26eab8a-482b-4fb1-a232-24235775b5fb",
		IssuerDigest: issuerDigest})
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		bound, err := profile.ResolveSlice6FinalPostgresAuthority(target.SubjectDeployment)
		if err != nil {
			b.Fatal(err)
		}
		for _, principal := range profile.Principals {
			if principal.Name == target.SubjectDeployment {
				sources.Edges = append(sources.Edges, PeerCRLEdgeBinding{EdgeID: bound.PeerEdgeID,
					LocalPrincipalDigest: principal.PrincipalDigest, Direction: "outbound",
					PeerAnchorID: bound.ServerAnchor.ID, SourceID: sourceID})
			}
		}
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
	if sources.Validate(profile) != nil {
		b.Fatal("synthetic complete final source inventory invalid")
	}
	role, err := DerivePostgresPeerCRLRoleDocument(profile, sources, owner)
	if err != nil || len(role.Edges) != 1 {
		b.Fatal("migration role derivative invalid")
	}
	compiled, err := CompilePeerCRLAuthorizer(profile, sources)
	if err != nil {
		b.Fatal(err)
	}
	compiledLookup := func() {
		id, err := compiled.AuthorizedSourceID(profile.ProfileDigest, compiled.MappingDigest(),
			authority.PeerEdgeID, subjectDigest, "outbound", authority.ServerAnchor.ID,
			issuerDigest, owner)
		if err != nil || id != sourceID {
			b.Fatal("compiled migration source authorization failed")
		}
	}
	lookup := func() {
		id, err := sources.AuthorizedSourceID(profile, authority.PeerEdgeID, subjectDigest,
			"outbound", authority.ServerAnchor.ID, issuerDigest)
		if err != nil || id != sourceID {
			b.Fatal("migration source authorization failed")
		}
	}
	for _, sample := range []struct {
		name string
		call func()
	}{
		{"agent_owner_edge_check", func() {
			if !profile.IsSlice6FinalPostgresPeerEdge(authority.PeerEdgeID, subjectDigest) {
				b.Fatal("migration owner edge invalid")
			}
		}},
		{"agent_source_authorization", lookup},
		{"controller_source_authorization", lookup},
		{"compiled_agent_source_authorization", compiledLookup},
		{"compiled_controller_source_authorization", compiledLookup},
		{"compiled_two_process_authorization_sequence", func() {
			compiledLookup() // agent
			compiledLookup() // controller
		}},
		{"compile_index_once", func() {
			if _, err := CompilePeerCRLAuthorizer(profile, sources); err != nil {
				b.Fatal("constructor-time compilation failed")
			}
		}},
		{"two_process_authorization_sequence", func() {
			if !profile.IsSlice6FinalPostgresPeerEdge(authority.PeerEdgeID, subjectDigest) {
				b.Fatal("migration owner edge invalid")
			}
			lookup() // agent
			lookup() // controller
		}},
		{"role_binding", func() {
			if _, err := role.Binding(authority.PeerEdgeID, "outbound"); err != nil {
				b.Fatal("migration role binding failed")
			}
		}},
	} {
		b.Run(sample.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sample.call()
			}
		})
	}
}
