package phase6security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// This opt-in export is synthetic benchmark input, never a gate manifest or
// live issuer artifact. It lets the separate agent package time its actual
// constructor without duplicating the large final-Profile fixture builder.
func TestExportSyntheticPeerCRLConstructorFixture(t *testing.T) {
	directory := os.Getenv("SANDBOX_RUNTIME_PEERCRL_CONSTRUCTOR_FIXTURE_DIR")
	if directory == "" {
		t.Skip("synthetic constructor fixture export not requested")
	}
	if !filepath.IsAbs(directory) {
		t.Fatal("fixture directory must be absolute")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("fixture directory must be an existing real directory")
	}
	profile, sources := finalPeerCRLAuthorizerFixture(t)
	for _, item := range []struct {
		name  string
		value any
	}{
		{"profile.json", profile},
		{"sources.json", sources},
	} {
		encoded, err := json.Marshal(item.value)
		if err != nil {
			t.Fatal("synthetic fixture export failed")
		}
		file, err := os.OpenFile(filepath.Join(directory, item.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal("synthetic fixture already exists or cannot be written")
		}
		_, writeErr := file.Write(encoded)
		closeErr := file.Close()
		clear(encoded)
		if writeErr != nil || closeErr != nil {
			t.Fatal("synthetic fixture export incomplete")
		}
	}
}

func finalPeerCRLAuthorizerFixture(t testing.TB) (Profile, PeerCRLSources) {
	t.Helper()
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
		for _, principal := range profile.Principals {
			if principal.Name == target.SubjectDeployment {
				sources.Edges = append(sources.Edges, PeerCRLEdgeBinding{EdgeID: authority.PeerEdgeID,
					LocalPrincipalDigest: principal.PrincipalDigest, Direction: "outbound",
					PeerAnchorID: authority.ServerAnchor.ID, SourceID: "postgres-server-peer"})
			}
		}
	}
	sortPeerCRLTestEdges(sources.Edges)
	if err := sources.Validate(profile); err != nil {
		t.Fatal(err)
	}
	return profile, sources
}

func TestCompiledPeerCRLAuthorizerMatchesClosedSources(t *testing.T) {
	profile, sources := finalPeerCRLAuthorizerFixture(t)
	index, err := CompilePeerCRLAuthorizer(profile, sources)
	if err != nil {
		t.Fatal(err)
	}
	issuerBySource := map[string]string{}
	for _, source := range sources.Sources {
		issuerBySource[source.ID] = source.IssuerDigest
	}
	ownerByTuple := map[[2]string]string{}
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		authority, err := profile.ResolveSlice6FinalPostgresAuthority(target.SubjectDeployment)
		if err != nil {
			t.Fatal(err)
		}
		for _, principal := range profile.Principals {
			if principal.Name == target.SubjectDeployment {
				ownerByTuple[[2]string{authority.PeerEdgeID, principal.PrincipalDigest}] = target.SubjectDeployment
			}
		}
	}
	ordinary, postgres, dns := 0, 0, 0
	var first PeerCRLEdgeBinding
	var firstIssuer string
	for _, edge := range sources.Edges {
		issuerDigest := issuerBySource[edge.SourceID]
		owner := ownerByTuple[[2]string{edge.EdgeID, edge.LocalPrincipalDigest}]
		old, oldErr := sources.AuthorizedSourceID(profile, edge.EdgeID, edge.LocalPrincipalDigest,
			edge.Direction, edge.PeerAnchorID, issuerDigest)
		got, err := index.AuthorizedSourceID(profile.ProfileDigest, sources.Digest(), edge.EdgeID,
			edge.LocalPrincipalDigest, edge.Direction, edge.PeerAnchorID, issuerDigest, owner)
		if oldErr != nil || err != nil || got != old || got != edge.SourceID {
			t.Fatalf("compiled authority drift for %s: %q/%q, %v/%v", edge.EdgeID, old, got, oldErr, err)
		}
		if owner != "" {
			postgres++
			for _, wrong := range []string{"", "provider-runtime", "product-runtime"} {
				if wrong == owner {
					continue
				}
				if _, err := index.AuthorizedSourceID(profile.ProfileDigest, sources.Digest(), edge.EdgeID,
					edge.LocalPrincipalDigest, edge.Direction, edge.PeerAnchorID, issuerDigest, wrong); err == nil {
					t.Fatal("PostgreSQL source crossed purpose or owner")
				}
			}
		} else {
			ordinary++
			if first.EdgeID == "" {
				first, firstIssuer = edge, issuerDigest
			}
			if profile.IsSlice6DNSPeerEdge(edge.EdgeID, edge.LocalPrincipalDigest, edge.Direction) {
				dns++
			}
			if _, err := index.AuthorizedSourceID(profile.ProfileDigest, sources.Digest(), edge.EdgeID,
				edge.LocalPrincipalDigest, edge.Direction, edge.PeerAnchorID, issuerDigest,
				"product-migration-job"); err == nil {
				t.Fatal("ordinary source crossed PostgreSQL purpose")
			}
		}
		for _, changed := range []peerCRLAuthorizationKey{
			{edge.EdgeID + "-other", edge.LocalPrincipalDigest, edge.Direction, edge.PeerAnchorID, issuerDigest},
			{edge.EdgeID, testDigest("other-subject"), edge.Direction, edge.PeerAnchorID, issuerDigest},
			{edge.EdgeID, edge.LocalPrincipalDigest, "other", edge.PeerAnchorID, issuerDigest},
			{edge.EdgeID, edge.LocalPrincipalDigest, edge.Direction, "other-anchor", issuerDigest},
			{edge.EdgeID, edge.LocalPrincipalDigest, edge.Direction, edge.PeerAnchorID, testDigest("other-issuer")},
		} {
			if _, err := index.AuthorizedSourceID(profile.ProfileDigest, sources.Digest(), changed.edgeID,
				changed.localPrincipalDigest, changed.direction, changed.peerAnchorID,
				changed.issuerDigest, owner); err == nil {
				t.Fatal("changed tuple admitted")
			}
		}
	}
	if ordinary < 1 || postgres != 9 || dns < 1 {
		t.Fatalf("incomplete complete-source coverage: ordinary=%d postgres=%d dns=%d", ordinary, postgres, dns)
	}
	issuer := firstIssuer
	for _, pair := range [][2]string{{testDigest("other-profile"), sources.Digest()},
		{profile.ProfileDigest, testDigest("other-mapping")}} {
		if _, err := index.AuthorizedSourceID(pair[0], pair[1], first.EdgeID,
			first.LocalPrincipalDigest, first.Direction, first.PeerAnchorID, issuer, ""); err == nil {
			t.Fatal("new profile or mapping digest admitted into old index")
		}
	}
	if _, err := (PeerCRLAuthorizer{}).AuthorizedSourceID(profile.ProfileDigest, sources.Digest(),
		first.EdgeID, first.LocalPrincipalDigest, first.Direction, first.PeerAnchorID, issuer, ""); err == nil {
		t.Fatal("zero index admitted")
	}
	changedSources := sources
	changedSources.Edges = slices.Clone(sources.Edges)
	changedSources.Edges[0].PeerAnchorID = "wrong"
	if _, err := CompilePeerCRLAuthorizer(profile, changedSources); err == nil {
		t.Fatal("changed source document compiled")
	}
	duplicate := sources
	duplicate.Edges = append(slices.Clone(sources.Edges), sources.Edges[0])
	if _, err := CompilePeerCRLAuthorizer(profile, duplicate); err == nil {
		t.Fatal("duplicate tuple compiled")
	}
	// Caller-owned graph mutation after construction cannot alter scalar
	// entries already retained in the private index.
	sources.Edges[0].SourceID = "other"
	profile.TrustEdges[0].ID = "mutated"
	if got, err := index.AuthorizedSourceID(index.profileDigest, index.mappingDigest, first.EdgeID,
		first.LocalPrincipalDigest, first.Direction, first.PeerAnchorID, issuer, ""); err != nil || got == "" {
		t.Fatal("caller mutation changed compiled authority")
	}
	var wait sync.WaitGroup
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 16; j++ {
				if got, err := index.AuthorizedSourceID(index.profileDigest, index.mappingDigest,
					first.EdgeID, first.LocalPrincipalDigest, first.Direction, first.PeerAnchorID,
					issuer, ""); err != nil || got == "" {
					t.Error("concurrent fixed lookup failed")
					return
				}
			}
		}()
	}
	wait.Wait()
}

func TestPrivatePeerCRLAuthorizerCopiesAndRejectsInvalidSource(t *testing.T) {
	profile, sources := finalPeerCRLAuthorizerFixture(t)
	privateProfile, privateSources, index, err := CompilePrivatePeerCRLAuthorizer(profile, sources)
	if err != nil || privateProfile.ProfileDigest != profile.ProfileDigest ||
		privateSources.Digest() != sources.Digest() {
		t.Fatal("private constructor rejected complete fixture")
	}
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		var principalDigest string
		for _, principal := range profile.Principals {
			if principal.Name == target.SubjectDeployment {
				principalDigest = principal.PrincipalDigest
			}
		}
		if got, ok := index.PostgresSubjectForOwner(target.SubjectDeployment); !ok || got != principalDigest {
			t.Fatal("private index lost validated PostgreSQL owner")
		}
	}
	profile.Principals[0].Name = "mutated"
	sources.Edges[0].SourceID = "mutated"
	if privateProfile.Principals[0].Name == "mutated" || privateSources.Edges[0].SourceID == "mutated" {
		t.Fatal("constructor retained caller-owned graph")
	}
	if _, _, _, err := CompilePrivatePeerCRLAuthorizer(profile, sources); err == nil {
		t.Fatal("mutated profile/source pair admitted")
	}
	if _, _, _, err := CompilePrivatePeerCRLAuthorizer(Profile{}, PeerCRLSources{}); err == nil {
		t.Fatal("zero authority admitted")
	}
}
