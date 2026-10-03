package workloadtlsagent

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var benchmarkPeerCRLProvider *ControllerPeerCRLProvider

func loadSyntheticPeerCRLConstructorFixture(t testing.TB) (phase6security.Profile, phase6security.PeerCRLSources, string) {
	t.Helper()
	directory := os.Getenv("SANDBOX_RUNTIME_PEERCRL_CONSTRUCTOR_FIXTURE_DIR")
	if directory == "" {
		t.Skip("set synthetic constructor fixture directory")
	}
	profileDocument, err := os.ReadFile(filepath.Join(directory, "profile.json"))
	if err != nil || len(profileDocument) > 2<<20 {
		t.Fatal("synthetic profile unavailable")
	}
	profile, err := phase6security.Decode(profileDocument)
	clear(profileDocument)
	if err != nil {
		t.Fatal("synthetic profile invalid")
	}
	sourcesDocument, err := os.ReadFile(filepath.Join(directory, "sources.json"))
	if err != nil || len(sourcesDocument) > 128<<10 {
		t.Fatal("synthetic source mapping unavailable")
	}
	sources, err := phase6security.DecodePeerCRLSources(sourcesDocument, profile)
	clear(sourcesDocument)
	if err != nil {
		t.Fatal("synthetic source mapping invalid")
	}
	const owner = "product-migration-job"
	var subjectDigest string
	for _, principal := range profile.Principals {
		if principal.Name == owner {
			subjectDigest = principal.PrincipalDigest
		}
	}
	if subjectDigest == "" {
		t.Fatal("migration subject unavailable")
	}
	return profile, sources, subjectDigest
}

// The input is an opt-in synthetic final Profile/source fixture exported by
// phase6security tests. Timer starts after file decoding and ends at actual
// NewPostgresControllerPeerCRLProvider return; CLI startup is broader.
func BenchmarkPostgresControllerPeerCRLProviderConstructor(b *testing.B) {
	profile, sources, subjectDigest := loadSyntheticPeerCRLConstructorFixture(b)
	controller := &hotPeerController{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		provider, err := NewPostgresControllerPeerCRLProvider(profile, sources, "product-migration-job",
			subjectDigest, controller, time.Now)
		if err != nil {
			b.Fatal("actual private provider constructor failed")
		}
		benchmarkPeerCRLProvider = provider
	}
}

func TestPostgresControllerPeerCRLProviderConstructorRejectsDrift(t *testing.T) {
	profile, sources, subjectDigest := loadSyntheticPeerCRLConstructorFixture(t)
	client := &hotPeerController{}
	if provider, err := NewPostgresControllerPeerCRLProvider(profile, sources,
		"product-migration-job", subjectDigest, client, time.Now); err != nil || provider == nil {
		t.Fatal("complete private provider constructor rejected")
	}
	for _, candidate := range []struct {
		name    string
		profile phase6security.Profile
		sources phase6security.PeerCRLSources
		owner   string
		subject string
	}{
		{"wrong owner", profile, sources, "provider-runtime", subjectDigest},
		{"wrong subject", profile, sources, "product-migration-job", peerCRLTestDigest("other")},
		{"changed source", profile, func() phase6security.PeerCRLSources {
			copySources := sources
			copySources.Edges = slices.Clone(sources.Edges)
			copySources.Edges[0].PeerAnchorID = "wrong"
			return copySources
		}(), "product-migration-job", subjectDigest},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			if provider, err := NewPostgresControllerPeerCRLProvider(candidate.profile,
				candidate.sources, candidate.owner, candidate.subject, client, time.Now); err == nil || provider != nil {
				t.Fatal("drifted private provider constructor admitted")
			}
		})
	}
}
