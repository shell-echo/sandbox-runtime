package workloadtlsagent

import (
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestPostgresPeerCRLConstructorsRejectEmptyOwnerBeforeDependencies(t *testing.T) {
	for _, typed := range []bool{false, true} {
		name := "existing-profile"
		if typed {
			name = "current-profile"
		}
		t.Run(name, func(t *testing.T) {
			client := &hotPeerController{}
			clockCalls := 0
			now := func() time.Time {
				clockCalls++
				return time.Now()
			}
			var provider *ControllerPeerCRLProvider
			var err error
			if typed {
				provider, err = NewPostgresControllerPeerCRLProviderV2(phase6security.ProfileV2{},
					phase6security.PeerCRLSources{}, "", "", "ordinary-subject", client, now)
			} else {
				provider, err = NewPostgresControllerPeerCRLProvider(phase6security.Profile{},
					phase6security.PeerCRLSources{}, "", "ordinary-subject", client, now)
			}
			if provider != nil || !errors.Is(err, ErrUnavailable) || clockCalls != 0 || client.called != 0 {
				t.Fatalf("empty owner reached dependencies: provider=%v err=%v clock=%d controller=%d",
					provider, err, clockCalls, client.called)
			}
		})
	}
}

func TestPeerCRLConstructorsRejectInvalidDependencies(t *testing.T) {
	entries := map[string]func(PeerCRLControllerClient, func() time.Time) (*ControllerPeerCRLProvider, error){
		"ordinary": func(c PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
			return NewControllerPeerCRLProvider(phase6security.Profile{}, phase6security.PeerCRLSources{}, "subject", c, now)
		},
		"postgres": func(c PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
			return NewPostgresControllerPeerCRLProvider(phase6security.Profile{}, phase6security.PeerCRLSources{}, "product-migration-job", "subject", c, now)
		},
		"current-ordinary": func(c PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
			return NewControllerPeerCRLProviderV2(phase6security.ProfileV2{}, phase6security.PeerCRLSources{}, "", "subject", c, now)
		},
		"current-postgres": func(c PeerCRLControllerClient, now func() time.Time) (*ControllerPeerCRLProvider, error) {
			return NewPostgresControllerPeerCRLProviderV2(phase6security.ProfileV2{}, phase6security.PeerCRLSources{}, "", "product-migration-job", "subject", c, now)
		},
	}
	for name, entry := range entries {
		t.Run(name, func(t *testing.T) {
			for _, dependency := range []string{"nil-client", "nil-clock", "zero-clock", "invalid-profile"} {
				t.Run(dependency, func(t *testing.T) {
					client := &hotPeerController{}
					var argument PeerCRLControllerClient = client
					clockCalls, expectedCalls := 0, 1
					now := func() time.Time {
						clockCalls++
						if dependency == "zero-clock" {
							return time.Time{}
						}
						return time.Now()
					}
					if dependency == "nil-client" {
						argument, expectedCalls = nil, 0
					}
					if dependency == "nil-clock" {
						now, expectedCalls = nil, 0
					}
					provider, err := entry(argument, now)
					if provider != nil || !errors.Is(err, ErrUnavailable) || clockCalls != expectedCalls || client.called != 0 {
						t.Fatalf("invalid dependency admitted: provider=%v err=%v clocks=%d controller=%d", provider, err, clockCalls, client.called)
					}
				})
			}
		})
	}
}

func syntheticOrdinaryPeerSubject(t testing.TB, profile phase6security.Profile) (string, int) {
	t.Helper()
	index := -1
	for i, binding := range profile.TLSAgentBindings {
		if binding.SubjectDeployment == "guest-runtime" {
			if index != -1 || binding.SubjectPrincipalDigest == "" {
				t.Fatal("fixture has an ambiguous ordinary guest subject")
			}
			index = i
		}
	}
	if index == -1 {
		t.Fatal("fixture has no ordinary guest subject")
	}
	return profile.TLSAgentBindings[index].SubjectPrincipalDigest, index
}

func TestControllerPeerCRLProviderSnapshotConstruction(t *testing.T) {
	profile, sources, postgresSubject := loadSyntheticPeerCRLConstructorFixture(t)
	privateProfile, _, identity, err := phase6security.CompilePrivatePeerCRLAuthorizer(profile, sources)
	if err != nil {
		t.Fatal(err)
	}
	ordinarySubject, _ := syntheticOrdinaryPeerSubject(t, privateProfile)
	otherSubject, present := identity.PostgresSubjectForOwner("provider-runtime")
	if !present || otherSubject == postgresSubject {
		t.Fatal("fixture needs two distinct PostgreSQL owners")
	}
	for _, test := range []struct {
		name, owner, subject string
		bindings             []phase6security.TLSAgentBinding
		accept               bool
	}{
		{"ordinary", "", ordinarySubject, privateProfile.TLSAgentBindings, true},
		{"unknown-ordinary", "", peerCRLTestDigest("unknown"), privateProfile.TLSAgentBindings, false},
		{"empty-ordinary", "", "", privateProfile.TLSAgentBindings, false},
		{"absent-ordinary-bindings", "", ordinarySubject, nil, false},
		{"postgres", "product-migration-job", postgresSubject, nil, true},
		{"unknown-owner", "unknown-owner", postgresSubject, privateProfile.TLSAgentBindings, false},
		{"other-owner", "provider-runtime", postgresSubject, privateProfile.TLSAgentBindings, false},
		{"wrong-postgres-subject", "product-migration-job", otherSubject, privateProfile.TLSAgentBindings, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &hotPeerController{}
			clockCalls := 0
			now := func() time.Time { clockCalls++; return time.Now() }
			provider, err := newControllerPeerCRLProviderFromSnapshot(privateProfile.ProfileDigest,
				test.bindings, identity, test.subject, test.owner, client, now)
			if test.accept {
				if err != nil || provider == nil || provider.profileDigest != privateProfile.ProfileDigest ||
					provider.subjectDigest != test.subject || provider.postgresOwner != test.owner || provider.client != client || provider.now == nil {
					t.Fatalf("validated snapshot rejected or changed: %v", err)
				}
			} else if provider != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("unbound purpose accepted: provider=%v err=%v", provider, err)
			}
			if client.called != 0 || clockCalls != 0 {
				t.Fatal("post-admission selection repeated dependency work")
			}
		})
	}
}

func TestControllerPeerCRLProviderConstructorsFreezeCallerInputs(t *testing.T) {
	profile, sources, postgresSubject := loadSyntheticPeerCRLConstructorFixture(t)
	privateProfile, privateSources, identity, err := phase6security.CompilePrivatePeerCRLAuthorizer(profile, sources)
	if err != nil {
		t.Fatal(err)
	}
	client := &hotPeerController{}
	ordinarySubject, ordinaryIndex := syntheticOrdinaryPeerSubject(t, privateProfile)
	ordinary, err := NewControllerPeerCRLProvider(profile, sources, ordinarySubject, client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	postgres, err := NewPostgresControllerPeerCRLProvider(profile, sources, "product-migration-job", postgresSubject, client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	profile.ProfileDigest = peerCRLTestDigest("mutated-profile")
	profile.TLSAgentBindings[ordinaryIndex].SubjectPrincipalDigest = peerCRLTestDigest("mutated-binding")
	for i := range profile.Principals {
		if profile.Principals[i].Name == "guest-runtime" {
			profile.Principals[i].PrincipalDigest = peerCRLTestDigest("mutated-principal")
			profile.Principals[i].TLS.URI = "spiffe://mutated.test/guest"
		}
	}
	sources.SecurityProfileDigest = peerCRLTestDigest("mutated-source-profile")
	for i := range sources.Sources {
		sources.Sources[i].IssuerDigest = peerCRLTestDigest("mutated-issuer")
	}
	for i := range sources.Edges {
		if sources.Edges[i].LocalPrincipalDigest == ordinarySubject || sources.Edges[i].LocalPrincipalDigest == postgresSubject {
			sources.Edges[i].PeerAnchorID = "mutated-anchor"
		}
	}
	for _, provider := range []*ControllerPeerCRLProvider{ordinary, postgres} {
		found := false
		for _, binding := range privateSources.Edges {
			if binding.LocalPrincipalDigest != provider.subjectDigest {
				continue
			}
			for _, source := range privateSources.Sources {
				if source.ID != binding.SourceID {
					continue
				}
				expected, err := identity.AuthorizedSourceID(privateProfile.ProfileDigest, privateSources.Digest(),
					binding.EdgeID, binding.LocalPrincipalDigest, binding.Direction, binding.PeerAnchorID, source.IssuerDigest, provider.postgresOwner)
				if err != nil {
					continue
				}
				actual, err := provider.identity.AuthorizedSourceID(provider.profileDigest, privateSources.Digest(),
					binding.EdgeID, provider.subjectDigest, binding.Direction, binding.PeerAnchorID, source.IssuerDigest, provider.postgresOwner)
				if err != nil || actual != expected || provider.profileDigest != privateProfile.ProfileDigest {
					t.Fatalf("caller mutation changed private authorization: source=%q err=%v", actual, err)
				}
				found = true
			}
		}
		if !found || client.called != 0 {
			t.Fatal("private ordinary/PostgreSQL binding unavailable or reached controller")
		}
	}
}
