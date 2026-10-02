package phase6security

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// This unit-only fixture supplies synthetic digests. It is never a source
// artifact, launch config, or claim that CoreDNS accepted/rejected a leaf.
func bindSyntheticSlice6DNSClientCA(t *testing.T, profile Profile) Profile {
	t.Helper()
	profile.External = append([]ExternalService(nil), profile.External...)
	profile.TrustEdges = append([]TrustEdge(nil), profile.TrustEdges...)
	for index := range profile.External {
		service := &profile.External[index]
		if service.Name != "dns" {
			continue
		}
		service.DNSClientCA = &DNSClientCA{
			ArtifactID: "dns-broker-client-ca", BundleDigest: testDigest("dns-ca-bundle"),
			IssuerID: "11111111-1111-4111-8111-111111111111", IssuerDigest: testDigest("dns-ca-der"),
			AllowedSubjects: Slice6DNSBrokerSubjects(),
		}
		runtime := Slice6DNSRuntimePolicy(Resources{MemoryBytes: 128 << 20, CPUMillis: 1000, PIDs: 32})
		service.DNSRuntime = &runtime
		service.ImageReference = "docker.io/coredns/coredns@" + slice6DNSImageIndex
		service.ImageDigest = slice6DNSImageIndex
		service.ImagePlatform = "linux/arm64/v8"
		service.ImageIdentityKind = ImageIdentityOCIIndex
		service.ImageSelectedManifestDigest = slice6DNSARMManifest
		service.IdentityDigest = service.Digest()
		for edgeIndex := range profile.TrustEdges {
			if profile.TrustEdges[edgeIndex].To == "dns" {
				profile.TrustEdges[edgeIndex].ExternalIdentityDigest = service.IdentityDigest
			}
		}
		independent, credential := map[string]ed25519.PublicKey{}, map[string]ed25519.PublicKey{}
		for _, id := range Slice6DesiredBreakGlassIndependentKeyIDs() {
			seed := sha256.Sum256([]byte("synthetic-test-only/" + id))
			independent[id] = ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		}
		for _, id := range Slice6DesiredCredentialKeyIDs() {
			seed := sha256.Sum256([]byte("synthetic-test-only/" + id))
			credential[id] = ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		}
		authority, err := BuildSlice6BreakGlassKeyAuthority(independent, credential)
		if err != nil {
			t.Fatal("synthetic key inventory")
		}
		profile.BreakGlassKeyAuthority = authority
		profile.BreakGlassExecutableArtifact = Slice6BreakGlassExecutableArtifact{
			ID: "break-glass-operator", SourceRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SourceTreeDigest: testDigest("synthetic-break-glass-source"), Toolchain: "go1.26.8",
			ToolchainDigest: testDigest("synthetic-break-glass-toolchain"),
			BuildTarget:     "./cmd/phase6-break-glass-operator", BuildParameters: Slice6BreakGlassBuildParameters,
			Platform: "linux/arm64/v8", BinaryDigest: testDigest("synthetic-break-glass-binary"),
			BinaryBytes: 4096, ContainerPath: "/phase6-break-glass-operator",
			CarrierReference: slice6BreakGlassImage, CarrierIndexDigest: Slice6BreakGlassCarrierIndexDigest,
			CarrierSelectedManifestDigest: Slice6BreakGlassCarrierManifestDigest,
			CarrierConfigDigest:           Slice6BreakGlassCarrierConfigDigest, CarrierPlatform: "linux/arm64/v8"}
		profile.Revision = "slice6-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		profile.ProfileDigest = profile.Digest()
		return profile
	}
	t.Fatal("synthetic fixture lacks DNS external service")
	return Profile{}
}

func TestSlice6FinalGateProfileRejectsEarlierCandidates(t *testing.T) {
	draft := reviewedSlice6ImageFixture(t)
	if VerifySlice6FinalGateProfile(draft) == nil {
		t.Fatal("historical 17/12 draft admitted to the live gate")
	}
	intermediate, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatalf("intermediate candidate: %v", err)
	}
	if VerifySlice6FinalGateProfile(intermediate) == nil {
		t.Fatal("historical 28/33 candidate admitted to the live gate")
	}
	final, err := BuildSlice6FinalExternalProfileTarget(draft)
	if err != nil {
		t.Fatalf("final static candidate: %v", err)
	}
	final = bindSyntheticSlice6DNSClientCA(t, final)
	if err := VerifySlice6FinalGateProfile(final); err != nil {
		t.Fatalf("final static candidate rejected: %v", err)
	}
	final.PostgresServerAuth.HBADigest = testDigest("wrong-hba")
	final.ProfileDigest = final.Digest()
	if VerifySlice6FinalGateProfile(final) == nil {
		t.Fatal("self-consistent profile with wrong HBA bytes admitted")
	}
}

func TestSlice6DNSRuntimeExceptionRejectsSelfConsistentPrivilegeDrift(t *testing.T) {
	final, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	final = bindSyntheticSlice6DNSClientCA(t, final)
	if VerifySlice6FinalGateProfile(final) != nil {
		t.Fatal("synthetic final fixture rejected")
	}
	for name, mutate := range map[string]func(*ExternalService){
		"extra capability": func(s *ExternalService) {
			s.DNSRuntime.AddedCapabilities = []string{"CAP_NET_BIND_SERVICE", "CAP_NET_RAW"}
		},
		"missing capability":      func(s *ExternalService) { s.DNSRuntime.AddedCapabilities = nil },
		"wrong uid":               func(s *ExternalService) { s.DNSRuntime.UID = 20000 },
		"writable root":           func(s *ExternalService) { s.DNSRuntime.ReadOnlyRootFilesystem = false },
		"host publish":            func(s *ExternalService) { s.DNSRuntime.HostPublish = true },
		"wrong selected manifest": func(s *ExternalService) { s.ImageSelectedManifestDigest = testDigest("other-core-dns") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := final
			changed.External = append([]ExternalService(nil), final.External...)
			changed.TrustEdges = append([]TrustEdge(nil), final.TrustEdges...)
			for index := range changed.External {
				service := &changed.External[index]
				if service.Name != "dns" {
					continue
				}
				policy := *service.DNSRuntime
				service.DNSRuntime = &policy
				mutate(service)
				service.IdentityDigest = service.Digest()
				for edgeIndex := range changed.TrustEdges {
					if changed.TrustEdges[edgeIndex].To == "dns" {
						changed.TrustEdges[edgeIndex].ExternalIdentityDigest = service.IdentityDigest
					}
				}
			}
			changed.ProfileDigest = changed.Digest()
			if changed.Validate() != nil {
				t.Fatal("drift fixture is not self-consistent")
			}
			if VerifySlice6FinalGateProfile(changed) == nil {
				t.Fatal("self-consistent DNS privilege drift admitted")
			}
		})
	}
}
