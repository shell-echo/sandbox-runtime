package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestSlice6ScenarioRequirementsAreFrozenCopies(t *testing.T) {
	required := RequiredSlice6Scenarios()
	if len(required) != 16 {
		t.Fatalf("Slice 6 frozen scenario count = %d", len(required))
	}
	for index, item := range required {
		if item.Name != slice6ScenarioNames[index] ||
			!slices.Equal(item.Participants, slice6RequiredParticipants[item.Name]) ||
			!slices.Equal(item.Assertions, slice6RequiredAssertions[item.Name]) {
			t.Fatalf("Slice 6 frozen scenario %d drifted: %#v", index, item)
		}
	}
	required[0].Name = "rewritten"
	required[0].Participants[0] = "rewritten"
	required[0].Assertions[0] = "rewritten"
	again := RequiredSlice6Scenarios()
	if again[0].Name != slice6ScenarioNames[0] ||
		!slices.Equal(again[0].Participants, slice6RequiredParticipants[again[0].Name]) ||
		!slices.Equal(again[0].Assertions, slice6RequiredAssertions[again[0].Name]) {
		t.Fatal("caller mutated Slice 6 verifier requirements")
	}
}

func TestSlice6ImageIdentityKindsAndRuntimeObservation(t *testing.T) {
	profile := validProfile()
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Principal){
		"missing kind":                    func(p *Principal) { p.ImageIdentityKind = "" },
		"unknown kind":                    func(p *Principal) { p.ImageIdentityKind = "oci_config" },
		"manifest as config":              func(p *Principal) { p.ImageIdentityKind = ImageIdentityLocalConfig },
		"config as manifest":              func(p *Principal) { p.ImageReference = p.ImageConfigDigest },
		"tag fallback":                    func(p *Principal) { p.ImageReference = "registry.example.test/runtime:latest" },
		"wrong platform":                  func(p *Principal) { p.ImagePlatform = "linux/386" },
		"missing config":                  func(p *Principal) { p.ImageConfigDigest = "" },
		"wrong config":                    func(p *Principal) { p.ImageConfigDigest = p.ImageDigest },
		"index missing selected manifest": func(p *Principal) { p.ImageIdentityKind = ImageIdentityOCIIndex },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			candidate.Principals = append([]Principal(nil), profile.Principals...)
			mutate(&candidate.Principals[0])
			candidate.ProfileDigest = candidate.Digest()
			if candidate.Validate() == nil {
				t.Fatal("image identity drift accepted")
			}
		})
	}
	local := profile
	local.Principals = append([]Principal(nil), profile.Principals...)
	local.Principals[0].ImageLocation = "local"
	local.Principals[0].ImageIdentityKind = ImageIdentityLocalConfig
	local.Principals[0].ImageReference = local.Principals[0].ImageConfigDigest
	local.Principals[0].ImageDigest = local.Principals[0].ImageConfigDigest
	local.Principals[0].ImageConfigDigest = ""
	local.ProfileDigest = local.Digest()
	if err := local.Validate(); err != nil {
		t.Fatalf("local config identity rejected: %v", err)
	}
	observations := validObservations(local)
	observations.ProfileDigest = local.ProfileDigest
	observations.Containers[0].ImageReference = local.Principals[0].ImageReference
	observations.Containers[0].RuntimeStoreDescriptor = ImageDescriptor{}
	observations.Containers[0].SelectedManifestDescriptor = ImageDescriptor{}
	observations.Containers[0].OCIConfigDigest = local.Principals[0].ImageDigest
	observations.Containers[0].ImageDescriptorProofDigest = ""
	if err := ValidateObservations(local, observations); err != nil {
		t.Fatalf("matched local runtime ImageID rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ObservationSet){
		"config copied as store ID": func(o *ObservationSet) { o.Containers[1].RuntimeStoreImageID = profile.Principals[1].ImageConfigDigest },
		"wrong local image ID":      func(o *ObservationSet) { o.Containers[0].RuntimeStoreImageID = testDigest("wrong-image") },
		"wrong observed platform":   func(o *ObservationSet) { o.Containers[0].RuntimePlatform = "linux/amd64" },
		"fake local descriptor":     func(o *ObservationSet) { o.Containers[0].ImageDescriptorProofDigest = testDigest("fake") },
		"missing manifest proof":    func(o *ObservationSet) { o.Containers[1].ImageDescriptorProofDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := observations
			candidate.Containers = append([]ContainerObservation(nil), observations.Containers...)
			mutate(&candidate)
			if ValidateObservations(local, candidate) == nil {
				t.Fatal("runtime observation substitution accepted")
			}
		})
	}
}

func validSlice6EvidenceFixture(t *testing.T) Slice6Evidence {
	t.Helper()
	profile := validProfile()
	observations := validObservations(profile)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	later := time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	evidence := Slice6Evidence{ID: Slice6EvidenceID, Version: Slice6EvidenceVersion,
		RunID: strings.Repeat("c", 32), ReceiptIndexDigest: testDigest("receipt-index"),
		Scope: "same_host_local_candidate_non_release", RuntimeRevision: strings.Repeat("a", 40),
		RuntimeTreeDigest: testDigest("runtime-tree"), EvidenceRevision: strings.Repeat("b", 40),
		EvidenceTreeDigest: testDigest("evidence-tree"), ObservedAt: now, Profile: profile,
		Observations: observations,
		NonClaims:    []string{"independent_host_or_platform_enforcement", "complete_application_image_publication_and_signing", "production_readiness"}}
	for index, principal := range profile.Principals {
		evidence.Processes = append(evidence.Processes, Slice6ProcessEvidence{
			DeploymentName: principal.Name, Sequence: 1, ContainerID: observations.Containers[index].ContainerID,
			CommandDigest: testDigest("command/" + principal.Name), ConfigDigest: testDigest("config/" + principal.Name),
			InspectDigest: observations.Containers[index].ContainerInspectDigest, StartedAt: now, FinishedAt: later, Final: true})
	}
	for _, component := range observations.Components {
		evidence.Components = append(evidence.Components, Slice6ComponentEvidence{
			Name: component.Name, ParentContainerID: component.ParentContainerID,
			PID: component.PID, ProcessStartTicks: component.ProcessStartTicks,
			ProcessInspectDigest: component.ProcessInspectDigest, SocketInspectDigest: component.SocketInspectDigest,
			SessionAssociationDigest: component.SessionAssociationDigest,
		})
	}
	for _, external := range profile.External {
		item := Slice6ExternalEvidence{Name: external.Name,
			IdentityDigest: external.IdentityDigest, ImageReference: external.ImageReference,
			RuntimeStoreImageID: external.ImageDigest, SelectedManifestDigest: external.ImageDigest,
			OCIConfigDigest: external.ImageConfigDigest, RuntimePlatform: external.ImagePlatform,
			DescriptorProofDigest:   testDigest("external-descriptor/" + external.Name),
			TLSProbeDigest:          testDigest("tls/" + external.Name),
			ReachabilityProbeDigest: testDigest("reachability/" + external.Name),
			RestoreDomainSeparated:  external.Name == "action-history-postgres" || external.Name == "capacity-valkey"}
		if external.Name == profile.PostgresServerAuth.ServiceName {
			var clientCA TrustAnchor
			for _, anchor := range profile.TrustAnchors {
				if anchor.ID == profile.PostgresServerAuth.ClientCAAnchorID {
					clientCA = anchor
				}
			}
			item.PostgresServerAuth = &Slice6PostgresServerAuthEvidence{
				ProfileDigest: profile.ProfileDigest, HBAArtifactID: profile.PostgresServerAuth.HBAArtifactID,
				HBADigest: profile.PostgresServerAuth.HBADigest, ClientCAArtifactID: clientCA.ArtifactID,
				ClientCABundleDigest: clientCA.BundleDigest, ApprovedIngressCIDR: profile.PostgresServerAuth.IngressCIDR,
				ReadOnlyMountInspectDigest:   testDigest("postgres/mount"),
				ServerSettingsProbeDigest:    testDigest("postgres/settings"),
				OrderedParsedRulesDigest:     testDigest("postgres/rules"),
				StartupOrReloadResultDigest:  testDigest("postgres/reload"),
				NewConnectionResultsDigest:   testDigest("postgres/connections"),
				RestartReconcileResultDigest: testDigest("postgres/restart"),
			}
		}
		evidence.External = append(evidence.External, item)
	}
	for _, name := range slice6ScenarioNames {
		participants := append([]string(nil), slice6RequiredParticipants[name]...)
		sort.Strings(participants)
		evidence.Scenarios = append(evidence.Scenarios, Slice6ScenarioEvidence{Name: name,
			Outcome: "passed", Participants: participants,
			EvidenceDigest: testDigest("scenario/" + name)})
	}
	for _, name := range slice6CleanupNames {
		evidence.Cleanup = append(evidence.Cleanup, Slice6ResourceEvidence{Name: name,
			InspectorDigest: testDigest("cleanup/" + name)})
	}
	evidence.ManifestDigest = slice6EvidenceDigest(evidence)
	return evidence
}

func TestSlice6EvidenceRequiresCompleteClosedInventory(t *testing.T) {
	evidence := validSlice6EvidenceFixture(t)
	document, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6Evidence(document); err != nil {
		t.Fatalf("closed unit fixture rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Slice6Evidence){
		"missing run ID":          func(e *Slice6Evidence) { e.RunID = "" },
		"wrong run ID format":     func(e *Slice6Evidence) { e.RunID = strings.Repeat("C", 32) },
		"missing receipt index":   func(e *Slice6Evidence) { e.ReceiptIndexDigest = "" },
		"legacy evidence version": func(e *Slice6Evidence) { e.Version = 1 },
		"missing process":         func(e *Slice6Evidence) { e.Processes = e.Processes[1:] },
		"missing component":       func(e *Slice6Evidence) { e.Components = nil },
		"component pid drift":     func(e *Slice6Evidence) { e.Components[0].PID++ },
		"wrong process image":     func(e *Slice6Evidence) { e.Observations.Containers[0].RuntimeStoreImageID = testDigest("wrong") },
		"missing external":        func(e *Slice6Evidence) { e.External = e.External[1:] },
		"false restore isolation": func(e *Slice6Evidence) { e.External[0].RestoreDomainSeparated = false },
		"missing scenario":        func(e *Slice6Evidence) { e.Scenarios = e.Scenarios[1:] },
		"failed scenario":         func(e *Slice6Evidence) { e.Scenarios[0].Outcome = "passed_with_probe" },
		"wrong participants":      func(e *Slice6Evidence) { e.Scenarios[0].Participants = []string{"gateway-runtime", "product-runtime"} },
		"missing cleanup":         func(e *Slice6Evidence) { e.Cleanup = e.Cleanup[1:] },
		"resource remains":        func(e *Slice6Evidence) { e.Cleanup[0].Remaining = 1 },
		"production overclaim":    func(e *Slice6Evidence) { e.NonClaims[2] = "production_ready" },
		"obsolete image nonclaim": func(e *Slice6Evidence) { e.NonClaims[1] = "published_or_signed_application_images" },
		"digest mismatch":         func(e *Slice6Evidence) { e.RuntimeTreeDigest = testDigest("other") },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate Slice6Evidence
			if err := json.Unmarshal(document, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			candidateDocument, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifySlice6Evidence(candidateDocument); !errors.Is(err, ErrInvalidSlice6Evidence) {
				t.Fatalf("invalid gate evidence accepted: %v", err)
			}
		})
	}
	postgresIndex := -1
	otherIndex := -1
	for index, item := range evidence.External {
		if item.Name == evidence.Profile.PostgresServerAuth.ServiceName {
			postgresIndex = index
		} else if otherIndex < 0 {
			otherIndex = index
		}
	}
	if postgresIndex < 0 || otherIndex < 0 {
		t.Fatal("PostgreSQL evidence fixture inventory is incomplete")
	}
	for name, mutate := range map[string]func(*Slice6Evidence){
		"missing PostgreSQL proof": func(e *Slice6Evidence) { e.External[postgresIndex].PostgresServerAuth = nil },
		"wrong HBA bytes": func(e *Slice6Evidence) {
			e.External[postgresIndex].PostgresServerAuth.HBADigest = testDigest("wrong-hba")
		},
		"wrong client CA": func(e *Slice6Evidence) {
			e.External[postgresIndex].PostgresServerAuth.ClientCABundleDigest = testDigest("wrong-ca")
		},
		"wrong ingress": func(e *Slice6Evidence) {
			e.External[postgresIndex].PostgresServerAuth.ApprovedIngressCIDR = "10.0.0.1/32"
		},
		"missing reload result": func(e *Slice6Evidence) {
			e.External[postgresIndex].PostgresServerAuth.StartupOrReloadResultDigest = ""
		},
		"missing new connections": func(e *Slice6Evidence) {
			e.External[postgresIndex].PostgresServerAuth.NewConnectionResultsDigest = ""
		},
		"proof on unrelated external": func(e *Slice6Evidence) {
			copy := *e.External[postgresIndex].PostgresServerAuth
			e.External[otherIndex].PostgresServerAuth = &copy
		},
	} {
		t.Run(name, func(t *testing.T) {
			var candidate Slice6Evidence
			if err := json.Unmarshal(document, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			candidate.ManifestDigest = slice6EvidenceDigest(candidate)
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifySlice6Evidence(encoded); !errors.Is(err, ErrInvalidSlice6Evidence) {
				t.Fatalf("invalid PostgreSQL gate observation accepted: %v", err)
			}
		})
	}
	for _, malformed := range [][]byte{
		bytes.Replace(document, []byte(`"id":`), []byte(`"id":"duplicate","id":`), 1),
		append(append([]byte(nil), document...), []byte(`{}`)...),
		bytes.Replace(document, []byte(`"version":2`), []byte(`"version":2,"unknown":true`), 1),
	} {
		if _, err := VerifySlice6Evidence(malformed); !errors.Is(err, ErrInvalidSlice6Evidence) {
			t.Fatalf("invalid JSON accepted: %v", err)
		}
	}
	privateFile := filepath.Join(t.TempDir(), "slice6.json")
	if err := os.WriteFile(privateFile, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceFile(privateFile); err != nil {
		t.Fatalf("private evidence file rejected: %v", err)
	}
	if err := os.Chmod(privateFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6EvidenceFile(privateFile); !errors.Is(err, ErrInvalidSlice6Evidence) {
		t.Fatal("public evidence file accepted")
	}
}

func TestSlice6EvidenceLocalCandidateRequiresRetainedBuildAndArchiveBinding(t *testing.T) {
	evidence := validSlice6EvidenceFixture(t)
	principal := &evidence.Profile.Principals[0]
	principal.ImageLocation = "local"
	principal.ImageIdentityKind = ImageIdentityLocalConfig
	principal.ImageReference = principal.ImageConfigDigest
	principal.ImageDigest = principal.ImageConfigDigest
	principal.ImageConfigDigest = ""
	evidence.Profile.ProfileDigest = evidence.Profile.Digest()
	evidence.Observations.ProfileDigest = evidence.Profile.ProfileDigest
	for index := range evidence.External {
		if evidence.External[index].PostgresServerAuth != nil {
			evidence.External[index].PostgresServerAuth.ProfileDigest = evidence.Profile.ProfileDigest
		}
	}
	evidence.Observations.Containers[0].ImageReference = principal.ImageReference
	evidence.Observations.Containers[0].RuntimeStoreImageID = principal.ImageDigest
	evidence.Observations.Containers[0].RuntimeStoreDescriptor = ImageDescriptor{}
	evidence.Observations.Containers[0].SelectedManifestDescriptor = ImageDescriptor{}
	evidence.Observations.Containers[0].OCIConfigDigest = principal.ImageDigest
	evidence.Observations.Containers[0].ImageDescriptorProofDigest = ""
	evidence.Candidates = []Slice6CandidateImage{{RuntimeStoreImageID: principal.ImageDigest, OCIConfigDigest: principal.ImageDigest, Platform: principal.ImagePlatform,
		SourceRevision: evidence.RuntimeRevision, SourceTreeDigest: evidence.RuntimeTreeDigest,
		BuildContextDigest: testDigest("context"), DockerfileDigest: testDigest("dockerfile"),
		ToolchainDigest: testDigest("toolchain"), BaseImageDigest: testDigest("base"),
		DependencyLockDigest: testDigest("lock"), BuildParametersDigest: testDigest("parameters"),
		ArchiveDigest: testDigest("archive"), RootFSChainDigest: testDigest("rootfs")}}
	evidence.ManifestDigest = slice6EvidenceDigest(evidence)
	document, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6Evidence(document); err != nil {
		t.Fatalf("complete local candidate fixture rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Slice6Evidence){
		"missing archive":   func(e *Slice6Evidence) { e.Candidates[0].ArchiveDigest = "" },
		"wrong image ID":    func(e *Slice6Evidence) { e.Candidates[0].RuntimeStoreImageID = testDigest("other-image") },
		"wrong source":      func(e *Slice6Evidence) { e.Candidates[0].SourceRevision = strings.Repeat("c", 40) },
		"candidate omitted": func(e *Slice6Evidence) { e.Candidates = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var candidate Slice6Evidence
			if err := json.Unmarshal(document, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(&candidate)
			candidate.ManifestDigest = slice6EvidenceDigest(candidate)
			encoded, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifySlice6Evidence(encoded); !errors.Is(err, ErrInvalidSlice6Evidence) {
				t.Fatalf("incomplete local candidate accepted: %v", err)
			}
		})
	}
}
