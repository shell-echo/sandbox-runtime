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
	draft := reviewedSlice6ImageFixture(t)
	for index := range draft.Principals {
		principal := &draft.Principals[index]
		target, err := Slice6DesiredImageTarget(principal.Name)
		if err != nil {
			t.Fatal(err)
		}
		if target == Slice6BrowserPublishedImage {
			continue
		}
		principal.ImageDigest = testDigest("fixture-image/" + target)
		principal.ImageReference = principal.ImageDigest
		principal.ImageConfigDigest = testDigest("fixture-config/" + target)
		refreshSlice6ImageSlotDigest(&draft, *principal)
	}
	draft.ProfileDigest = draft.Digest()
	profile, err := BuildSlice6FinalExternalProfileTarget(draft)
	if err == nil {
		profile = bindSyntheticSlice6DNSClientCA(t, profile)
	}
	if err != nil || VerifySlice6FinalGateProfile(profile) != nil {
		t.Fatalf("final-only synthetic evidence profile: %v", err)
	}
	observations := validFinalSlice6EvidenceObservations(t, profile)
	baseTime := time.Now().UTC()
	now := baseTime.Add(-10 * time.Second).Format(time.RFC3339Nano)
	later := baseTime.Add(-9 * time.Second).Format(time.RFC3339Nano)
	evidence := Slice6Evidence{ID: Slice6EvidenceID, Version: Slice6EvidenceVersion,
		RunID: strings.Repeat("c", 32), ReceiptIndexDigest: testDigest("receipt-index"),
		Scope: "same_host_local_candidate_non_release", RuntimeRevision: strings.Repeat("a", 40),
		RuntimeTreeDigest: testDigest("runtime-tree"), EvidenceRevision: strings.Repeat("b", 40),
		EvidenceTreeDigest: testDigest("evidence-tree"), ObservedAt: baseTime.Format(time.RFC3339Nano), Profile: profile,
		Observations: observations,
		NonClaims:    []string{"independent_host_or_platform_enforcement", "complete_application_image_publication_and_signing", "production_readiness"}}
	for index, principal := range profile.Principals {
		sequence := 1
		if slices.Contains(slice6RestartSubjects, principal.Name) {
			evidence.Processes = append(evidence.Processes, Slice6ProcessEvidence{
				DeploymentName: principal.Name, Sequence: 1,
				ContainerID:   testDigest("old-container/" + principal.Name)[7:],
				CommandDigest: testDigest("command/" + principal.Name),
				ConfigDigest:  testDigest("old-config/" + principal.Name),
				InspectDigest: testDigest("old-inspect/" + principal.Name),
				StartedAt:     now, FinishedAt: baseTime.Add(-8 * time.Second).Format(time.RFC3339Nano)})
			sequence = 2
		}
		evidence.Processes = append(evidence.Processes, Slice6ProcessEvidence{
			DeploymentName: principal.Name, Sequence: sequence, ContainerID: observations.Containers[index].ContainerID,
			CommandDigest: testDigest("command/" + principal.Name), ConfigDigest: testDigest("config/" + principal.Name),
			InspectDigest: observations.Containers[index].ContainerInspectDigest, StartedAt: now, FinishedAt: later, Final: true})
		if sequence == 2 {
			evidence.Processes[len(evidence.Processes)-1].StartedAt = baseTime.Add(-7 * time.Second).Format(time.RFC3339Nano)
			evidence.Processes[len(evidence.Processes)-1].FinishedAt = baseTime.Add(-6 * time.Second).Format(time.RFC3339Nano)
		}
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
		selected := external.ImageDigest
		storeMediaType := "application/vnd.oci.image.manifest.v1+json"
		if external.ImageIdentityKind == ImageIdentityOCIIndex {
			selected = external.ImageSelectedManifestDigest
			storeMediaType = "application/vnd.oci.image.index.v1+json"
		}
		item := Slice6ExternalEvidence{Name: external.Name,
			IdentityDigest: external.IdentityDigest, ContainerID: testDigest("external-container/" + external.Name)[7:],
			ImageReference:      external.ImageReference,
			RuntimeStoreImageID: external.ImageDigest, SelectedManifestDigest: selected,
			RuntimeStoreDescriptor:     ImageDescriptor{MediaType: storeMediaType, Digest: external.ImageDigest, Size: 1234},
			SelectedManifestDescriptor: ImageDescriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Digest: selected, Size: 1234},
			OCIConfigDigest:            external.ImageConfigDigest, RuntimePlatform: external.ImagePlatform,
			DescriptorProofDigest:   testDigest("external-descriptor/" + external.Name),
			ContainerInspectDigest:  testDigest("external-container-inspect/" + external.Name),
			ImageInspectDigest:      testDigest("external-image-inspect/" + external.Name),
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
			rules, err := Slice6DesiredFinalSharedPostgresHBARules()
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range rules {
				item.PostgresServerAuth.ApprovedSourceCIDRs = append(item.PostgresServerAuth.ApprovedSourceCIDRs, rule.SourceCIDR)
			}
		}
		if external.Name == "dns" {
			ca := external.DNSClientCA
			item.DNSClientCA = &Slice6DNSClientCAEvidence{
				ProfileDigest: profile.ProfileDigest, ArtifactID: ca.ArtifactID,
				BundleDigest: ca.BundleDigest, IssuerID: ca.IssuerID,
				IssuerDigest: ca.IssuerDigest, AllowedSubjects: slices.Clone(ca.AllowedSubjects),
				ObservedMountedBundleDigest: ca.BundleDigest,
				ReadOnlyMountInspectDigest:  testDigest("dns/client-ca-mount"),
				VaultIssuerInspectDigest:    testDigest("dns/vault-issuer"),
				BrokerHandshakeProbeDigest:  testDigest("dns/broker-handshake"),
				GeneralRejectionProbeDigest: testDigest("dns/general-rejection"),
			}
			runtime := external.DNSRuntime
			item.DNSRuntime = &Slice6DNSRuntimeEvidence{
				ProfileDigest: profile.ProfileDigest, UID: runtime.UID, GID: runtime.GID,
				DroppedCapabilities: slices.Clone(runtime.DroppedCapabilities),
				AddedCapabilities:   slices.Clone(runtime.AddedCapabilities),
				NoNewPrivileges:     runtime.NoNewPrivileges, ReadOnlyRootFilesystem: runtime.ReadOnlyRootFilesystem,
				SeccompMode: runtime.SeccompMode, Resources: runtime.Resources,
				CapInh: "0000000000000000", CapPrm: "0000000000000400", CapEff: "0000000000000400",
				CapBnd: "0000000000000400", CapAmb: "0000000000000000",
				InspectorTarget: runtime.InspectorTarget, InspectorReadOnly: runtime.InspectorReadOnly,
				InspectorBinaryDigest:       testDigest("dns/inspector-binary"),
				InspectorBuildReceiptDigest: testDigest("dns/inspector-build"),
				InspectorMountInspectDigest: testDigest("dns/inspector-mount"),
				InspectorExecInspectDigest:  testDigest("dns/inspector-exec"),
				ProcessStatusInspectDigest:  testDigest("dns/process-status"),
			}
		}
		evidence.External = append(evidence.External, item)
	}
	for _, principal := range profile.Principals {
		evidence.DescriptorReceipts = append(evidence.DescriptorReceipts, Slice6DescriptorReceipt{
			Kind: "container", Subject: principal.Name, ReceiptDigest: testDigest("descriptor-payload/" + principal.Name),
		})
	}
	for _, external := range profile.External {
		evidence.DescriptorReceipts = append(evidence.DescriptorReceipts, Slice6DescriptorReceipt{
			Kind: "external", Subject: external.Name, ReceiptDigest: testDigest("descriptor-payload/" + external.Name),
		})
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
	seenCandidates := map[string]bool{}
	for _, principal := range profile.Principals {
		if principal.ImageLocation != "local" || seenCandidates[principal.ImageDigest] {
			continue
		}
		seenCandidates[principal.ImageDigest] = true
		target, err := Slice6DesiredImageTarget(principal.Name)
		if err != nil {
			t.Fatal(err)
		}
		var observation ContainerObservation
		for _, item := range observations.Containers {
			if item.DeploymentName == principal.Name {
				observation = item
				break
			}
		}
		candidate := Slice6CandidateImage{Kind: Slice6CandidateRepositoryRole,
			ManifestSchema: Slice6RoleManifestSchema, ManifestDigest: testDigest("fixture-manifest/" + target),
			RuntimeStoreImageID: principal.ImageDigest, ImageIdentityKind: principal.ImageIdentityKind,
			SelectedManifestDigest: principal.ImageDigest, OCIConfigDigest: principal.ImageConfigDigest,
			DescriptorProofDigest: observation.ImageDescriptorProofDigest, Platform: principal.ImagePlatform,
			SourceRevision: evidence.RuntimeRevision, SourceTreeDigest: evidence.RuntimeTreeDigest,
			ArchiveDigest: testDigest("fixture-archive/" + target), ArchiveSize: 1234,
			Role: &Slice6RoleCandidateRef{SourceDeployment: principal.Name, BuildTarget: target}}
		if target == Slice6DesktopCandidateImage {
			candidate.Kind = Slice6CandidateDesktop
			candidate.ManifestSchema = Slice6DesktopManifestSchema
			candidate.Role = nil
			candidate.Desktop = &Slice6DesktopCandidateRef{ProfileID: "desktop-phase6-local"}
		}
		evidence.Candidates = append(evidence.Candidates, candidate)
	}
	sort.Slice(evidence.Candidates, func(i, j int) bool {
		return evidence.Candidates[i].RuntimeStoreImageID < evidence.Candidates[j].RuntimeStoreImageID
	})
	evidence.ManifestDigest = slice6EvidenceDigest(evidence)
	return evidence
}

func validFinalSlice6EvidenceObservations(t *testing.T, profile Profile) ObservationSet {
	t.Helper()
	observations := validObservations(profile)
	for index := range observations.Containers {
		value := &observations.Containers[index]
		principal := profile.Principals[index]
		target, err := Slice6DesiredImageTarget(principal.Name)
		if err != nil {
			t.Fatal(err)
		}
		value.ImageDescriptorProofDigest = testDigest("fixture-descriptor/" + target)
		if principal.ImageIdentityKind == ImageIdentityOCIIndex {
			value.RuntimeStoreDescriptor.MediaType = "application/vnd.oci.image.index.v1+json"
			value.SelectedManifestDescriptor.Digest = principal.ImageSelectedManifestDigest
		}
	}
	for index, network := range profile.Networks {
		observed := &observations.Networks[index]
		observed.ContainerIDs = nil
		observed.Endpoints = nil
		for _, principal := range network.Principals {
			address, err := Slice6DesiredEndpointAddress(network.Name, principal)
			if err != nil {
				address, err = Slice6DesiredFinalServiceEndpointAddress(network.Name, principal)
			}
			if err != nil {
				t.Fatalf("planned fixture endpoint %s/%s: %v", network.Name, principal, err)
			}
			containerID := testDigest("container/" + principal)[7:]
			observed.ContainerIDs = append(observed.ContainerIDs, containerID)
			observed.Endpoints = append(observed.Endpoints, NetworkEndpointObservation{
				ContainerID: containerID, IPv4Address: address})
		}
		for _, service := range network.ExternalServices {
			address, err := Slice6DesiredFinalServiceEndpointAddress(network.Name, service)
			if err != nil {
				t.Fatal(err)
			}
			containerID := testDigest("external-container/" + service)[7:]
			observed.ContainerIDs = append(observed.ContainerIDs, containerID)
			observed.Endpoints = append(observed.Endpoints, NetworkEndpointObservation{
				ContainerID: containerID, IPv4Address: address})
		}
		sort.Strings(observed.ContainerIDs)
		sort.Slice(observed.Endpoints, func(i, j int) bool {
			return observed.Endpoints[i].ContainerID < observed.Endpoints[j].ContainerID
		})
	}
	return observations
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
		"missing run ID":             func(e *Slice6Evidence) { e.RunID = "" },
		"wrong run ID format":        func(e *Slice6Evidence) { e.RunID = strings.Repeat("C", 32) },
		"missing receipt index":      func(e *Slice6Evidence) { e.ReceiptIndexDigest = "" },
		"legacy evidence version":    func(e *Slice6Evidence) { e.Version = 1 },
		"missing process":            func(e *Slice6Evidence) { e.Processes = e.Processes[1:] },
		"missing component":          func(e *Slice6Evidence) { e.Components = nil },
		"component pid drift":        func(e *Slice6Evidence) { e.Components[0].PID++ },
		"wrong process image":        func(e *Slice6Evidence) { e.Observations.Containers[0].RuntimeStoreImageID = testDigest("wrong") },
		"missing external":           func(e *Slice6Evidence) { e.External = e.External[1:] },
		"missing descriptor receipt": func(e *Slice6Evidence) { e.DescriptorReceipts = e.DescriptorReceipts[1:] },
		"false restore isolation":    func(e *Slice6Evidence) { e.External[0].RestoreDomainSeparated = false },
		"missing scenario":           func(e *Slice6Evidence) { e.Scenarios = e.Scenarios[1:] },
		"failed scenario":            func(e *Slice6Evidence) { e.Scenarios[0].Outcome = "passed_with_probe" },
		"wrong participants":         func(e *Slice6Evidence) { e.Scenarios[0].Participants = []string{"gateway-runtime", "product-runtime"} },
		"missing cleanup":            func(e *Slice6Evidence) { e.Cleanup = e.Cleanup[1:] },
		"resource remains":           func(e *Slice6Evidence) { e.Cleanup[0].Remaining = 1 },
		"production overclaim":       func(e *Slice6Evidence) { e.NonClaims[2] = "production_ready" },
		"obsolete image nonclaim":    func(e *Slice6Evidence) { e.NonClaims[1] = "published_or_signed_application_images" },
		"digest mismatch":            func(e *Slice6Evidence) { e.RuntimeTreeDigest = testDigest("other") },
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
	dnsIndex := -1
	for index := range evidence.External {
		if evidence.External[index].Name == "dns" {
			dnsIndex = index
		}
	}
	if dnsIndex < 0 {
		t.Fatal("synthetic DNS external missing")
	}
	for name, mutate := range map[string]func(*Slice6Evidence){
		"missing DNS CA proof": func(e *Slice6Evidence) { e.External[dnsIndex].DNSClientCA = nil },
		"different mounted CA": func(e *Slice6Evidence) {
			e.External[dnsIndex].DNSClientCA.ObservedMountedBundleDigest = testDigest("other-ca")
		},
		"different issuer": func(e *Slice6Evidence) {
			e.External[dnsIndex].DNSClientCA.IssuerID = "22222222-2222-4222-8222-222222222222"
		},
		"missing general rejection": func(e *Slice6Evidence) {
			e.External[dnsIndex].DNSClientCA.GeneralRejectionProbeDigest = ""
		},
		"wrong broker set": func(e *Slice6Evidence) {
			e.External[dnsIndex].DNSClientCA.AllowedSubjects[0] = "product-runtime"
		},
		"DNS proof on another service": func(e *Slice6Evidence) {
			copy := *e.External[dnsIndex].DNSClientCA
			e.External[otherIndex].DNSClientCA = &copy
		},
		"missing DNS runtime": func(e *Slice6Evidence) { e.External[dnsIndex].DNSRuntime = nil },
		"extra DNS capability": func(e *Slice6Evidence) {
			e.External[dnsIndex].DNSRuntime.AddedCapabilities = []string{"CAP_NET_BIND_SERVICE", "CAP_NET_RAW"}
		},
		"effective capability drift": func(e *Slice6Evidence) {
			e.External[dnsIndex].DNSRuntime.CapEff = "0000000000001400"
		},
		"DNS uid drift":    func(e *Slice6Evidence) { e.External[dnsIndex].DNSRuntime.UID = 20000 },
		"DNS host publish": func(e *Slice6Evidence) { e.External[dnsIndex].DNSRuntime.HostPublish = true },
		"missing DNS process status": func(e *Slice6Evidence) {
			e.External[dnsIndex].DNSRuntime.ProcessStatusInspectDigest = ""
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
				t.Fatalf("invalid DNS gate observation accepted: %v", err)
			}
		})
	}
	for _, malformed := range [][]byte{
		bytes.Replace(document, []byte(`"id":`), []byte(`"id":"duplicate","id":`), 1),
		append(append([]byte(nil), document...), []byte(`{}`)...),
		bytes.Replace(document, []byte(`"version":4`), []byte(`"version":4,"unknown":true`), 1),
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

func TestSlice6EvidenceEntryRejectsOldSelfConsistentProfileInventories(t *testing.T) {
	finalEvidence := validSlice6EvidenceFixture(t)
	if VerifySlice6FinalGateProfile(finalEvidence.Profile) != nil || finalEvidence.Validate() != nil {
		t.Fatal("final-only synthetic fixture is invalid")
	}
	draft := reviewedSlice6ImageFixture(t)
	intermediate, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatal(err)
	}
	for name, profile := range map[string]Profile{"historical_17_12": draft, "intermediate_28_33": intermediate} {
		t.Run(name, func(t *testing.T) {
			if profile.Validate() != nil || VerifySlice6FinalGateProfile(profile) == nil {
				t.Fatal("negative profile must be structurally valid but not final")
			}
			candidate := finalEvidence
			candidate.Profile = profile
			candidate.Observations.ProfileDigest = profile.ProfileDigest
			candidate.External = append([]Slice6ExternalEvidence(nil), finalEvidence.External...)
			for index := range candidate.External {
				if candidate.External[index].PostgresServerAuth != nil {
					proof := *candidate.External[index].PostgresServerAuth
					proof.ProfileDigest = profile.ProfileDigest
					candidate.External[index].PostgresServerAuth = &proof
				}
			}
			candidate.ManifestDigest = slice6EvidenceDigest(candidate)
			document, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifySlice6Evidence(document); !errors.Is(err, ErrInvalidSlice6Evidence) {
				t.Fatal("older self-consistent profile admitted through evidence entry")
			}
		})
	}
}

func TestSlice6EvidenceLocalCandidateRequiresTypedArtifactBinding(t *testing.T) {
	evidence := validSlice6EvidenceFixture(t)
	candidateIndex := -1
	for index, candidate := range evidence.Candidates {
		if candidate.Kind == Slice6CandidateRepositoryRole {
			candidateIndex = index
			break
		}
	}
	if candidateIndex < 0 {
		t.Fatal("final-only fixture lacks repository role candidates")
	}
	document, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySlice6Evidence(document); err != nil {
		t.Fatalf("complete local candidate fixture rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Slice6Evidence){
		"wrong build target":    func(e *Slice6Evidence) { e.Candidates[candidateIndex].Role.BuildTarget = "gateway" },
		"missing archive":       func(e *Slice6Evidence) { e.Candidates[candidateIndex].ArchiveDigest = "" },
		"wrong image ID":        func(e *Slice6Evidence) { e.Candidates[candidateIndex].RuntimeStoreImageID = testDigest("other-image") },
		"wrong source":          func(e *Slice6Evidence) { e.Candidates[candidateIndex].SourceRevision = strings.Repeat("c", 40) },
		"candidate omitted":     func(e *Slice6Evidence) { e.Candidates = nil },
		"wrong candidate kind":  func(e *Slice6Evidence) { e.Candidates[candidateIndex].Kind = Slice6CandidateDesktop },
		"wrong manifest schema": func(e *Slice6Evidence) { e.Candidates[candidateIndex].ManifestSchema = "old" },
		"wrong descriptor proof": func(e *Slice6Evidence) {
			e.Candidates[candidateIndex].DescriptorProofDigest = testDigest("other-proof")
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
				t.Fatalf("incomplete local candidate accepted: %v", err)
			}
		})
	}
}
