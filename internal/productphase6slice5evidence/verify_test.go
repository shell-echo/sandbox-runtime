package productphase6slice5evidence

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func testDigest(string) string { return "sha256:" + strings.Repeat("a", 64) }

func validRuntimeGate(t *testing.T) productphase6evidence.Manifest {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	stress := productphase6evidence.StressMeasurements{Harness: "phase6-desktop-mux-stress-v2", Runs50: 50, Runs100: 100, TotalRuns: 150, InputsPerRun: 5, TotalInputs: 750, TerminalCauses: []string{}}
	stress.CommandDigest = productphase6evidence.StressCommandDigest(stress)
	stress.EvidenceDigest = productphase6evidence.StressEvidenceDigest(stress)
	media := productphase6evidence.DesktopMediaMeasurements{Harness: "phase6-desktop-media-v2", Sessions: 20, FirstFrameP95Microseconds: 100, FirstFrameMaxMicroseconds: 200, FirstFrameLimitMilliseconds: 30_000,
		WindowMilliseconds: 2_000, RTPPackets: 100, RTPMarkerFrames: 100, RTPBytes: 10_000, AllowedPacketLoss: 0, MaxFPSMilli: 1_000, FPSLimitMilli: 30_000,
		MaxBitrateBPS: 100_000, BitrateLimitBPS: 2_000_000, ConcurrentInputs: 201, MaxInputRoundtripMicroseconds: 100, InputProcessDeadlineMilliseconds: 1_000,
		BackpressureStage: "media_reader", BackpressureCause: "backpressure_limit", Recovery: true, GoroutineBoundary: productphase6evidence.SteadyStateGoroutineBoundary,
		GoroutinesBaseline: 2, GoroutinesFinal: 2}
	media.CommandDigest = productphase6evidence.DesktopMediaCommandDigest(media)
	media.EvidenceDigest = productphase6evidence.DesktopMediaEvidenceDigest(media)
	runtime := productphase6evidence.Manifest{Identity: productphase6evidence.Identity{
		RuntimeImplementationRevision: strings.Repeat("a", 40), RuntimeImplementationTreeDigest: testDigest("runtime"),
		EvidenceToolRevision: strings.Repeat("b", 40), EvidenceToolTreeDigest: testDigest("evidence"), ConfigDigest: testDigest("config"), ObservedAt: now,
		CandidateClassification: "local-candidate-non-release", DesktopCandidateManifestDigest: testDigest("candidate"), DesktopCandidateImageDigest: testDigest("image"), DesktopCandidatePlatform: "linux/arm64/v8"},
		Stress: stress, DesktopMedia: media,
		NonClaims: []string{"local-candidate OCI is not a published or signed artifact", "local-candidate evidence is not production release qualification", "evidence proves role boundaries and internal executor data paths only", "complete Product-to-Gateway-to-Provider public E2E remains unproven", "production readiness remains unproven", "measured bitrate upper-bound does not prove visual quality", "thirty-second first-frame limit is a test safety bound, not a production SLO"}}
	for _, role := range []string{"product", "gateway", "provider", "guest", "browser", "desktop"} {
		runtime.Roles = append(runtime.Roles, productphase6evidence.Role{Name: role, Command: role + " serve", ImageDigest: testDigest(role), ProcessIdentity: role + "-pid", StartedAt: now, FinishedAt: now, Ready: true, EvidenceDigest: testDigest(role)})
	}
	for _, name := range productphase6evidence.ScenarioNames() {
		runtime.Scenarios = append(runtime.Scenarios, productphase6evidence.Scenario{Name: name, Outcome: "passed", Roles: []string{"provider", "desktop"}, EvidenceDigest: testDigest(name)})
	}
	runtime.Cleanup = productphase6evidence.Cleanup{ZeroResources: true, Boundary: productphase6evidence.TopologyCleanupBoundary,
		Teardown: []productphase6evidence.Resource{{Name: "role_processes"}, {Name: "executor_backend_processes"}, {Name: "desktop_namespace_containers"}, {Name: "desktop_namespace_networks"}, {Name: "postgres_and_chromium_containers"}, {Name: "desktop_broker_socket"}, {Name: "browser_gateway_image"}, {Name: "guest_fixture_listener"}}}
	runtime.Cleanup.EvidenceDigest = productphase6evidence.CleanupEvidenceDigest(runtime.Cleanup)
	sealed, err := productphase6evidence.Seal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func validManifest(t *testing.T) Manifest {
	t.Helper()
	runtime := validRuntimeGate(t)
	roleEvidence := RoleMaterialAndCredentials{Harness: RoleMaterialHarness, CommandDigest: testDigest("command"), ConfigDigest: runtime.Identity.ConfigDigest,
		VaultImage: VaultImage, VaultTLS: true, WorkloadMaterialProtocol: "sandbox-runtime.workload-material.v1", WorkloadCredentialProtocol: "sandbox-runtime.workload-credential.v1",
		BreakGlassProtocol: "sandbox-runtime.break-glass.v1", ManagementCredentialTransport: "inherited_fd_3", CredentialControllerProcesses: 2,
		WorkloadMaterialAgentProcesses: 10, CredentialTTLSeconds: 30, CredentialOverlapSeconds: 3,
		BreakGlass: BreakGlassEvidence{ControllerProcesses: 1, PersistentAuthority: true, DistinctApproversRequired: 2, MaxTTLSeconds: 900, MaxUses: 1,
			RequestRecords: 3, ConsumedRecords: 1, RevokedRecords: 1, ExpiredRecords: 1, AuditEntries: 15, AuditHead: testDigest("head"), LedgerDigest: testDigest("ledger"), AuditDigest: testDigest("audit"),
			HashChainedAudit: true, ReasonTicketDigestOnly: true, TargetAgentBound: true, OnlineAtomicConsume: true, MigrationDenied: true},
		PlaintextExclusion: PlaintextExclusionEvidence{Scope: "role_configs_process_arguments_logs_control_ledgers_and_manifest", KnownSecretValues: 20, FilesScanned: 10, ProcessCommandLinesScanned: 6, ScanDigest: testDigest("scan")}}
	for agentID, role := range agentRoles {
		migration := strings.Contains(agentID, "-migration-")
		agent := AgentEvidence{AgentID: agentID, Role: role, IdentityDigest: testDigest(agentID), BindingDigest: testDigest(agentID), LeaseRecords: 1,
			MaxRevision: 2, Renewable: !migration, Migration: migration, RotationObserved: !migration}
		if migration {
			agent.RevokedLeases = 1
		} else {
			agent.ActiveLeases = 1
		}
		roleEvidence.Agents = append(roleEvidence.Agents, agent)
	}
	for _, name := range ScenarioNames("material") {
		roleEvidence.Scenarios = append(roleEvidence.Scenarios, Scenario{Name: name, Outcome: "passed", EvidenceDigest: testDigest(name)})
	}
	roleEvidence.EvidenceDigest = RoleMaterialEvidenceDigest(roleEvidence)
	recording := RecordingTransitEvidence{Harness: RecordingHarness,
		RuntimeImplementationRevision: runtime.Identity.RuntimeImplementationRevision, RuntimeImplementationTreeDigest: runtime.Identity.RuntimeImplementationTreeDigest,
		EvidenceToolRevision: runtime.Identity.EvidenceToolRevision, EvidenceToolTreeDigest: runtime.Identity.EvidenceToolTreeDigest,
		ObservedAt: runtime.Identity.ObservedAt, CommandDigest: testDigest("recording-command"), ConfigDigest: testDigest("recording-config"), VaultImage: VaultImage, PostgresImage: PostgresImage,
		VaultTLS: true, VaultTransitMount: "transit", VaultKeyIdentityDigest: testDigest("key"), BindingDigest: testDigest("binding"), Purpose: secretref.PurposeRecordingEnvelopeKey,
		Role: secretref.RoleProduct, StoreSchema: "recordings-kms-v1", HandleSchema: "rkms1", CredentialClass: "vault_nonrenewable_scoped_token", FreshPostgresSchema: true,
		Cleanup: []Resource{{Name: "vault_containers"}, {Name: "postgres_containers"}, {Name: "recording_directories"}, {Name: "database_connections"}, {Name: "scoped_vault_tokens"}}}
	for _, name := range ScenarioNames("recording") {
		recording.Scenarios = append(recording.Scenarios, Scenario{Name: name, Outcome: "passed", EvidenceDigest: testDigest(name)})
	}
	recording.EvidenceDigest = RecordingEvidenceDigest(recording)
	manifest := Manifest{RuntimeGate: runtime, RoleMaterialAndCredentials: roleEvidence, RecordingTransitAdapter: recording,
		CapabilityBoundary: CapabilityBoundary{ProductKernelCapabilityReadiness: "unavailable", ProductionConfigEnablement: "schema_absent_and_unknown_fields_rejected"},
		FutureGates:        []FutureGate{{Slice: 8, Requirement: "compose KMS RecordingContentStore into the real Product or recording worker with write/read/rotation/restart/loss/integrity/cleanup evidence"}, {Slice: 11, Requirement: "verify deployment configuration cannot enable any uncomposed recording-content capability"}, {Slice: 14, Requirement: "run black-box encrypted recording E2E from published artifacts before release-candidate eligibility"}},
		NonClaims:          []string{"Product OS process has not composed the KMS RecordingContentStore", "public Product recording content E2E remains unproven", "ticket and data envelope consumers are not composed", "Vault software Transit evidence is not HSM evidence", "distinct OS UIDs, service accounts and platform identity federation remain unproven", "deployment, HA and production readiness remain unproven", "metadata and catalog behavior is not encrypted content durability", "the local Desktop candidate is not a published or signed artifact"}}
	for name := range cleanupResources {
		manifest.Cleanup.Resources = append(manifest.Cleanup.Resources, Resource{Name: name})
	}
	manifest.Cleanup.ZeroResources, manifest.Cleanup.Boundary = true, CleanupBoundary
	manifest.Cleanup.EvidenceDigest = CleanupEvidenceDigest(manifest.Cleanup)
	sealed, err := Seal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestVerifyAcceptsClosedDualGateEvidence(t *testing.T) {
	manifest := validManifest(t)
	document, _ := json.Marshal(manifest)
	if _, err := Verify(document); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsClaimAndSubEvidenceDrift(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"runtime revision": func(value *Manifest) {
			value.RecordingTransitAdapter.RuntimeImplementationRevision = strings.Repeat("c", 40)
		},
		"renewal": func(value *Manifest) {
			for index := range value.RoleMaterialAndCredentials.Agents {
				if value.RoleMaterialAndCredentials.Agents[index].AgentID == "product-runtime-agent" {
					value.RoleMaterialAndCredentials.Agents[index].RotationObserved = false
					return
				}
			}
		},
		"break glass": func(value *Manifest) { value.RoleMaterialAndCredentials.BreakGlass.MaxUses = 2 },
		"plaintext":   func(value *Manifest) { value.RoleMaterialAndCredentials.PlaintextExclusion.ForbiddenMatches = 1 },
		"recording":   func(value *Manifest) { value.RecordingTransitAdapter.RawKeyExported = true },
		"capability":  func(value *Manifest) { value.CapabilityBoundary.RecordingContentStoreComposed = true },
		"future gate": func(value *Manifest) { value.FutureGates[0].Slice = 9 },
		"cleanup":     func(value *Manifest) { value.Cleanup.Resources[0].Count = 1 },
		"nonclaim":    func(value *Manifest) { value.NonClaims[0] = "production ready" },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := validManifest(t)
			mutate(&manifest)
			manifest.ManifestDigest = manifestDigest(manifest)
			document, _ := json.Marshal(manifest)
			if _, err := Verify(document); err == nil {
				t.Fatal("invalid Slice 5 evidence accepted")
			}
		})
	}
}

func TestVerifyRejectsIndependentlyValidRecordingEvidenceFromAnotherRuntime(t *testing.T) {
	manifest := validManifest(t)
	manifest.RecordingTransitAdapter.RuntimeImplementationRevision = strings.Repeat("c", 40)
	manifest.RecordingTransitAdapter.EvidenceDigest = RecordingEvidenceDigest(manifest.RecordingTransitAdapter)
	manifest.ManifestDigest = manifestDigest(manifest)
	document, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(document); err == nil {
		t.Fatal("recording evidence from a different runtime revision was accepted")
	}
}

func TestVerifyRejectsIndependentlyValidRoleMaterialEvidenceFromAnotherConfig(t *testing.T) {
	manifest := validManifest(t)
	manifest.RoleMaterialAndCredentials.ConfigDigest = "sha256:" + strings.Repeat("c", 64)
	manifest.RoleMaterialAndCredentials.EvidenceDigest = RoleMaterialEvidenceDigest(manifest.RoleMaterialAndCredentials)
	manifest.ManifestDigest = manifestDigest(manifest)
	document, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(document); err == nil {
		t.Fatal("role-material evidence from a different configuration was accepted")
	}
}

func TestVerifyRejectsUnknownDuplicateAndNonCanonicalJSON(t *testing.T) {
	document, _ := json.Marshal(validManifest(t))
	unknown := append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"unknown":true}`)...)
	if _, err := Verify(unknown); err == nil {
		t.Fatal("unknown evidence field accepted")
	}
	duplicate := append([]byte(`{"id":"product-v1-phase-6-slice-5",`), append([]byte(nil), document[1:]...)...)
	if _, err := Verify(duplicate); err == nil {
		t.Fatal("duplicate evidence field accepted")
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, document, "", "  ") != nil {
		t.Fatal("indent evidence")
	}
	if _, err := Verify(pretty.Bytes()); err == nil {
		t.Fatal("non-canonical evidence accepted")
	}
}

func TestRecordingEvidenceFileRequiresPrivateMode(t *testing.T) {
	evidence := validManifest(t).RecordingTransitAdapter
	document, _ := json.Marshal(evidence)
	path := filepath.Join(t.TempDir(), "recording.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecordingFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRecordingFile(path); err == nil {
		t.Fatal("public recording evidence accepted")
	}
}
