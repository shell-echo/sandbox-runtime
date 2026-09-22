//go:build phase6slicegate

package productphase6gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	slice5evidence "github.com/shell-echo/sandbox-runtime/internal/productphase6slice5evidence"
)

type scenarioObservation struct {
	Name       string    `json:"name"`
	Roles      []string  `json:"roles"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Detail     string    `json:"detail"`
}

func recordScenario(environment *gateEnvironment, name string, roles []string, startedAt, finishedAt time.Time, detail string) {
	if _, exists := environment.scenarios[name]; exists {
		panic("duplicate Phase 6 scenario observation: " + name)
	}
	environment.scenarios[name] = scenarioObservation{
		Name: name, Roles: append([]string(nil), roles...), StartedAt: startedAt.UTC(), FinishedAt: finishedAt.UTC(), Detail: detail,
	}
}

func writePhase6Evidence(t *testing.T, environment *gateEnvironment) {
	t.Helper()
	cleanup := cleanGateEnvironment(t, environment)
	roles := observedRoles(t, environment)
	roleDigests := make(map[string]string, len(roles))
	for _, role := range roles {
		roleDigests[role.Name] = role.EvidenceDigest
	}
	scenarios := observedScenarios(t, environment, roleDigests)
	runtimeManifest := productphase6evidence.Manifest{
		Identity: productphase6evidence.Identity{
			RuntimeImplementationRevision:   environment.repository.RuntimeImplementationRevision,
			RuntimeImplementationTreeDigest: environment.repository.RuntimeImplementationTreeDigest,
			EvidenceToolRevision:            environment.repository.EvidenceToolRevision,
			EvidenceToolTreeDigest:          environment.repository.EvidenceToolTreeDigest,
			ConfigDigest:                    gateConfigDigest(t, environment),
			ObservedAt:                      time.Now().UTC().Format(time.RFC3339Nano),
			CandidateClassification:         environment.candidate.Classification,
			DesktopCandidateManifestDigest:  environment.candidate.ManifestDigest,
			DesktopCandidateImageDigest:     environment.candidate.ImageDigest,
			DesktopCandidatePlatform:        environment.candidate.Platform,
		},
		Roles:        roles,
		Scenarios:    scenarios,
		Stress:       environment.stress,
		DesktopMedia: environment.desktopMedia,
		Cleanup: productphase6evidence.Cleanup{
			ZeroResources: true,
			Boundary:      productphase6evidence.TopologyCleanupBoundary,
			Teardown:      cleanup,
		},
		NonClaims: []string{
			"local-candidate OCI is not a published or signed artifact",
			"local-candidate evidence is not production release qualification",
			"evidence proves role boundaries and internal executor data paths only",
			"complete Product-to-Gateway-to-Provider public E2E remains unproven",
			"production readiness remains unproven",
			"measured bitrate upper-bound does not prove visual quality",
			"thirty-second first-frame limit is a test safety bound, not a production SLO",
		},
	}
	runtimeManifest.Cleanup.EvidenceDigest = productphase6evidence.CleanupEvidenceDigest(runtimeManifest.Cleanup)
	sealedRuntime, err := productphase6evidence.Seal(runtimeManifest)
	if err != nil {
		t.Fatalf("seal embedded Phase 6 runtime evidence: %v", err)
	}
	slice5Cleanup := observedSlice5Cleanup(t, environment)
	manifest := slice5evidence.Manifest{
		RuntimeGate: sealedRuntime, RoleMaterialAndCredentials: environment.roleMaterialEvidence,
		RecordingTransitAdapter: environment.recordingEvidence,
		CapabilityBoundary: slice5evidence.CapabilityBoundary{ProductKernelCapabilityReadiness: "unavailable",
			RecordingContentStoreComposed: false, RecordingContentE2E: false, TicketEnvelopeConsumerComposed: false,
			DataEnvelopeConsumerComposed: false, LegacyRecordingFallback: false, ProductionConfigEnablement: "schema_absent_and_unknown_fields_rejected"},
		FutureGates: []slice5evidence.FutureGate{
			{Slice: 8, Requirement: "compose KMS RecordingContentStore into the real Product or recording worker with write/read/rotation/restart/loss/integrity/cleanup evidence"},
			{Slice: 11, Requirement: "verify deployment configuration cannot enable any uncomposed recording-content capability"},
			{Slice: 14, Requirement: "run black-box encrypted recording E2E from published artifacts before release-candidate eligibility"},
		},
		Cleanup: slice5evidence.Cleanup{ZeroResources: true, Boundary: slice5evidence.CleanupBoundary, Resources: slice5Cleanup},
		NonClaims: []string{
			"Product OS process has not composed the KMS RecordingContentStore",
			"public Product recording content E2E remains unproven",
			"ticket and data envelope consumers are not composed",
			"Vault software Transit evidence is not HSM evidence",
			"distinct OS UIDs, service accounts and platform identity federation remain unproven",
			"deployment, HA and production readiness remain unproven",
			"metadata and catalog behavior is not encrypted content durability",
			"the local Desktop candidate is not a published or signed artifact",
		},
	}
	manifest.Cleanup.EvidenceDigest = slice5evidence.CleanupEvidenceDigest(manifest.Cleanup)
	sealed, err := slice5evidence.Seal(manifest)
	if err != nil {
		t.Fatalf("seal observed Phase 6 Slice 5 evidence: %v", err)
	}
	document, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	assertEvidenceExcludesManagedPlaintext(t, environment, document)
	writeEvidenceFile(t, os.Getenv(evidencePathEnv), document)
	verified, err := slice5evidence.VerifyFile(os.Getenv(evidencePathEnv))
	if err != nil || verified.ManifestDigest != sealed.ManifestDigest {
		t.Fatalf("verify written Phase 6 Slice 5 evidence: manifest=%#v err=%v", verified, err)
	}
	t.Logf("verified Phase 6 Slice 5 evidence %s at %s", sealed.ManifestDigest, os.Getenv(evidencePathEnv))
}

func observedRoles(t *testing.T, environment *gateEnvironment) []productphase6evidence.Role {
	t.Helper()
	names := []string{"product", "gateway", "provider", "guest", "browser", "desktop"}
	result := make([]productphase6evidence.Role, 0, len(names))
	imageDigest := fileDigest(t, environment.paths.binary)
	for _, name := range names {
		instances := environment.roleHistory[name]
		if len(instances) == 0 {
			t.Fatalf("missing %s process history", name)
		}
		var startedAt, finishedAt time.Time
		ready := true
		pids := make([]string, 0, len(instances))
		commands := make([]string, 0, len(instances))
		evidence := make([]any, 0, len(instances))
		for _, process := range instances {
			process.mu.Lock()
			started, finished, exitCode, processReady := process.startedAt, process.finished, process.exitCode, process.ready
			state := process.cmd.ProcessState
			pid := process.cmd.Process.Pid
			process.mu.Unlock()
			if state == nil || !state.Exited() || exitCode != 0 || finished.IsZero() {
				t.Fatalf("%s process %d did not finish cleanly: exit=%d log=%s", name, pid, exitCode, gateLog(process))
			}
			if startedAt.IsZero() || started.Before(startedAt) {
				startedAt = started
			}
			if finished.After(finishedAt) {
				finishedAt = finished
			}
			ready = ready && processReady
			pids = append(pids, fmt.Sprintf("%d", pid))
			command := sanitizedCommand(environment, process.command)
			commands = append(commands, command)
			evidence = append(evidence, struct {
				PID        int    `json:"pid"`
				Command    string `json:"command"`
				StartedAt  string `json:"started_at"`
				FinishedAt string `json:"finished_at"`
				ExitCode   int    `json:"exit_code"`
				Ready      bool   `json:"ready"`
				LogDigest  string `json:"log_digest"`
			}{pid, command, started.UTC().Format(time.RFC3339Nano), finished.UTC().Format(time.RFC3339Nano), exitCode, processReady, fileDigest(t, process.logPath)})
		}
		result = append(result, productphase6evidence.Role{
			Name: name, Command: strings.Join(commands, " ; "), ImageDigest: imageDigest,
			ProcessIdentity: name + ":pids:" + strings.Join(pids, ","),
			StartedAt:       startedAt.UTC().Format(time.RFC3339Nano),
			FinishedAt:      finishedAt.UTC().Format(time.RFC3339Nano),
			ExitCode:        0,
			Ready:           ready,
			EvidenceDigest:  evidenceDigest("sandbox-runtime/phase6-slice4/role/v1", evidence),
		})
	}
	return result
}

func observedScenarios(t *testing.T, environment *gateEnvironment, roleDigests map[string]string) []productphase6evidence.Scenario {
	t.Helper()
	names := productphase6evidence.ScenarioNames()
	result := make([]productphase6evidence.Scenario, 0, len(names))
	for _, name := range names {
		observation, ok := environment.scenarios[name]
		if !ok || observation.StartedAt.IsZero() || observation.FinishedAt.Before(observation.StartedAt) || strings.TrimSpace(observation.Detail) == "" {
			t.Fatalf("missing or invalid observation for Phase 6 scenario %s", name)
		}
		boundRoles := make([]struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		}, 0, len(observation.Roles))
		for _, role := range observation.Roles {
			digest, exists := roleDigests[role]
			if !exists {
				t.Fatalf("scenario %s references unobserved role %s", name, role)
			}
			boundRoles = append(boundRoles, struct {
				Name   string `json:"name"`
				Digest string `json:"digest"`
			}{role, digest})
		}
		result = append(result, productphase6evidence.Scenario{
			Name: name, Outcome: "passed", Roles: append([]string(nil), observation.Roles...),
			EvidenceDigest: evidenceDigest("sandbox-runtime/phase6-slice4/scenario/v1", struct {
				Observation scenarioObservation `json:"observation"`
				Roles       any                 `json:"roles"`
			}{observation, boundRoles}),
		})
	}
	return result
}

func cleanGateEnvironment(t *testing.T, environment *gateEnvironment) []productphase6evidence.Resource {
	t.Helper()
	if err := environment.guest.close(); err != nil {
		t.Fatalf("close Guest fixture: %v", err)
	}
	environment.productDB.admin.Close()
	environment.providerDB.admin.Close()
	for _, container := range []string{environment.productDB.container, environment.providerDB.container, environment.chromiumName, environment.vaultContainer} {
		runDockerCleanup(t, "rm", "-f", container)
	}
	waitFor(t, 15*time.Second, "zero Phase 6 namespace resources before uplink removal", func() bool {
		count, err := managedResourceCount(environment)
		return err == nil && count == 0
	})
	runDockerCleanup(t, "network", "rm", environment.uplinkNetwork)
	runDockerCleanup(t, "image", "rm", "-f", environment.gatewayImage)
	if err := os.RemoveAll(environment.paths.brokerDirectory); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "exact Phase 6 teardown", func() bool {
		return remainingProcessCount(environment) == 0 &&
			dockerObjectCount("ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5") == 0 &&
			dockerObjectCount("network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5") == 0 &&
			dockerContainerCount(environment.productDB.container, environment.providerDB.container, environment.chromiumName, environment.vaultContainer) == 0 &&
			dockerImageCount(environment.gatewayImage) == 0 &&
			pathCount(environment.paths.brokerSocket)+gateAuthoritySocketCount(environment) == 0 &&
			listenerCount(environment.guest.address) == 0
	})
	authorityDirectories := map[string]struct{}{
		filepath.Dir(environment.paths.credentialLedger): {},
		filepath.Dir(environment.paths.breakGlassLedger): {},
	}
	for _, path := range environment.paths.materialSockets {
		authorityDirectories[filepath.Dir(path)] = struct{}{}
	}
	for _, path := range environment.paths.breakGlassSockets {
		authorityDirectories[filepath.Dir(path)] = struct{}{}
	}
	for directory := range authorityDirectories {
		if err := os.RemoveAll(directory); err != nil {
			t.Fatal(err)
		}
	}
	resources := []productphase6evidence.Resource{
		{Name: "role_processes", Count: remainingRoleProcessCount(environment)},
		{Name: "executor_backend_processes", Count: remainingDependencyProcessCount(environment)},
		{Name: "desktop_namespace_containers", Count: dockerObjectCount("ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5")},
		{Name: "desktop_namespace_networks", Count: dockerObjectCount("network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5")},
		{Name: "postgres_and_chromium_containers", Count: dockerContainerCount(environment.productDB.container, environment.providerDB.container, environment.chromiumName, environment.vaultContainer)},
		{Name: "desktop_broker_socket", Count: pathCount(environment.paths.brokerSocket) + gateAuthoritySocketCount(environment)},
		{Name: "browser_gateway_image", Count: dockerImageCount(environment.gatewayImage)},
		{Name: "guest_fixture_listener", Count: listenerCount(environment.guest.address)},
	}
	for _, resource := range resources {
		if resource.Count != 0 {
			t.Fatalf("Phase 6 cleanup left %s=%d", resource.Name, resource.Count)
		}
	}
	return resources
}

func observedSlice5Cleanup(t *testing.T, environment *gateEnvironment) []slice5evidence.Resource {
	t.Helper()
	materialSockets, breakGlassSockets := 0, 0
	for _, path := range environment.paths.materialSockets {
		materialSockets += pathCount(path)
	}
	for _, path := range environment.paths.breakGlassSockets {
		breakGlassSockets += pathCount(path)
	}
	resources := []slice5evidence.Resource{
		{Name: "role_processes", Count: remainingRoleProcessCount(environment)},
		{Name: "executor_backend_processes", Count: remainingNamedProcesses(environment.dependencies, "browser-backend", "desktop-backend")},
		{Name: "workload_material_agent_processes", Count: remainingGateProcesses(environment.materialAgentHistory)},
		{Name: "workload_credential_controller_processes", Count: remainingNamedProcesses(environment.dependencies, "workload-credential-controller")},
		{Name: "break_glass_controller_processes", Count: remainingNamedProcesses(environment.dependencies, "break-glass-controller")},
		{Name: "desktop_namespace_containers", Count: dockerObjectCount("ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5")},
		{Name: "desktop_namespace_networks", Count: dockerObjectCount("network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5")},
		{Name: "postgres_containers", Count: dockerContainerCount(environment.productDB.container, environment.providerDB.container)},
		{Name: "chromium_containers", Count: dockerContainerCount(environment.chromiumName)},
		{Name: "vault_containers", Count: dockerContainerCount(environment.vaultContainer)},
		{Name: "browser_gateway_images", Count: dockerImageCount(environment.gatewayImage)},
		{Name: "desktop_broker_sockets", Count: pathCount(environment.paths.brokerSocket)},
		{Name: "material_agent_sockets", Count: materialSockets},
		{Name: "credential_controller_sockets", Count: pathCount(environment.paths.credentialSocket)},
		{Name: "break_glass_sockets", Count: pathCount(environment.paths.breakGlassControllerSocket) + breakGlassSockets},
		{Name: "credential_state_files", Count: pathCount(environment.paths.credentialLedger)},
		{Name: "break_glass_state_files", Count: pathCount(environment.paths.breakGlassLedger) + pathCount(environment.paths.breakGlassAudit)},
		{Name: "guest_fixture_listeners", Count: listenerCount(environment.guest.address)},
	}
	for _, resource := range resources {
		if resource.Count != 0 {
			t.Fatalf("Phase 6 Slice 5 cleanup left %s=%d", resource.Name, resource.Count)
		}
	}
	return resources
}

func remainingGateProcesses(processes []*gateProcess) int {
	count := 0
	seen := make(map[*gateProcess]struct{}, len(processes))
	for _, process := range processes {
		if process == nil {
			continue
		}
		if _, duplicate := seen[process]; duplicate {
			continue
		}
		seen[process] = struct{}{}
		process.mu.Lock()
		state := process.cmd.ProcessState
		process.mu.Unlock()
		if state == nil || !state.Exited() {
			count++
		}
	}
	return count
}

func remainingNamedProcesses(processes []*gateProcess, names ...string) int {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	selected := make([]*gateProcess, 0, len(processes))
	for _, process := range processes {
		if process != nil {
			if _, ok := wanted[process.name]; ok {
				selected = append(selected, process)
			}
		}
	}
	return remainingGateProcesses(selected)
}

func assertEvidenceExcludesManagedPlaintext(t *testing.T, environment *gateEnvironment, document []byte) {
	t.Helper()
	check := func(name string, value []byte) {
		if len(value) >= 16 && bytes.Contains(document, value) {
			t.Fatalf("Slice 5 evidence contains managed plaintext %s", name)
		}
	}
	check("Vault management credential", []byte(environment.vaultRootToken))
	check("Provider admission key", environment.admissionKey)
	check("Product signing key", environment.productToken)
	check("break-glass controller key", environment.breakGlassControllerKey)
	for name, key := range environment.credentialKeys {
		check(name+" credential identity", key)
	}
	for name, key := range environment.breakGlassKeys {
		check(name+" break-glass identity", key)
	}
	for name, materials := range environment.materials {
		for index, material := range materials {
			check(fmt.Sprintf("%s material %d", name, index), material.Bytes)
		}
	}
}

func gateAuthoritySocketCount(environment *gateEnvironment) int {
	count := pathCount(environment.paths.credentialSocket) + pathCount(environment.paths.breakGlassControllerSocket)
	for _, path := range environment.paths.materialSockets {
		count += pathCount(path)
	}
	for _, path := range environment.paths.breakGlassSockets {
		count += pathCount(path)
	}
	return count
}

func runDockerCleanup(t *testing.T, arguments ...string) {
	t.Helper()
	if output, err := exec.Command("docker", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
}

func remainingProcessCount(environment *gateEnvironment) int {
	return remainingRoleProcessCount(environment) + remainingDependencyProcessCount(environment)
}

func remainingRoleProcessCount(environment *gateEnvironment) int {
	count := 0
	for _, processes := range environment.roleHistory {
		for _, process := range processes {
			process.mu.Lock()
			state := process.cmd.ProcessState
			process.mu.Unlock()
			if state == nil || !state.Exited() {
				count++
			}
		}
	}
	return count
}

func remainingDependencyProcessCount(environment *gateEnvironment) int {
	count := 0
	for _, process := range environment.dependencies {
		process.mu.Lock()
		state := process.cmd.ProcessState
		process.mu.Unlock()
		if state == nil || !state.Exited() {
			count++
		}
	}
	return count
}

func dockerObjectCount(arguments ...string) int {
	output, err := exec.Command("docker", arguments...).Output()
	if err != nil {
		return -1
	}
	return len(strings.Fields(string(output)))
}

func dockerContainerCount(names ...string) int {
	count := 0
	for _, name := range names {
		if exec.Command("docker", "container", "inspect", name).Run() == nil {
			count++
		}
	}
	return count
}

func dockerImageCount(reference string) int {
	if exec.Command("docker", "image", "inspect", reference).Run() == nil {
		return 1
	}
	return 0
}

func pathCount(path string) int {
	if _, err := os.Lstat(path); err == nil {
		return 1
	} else if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	return -1
}

func listenerCount(address string) int {
	connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err != nil {
		return 0
	}
	_ = connection.Close()
	return 1
}

func gateConfigDigest(t *testing.T, environment *gateEnvironment) string {
	t.Helper()
	type entry struct {
		Name   string `json:"name"`
		Digest string `json:"digest"`
	}
	entries := make([]entry, 0, 32)
	err := filepath.WalkDir(environment.paths.directory, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return nil
		}
		suffix := filepath.Ext(path)
		if suffix != ".toml" && suffix != ".json" && suffix != ".pem" && suffix != ".key" && suffix != ".dsn" {
			return nil
		}
		relative, err := filepath.Rel(environment.paths.directory, path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{Name: filepath.ToSlash(relative), Digest: fileDigest(t, path)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	if len(entries) == 0 {
		t.Fatal("Phase 6 configuration evidence is empty")
	}
	return evidenceDigest("sandbox-runtime/phase6-slice4/config/v1", entries)
}

func sanitizedCommand(environment *gateEnvironment, command string) string {
	command = strings.ReplaceAll(command, environment.paths.directory, "<private-gate-root>")
	command = strings.ReplaceAll(command, environment.paths.brokerDirectory, "<private-broker-root>")
	return command
}

func evidenceDigest(domain string, value any) string {
	document, _ := json.Marshal(value)
	digest := sha256.Sum256(append(append([]byte(nil), []byte(domain)...), append([]byte{0}, document...)...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func writeEvidenceFile(t *testing.T, path string, document []byte) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("Phase 6 evidence path must be absolute")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			t.Fatal("Phase 6 evidence target must be a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".phase6-slice5-evidence-*")
	if err != nil {
		t.Fatal(err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		t.Fatal(err)
	}
	if _, err := temporary.Write(document); err != nil {
		_ = temporary.Close()
		t.Fatal(err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		t.Fatal(err)
	}
}
