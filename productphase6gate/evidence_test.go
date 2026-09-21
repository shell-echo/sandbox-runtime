//go:build phase6slicegate

package productphase6gate

import (
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
	manifest := productphase6evidence.Manifest{
		Identity: productphase6evidence.Identity{
			SourceRevision:                 environment.candidate.SourceRevision,
			SourceTreeDigest:               environment.candidate.SourceTreeDigest,
			ConfigDigest:                   gateConfigDigest(t, environment),
			ObservedAt:                     time.Now().UTC().Format(time.RFC3339Nano),
			CandidateClassification:        environment.candidate.Classification,
			DesktopCandidateManifestDigest: environment.candidate.ManifestDigest,
			DesktopCandidateImageDigest:    environment.candidate.ImageDigest,
			DesktopCandidatePlatform:       environment.candidate.Platform,
		},
		Roles:     roles,
		Scenarios: scenarios,
		Cleanup: productphase6evidence.Cleanup{
			ZeroResources:  true,
			Teardown:       cleanup,
			EvidenceDigest: evidenceDigest("sandbox-runtime/phase6-slice4/cleanup/v1", cleanup),
		},
		NonClaims: []string{
			"local-candidate OCI is not a published or signed artifact",
			"local-candidate evidence is not production release qualification",
			"evidence proves role boundaries and internal executor data paths only",
			"complete Product-to-Gateway-to-Provider public E2E remains unproven",
			"production readiness remains unproven",
		},
	}
	sealed, err := productphase6evidence.Seal(manifest)
	if err != nil {
		t.Fatalf("seal observed Phase 6 evidence: %v", err)
	}
	document, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	writeEvidenceFile(t, os.Getenv(evidencePathEnv), document)
	verified, err := productphase6evidence.VerifyFile(os.Getenv(evidencePathEnv))
	if err != nil || verified.ManifestDigest != sealed.ManifestDigest {
		t.Fatalf("verify written Phase 6 evidence: manifest=%#v err=%v", verified, err)
	}
	t.Logf("verified Phase 6 Slice 4 evidence %s at %s", sealed.ManifestDigest, os.Getenv(evidencePathEnv))
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
	for _, container := range []string{environment.productDB.container, environment.providerDB.container, environment.chromiumName} {
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
			dockerObjectCount("ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4") == 0 &&
			dockerObjectCount("network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4") == 0 &&
			dockerContainerCount(environment.productDB.container, environment.providerDB.container, environment.chromiumName) == 0 &&
			dockerImageCount(environment.gatewayImage) == 0 &&
			pathCount(environment.paths.brokerSocket) == 0 &&
			listenerCount(environment.guest.address) == 0
	})
	resources := []productphase6evidence.Resource{
		{Name: "role_processes", Count: remainingRoleProcessCount(environment)},
		{Name: "executor_backend_processes", Count: remainingDependencyProcessCount(environment)},
		{Name: "desktop_namespace_containers", Count: dockerObjectCount("ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4")},
		{Name: "desktop_namespace_networks", Count: dockerObjectCount("network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4")},
		{Name: "postgres_and_chromium_containers", Count: dockerContainerCount(environment.productDB.container, environment.providerDB.container, environment.chromiumName)},
		{Name: "desktop_broker_socket", Count: pathCount(environment.paths.brokerSocket)},
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
	temporary, err := os.CreateTemp(filepath.Dir(path), ".phase6-slice4-evidence-*")
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
