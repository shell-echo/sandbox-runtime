package lock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
)

func TestParentProviderCheckoutMatchesLock(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err != nil {
		t.Fatal(err)
	}
}

func TestProviderDocumentationPathIsNarrow(t *testing.T) {
	for path, want := range map[string]bool{
		"README.md":             true,
		"docs/STATUS.md":        true,
		"docs/plan/p2.5.md":     true,
		"README.md/embedded.go": false,
		"cmd/README.md":         false,
		"provider/code.go":      false,
	} {
		if got := providerDocumentationPath(path); got != want {
			t.Errorf("providerDocumentationPath(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestProviderChangePathAllowsOnlyHarnessAndDocumentation(t *testing.T) {
	for path, want := range map[string]bool{
		"README.md":                                    true,
		"docs/STATUS.md":                               true,
		"e2e/cmd/caller/main.go":                       true,
		"e2e/internal/lock/lock.go":                    true,
		".github/workflows/reference-e2e.yml":          true,
		".github/workflows/platform-candidate-e2e.yml": true,
		".github/workflows/browser-e2e.yml":            true,
		".github/workflows/shared-capacity-e2e.yml":    true,
		".github/workflows/durable-revocation-e2e.yml": true,
		".github/workflows/downstream-fencing-e2e.yml": true,
		".github/workflows/unrelated.yml":              false,
		"cmd/serve.go":                                 false,
		"provider/code.go":                             false,
		"e2e/../provider/code.go":                      false,
	} {
		if got := providerChangePath(path); got != want {
			t.Errorf("providerChangePath(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestSharedCapacityLock(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		locked, err := LoadSharedCapacity(root, platform)
		if err != nil {
			t.Fatalf("LoadSharedCapacity(%q): %v", platform, err)
		}
		if locked.ProviderCommit != ProviderCommit || locked.GatewayProcesses != 2 {
			t.Fatalf("LoadSharedCapacity(%q) returned the wrong baseline: %#v", platform, locked)
		}
		if locked.Valkey.SelectedPlatform != platform || locked.Valkey.SelectedChildDigest != locked.Valkey.PlatformDigests[platform] {
			t.Fatalf("LoadSharedCapacity(%q) selected %q at %q", platform, locked.Valkey.SelectedPlatform, locked.Valkey.SelectedChildDigest)
		}
		if got := locked.Scenarios; len(got) != 10 || got[0] != "cross-process session limit after WebSocket upgrade" ||
			got[len(got)-1] != "sensitive values absent from evidence" {
			t.Fatalf("LoadSharedCapacity(%q) scenarios = %#v", platform, got)
		}
	}
	if _, err := LoadSharedCapacity(root, "linux/ppc64le"); err == nil || !strings.Contains(err.Error(), "is not locked") {
		t.Fatalf("unsupported LoadSharedCapacity() error = %v", err)
	}
}

func TestSharedCapacityScenarioNamesReturnsCopy(t *testing.T) {
	first := SharedCapacityScenarioNames()
	first[0] = "changed"
	if second := SharedCapacityScenarioNames(); second[0] == "changed" {
		t.Fatal("SharedCapacityScenarioNames returned mutable package state")
	}
}

func TestDurableRevocationLock(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		locked, err := LoadDurableRevocation(root, platform)
		if err != nil {
			t.Fatalf("LoadDurableRevocation(%q): %v", platform, err)
		}
		if locked.ProviderCommit != ProviderCommit || locked.Contract.Exercised ||
			locked.Processes != (DurableRevocationProcesses{Gateways: 2, Callers: 2, Revokers: 1}) ||
			locked.LocalCapacity != (DurableRevocationLocalCapacity{MaxTotal: 16, MaxPerTenant: 8, MaxPerSession: 4}) ||
			locked.Reconnect != (DurableRevocationReconnect{MaxReconnects: 1, ReconnectBackoffMillis: 10}) {
			t.Fatalf("LoadDurableRevocation(%q) returned the wrong baseline: %#v", platform, locked)
		}
		if locked.Valkey.SelectedPlatform != platform || locked.Valkey.SelectedChildDigest != locked.Valkey.PlatformDigests[platform] {
			t.Fatalf("LoadDurableRevocation(%q) selected %q at %q", platform, locked.Valkey.SelectedPlatform, locked.Valkey.SelectedChildDigest)
		}
		if got := locked.Scenarios; len(got) != 7 ||
			got[0] != "independent revoker disconnects the same exact active grant on both Gateways within bound" ||
			got[len(got)-1] != "sensitive values are absent from evidence" {
			t.Fatalf("LoadDurableRevocation(%q) scenarios = %#v", platform, got)
		}
	}
	if _, err := LoadDurableRevocation(root, "linux/ppc64le"); err == nil || !strings.Contains(err.Error(), "is not locked") {
		t.Fatalf("unsupported LoadDurableRevocation() error = %v", err)
	}
}

func TestDurableRevocationScenarioNamesReturnsCopy(t *testing.T) {
	first := DurableRevocationScenarioNames()
	first[0] = "changed"
	if second := DurableRevocationScenarioNames(); second[0] == "changed" {
		t.Fatal("DurableRevocationScenarioNames returned mutable package state")
	}
}

func TestDecodeStrictFileRejectsUnknownAndTrailingInput(t *testing.T) {
	for name, content := range map[string]string{
		"unknown":          `{"schema_version":1,"unknown":true}`,
		"duplicate":        `{"schema_version":1,"schema_version":1}`,
		"nested duplicate": `{"schema_version":1,"valkey":{"image":"first","image":"second"}}`,
		"trailing":         `{"schema_version":1} {"schema_version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "lock.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			var target SharedCapacityLock
			if err := decodeStrictFile(path, &target); err == nil {
				t.Fatal("decodeStrictFile accepted invalid lock input")
			}
		})
	}
}

func TestSharedCapacityNormalizedConfigurationDigests(t *testing.T) {
	if got, want := normalizedSHA256(SharedCapacityServerConfig), "sha256:12a690a249f1c28c5d3617bcc051216c3261270237035494dcb17764aa2111d2"; got != want {
		t.Fatalf("server config digest = %s, want %s", got, want)
	}
	if got, want := normalizedSHA256(SharedCapacityACLTemplate), "sha256:4d660aa0861d5a7396f5e50bec072a813395ad13f19b23df53317d222c43743a"; got != want {
		t.Fatalf("ACL template digest = %s, want %s", got, want)
	}
}

func TestDurableRevocationNormalizedConfigurationDigests(t *testing.T) {
	if got, want := normalizedSHA256(DurableRevocationServerConfig), "sha256:12a690a249f1c28c5d3617bcc051216c3261270237035494dcb17764aa2111d2"; got != want {
		t.Fatalf("server config digest = %s, want %s", got, want)
	}
	if got, want := normalizedSHA256(DurableRevocationACLTemplate), "sha256:901e39fd2ff5385dbbb8b93594bbbc737f669abeac27e982a409f290ac1e266a"; got != want {
		t.Fatalf("ACL template digest = %s, want %s", got, want)
	}
}

func TestE2EProviderLockMatchesCompiledBaseline(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyE2EProviderLock(root); err != nil {
		t.Fatal(err)
	}
}

func TestSharedCapacityDescriptorMatchesAdapter(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	policy := SharedCapacityPolicy{
		MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1,
		LeaseTTLMillis: 2000, RenewIntervalMillis: 400,
		RenewalSafetyMarginMillis: 500, OperationTimeoutMillis: 200,
	}
	want, err := currentSharedCapacityDescriptor(root, policy)
	if err != nil {
		t.Fatal(err)
	}
	timeout := time.Duration(policy.OperationTimeoutMillis) * time.Millisecond
	client := goredis.NewClient(&goredis.Options{
		Addr: "127.0.0.1:6379", MaxRetries: -1, ContextTimeoutEnabled: true,
		Protocol: 2, DisableIdentity: true, DialTimeout: timeout, ReadTimeout: timeout,
		WriteTimeout: timeout, PoolTimeout: timeout,
	})
	t.Cleanup(func() { _ = client.Close() })
	capacity, err := rediscapacity.New(rediscapacity.Options{
		Client: client, Namespace: "shared-capacity-lock-test",
		MaxTotal: policy.MaxTotal, MaxPerTenant: policy.MaxPerTenant, MaxPerSession: policy.MaxPerSession,
		LeaseTTL:            time.Duration(policy.LeaseTTLMillis) * time.Millisecond,
		RenewInterval:       time.Duration(policy.RenewIntervalMillis) * time.Millisecond,
		RenewalSafetyMargin: time.Duration(policy.RenewalSafetyMarginMillis) * time.Millisecond,
		OperationTimeout:    timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := capacity.Descriptor()
	if got.PolicyFormat != want.PolicyFormat || got.PolicyFingerprint != want.PolicyFingerprint ||
		got.ProvisionScript != want.ProvisionScript || got.AcquireScript != want.AcquireScript ||
		got.RenewScript != want.RenewScript || got.ReleaseScript != want.ReleaseScript {
		t.Fatalf("adapter Descriptor() = %#v, want %#v", got, want)
	}
}

func TestHarnessRevisionRequiresCleanCommit(t *testing.T) {
	root := t.TempDir()
	runTestGit(t, root, "init", "-q")
	tracked := filepath.Join(root, "tracked.txt")
	if err := os.WriteFile(tracked, []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, root, "add", "tracked.txt")
	runTestGit(t, root, "-c", "user.name=E2E Test", "-c", "user.email=e2e-test@example.invalid", "commit", "-qm", "initial")

	revision, err := HarnessRevision(root)
	if err != nil || !commitPattern.MatchString(revision) {
		t.Fatalf("HarnessRevision() = %q, %v", revision, err)
	}
	if err := os.WriteFile(tracked, []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HarnessRevision(root); !errors.Is(err, errDirtyHarness) {
		t.Fatalf("dirty HarnessRevision() error = %v", err)
	}
}

func runTestGit(t *testing.T, root string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}
