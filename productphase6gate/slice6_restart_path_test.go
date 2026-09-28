//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6RestartPathEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_RESTART_PATH_DIAGNOSTIC"

type slice6RestartContainerInspect struct {
	ID     string `json:"Id"`
	Config struct {
		Cmd    []string          `json:"Cmd"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	State struct {
		Running    bool   `json:"Running"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
}

// This exercises a real replacement restart at one reviewed network/IP: the
// old container stops and is removed before a different container starts.
// Alpine is a diagnostic process, NOT Provider; it cannot close the final
// Provider/executor restart scenario or issue a release receipt bundle.
func TestPhase6Slice6ReplacementRestartPathDiagnostic(t *testing.T) {
	if os.Getenv(slice6RestartPathEnv) != "1" {
		t.Skip("set " + slice6RestartPathEnv + "=1 for real two-instance restart diagnostic")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := run.cleanup(cleanupCtx); err != nil {
			t.Errorf("exact replacement-restart diagnostic cleanup: %v", err)
		}
	})
	var network phase6security.Network
	for _, expected := range phase6security.Slice6DesiredFinalNetworks() {
		if expected.Name == "network-provider-runtime" {
			network = expected
			break
		}
	}
	if network.Name == "" || !network.Internal || network.GatewayModeIPv4 != "isolated" ||
		!slices.Equal(network.Principals, []string{"provider-runtime"}) {
		t.Fatal("reviewed Provider isolated bridge is unavailable")
	}
	created, err := createSlice6ProfileNetwork(ctx, run, network)
	if err != nil {
		t.Fatal(err)
	}
	address, err := phase6security.Slice6DesiredEndpointAddress(network.Name, "provider-runtime")
	if err != nil {
		t.Fatal(err)
	}
	start := func(name string) (string, []byte, slice6RestartContainerInspect) {
		t.Helper()
		output, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", name,
			"--label", run.label(), "--network", created.NetworkID, "--ip", address,
			"--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
			"--user", "20000:30000", "--pids-limit", "16", "--memory", "64m",
			slice6NetworkProbeImageID, "sleep", "120")
		id := strings.TrimSpace(string(output))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("run-owned diagnostic process did not start")
		}
		raw, err := run.docker(ctx, "inspect", id)
		if err != nil {
			t.Fatal("inspect real diagnostic process")
		}
		var values []slice6RestartContainerInspect
		if json.Unmarshal(raw, &values) != nil || len(values) != 1 || values[0].ID != id ||
			!values[0].State.Running || values[0].Config.Labels[slice6RunLabel] != run.id ||
			!slices.Equal(values[0].Config.Cmd, []string{"sleep", "120"}) {
			t.Fatal("real diagnostic process inspect does not match launch")
		}
		return id, raw, values[0]
	}
	oldID, _, oldStarted := start("sr-p6-old-" + run.id)
	if _, err := run.docker(ctx, "stop", "-t", "1", oldID); err != nil {
		t.Fatal("stop old process before replacement")
	}
	oldRaw, err := run.docker(ctx, "inspect", oldID)
	if err != nil {
		t.Fatal("retain old stopped process inspect")
	}
	var stopped []slice6RestartContainerInspect
	if json.Unmarshal(oldRaw, &stopped) != nil || len(stopped) != 1 || stopped[0].State.Running {
		t.Fatal("old diagnostic process still runs")
	}
	if _, err := run.docker(ctx, "rm", oldID); err != nil {
		t.Fatal("remove old process before reusing reviewed IP")
	}
	newID, newRaw, newStarted := start("sr-p6-new-" + run.id)
	if oldID == newID || sha256.Sum256(oldRaw) == sha256.Sum256(newRaw) {
		t.Fatal("replacement reused the old process instance or inspect bytes")
	}
	oldStart, oldStartErr := time.Parse(time.RFC3339Nano, oldStarted.State.StartedAt)
	oldFinish, oldFinishErr := time.Parse(time.RFC3339Nano, stopped[0].State.FinishedAt)
	newStart, newStartErr := time.Parse(time.RFC3339Nano, newStarted.State.StartedAt)
	if oldStartErr != nil || oldFinishErr != nil || newStartErr != nil ||
		!oldStart.Before(oldFinish) || newStart.Before(oldFinish) {
		t.Fatal("replacement process event ordering is not observed")
	}
	if _, err := run.docker(ctx, "exec", newID, "true"); err != nil {
		t.Fatal("new process is not live after replacement")
	}
	if _, err := observeSlice6ProfileNetwork(ctx, run, created.NetworkID, network,
		map[string]string{"provider-runtime": newID}); err != nil {
		t.Fatal("replacement did not occupy the reviewed isolated endpoint alone")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("exact two-instance diagnostic cleanup: %v", err)
	}
	t.Log("real distinct-instance stop/remove/start, same command and endpoint, live replacement, exact cleanup passed; no Provider authority claim")
}
