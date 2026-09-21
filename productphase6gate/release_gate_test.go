//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
)

func TestPhase6Slice4ReleaseGate(t *testing.T) {
	if os.Getenv(gateEnabledEnv) != "1" {
		t.Skip("set " + gateEnabledEnv + "=1 to run the six-process Phase 6 Slice 4 gate")
	}
	for name, value := range map[string]string{
		candidateEnv:    os.Getenv(candidateEnv),
		evidencePathEnv: os.Getenv(evidencePathEnv),
	} {
		if value == "" || !filepath.IsAbs(value) {
			t.Fatalf("%s must be an absolute path", name)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	environment := prepareGateEnvironment(t, ctx)
	startGateTopology(t, ctx, environment)
	assertProductBoundary(t, environment)
	assertGatewayBoundary(t, environment)
	browserStarted := time.Now().UTC()
	runBrowserExecutorScenarios(t, ctx, environment)
	browserFinished := time.Now().UTC()
	for name, detail := range map[string]string{
		"authority_expiry":  "Browser executor rejected an already-expired authority and closed an accepted session at its bounded authority expiry.",
		"executor_capacity": "Browser executor enforced its one-session production capacity while a real Chromium CDP session was active.",
		"replay_rejection":  "Browser executor rejected replay of the exact previously accepted executor.v2 authority.",
	} {
		recordScenario(environment, name, []string{"provider", "browser"}, browserStarted, browserFinished, detail)
	}
	guestStarted := time.Now().UTC()
	runGuestReconnectScenario(t, environment)
	recordScenario(environment, "bounded_reconnect", []string{"product", "guest"}, guestStarted, time.Now().UTC(), "Guest readiness failed closed during a real authenticated dependency outage and recovered through bounded reconnect and a development.health round trip.")
	providerLossStarted := time.Now().UTC()
	runProviderDependencyLossScenario(t, ctx, environment)
	recordScenario(environment, "provider_dependency_loss", []string{"gateway", "provider"}, providerLossStarted, time.Now().UTC(), "Provider readiness failed closed while its PostgreSQL authority was paused and recovered after the dependency returned; Gateway remained a separate process boundary.")
	desktopStarted := time.Now().UTC()
	runProviderDesktopScenarios(t, ctx, environment)
	desktopFinished := time.Now().UTC()
	for name, detail := range map[string]string{
		"normal_attach_media_input":    "Provider private Desktop attach crossed the Desktop role, executor backend and candidate broker, observed a real VP8 RTP frame, and completed a pointer input result.",
		"fence_generation_epoch_drift": "The durable Desktop binding rejected combined generation, epoch and controller-fence drift and separately rejected media-policy drift.",
		"broker_restart":               "A closed broker session was recreated through the Provider-owned host mux and again produced real media and input results.",
		"executor_restart":             "The Desktop role was terminated, restarted as a new OS process, became ready from a verified allocation, and reattached media and input.",
		"provider_restart":             "The Provider was gracefully restarted as a new OS process, restored its durable authority and broker mux, and opened a second real Desktop session.",
		"close_cleanup":                "Both Provider Desktop session closes completed and each converged the namespace to zero dynamic runtime resources before topology teardown.",
	} {
		recordScenario(environment, name, []string{"provider", "desktop"}, desktopStarted, desktopFinished, detail)
	}

	drainOpen := newBrowserOpen(t, "drain", 4*time.Second)
	drainConnection, drainResponse := dialBrowserExecutor(t, ctx, environment, drainOpen)
	if drainResponse.Status != executorprotocol.StatusAccepted {
		drainConnection.CloseNow()
		t.Fatalf("Browser drain authority response=%#v", drainResponse)
	}
	drainStarted := time.Now()
	stopGateProcess(t, environment.roles["browser"], 12*time.Second)
	if elapsed := time.Since(drainStarted); elapsed > 10*time.Second {
		drainConnection.CloseNow()
		t.Fatalf("Browser drain exceeded bound: %s", elapsed)
	}
	drainConnection.CloseNow()
	recordScenario(environment, "drain_cancellation", []string{"provider", "browser"}, drainStarted.UTC(), time.Now().UTC(), "Browser role SIGTERM drained an active executor.v2 connection within the ten-second gate bound.")

	stopGateTopology(t, environment)
	writePhase6Evidence(t, environment)
}
