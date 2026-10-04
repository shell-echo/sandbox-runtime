//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// Two disposable Alpine PID1s test only E's exact Product–PG edge mutation.
// The "postgres" name here is a no-issuer carrier, not a PostgreSQL service
// or nine-network source proof.
func TestSlice6ProductPGFaultEdgeNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_PG_FAULT_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_PG_FAULT_NO_ISSUER=1 for isolated Product-PG edge drill")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("Product-PG fault exact cleanup: %v", err)
		}
	})
	serviceName := "sr-p6-product-pg-fault-" + run.id
	otherName := "sr-p6-product-preserve-" + run.id
	createNetwork := func(name string) string {
		created, err := run.docker(ctx, "network", "create", "--driver=bridge", "--internal",
			"--label", run.label(), "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", name)
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("create exact no-issuer Product-PG network")
		}
		return id
	}
	serviceID := createNetwork(serviceName)
	otherID := createNetwork(otherName)
	start := func(name string) string {
		created, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", name,
			"--label", run.label(), "--network", serviceID, "--restart=no",
			"--read-only", "--user=10001:10001", "--cap-drop=ALL",
			"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
			slice6PinnedAlpineImage, "sleep", "60")
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("start exact no-issuer Product-PG PID1")
		}
		return id
	}
	productID := start("sr-p6-product-runtime-" + run.id)
	postgresID := start("sr-p6-postgres-" + run.id)
	if output, err := run.docker(ctx, "network", "connect", otherID, productID); err != nil || len(output) != 0 {
		t.Fatal("attach original Product other edge")
	}
	product, err := slice6InspectGuestEdgeProcess(ctx, run, productID, "sr-p6-product-runtime-"+run.id)
	if err != nil {
		t.Fatal(err)
	}
	postgres, err := slice6InspectGuestEdgeProcess(ctx, run, postgresID, "sr-p6-postgres-"+run.id)
	if err != nil {
		t.Fatal(err)
	}
	const imageID = "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"
	edge := slice6ProductPGFaultEdge{Run: run, ProductID: productID, PostgresID: postgresID,
		NetworkName: serviceName, NetworkID: serviceID,
		ProductIP:       product.Networks[serviceName].IPAddress,
		PostgresIP:      postgres.Networks[serviceName].IPAddress,
		PostgresImageID: imageID, ImageRef: slice6PinnedAlpineImage}
	if !edge.valid() {
		t.Fatal("observed no-issuer Product-PG edge invalid")
	}
	wrong := edge
	wrong.NetworkID = otherID
	if _, err := slice6DisconnectProductPGEdge(ctx, wrong); err == nil {
		t.Fatal("Product-PG fault admitted a wrong original network")
	}
	recorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := slice6DisconnectProductPGEdgeWithProbeRecorded(ctx, edge,
		slice6GuestNetworkCommand, slice6CheckProductPGFaultSnapshot, recorder)
	if err != nil || !detached.Disconnected || detached.AfterDigest == "" ||
		detached.ProductPID != product.PID || detached.PostgresPID != postgres.PID {
		t.Fatalf("exact Product-PG disconnection unavailable: %v", err)
	}
	if _, err := slice6DisconnectProductPGEdge(ctx, edge); err == nil {
		t.Fatal("Product-PG fault admitted duplicate disconnect")
	}
	restored, err := slice6RestoreProductPGEdgeWithProbeRecorded(ctx, edge, detached,
		slice6GuestNetworkCommand, slice6CheckProductPGFaultSnapshot, recorder)
	if err != nil || restored.Disconnected || restored.AfterDigest != detached.BeforeDigest ||
		restored.ProductPID != detached.ProductPID || restored.PostgresPID != detached.PostgresPID {
		t.Fatalf("exact Product-PG original-IP restore unavailable: %v", err)
	}
	if _, err := slice6RestoreProductPGEdge(ctx, edge, detached); err == nil {
		t.Fatal("Product-PG fault admitted duplicate restore")
	}
	if len(recorder.events) != 4 || recorder.events[0].Kind != "pg_down_call" ||
		recorder.events[1].Kind != "pg_down_observed" ||
		recorder.events[2].Kind != "pg_up_call" || recorder.events[3].Kind != "pg_up_observed" ||
		recorder.events[0].ElapsedNanos >= recorder.events[1].ElapsedNanos ||
		recorder.events[1].ElapsedNanos >= recorder.events[2].ElapsedNanos ||
		recorder.events[2].ElapsedNanos >= recorder.events[3].ElapsedNanos {
		t.Fatal("real no-issuer Product-PG action call/observation journal drift")
	}
	lostResponse := func(ctx context.Context, args ...string) ([]byte, error, bool) {
		output, err, overflow := slice6GuestNetworkCommand(ctx, args...)
		if err != nil || overflow {
			return output, err, overflow
		}
		return output, errors.New("injected Docker response loss after mutation"), false
	}
	unknownRecorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := slice6DisconnectProductPGEdgeWithProbeRecorded(ctx, edge,
		lostResponse, slice6CheckProductPGFaultSnapshot, unknownRecorder); err == nil ||
		!outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown {
		t.Fatalf("response-lost Product-PG disconnect did not fail closed and restore: %v", err)
	}
	if len(unknownRecorder.events) != 1 || unknownRecorder.events[0].Kind != "pg_down_call" {
		t.Fatal("unknown Product-PG action incorrectly gained an observed event")
	}
	if _, err := slice6CheckProductPGFaultSnapshot(ctx, edge, true); err != nil {
		t.Fatalf("response-lost Product-PG disconnect left original edge detached: %v", err)
	}
	detached, err = slice6DisconnectProductPGEdge(ctx, edge)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := slice6RestoreProductPGEdgeWithCommand(ctx, edge, detached, lostResponse); err == nil ||
		!outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown || outcome.AfterDigest != detached.BeforeDigest {
		t.Fatalf("response-lost Product-PG restore did not classify original edge: %v", err)
	}
	failedInspect := false
	probe := func(ctx context.Context, candidate slice6ProductPGFaultEdge, connected bool) (slice6ProductPGFaultAction, error) {
		if !connected && !failedInspect {
			failedInspect = true
			return slice6ProductPGFaultAction{}, errors.New("injected post-mutation inspect failure")
		}
		return slice6CheckProductPGFaultSnapshot(ctx, candidate, connected)
	}
	if outcome, err := slice6DisconnectProductPGEdgeWithProbe(ctx, edge, slice6GuestNetworkCommand, probe); err == nil ||
		!failedInspect || !outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown {
		t.Fatalf("post-inspect-failed Product-PG disconnect did not restore exact edge: %v", err)
	}
	if _, err := slice6CheckProductPGFaultSnapshot(ctx, edge, true); err != nil {
		t.Fatalf("post-inspect-failed Product-PG disconnect left edge changed: %v", err)
	}
	detached, err = slice6DisconnectProductPGEdge(ctx, edge)
	if err != nil {
		t.Fatal(err)
	}
	failedRestoreInspect := false
	restoreProbe := func(ctx context.Context, candidate slice6ProductPGFaultEdge, connected bool) (slice6ProductPGFaultAction, error) {
		if connected && !failedRestoreInspect {
			failedRestoreInspect = true
			return slice6ProductPGFaultAction{}, errors.New("injected restore inspect failure")
		}
		return slice6CheckProductPGFaultSnapshot(ctx, candidate, connected)
	}
	if outcome, err := slice6RestoreProductPGEdgeWithProbe(ctx, edge, detached, slice6GuestNetworkCommand, restoreProbe); err == nil ||
		!failedRestoreInspect || !outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown ||
		outcome.AfterDigest != detached.BeforeDigest {
		t.Fatalf("post-inspect-failed Product-PG restore did not classify original edge: %v", err)
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := slice6DisconnectProductPGEdge(canceled, edge); err == nil {
		t.Fatal("Product-PG fault admitted a canceled action")
	}
	if _, err := slice6CheckProductPGFaultSnapshot(ctx, edge, true); err != nil {
		t.Fatalf("canceled Product-PG action changed original graph: %v", err)
	}
}
