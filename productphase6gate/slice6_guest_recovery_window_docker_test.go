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

// Disposable no-issuer network drill only. It proves exact detach/reattach
// mechanics and PID1 continuity, not the prerequisite PostgreSQL fault or
// Product/Guest signed lifecycle receipt in a source-bound deployment.
func TestSlice6GuestRecoveryEdgeWindowNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_WINDOW_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_WINDOW_NO_ISSUER=1 for isolated network window drill")
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
			t.Errorf("network-window exact cleanup: %v", err)
		}
	})
	productNetworkName := "sr-p6-window-product-" + run.id
	runtimeNetworkName := "sr-p6-window-runtime-" + run.id
	createNetwork := func(name string) string {
		created, err := run.docker(ctx, "network", "create", "--driver=bridge", "--internal",
			"--label", run.label(), "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", name)
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("create exact no-issuer isolated window network")
		}
		return id
	}
	productNetworkID := createNetwork(productNetworkName)
	runtimeNetworkID := createNetwork(runtimeNetworkName)
	start := func(name string) string {
		created, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", name,
			"--label", run.label(), "--network", productNetworkID, "--restart=no",
			"--read-only", "--user=10001:10001", "--cap-drop=ALL",
			"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
			slice6PinnedAlpineImage, "sleep", "60")
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("start exact no-issuer window PID1")
		}
		return id
	}
	productID := start("sr-p6-product-runtime-" + run.id)
	guestID := start("sr-p6-guest-runtime-" + run.id)
	if output, err := run.docker(ctx, "network", "connect", runtimeNetworkID, guestID); err != nil || len(output) != 0 {
		t.Fatal("attach original Guest runtime network")
	}
	product, err := slice6InspectGuestEdgeProcess(ctx, run, productID, "sr-p6-product-runtime-"+run.id)
	if err != nil {
		t.Fatal(err)
	}
	productNetworkRaw, err := slice6ReadGuestSourceProductNetworks(ctx, run.id, productID)
	if err != nil {
		t.Fatal(err)
	}
	productNetworkProjection, err := slice6ParseGuestSourceProductNetworks(productNetworkRaw, run.id, productID)
	clear(productNetworkRaw)
	if err != nil || productNetworkProjection[productNetworkName].NetworkID != productNetworkID ||
		productNetworkProjection[productNetworkName].IPAddress != product.Networks[productNetworkName].IPAddress {
		t.Fatal("bounded no-issuer Product network source projection drift")
	}
	guest, err := slice6InspectGuestEdgeProcess(ctx, run, guestID, "sr-p6-guest-runtime-"+run.id)
	if err != nil {
		t.Fatal(err)
	}
	edge := slice6GuestRecoveryEdge{Run: run, ProductID: productID, GuestID: guestID,
		ProductNetworkName: productNetworkName, ProductNetworkID: productNetworkID,
		ProductIP:          product.Networks[productNetworkName].IPAddress,
		GuestIP:            guest.Networks[productNetworkName].IPAddress,
		RuntimeNetworkName: runtimeNetworkName, RuntimeNetworkID: runtimeNetworkID,
		GuestRuntimeIP: guest.Networks[runtimeNetworkName].IPAddress}
	if !edge.valid() {
		t.Fatal("observed no-issuer Guest edge invalid")
	}
	wrong := edge
	wrong.ProductNetworkID = runtimeNetworkID
	if _, err := slice6DetachGuestProductEdge(ctx, wrong); err == nil {
		t.Fatal("network-window accepted wrong original edge")
	}
	recorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := slice6DetachGuestProductEdgeWithProbeRecorded(ctx, edge,
		slice6GuestNetworkCommand, slice6CheckGuestEdgeSnapshot, recorder)
	if err != nil || !detached.Disconnected || detached.AfterDigest == "" ||
		detached.ProductPID != product.PID || detached.GuestPID != guest.PID {
		t.Fatalf("exact Guest edge detachment unavailable: %v", err)
	}
	if _, err := slice6DetachGuestProductEdge(ctx, edge); err == nil {
		t.Fatal("network-window accepted duplicate detach")
	}
	restored, err := slice6RestoreGuestProductEdgeWithProbeRecorded(ctx, edge, detached,
		slice6GuestNetworkCommand, slice6CheckGuestEdgeSnapshot, recorder)
	if err != nil || restored.Disconnected || restored.AfterDigest != detached.BeforeDigest ||
		restored.ProductPID != detached.ProductPID || restored.GuestPID != detached.GuestPID {
		t.Fatalf("exact original-IP Guest edge restoration unavailable: %v", err)
	}
	if _, err := slice6RestoreGuestProductEdge(ctx, edge, detached); err == nil {
		t.Fatal("network-window accepted duplicate restore")
	}
	if len(recorder.events) != 4 || recorder.events[0].Kind != "guest_off_call" ||
		recorder.events[1].Kind != "guest_off_observed" ||
		recorder.events[2].Kind != "guest_on_call" ||
		recorder.events[3].Kind != "guest_on_observed" ||
		recorder.events[0].ElapsedNanos >= recorder.events[1].ElapsedNanos ||
		recorder.events[1].ElapsedNanos >= recorder.events[2].ElapsedNanos ||
		recorder.events[2].ElapsedNanos >= recorder.events[3].ElapsedNanos {
		t.Fatal("real no-issuer Guest action call/observation monotonic journal drift")
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
	if outcome, err := slice6DetachGuestProductEdgeWithProbeRecorded(ctx, edge,
		lostResponse, slice6CheckGuestEdgeSnapshot, unknownRecorder); err == nil ||
		!outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown {
		t.Fatalf("response-lost Guest disconnect did not fail closed and restore: %v", err)
	}
	if len(unknownRecorder.events) != 1 || unknownRecorder.events[0].Kind != "guest_off_call" {
		t.Fatal("unknown Guest action incorrectly gained an observed event")
	}
	if _, err := slice6CheckGuestEdgeSnapshot(ctx, edge, true); err != nil {
		t.Fatalf("response-lost Guest disconnect left original edge detached: %v", err)
	}
	detached, err = slice6DetachGuestProductEdge(ctx, edge)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := slice6RestoreGuestProductEdgeWithCommand(ctx, edge, detached, lostResponse); err == nil ||
		!outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown || outcome.AfterDigest != detached.BeforeDigest {
		t.Fatalf("response-lost Guest restore did not classify original edge: %v", err)
	}
	failedInspect := false
	probe := func(ctx context.Context, candidate slice6GuestRecoveryEdge, connected bool) (slice6GuestRecoveryEdgeAction, error) {
		if !connected && !failedInspect {
			failedInspect = true
			return slice6GuestRecoveryEdgeAction{}, errors.New("injected post-mutation inspect failure")
		}
		return slice6CheckGuestEdgeSnapshot(ctx, candidate, connected)
	}
	if outcome, err := slice6DetachGuestProductEdgeWithProbe(ctx, edge, slice6GuestNetworkCommand, probe); err == nil ||
		!failedInspect || !outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown {
		t.Fatalf("post-inspect-failed Guest detach did not restore exact edge: %v", err)
	}
	if _, err := slice6CheckGuestEdgeSnapshot(ctx, edge, true); err != nil {
		t.Fatalf("post-inspect-failed Guest detach left edge changed: %v", err)
	}
	detached, err = slice6DetachGuestProductEdge(ctx, edge)
	if err != nil {
		t.Fatal(err)
	}
	failedRestoreInspect := false
	restoreProbe := func(ctx context.Context, candidate slice6GuestRecoveryEdge, connected bool) (slice6GuestRecoveryEdgeAction, error) {
		if connected && !failedRestoreInspect {
			failedRestoreInspect = true
			return slice6GuestRecoveryEdgeAction{}, errors.New("injected restore inspect failure")
		}
		return slice6CheckGuestEdgeSnapshot(ctx, candidate, connected)
	}
	if outcome, err := slice6RestoreGuestProductEdgeWithProbe(ctx, edge, detached, slice6GuestNetworkCommand, restoreProbe); err == nil ||
		!failedRestoreInspect || !outcome.Attempted || outcome.Disconnected || outcome.OutcomeUnknown ||
		outcome.AfterDigest != detached.BeforeDigest {
		t.Fatalf("post-inspect-failed Guest restore did not classify original edge: %v", err)
	}
	canceled, stopCanceled := context.WithCancel(ctx)
	stopCanceled()
	if _, err := slice6DetachGuestProductEdge(canceled, edge); err == nil {
		t.Fatal("network-window accepted cancellation before detach")
	}
	if _, err := slice6CheckGuestEdgeSnapshot(ctx, edge, true); err != nil {
		t.Fatalf("canceled window changed the restored edge: %v", err)
	}
}
