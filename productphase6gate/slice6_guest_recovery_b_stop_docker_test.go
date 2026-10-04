//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

// This no-issuer drill proves B shutdown and exact removal without claiming
// the signed E scenario. The formal 29-event journal has no B stop event.
func TestSlice6GuestRecoveryBStopAndRemovalNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_B_STOP_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_B_STOP_NO_ISSUER=1 for B shutdown drill")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("B stop no-issuer exact cleanup: %v", err)
		}
	})
	privateRoot := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	privateRoot, err = filepath.EvalSymlinks(privateRoot)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(privateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	evidence, err := root.newRun(run.id)
	if err != nil {
		t.Fatal(err)
	}
	defer evidence.closeV2Incomplete()
	recorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		t.Fatal(err)
	}
	profile := "sha256:" + strings.Repeat("a", 64)
	config := "sha256:" + strings.Repeat("b", 64)
	begin, err := json.Marshal(phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
		Role: "product", Event: "begin", Sequence: 1, ElapsedNanos: 1,
		UnixMillis: 1_700_000_000_000, ProfileDigest: profile, ConfigDigest: config})
	if err != nil {
		t.Fatal(err)
	}
	seal, err := json.Marshal(phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
		Role: "product", Event: "seal", Sequence: 2, ElapsedNanos: 2,
		UnixMillis: 1_700_000_000_001})
	if err != nil {
		t.Fatal(err)
	}
	created, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-v2-capture-product-b-"+run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no",
		"--user=65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
		"-e", "BEGIN="+string(begin), "-e", "SEAL="+string(seal),
		"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec",
		"trap 'printf \"%s\\n\" \"$SEAL\"; exit 0' TERM; printf '%s\\n' \"$BEGIN\"; while :; do sleep 1; done")
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("B no-issuer PID1 create unavailable")
	}
	startup, stopStartup := context.WithTimeout(ctx, 10*time.Second)
	capture, err := slice6StartGuestRecoveryCaptureWithPreflight(ctx, startup, run, evidence, "product-b", id,
		"sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c",
		slice6PinnedAlpineImage, profile, config, recorder)
	stopStartup()
	if err != nil {
		t.Fatal(err)
	}
	defer capture.abort()
	for attempt := 0; attempt < 30 && capture.pid == 0 && ctx.Err() == nil; attempt++ {
		if capture.observeRunning(ctx, run) == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if capture.pid < 1 || len(recorder.events) != 2 {
		t.Fatal("B no-issuer start observation unavailable")
	}
	select {
	case <-capture.done:
		t.Fatal("startup budget canceled the long-lived attached B capture")
	case <-time.After(200 * time.Millisecond):
	}
	if err := capture.confirmStillRunning(ctx, run); err != nil {
		t.Fatal("B capture not live after startup budget ended")
	}
	binding, records, err := slice6StopGuestRecoveryReplacementCapture(ctx, run, capture)
	if err != nil || len(records) != 2 || binding.ContainerID != id || !capture.stopAdmitted ||
		len(recorder.events) != 2 {
		t.Fatalf("B no-issuer sealed shutdown unavailable: %v", err)
	}
	wrong := binding
	wrong.ConfigDigest = "sha256:" + strings.Repeat("c", 64)
	if slice6RemoveGuestRecoverySealedProcess(ctx, run, capture, wrong) == nil {
		t.Fatal("B no-issuer wrong binding authorized removal")
	}
	if err := slice6RemoveGuestRecoverySealedProcess(ctx, run, capture, binding); err != nil {
		t.Fatal(err)
	}
	if !slice6GuestRecoveryProductPriorAbsent(ctx, id) {
		t.Fatal("B no-issuer exact ID remains after removal")
	}
}
