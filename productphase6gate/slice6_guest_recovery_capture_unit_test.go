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

func TestSlice6V2RawFilenamesRemainSeparateFromHistoricalV1(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, process := range []string{"product-a", "guest-a", "product-b", "guest-b"} {
		name := slice6GuestRecoveryRawName(process)
		if name == "" {
			t.Fatal("known v2 process has no private filename")
		}
		if _, err := run.createFile(name); err == nil {
			t.Fatal("historical v1 writer admitted a v2 raw name")
		}
		file, err := run.createV2RawFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if info, err := file.Stat(); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("v2 raw file not private")
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := run.createV2RawFile(name); err == nil {
			t.Fatal("duplicate v2 raw file was accepted")
		}
	}
	for _, process := range []string{"product", "guest", "product-c", "Product-a", "../guest-a"} {
		if name := slice6GuestRecoveryRawName(process); name != "" {
			t.Fatalf("non-v2 process received raw filename: %q", name)
		}
	}
	if err := run.closeV2Incomplete(); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join(rootPath, run.id, "incomplete.json"))
	if err != nil || !strings.Contains(string(marker), `"protocol":"sandbox-runtime.phase6-guest-recovery-evidence.v2"`) ||
		strings.Contains(string(marker), `"disposition":"component_verified"`) {
		t.Fatal("v2 collection emitted a v1 or accepted marker")
	}
}

func TestSlice6LiveV2PrefixSnapshotDoesNotAcceptPartialWrite(t *testing.T) {
	rootPath := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}
	rootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	run, err := root.newRun(strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	file, err := run.createV2RawFile(slice6GuestRecoveryRawName("product-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	profile := "sha256:" + strings.Repeat("b", 64)
	config := "sha256:" + strings.Repeat("c", 64)
	begin := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
		Role: "product", Event: "begin", Sequence: 1, ElapsedNanos: 1,
		UnixMillis: time.Now().UnixMilli(), ProfileDigest: profile, ConfigDigest: config}
	line, err := json.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	output := &slice6ReceiptBoundedFile{file: file}
	capture := &slice6GuestRecoveryCapture{run: run, process: "product-a", role: "product",
		profile: profile, config: config, pid: 123, done: make(chan struct{}), output: output}
	if _, err := output.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	initial, ready, err := capture.readLivePrefix(t.Context())
	if err != nil || !ready || len(initial) == 0 {
		t.Fatalf("complete live begin unavailable: %v", err)
	}
	clear(initial)
	if _, err := output.Write([]byte(`{"protocol":`)); err != nil {
		t.Fatal(err)
	}
	partial, ready, err := capture.readLivePrefix(t.Context())
	if err != nil || ready || len(partial) != 0 {
		t.Fatalf("partial live Docker chunk was accepted: %v", err)
	}
	close(capture.done)
	if _, _, err := capture.readLivePrefix(t.Context()); err == nil {
		t.Fatal("stopped collector prefix accepted as a live action trigger")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run.closeV2Incomplete(); err != nil {
		t.Fatal(err)
	}
}

func TestSlice6FourProcessOrderRejectsSpliceAndOverlap(t *testing.T) {
	runID := strings.Repeat("a", 32)
	profile := "sha256:" + strings.Repeat("a", 64)
	image := "sha256:" + strings.Repeat("b", 64)
	imageRef := "example.invalid/core@" + image
	base := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	var bindings [4]slice6GuestRecoveryRawBinding
	for i, process := range []string{"product-a", "guest-a", "product-b", "guest-b"} {
		start := base.Add(time.Duration(i/2*10+i%2) * time.Second)
		config := "sha256:" + strings.Repeat("c", 64)
		if i%2 == 1 {
			config = "sha256:" + strings.Repeat("d", 64)
		}
		bindings[i] = slice6GuestRecoveryRawBinding{Process: process,
			Role: strings.SplitN(process, "-", 2)[0], File: slice6GuestRecoveryRawName(process),
			RunID: runID, ContainerID: strings.Repeat(string(rune('a'+i)), 64), PID: 100 + i,
			StartedAt: start.Format(time.RFC3339Nano), FinishedAt: start.Add(5 * time.Second).Format(time.RFC3339Nano),
			ImageID: image, ImageRef: imageRef, ProfileDigest: profile, ConfigDigest: config,
			SHA256: "sha256:" + strings.Repeat(string(rune('a'+i)), 64), Bytes: 100,
			CaptureStartUTC:  start.Add(-time.Millisecond).Format(time.RFC3339Nano),
			CaptureFinishUTC: start.Add(6 * time.Second).Format(time.RFC3339Nano)}
	}
	exits := [4]int{0, 0, 0, 0}
	check := func(value [4]slice6GuestRecoveryRawBinding) error {
		return slice6VerifyGuestRecoveryProcessOrder(runID, profile, image, imageRef, value, exits)
	}
	if err := check(bindings); err != nil {
		t.Fatalf("ordered four-process structure = %v", err)
	}
	for _, change := range []struct {
		name  string
		alter func(*[4]slice6GuestRecoveryRawBinding)
	}{
		{"cross run", func(v *[4]slice6GuestRecoveryRawBinding) { v[3].RunID = strings.Repeat("b", 32) }},
		{"old ID splice", func(v *[4]slice6GuestRecoveryRawBinding) { v[2].ContainerID = v[0].ContainerID }},
		{"PID reuse", func(v *[4]slice6GuestRecoveryRawBinding) { v[3].PID = v[1].PID }},
		{"raw replay", func(v *[4]slice6GuestRecoveryRawBinding) { v[2].SHA256 = v[0].SHA256 }},
		{"overlap", func(v *[4]slice6GuestRecoveryRawBinding) {
			v[2].StartedAt = base.Add(time.Second).Format(time.RFC3339Nano)
			v[2].FinishedAt = base.Add(2 * time.Second).Format(time.RFC3339Nano)
		}},
		{"changed config", func(v *[4]slice6GuestRecoveryRawBinding) {
			v[2].ConfigDigest = "sha256:" + strings.Repeat("f", 64)
		}},
		{"wrong exit", func(v *[4]slice6GuestRecoveryRawBinding) { v[1].ExitCode = 3 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			modified := bindings
			change.alter(&modified)
			if err := check(modified); err == nil {
				t.Fatal("drifted four-process ordering accepted")
			}
		})
	}
}

func TestSlice6FourPID1V2CaptureNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_FOUR_PID1_CAPTURE_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_FOUR_PID1_CAPTURE_NO_ISSUER=1 for four-process Docker collector drill")
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
			t.Errorf("four PID1 no-issuer exact cleanup: %v", err)
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
	defer func() {
		if err := evidence.closeV2Incomplete(); err != nil {
			t.Errorf("v2 incomplete marker: %v", err)
		}
	}()
	recorder, err := newSlice6GuestRecoveryERecorder(run.id)
	if err != nil {
		t.Fatal(err)
	}
	const imageID = "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"
	profile := "sha256:" + strings.Repeat("a", 64)
	var captures []*slice6GuestRecoveryCapture
	ids := make(map[string]bool)
	for index, process := range []string{"product-a", "guest-a", "product-b", "guest-b"} {
		role := strings.TrimSuffix(strings.TrimSuffix(process, "-a"), "-b")
		config := "sha256:" + strings.Repeat(string(rune('b'+index)), 64)
		begin := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
			Role: role, Event: "begin", Sequence: 1, ElapsedNanos: 1,
			UnixMillis: 1_700_000_000_000, ProfileDigest: profile, ConfigDigest: config}
		seal := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
			Role: role, Event: "seal", Sequence: 2, ElapsedNanos: 2,
			UnixMillis: 1_700_000_000_001}
		beginJSON, err := json.Marshal(begin)
		if err != nil {
			t.Fatal(err)
		}
		sealJSON, err := json.Marshal(seal)
		if err != nil {
			t.Fatal(err)
		}
		created, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-v2-capture-"+process+"-"+run.id,
			"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no",
			"--user=65532:65532", "--read-only", "--cap-drop=ALL",
			"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
			"-e", "BEGIN="+string(beginJSON), "-e", "SEAL="+string(sealJSON),
			"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec",
			"printf '%s\\n' \"$BEGIN\"; sleep 4; printf '%s\\n' \"$SEAL\"")
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) || ids[id] {
			t.Fatal("distinct bounded PID1 create unavailable")
		}
		ids[id] = true
		if _, err := slice6StartGuestRecoveryCapture(ctx, run, evidence, process, id,
			"sha256:"+strings.Repeat("f", 64), slice6PinnedAlpineImage, profile, config); err == nil {
			t.Fatal("preflight admitted a stale selected image before creating the private file")
		}
		var recording []*slice6GuestRecoveryERecorder
		if index >= 2 {
			recording = []*slice6GuestRecoveryERecorder{recorder}
		}
		capture, err := slice6StartGuestRecoveryCapture(ctx, run, evidence, process, id, imageID,
			slice6PinnedAlpineImage, profile, config, recording...)
		if err != nil {
			t.Fatal("start attached v2 Docker capture unavailable")
		}
		defer capture.abort()
		captures = append(captures, capture)
		if index >= 2 {
			var observed error
			for attempt := 0; attempt < 30 && ctx.Err() == nil; attempt++ {
				observed = capture.observeRunning(ctx, run)
				if observed == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if observed != nil {
				t.Fatal("real replacement PID1 start observation unavailable")
			}
		}
	}
	pids := make(map[int]bool)
	for _, capture := range captures {
		var observed error
		if capture.pid == 0 {
			for attempt := 0; attempt < 30 && ctx.Err() == nil; attempt++ {
				observed = capture.observeRunning(ctx, run)
				if observed == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		if observed != nil || pids[capture.pid] {
			t.Fatal("four distinct live Docker PID1 identities unavailable")
		}
		pids[capture.pid] = true
	}
	if len(recorder.events) != 4 || recorder.events[0].Kind != "product_b_start_call" ||
		recorder.events[1].Kind != "product_b_start_observed" ||
		recorder.events[2].Kind != "guest_b_start_call" ||
		recorder.events[3].Kind != "guest_b_start_observed" {
		t.Fatal("real no-issuer replacement start call/observation journal drift")
	}
	for _, capture := range captures {
		binding, records, err := capture.verifyStopped(ctx, run, 0)
		if err != nil || len(records) != 2 || binding.Process != capture.process ||
			binding.ContainerID != capture.id || binding.PID != capture.pid || binding.Bytes < 1 {
			t.Fatalf("four-process v2 raw identity unavailable: process=%s err=%v", capture.process, err)
		}
		if (capture.process == "product-b" || capture.process == "guest-b") &&
			evidence.verifyGuestRecoveryStartRaw(binding) != nil {
			t.Fatal("real replacement start raw not bound to final PID1")
		}
	}
}

// Real no-issuer lifecycle mechanics only: two disposable PID1 shells emit
// begin/seal on SIGTERM. No signed Guest recovery or formal E source exists.
func TestSlice6OldAStopRecorderNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_A_STOP_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_A_STOP_NO_ISSUER=1 for A stop recorder drill")
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
			t.Errorf("A stop recorder exact cleanup: %v", err)
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
	const imageID = "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"
	profile := "sha256:" + strings.Repeat("a", 64)
	var captures [2]*slice6GuestRecoveryCapture
	for index, process := range []string{"product-a", "guest-a"} {
		role := strings.TrimSuffix(process, "-a")
		config := "sha256:" + strings.Repeat(string(rune('b'+index)), 64)
		begin := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
			Role: role, Event: "begin", Sequence: 1, ElapsedNanos: 1,
			UnixMillis: 1_700_000_000_000, ProfileDigest: profile, ConfigDigest: config}
		seal := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
			Role: role, Event: "seal", Sequence: 2, ElapsedNanos: 2,
			UnixMillis: 1_700_000_000_001}
		beginJSON, err := json.Marshal(begin)
		if err != nil {
			t.Fatal(err)
		}
		sealJSON, err := json.Marshal(seal)
		if err != nil {
			t.Fatal(err)
		}
		created, createErr := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-v2-stop-"+process+"-"+run.id,
			"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no",
			"--user=65532:65532", "--read-only", "--cap-drop=ALL",
			"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
			"-e", "BEGIN="+string(beginJSON), "-e", "SEAL="+string(sealJSON),
			"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec",
			`printf '%s\n' "$BEGIN"; trap 'printf "%s\n" "$SEAL"; exit 0' TERM; while :; do sleep 0.1; done`)
		id := strings.TrimSpace(string(created))
		if createErr != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("create exact A stop PID1")
		}
		capture, err := slice6StartGuestRecoveryCapture(ctx, run, evidence, process, id,
			imageID, slice6PinnedAlpineImage, profile, config, recorder)
		if err != nil {
			t.Fatal("start exact A stop PID1 capture")
		}
		defer capture.abort()
		for attempt := 0; attempt < 30 && ctx.Err() == nil; attempt++ {
			if capture.observeRunning(ctx, run) == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if capture.pid < 1 {
			t.Fatal("observe A PID1 running")
		}
		captures[index] = capture
	}
	binding, records, err := slice6StopGuestRecoveryCaptureRecorded(ctx, run, captures[1])
	if err != nil || len(records) != 2 || !guestRevokeFixtureDigestGate(binding.SHA256) {
		t.Fatalf("real Guest-A stop/exit/seal unavailable: %v", err)
	}
	if _, _, err := slice6StopGuestRecoveryCaptureRecorded(ctx, run, captures[0]); err == nil {
		t.Fatal("Product-A normal stop admitted without recovered live close observation")
	}
	kinds := []string{"guest_a_stop_call", "guest_a_exit_observed", "guest_a_sealed"}
	if len(recorder.events) != len(kinds) {
		t.Fatal("real A stop event count drift")
	}
	for index, want := range kinds {
		if recorder.events[index].Kind != want || recorder.events[index].Sequence != uint64(index+1) ||
			(index > 0 && recorder.events[index].ElapsedNanos <= recorder.events[index-1].ElapsedNanos) {
			t.Fatal("real A stop call/exit/seal monotonic journal drift")
		}
	}
}

func TestSlice6LiveV2ClosePrefixNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_PREFIX_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_PREFIX_NO_ISSUER=1 for attached live-prefix drill")
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
			t.Errorf("live-prefix exact cleanup: %v", err)
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
	defer func() {
		if err := evidence.closeV2Incomplete(); err != nil {
			t.Errorf("live-prefix incomplete marker: %v", err)
		}
	}()
	profile := "sha256:" + strings.Repeat("a", 64)
	initial := "sha256:" + strings.Repeat("b", 64)
	stamp := time.Now().UnixMilli()
	build := func(role, config string, events [][2]string) (string, string) {
		t.Helper()
		records := []phase6guestreceipt.Record{{Protocol: phase6guestreceipt.ProtocolV2,
			Role: role, Event: "begin", ProfileDigest: profile, ConfigDigest: config}}
		for _, event := range events {
			records = append(records, phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
				Role: role, Event: event[0], Reason: event[1],
				AttemptDigest: initial, BindingGeneration: 1})
		}
		var prefix strings.Builder
		for index := range records {
			records[index].Sequence = uint64(index + 1)
			records[index].ElapsedNanos = int64(index + 1)
			records[index].UnixMillis = stamp
			encoded, err := json.Marshal(records[index])
			if err != nil {
				t.Fatal(err)
			}
			prefix.Write(encoded)
			prefix.WriteByte('\n')
		}
		return prefix.String(), config
	}
	productEvents := [][2]string{
		{"product_auth_accepted", ""}, {"product_welcome_written", ""},
		{"product_peer_installed", ""}, {"product_authority_dependency_lost", ""},
		{"product_disconnect_pending", ""}, {"product_close_completed", "dependency_lost"},
	}
	guestEvents := [][2]string{
		{"guest_hello_written", ""}, {"guest_welcome_accepted", ""},
		{"guest_read_terminated", ""},
	}
	const imageID = "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"
	makeCapture := func(process string, events [][2]string, config string) *slice6GuestRecoveryCapture {
		t.Helper()
		role := strings.TrimSuffix(process, "-a")
		prefix, _ := build(role, config, events)
		created, err := run.docker(ctx, "create", "--pull=never",
			"--name", "sr-p6-v2-prefix-"+process+"-"+run.id,
			"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no",
			"--user=65532:65532", "--read-only", "--cap-drop=ALL",
			"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
			"-e", "PREFIX="+prefix, "--entrypoint=/bin/sh", slice6PinnedAlpineImage,
			"-ec", "printf '%s' \"$PREFIX\"; sleep 12")
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("create exact no-issuer prefix PID1")
		}
		capture, err := slice6StartGuestRecoveryCapture(ctx, run, evidence, process, id,
			imageID, slice6PinnedAlpineImage, profile, config)
		if err != nil {
			t.Fatal("start attached no-issuer prefix PID1")
		}
		for attempt := 0; attempt < 30 && ctx.Err() == nil; attempt++ {
			if capture.observeRunning(ctx, run) == nil {
				return capture
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("observe live no-issuer prefix PID1")
		return nil
	}
	product := makeCapture("product-a", productEvents, "sha256:"+strings.Repeat("c", 64))
	defer product.abort()
	guest := makeCapture("guest-a", guestEvents, "sha256:"+strings.Repeat("d", 64))
	defer guest.abort()
	observe, stopObserve := context.WithTimeout(ctx, 5*time.Second)
	defer stopObserve()
	trigger, err := slice6ObserveGuestRecoveryInitialClose(observe, run, product, guest, initial, 1)
	if err != nil || trigger.RunID != run.id || trigger.ProductID != product.id ||
		trigger.GuestID != guest.id || trigger.ProductPID != product.pid ||
		trigger.GuestPID != guest.pid || trigger.ProductPrefixBytes < 1 ||
		trigger.GuestPrefixBytes < 1 {
		t.Fatalf("attached live v2 close prefix unavailable: %v", err)
	}
}
