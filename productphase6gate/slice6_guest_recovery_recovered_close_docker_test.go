//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
)

// This uses synthetic v2 PID1 emitters to exercise the real Docker capture,
// Guest seal, live Product observation and guarded Product stop. It is not a
// real Product/Guest runtime or an E admission/issuer run.
func TestSlice6RecoveredCloseStopOrderNoIssuerDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_RECOVERED_CLOSE_NO_ISSUER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_SLICE6_RECOVERED_CLOSE_NO_ISSUER=1")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	dockerRun, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := dockerRun.cleanup(cleanup); err != nil {
			t.Errorf("recovered-close exact Docker cleanup: %v", err)
		}
	})
	privateRoot := filepath.Join(t.TempDir(), "private")
	if os.Mkdir(privateRoot, 0o700) != nil {
		t.Fatal("create private recovered-close root")
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
	run, err := root.newRun(dockerRun.id)
	if err != nil {
		t.Fatal(err)
	}
	defer run.closeV2Incomplete()
	recorder, err := newSlice6GuestRecoveryERecorder(dockerRun.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{
		"source_complete", "initial_sql_call", "initial_sql_observed", "pg_down_call", "pg_down_observed",
		"trigger_observed", "guest_off_call", "guest_off_observed", "pg_up_call", "pg_up_observed",
		"released_sql_call", "released_sql_observed", "guest_on_call", "guest_on_observed",
		"reconnected_sql_call", "reconnected_sql_observed",
	} {
		if err := recorder.record(kind, slice6ReceiptSHA256([]byte(kind))); err != nil {
			t.Fatal(err)
		}
	}
	profile := "sha256:" + strings.Repeat("a", 64)
	productConfig := "sha256:" + strings.Repeat("b", 64)
	guestConfig := "sha256:" + strings.Repeat("c", 64)
	initial := "sha256:" + strings.Repeat("d", 64)
	recovered := "sha256:" + strings.Repeat("e", 64)
	productEvents := []slice6SyntheticEvent{
		{guestagent.ObservationProductAuthAccepted, initial, ""},
		{guestagent.ObservationProductWelcomeWritten, initial, ""},
		{guestagent.ObservationProductPeerInstalled, initial, ""},
		{guestagent.ObservationProductAuthorityDependencyLost, initial, ""},
		{guestagent.ObservationProductDisconnectPending, initial, ""},
		{guestagent.ObservationProductCloseCompleted, initial, "dependency_lost"},
		{guestagent.ObservationProductDisconnectResolved, initial, "released"},
		{guestagent.ObservationProductAuthAccepted, recovered, ""},
		{guestagent.ObservationProductWelcomeWritten, recovered, ""},
		{guestagent.ObservationProductPeerInstalled, recovered, ""},
		{guestagent.ObservationProductDisconnectPending, recovered, ""},
		{guestagent.ObservationProductCloseCompleted, recovered, "handler_shutdown"},
		{guestagent.ObservationProductDisconnectResolved, recovered, "released"},
	}
	guestEvents := []slice6SyntheticEvent{
		{guestagent.ObservationGuestHelloWritten, initial, ""},
		{guestagent.ObservationGuestWelcomeAccepted, initial, ""},
		{guestagent.ObservationGuestReadTerminated, initial, ""},
		{guestagent.ObservationGuestHelloWritten, recovered, ""},
		{guestagent.ObservationGuestWelcomeAccepted, recovered, ""},
		{guestagent.ObservationGuestReadTerminated, recovered, ""},
	}
	productLines := slice6RecoveredCloseSyntheticLines(t, "product", profile, productConfig, productEvents)
	guestLines := slice6RecoveredCloseSyntheticLines(t, "guest", profile, guestConfig, guestEvents)
	const imageID = "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c"
	create := func(process string, prefix, tail, seal []string, onSignal bool) *slice6GuestRecoveryCapture {
		t.Helper()
		config := productConfig
		if process == "guest-a" {
			config = guestConfig
		}
		// stdout is the exact v2 original. Product's recovered close is emitted
		// only after Guest-A has stopped and the diagnostic sends USR1.
		script := `printf '%s\n' "$PREFIX"; trap 'printf "%s\n" "$SEAL"; exit 0' TERM; while :; do sleep 0.05; done`
		if onSignal {
			script = `printf '%s\n' "$PREFIX"; trap 'printf "%s\n" "$TAIL"' USR1; trap 'printf "%s\n" "$SEAL"; exit 0' TERM; while :; do sleep 0.05; done`
		}
		created, createErr := dockerRun.docker(ctx, "create", "--pull=never",
			"--name", "sr-p6-v2-recovered-"+process+"-"+dockerRun.id,
			"--label", dockerRun.label(), "--log-driver=none", "--network=none", "--restart=no",
			"--user=65532:65532", "--read-only", "--cap-drop=ALL",
			"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
			"-e", "PREFIX="+strings.Join(prefix, "\n"), "-e", "TAIL="+strings.Join(tail, "\n"),
			"-e", "SEAL="+strings.Join(seal, "\n"),
			"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec", script)
		id := strings.TrimSpace(string(created))
		if createErr != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("create recovered-close PID1")
		}
		capture, startErr := slice6StartGuestRecoveryCapture(ctx, dockerRun, run, process,
			id, imageID, slice6PinnedAlpineImage, profile, config, recorder)
		if startErr != nil {
			t.Fatalf("start recovered-close PID1: %v", startErr)
		}
		t.Cleanup(capture.abort)
		for attempt := 0; attempt < 40 && ctx.Err() == nil; attempt++ {
			if capture.observeRunning(ctx, dockerRun) == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if capture.pid < 1 {
			t.Fatal("observe recovered-close PID1 running")
		}
		return capture
	}
	product := create("product-a", productLines[:12], productLines[12:14], productLines[14:], true)
	guest := create("guest-a", guestLines[:6], nil, guestLines[6:], false)
	if _, _, err := slice6StopGuestRecoveryCaptureRecorded(ctx, dockerRun, product); err == nil {
		t.Fatal("Product normal stop admitted before Guest seal/recovered observation")
	}
	guestBinding, _, err := slice6StopGuestRecoveryCaptureRecorded(ctx, dockerRun, guest)
	if err != nil {
		t.Fatalf("Guest-A stop/seal: %v", err)
	}
	if _, _, err := slice6StopGuestRecoveryCaptureRecorded(ctx, dockerRun, product); err == nil {
		t.Fatal("Product normal stop admitted after Guest seal but before recovered release")
	}
	if _, err := dockerRun.docker(ctx, "kill", "--signal=USR1", product.id); err != nil {
		t.Fatal("signal exact Product diagnostic PID1")
	}
	digest, err := slice6ObserveGuestRecoveryRecoveredClose(ctx, dockerRun, product,
		guestBinding, initial, recovered, 1)
	if err != nil || !guestRevokeFixtureDigestGate(digest) {
		t.Fatalf("live recovered close not observed after Guest seal: %v", err)
	}
	if _, err := slice6ObserveGuestRecoveryRecoveredClose(ctx, dockerRun, product,
		guestBinding, initial, recovered, 1); err == nil {
		t.Fatal("replayed live recovered-close observation accepted")
	}
	productBinding, _, err := slice6StopGuestRecoveryCaptureRecorded(ctx, dockerRun, product)
	if err != nil {
		t.Fatalf("Product normal stop after recovered close: %v", err)
	}
	if _, err := slice6ObserveGuestRecoveryRecoveredClose(ctx, dockerRun, product,
		guestBinding, initial, recovered, 1); err == nil {
		t.Fatal("post-stop recovered-close observation accepted")
	}
	if len(recorder.events) != 23 || recorder.events[19].Kind != "recovered_close_observed" ||
		recorder.events[19].ReferenceDigest != digest ||
		recorder.events[20].Kind != "product_a_stop_call" ||
		recorder.events[22].Kind != "product_a_sealed" {
		t.Fatal("recovered close did not precede Product stop in one recorder")
	}
	if productBinding.SHA256 == "" || guestBinding.SHA256 == "" {
		t.Fatal("A PID1 originals not sealed")
	}
	input := slice6GuestRecoveryPrecleanupInput{
		Source:              slice6GuestOperatorFormalSource{profileDigest: profile},
		ProductConfigDigest: productConfig, GuestConfigDigest: guestConfig,
		InitialAttemptDigest: initial, RecoveredAttemptDigest: recovered,
		RecoveredCloseDigest: digest, Generation: 1,
	}
	input.Process[0], input.Process[1] = productBinding, guestBinding
	if err := run.verifyGuestRecoveryRecoveredClose(input); err != nil {
		t.Fatalf("sealed originals did not replay live observation: %v", err)
	}
	wrong := input
	wrong.Process[0].ContainerID = strings.Repeat("f", 64)
	if run.verifyGuestRecoveryRecoveredClose(wrong) == nil {
		t.Fatal("observation replay accepted replacement Product identity")
	}
	wrong = input
	wrong.RecoveredAttemptDigest = initial
	if run.verifyGuestRecoveryRecoveredClose(wrong) == nil {
		t.Fatal("observation replay accepted initial attempt as recovery")
	}
	original, err := run.readFile(productBinding.File, phase6guestreceipt.MaxTotalBytes)
	if err != nil {
		t.Fatal(err)
	}
	index := bytes.Index(original, []byte(`"unix_millis":`))
	if index < 0 {
		t.Fatal("Product original has no timestamp for same-inode tamper")
	}
	index += len(`"unix_millis":`)
	changed := append([]byte(nil), original...)
	if changed[index] != '1' {
		t.Fatal("unexpected Product timestamp digit")
	}
	changed[index] = '2'
	file, err := os.OpenFile(filepath.Join(privateRoot, dockerRun.id, productBinding.File), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	written, writeErr := file.WriteAt(changed[index:index+1], int64(index))
	if written != 1 || writeErr != nil || file.Sync() != nil || file.Close() != nil {
		t.Fatal("same-inode Product original tamper failed")
	}
	wrong = input
	wrong.Process[0].SHA256 = slice6ReceiptSHA256(changed)
	if run.verifyGuestRecoveryRecoveredClose(wrong) == nil {
		t.Fatal("same-inode Product prefix tamper replayed as observed close")
	}
}

func slice6RecoveredCloseSyntheticLines(t *testing.T, role, profile, config string,
	events []slice6SyntheticEvent) []string {
	t.Helper()
	lines := make([]string, 0, len(events)+2)
	base := time.Now().UnixMilli()
	for index := 0; index < len(events)+2; index++ {
		record := phase6guestreceipt.Record{Protocol: phase6guestreceipt.ProtocolV2,
			Role: role, Sequence: uint64(index + 1), ElapsedNanos: int64(index), UnixMillis: base}
		switch index {
		case 0:
			record.Event, record.ProfileDigest, record.ConfigDigest = "begin", profile, config
		case len(events) + 1:
			record.Event, record.EventCount = "seal", uint64(len(events))
		default:
			item := events[index-1]
			record.Event, record.AttemptDigest = item.event, item.digest
			record.BindingGeneration, record.Reason = 1, item.reason
		}
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal("encode synthetic recovered-close record")
		}
		lines = append(lines, string(raw))
	}
	return lines
}
