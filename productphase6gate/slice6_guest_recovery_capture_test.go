//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"golang.org/x/sys/unix"
)

// An unfinished v2 collection never writes the historical v1 incomplete
// marker or any accepted evidence binding.
func (run *slice6ReceiptEvidenceRun) closeV2Incomplete() error {
	if run == nil || run.check() != nil || run.complete {
		return phase6guestreceipt.ErrUnavailable
	}
	err := run.writeDocument("incomplete.json", struct {
		Protocol    string `json:"protocol"`
		Disposition string `json:"disposition"`
		RunID       string `json:"run_id"`
		RecordedUTC string `json:"recorded_utc"`
	}{"sandbox-runtime.phase6-guest-recovery-evidence.v2", "incomplete", run.id,
		time.Now().UTC().Format(time.RFC3339Nano)})
	run.mu.Lock()
	run.closed = true
	run.mu.Unlock()
	closeErr := unix.Close(run.fd)
	run.fd = -1
	if err != nil || closeErr != nil {
		return phase6guestreceipt.ErrUnavailable
	}
	return nil
}

// A and B are exact, distinct Product/Guest PID1 lifetimes. This E-only
// collector is not a fault/readback/cleanup verifier or an issuer gate.
func slice6GuestRecoveryRawName(process string) string {
	switch process {
	case "product-a", "guest-a", "product-b", "guest-b":
		return process + "-pid1.stdout"
	default:
		return ""
	}
}

type slice6GuestRecoveryCapture struct {
	cmd                  *exec.Cmd
	cancel               context.CancelFunc
	file                 *os.File
	output               *slice6ReceiptBoundedFile
	done                 chan struct{}
	waitErr              error
	finish               sync.Once
	fileErr              error
	run                  *slice6ReceiptEvidenceRun
	process              string
	role                 string
	id                   string
	image                string
	imageRef             string
	profile              string
	config               string
	path                 string
	pid                  int
	startedAt            string
	captureStarted       time.Time
	recorder             *slice6GuestRecoveryERecorder
	startInspectSHA256   string
	stopAdmitted         bool
	recoveredCloseDigest string
}

type slice6GuestRecoveryRawBinding struct {
	Process            string
	Role               string
	File               string
	RunID              string
	ContainerID        string
	PID                int
	StartedAt          string
	FinishedAt         string
	ImageID            string
	ImageRef           string
	ProfileDigest      string
	ConfigDigest       string
	SHA256             string
	Bytes              int
	ExitCode           int
	CaptureStartUTC    string
	CaptureFinishUTC   string
	StartInspectSHA256 string
}

func slice6GuestRecoveryStartInspectName(process string) string {
	switch process {
	case "product-b", "guest-b":
		return process + "-start.inspect"
	default:
		return ""
	}
}

// This checks only immutable four-process structure. It does not assert a PG
// fault, old nonce release, valid v2 causal pairs or complete resource cleanup.
// Those independent observations are mandatory before any persistent binding.
func slice6VerifyGuestRecoveryProcessOrder(runID, profile, image, imageRef string,
	bindings [4]slice6GuestRecoveryRawBinding, exits [4]int) error {
	if len(runID) != 32 || !lowerHexSlice6(runID) ||
		!guestRevokeFixtureDigestGate(profile) || !guestRevokeFixtureDigestGate(image) || imageRef == "" {
		return phase6guestreceipt.ErrUnavailable
	}
	wantProcess := [4]string{"product-a", "guest-a", "product-b", "guest-b"}
	ids := make(map[string]bool, 4)
	pids := make(map[int]bool, 4)
	starts := make(map[string]bool, 4)
	rawDigests := make(map[string]bool, 4)
	var startedAt, finishedAt [4]time.Time
	for index, binding := range bindings {
		start, startErr := time.Parse(time.RFC3339Nano, binding.StartedAt)
		finish, finishErr := time.Parse(time.RFC3339Nano, binding.FinishedAt)
		captureStart, captureStartErr := time.Parse(time.RFC3339Nano, binding.CaptureStartUTC)
		captureFinish, captureFinishErr := time.Parse(time.RFC3339Nano, binding.CaptureFinishUTC)
		if binding.Process != wantProcess[index] || binding.Role != strings.SplitN(binding.Process, "-", 2)[0] ||
			binding.File != slice6GuestRecoveryRawName(binding.Process) || binding.RunID != runID ||
			len(binding.ContainerID) != 64 || !lowerHexSlice6(binding.ContainerID) || ids[binding.ContainerID] ||
			binding.PID < 1 || binding.PID > 1<<22 || pids[binding.PID] ||
			startErr != nil || finishErr != nil || !finish.After(start) || starts[binding.StartedAt] ||
			captureStartErr != nil || captureFinishErr != nil || !captureFinish.After(captureStart) ||
			binding.ImageID != image || binding.ImageRef != imageRef || binding.ProfileDigest != profile ||
			!guestRevokeFixtureDigestGate(binding.ConfigDigest) || !guestRevokeFixtureDigestGate(binding.SHA256) ||
			rawDigests[binding.SHA256] || binding.Bytes < 1 || binding.Bytes > phase6guestreceipt.MaxTotalBytes ||
			binding.ExitCode != exits[index] {
			return phase6guestreceipt.ErrUnavailable
		}
		ids[binding.ContainerID], pids[binding.PID] = true, true
		starts[binding.StartedAt], rawDigests[binding.SHA256] = true, true
		startedAt[index], finishedAt[index] = start, finish
	}
	if bindings[0].ConfigDigest != bindings[2].ConfigDigest ||
		bindings[1].ConfigDigest != bindings[3].ConfigDigest ||
		!startedAt[0].Before(startedAt[1]) || !startedAt[1].Before(finishedAt[0]) ||
		!startedAt[2].Before(startedAt[3]) || !startedAt[3].Before(finishedAt[2]) {
		return phase6guestreceipt.ErrUnavailable
	}
	for _, old := range finishedAt[:2] {
		for _, replacement := range startedAt[2:] {
			if !replacement.After(old) {
				return phase6guestreceipt.ErrUnavailable
			}
		}
	}
	return nil
}

func slice6StartGuestRecoveryCapture(parent context.Context, dockerRun slice6DockerRun, run *slice6ReceiptEvidenceRun,
	process, id, image, imageRef, profile, config string,
	recorders ...*slice6GuestRecoveryERecorder) (*slice6GuestRecoveryCapture, error) {
	return slice6StartGuestRecoveryCaptureWithPreflight(parent, parent, dockerRun, run,
		process, id, image, imageRef, profile, config, recorders...)
}

// The startup budget may be shorter than the PID1 lifetime. Never use the
// startup context as the docker-start -a parent: canceling it after readiness
// would kill the collector while the actual container remained alive.
func slice6StartGuestRecoveryCaptureWithPreflight(parent, startup context.Context,
	dockerRun slice6DockerRun, run *slice6ReceiptEvidenceRun,
	process, id, image, imageRef, profile, config string,
	recorders ...*slice6GuestRecoveryERecorder) (*slice6GuestRecoveryCapture, error) {
	name := slice6GuestRecoveryRawName(process)
	var recorder *slice6GuestRecoveryERecorder
	if len(recorders) > 1 {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	if len(recorders) == 1 {
		recorder = recorders[0]
	}
	if parent == nil || parent.Err() != nil || startup == nil || startup.Err() != nil ||
		run == nil || run.check() != nil ||
		dockerRun.id != run.id || name == "" ||
		(recorder != nil && recorder.runID != run.id) ||
		len(id) != 64 || !lowerHexSlice6(id) || !guestRevokeFixtureDigestGate(image) ||
		imageRef == "" || !guestRevokeFixtureDigestGate(profile) || !guestRevokeFixtureDigestGate(config) {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	// Inspect before start or file creation: an arbitrary old ID, another run,
	// already-running process, stale image or log-driver cannot be attached.
	preflight, err, overflow := slice6DockerBounded(startup, 640, nil, "inspect", "--format",
		"{{.Id}} {{.Image}} {{.Config.Image}} {{index .Config.Labels \""+slice6RunLabel+"\"}} {{.HostConfig.LogConfig.Type}} {{.Config.Tty}} {{.State.Status}} {{.State.Running}} {{.State.Pid}} {{.State.OOMKilled}}", id)
	fields := strings.Fields(string(preflight))
	clear(preflight)
	if err != nil || overflow || startup.Err() != nil || len(fields) != 10 || fields[0] != id ||
		fields[1] != image || fields[2] != imageRef || fields[3] != dockerRun.id ||
		fields[4] != "none" || fields[5] != "false" || fields[6] != "created" ||
		fields[7] != "false" || fields[8] != "0" || fields[9] != "false" {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	file, err := run.createV2RawFile(name)
	if err != nil {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	output := &slice6ReceiptBoundedFile{file: file}
	cmd := exec.CommandContext(ctx, "docker", "start", "-a", id)
	cmd.Stdout, cmd.Stderr = output, io.Discard
	cmd.WaitDelay = 2 * time.Second
	captureStarted := time.Now().UTC()
	if recorder != nil && slice6GuestRecoveryStartInspectName(process) != "" {
		startCall := slice6GuestRecoveryRawBinding{Process: process, RunID: run.id,
			ContainerID: id, ImageID: image, ImageRef: imageRef,
			ProfileDigest: profile, ConfigDigest: config}
		if recorder.record(strings.ReplaceAll(process, "-", "_")+"_start_call", slice6GuestRecoveryStartCallRef(startCall)) != nil {
			cancel()
			_ = file.Close()
			return nil, phase6guestreceipt.ErrUnavailable
		}
	}
	if startup.Err() != nil {
		cancel()
		_ = file.Close()
		return nil, phase6guestreceipt.ErrUnavailable
	}
	if err := cmd.Start(); err != nil {
		cancel()
		_ = file.Close()
		return nil, phase6guestreceipt.ErrUnavailable
	}
	role := strings.TrimSuffix(process, "-a")
	role = strings.TrimSuffix(role, "-b")
	capture := &slice6GuestRecoveryCapture{cmd: cmd, cancel: cancel, file: file,
		output: output, done: make(chan struct{}), run: run, process: process, role: role,
		id: id, image: image, imageRef: imageRef, profile: profile, config: config,
		path: run.root.path + "/" + run.id + "/" + name, captureStarted: captureStarted,
		recorder: recorder}
	go func() {
		capture.waitErr = cmd.Wait()
		close(capture.done)
	}()
	if startup.Err() != nil {
		capture.abort()
		return nil, phase6guestreceipt.ErrUnavailable
	}
	return capture, nil
}

// The formal E launcher uses this wrapper for both B starts. The component
// collector above remains available to no-issuer drills, but cannot by itself
// authorize replacement of A before the frozen pre-B admission is durable.
func slice6StartGuestRecoveryReplacementCapture(parent context.Context,
	dockerRun slice6DockerRun, run *slice6ReceiptEvidenceRun,
	process, id, image, imageRef, profile, config, beforeBDigest string,
	recorder *slice6GuestRecoveryERecorder) (*slice6GuestRecoveryCapture, error) {
	return slice6StartGuestRecoveryReplacementCaptureWithPreflight(parent, parent, dockerRun,
		run, process, id, image, imageRef, profile, config, beforeBDigest, recorder)
}

func slice6StartGuestRecoveryReplacementCaptureWithPreflight(parent, startup context.Context,
	dockerRun slice6DockerRun, run *slice6ReceiptEvidenceRun,
	process, id, image, imageRef, profile, config, beforeBDigest string,
	recorder *slice6GuestRecoveryERecorder) (*slice6GuestRecoveryCapture, error) {
	if parent == nil || parent.Err() != nil || run == nil || dockerRun.id != run.id ||
		startup == nil || startup.Err() != nil ||
		run.checkGuestRecoveryReplacementStart(process, beforeBDigest, recorder) != nil {
		return nil, phase6guestreceipt.ErrUnavailable
	}
	return slice6StartGuestRecoveryCaptureWithPreflight(parent, startup, dockerRun, run, process, id,
		image, imageRef, profile, config, recorder)
}

func (run *slice6ReceiptEvidenceRun) checkGuestRecoveryReplacementStart(
	process, beforeBDigest string, recorder *slice6GuestRecoveryERecorder) error {
	if run == nil || run.check() != nil || recorder == nil || recorder.runID != run.id ||
		!guestRevokeFixtureDigestGate(beforeBDigest) {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := run.readFile(slice6GuestRecoveryBeforeBFile, 96)
	if err != nil || string(raw) != beforeBDigest+"\n" {
		clear(raw)
		return errors.New("Guest E B start without durable predecessor admission")
	}
	clear(raw)
	recorder.mu.Lock()
	want := slice6GuestRecoveryBeforeBEventCount
	if process == "guest-b" {
		want += 2
	}
	valid := (process == "product-b" || process == "guest-b") &&
		!recorder.sealed && len(recorder.events) == want
	if valid && process == "guest-b" {
		valid = recorder.events[25].Kind == "product_b_start_call" &&
			recorder.events[26].Kind == "product_b_start_observed" &&
			recorder.events[25].Sequence == 26 && recorder.events[26].Sequence == 27 &&
			recorder.events[26].ElapsedNanos > recorder.events[25].ElapsedNanos &&
			guestRevokeFixtureDigestGate(recorder.events[25].ReferenceDigest) &&
			guestRevokeFixtureDigestGate(recorder.events[26].ReferenceDigest)
	}
	recorder.mu.Unlock()
	if !valid {
		return errors.New("Guest E B start event boundary unavailable")
	}
	return nil
}

func (capture *slice6GuestRecoveryCapture) abort() {
	if capture == nil {
		return
	}
	capture.cancel()
	<-capture.done
	capture.finish.Do(func() {
		capture.fileErr = errors.Join(capture.file.Sync(), capture.file.Close())
	})
}

// observeRunning must be called while Docker still reports the exact PID1 as
// running. A stopped inspect cannot retroactively prove which process ran.
func (capture *slice6GuestRecoveryCapture) observeRunning(ctx context.Context, run slice6DockerRun) error {
	if capture == nil || ctx == nil || ctx.Err() != nil || run.id != capture.run.id || capture.pid != 0 {
		return phase6guestreceipt.ErrUnavailable
	}
	output, err, overflow := slice6DockerBounded(ctx, 640, nil, "inspect", "--format",
		"{{.Id}} {{.Image}} {{.Config.Image}} {{index .Config.Labels \""+slice6RunLabel+"\"}} {{.HostConfig.LogConfig.Type}} {{.Config.Tty}} {{.State.Running}} {{.State.Pid}} {{.State.StartedAt}} {{.State.OOMKilled}}", capture.id)
	defer clear(output)
	fields := strings.Fields(string(output))
	if err != nil || overflow || len(fields) != 10 || fields[0] != capture.id ||
		fields[1] != capture.image || fields[2] != capture.imageRef || fields[3] != run.id ||
		fields[4] != "none" || fields[5] != "false" || fields[6] != "true" || fields[9] != "false" {
		return phase6guestreceipt.ErrUnavailable
	}
	pid, err := strconv.Atoi(fields[7])
	started, timeErr := time.Parse(time.RFC3339Nano, fields[8])
	if err != nil || pid < 1 || pid > 1<<22 || timeErr != nil || started.IsZero() {
		return phase6guestreceipt.ErrUnavailable
	}
	select {
	case <-capture.done:
		return phase6guestreceipt.ErrUnavailable
	default:
	}
	capture.pid, capture.startedAt = pid, fields[8]
	if capture.recorder != nil && slice6GuestRecoveryStartInspectName(capture.process) != "" {
		name := slice6GuestRecoveryStartInspectName(capture.process)
		if name == "" || capture.run.writeV2BoundedPrivateFile(name, output, 640, false) != nil {
			return phase6guestreceipt.ErrUnavailable
		}
		capture.startInspectSHA256 = slice6ReceiptSHA256(output)
		observed := slice6GuestRecoveryRawBinding{Process: capture.process, RunID: run.id,
			ContainerID: capture.id, PID: capture.pid, StartedAt: capture.startedAt,
			StartInspectSHA256: capture.startInspectSHA256}
		if capture.recorder.record(strings.ReplaceAll(capture.process, "-", "_")+"_start_observed",
			slice6GuestRecoveryStartObservedRef(observed)) != nil {
			return phase6guestreceipt.ErrUnavailable
		}
	}
	return nil
}

// readLivePrefix takes an inode-checked snapshot while the bounded stdout
// writer is between writes. A partial Docker chunk is pending, never silently
// truncated into evidence. The final stopped verifier must reread the file.
func (capture *slice6GuestRecoveryCapture) readLivePrefix(ctx context.Context) ([]byte, bool, error) {
	if capture == nil || ctx == nil || ctx.Err() != nil || capture.pid < 1 ||
		capture.run == nil || capture.run.check() != nil || capture.output == nil {
		return nil, false, phase6guestreceipt.ErrUnavailable
	}
	select {
	case <-capture.done:
		return nil, false, phase6guestreceipt.ErrUnavailable
	default:
	}
	capture.output.mu.Lock()
	document, err := capture.run.readFile(slice6GuestRecoveryRawName(capture.process),
		phase6guestreceipt.MaxTotalBytes)
	written, overflow := capture.output.written, capture.output.overflow
	capture.output.mu.Unlock()
	if err != nil || overflow || len(document) != written || len(document) > phase6guestreceipt.MaxTotalBytes {
		clear(document)
		return nil, false, phase6guestreceipt.ErrUnavailable
	}
	if len(document) == 0 || document[len(document)-1] != '\n' {
		clear(document)
		return nil, false, nil
	}
	if _, err := phase6guestreceipt.VerifyV2OpenPrefix(document, capture.role,
		capture.profile, capture.config); err != nil {
		clear(document)
		return nil, false, err
	}
	return document, true, nil
}

func (capture *slice6GuestRecoveryCapture) confirmStillRunning(ctx context.Context,
	run slice6DockerRun) error {
	if capture == nil || ctx == nil || ctx.Err() != nil || capture.pid < 1 ||
		capture.startedAt == "" || run.id != capture.run.id {
		return phase6guestreceipt.ErrUnavailable
	}
	output, err, overflow := slice6DockerBounded(ctx, 640, nil, "inspect", "--format",
		"{{.Id}} {{.Image}} {{.Config.Image}} {{index .Config.Labels \""+slice6RunLabel+"\"}} {{.State.Running}} {{.State.Pid}} {{.State.StartedAt}} {{.State.OOMKilled}}", capture.id)
	defer clear(output)
	fields := strings.Fields(string(output))
	if err != nil || overflow || len(fields) != 8 || fields[0] != capture.id ||
		fields[1] != capture.image || fields[2] != capture.imageRef || fields[3] != run.id ||
		fields[4] != "true" || fields[5] != strconv.Itoa(capture.pid) ||
		fields[6] != capture.startedAt || fields[7] != "false" {
		return phase6guestreceipt.ErrUnavailable
	}
	select {
	case <-capture.done:
		return phase6guestreceipt.ErrUnavailable
	default:
		return nil
	}
}

type slice6GuestRecoveryCloseTrigger struct {
	RunID, ProductID, GuestID              string
	ProductPID, GuestPID                   int
	ProductStart, GuestStart               string
	ProductPrefixSHA256, GuestPrefixSHA256 string
	ProductPrefixBytes, GuestPrefixBytes   int
	ObservedUTC                            string
}

// This is a live action trigger, not a final receipt. The caller must
// separately prove Product's PG edge is still disconnected before using the
// one approved Guest isolation action.
func slice6ObserveGuestRecoveryInitialClose(ctx context.Context, run slice6DockerRun,
	product, guest *slice6GuestRecoveryCapture, initialDigest string, generation int64) (slice6GuestRecoveryCloseTrigger, error) {
	if ctx == nil || ctx.Err() != nil || product == nil || guest == nil ||
		product.process != "product-a" || guest.process != "guest-a" ||
		product.run.id != run.id || guest.run.id != run.id ||
		product.profile != guest.profile || !guestRevokeFixtureDigestGate(initialDigest) || generation < 1 {
		return slice6GuestRecoveryCloseTrigger{}, phase6guestreceipt.ErrUnavailable
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for ctx.Err() == nil {
		productRaw, productReady, productErr := product.readLivePrefix(ctx)
		guestRaw, guestReady, guestErr := guest.readLivePrefix(ctx)
		if productErr != nil || guestErr != nil {
			clear(productRaw)
			clear(guestRaw)
			return slice6GuestRecoveryCloseTrigger{}, phase6guestreceipt.ErrUnavailable
		}
		if productReady && guestReady && phase6guestreceipt.VerifyV2InitialClosedPrefix(productRaw,
			guestRaw, product.profile, product.config, guest.config, initialDigest, generation) == nil {
			result := slice6GuestRecoveryCloseTrigger{RunID: run.id,
				ProductID: product.id, GuestID: guest.id,
				ProductPID: product.pid, GuestPID: guest.pid,
				ProductStart: product.startedAt, GuestStart: guest.startedAt,
				ProductPrefixSHA256: slice6ReceiptSHA256(productRaw),
				GuestPrefixSHA256:   slice6ReceiptSHA256(guestRaw),
				ProductPrefixBytes:  len(productRaw), GuestPrefixBytes: len(guestRaw),
				ObservedUTC: time.Now().UTC().Format(time.RFC3339Nano)}
			clear(productRaw)
			clear(guestRaw)
			if product.confirmStillRunning(ctx, run) != nil || guest.confirmStillRunning(ctx, run) != nil {
				return slice6GuestRecoveryCloseTrigger{}, phase6guestreceipt.ErrUnavailable
			}
			return result, nil
		}
		clear(productRaw)
		clear(guestRaw)
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	return slice6GuestRecoveryCloseTrigger{}, phase6guestreceipt.ErrUnavailable
}

// Stop the old PID1 through one exact run-owned Docker command. Only a
// confirmed stop response may proceed to exit inspection and zero-drop seal.
func slice6StopGuestRecoveryCaptureRecorded(ctx context.Context, run slice6DockerRun,
	capture *slice6GuestRecoveryCapture) (slice6GuestRecoveryRawBinding, []phase6guestreceipt.Record, error) {
	if ctx == nil || ctx.Err() != nil || capture == nil || capture.recorder == nil ||
		capture.run == nil || run.id != capture.run.id || capture.stopAdmitted ||
		(capture.process != "guest-a" && capture.process != "product-a") ||
		(capture.process == "product-a" && capture.checkRecoveredCloseBeforeStop(ctx) != nil) ||
		capture.confirmStillRunning(ctx, run) != nil {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	partial := slice6GuestRecoveryRawBinding{Process: capture.process, RunID: run.id,
		ContainerID: capture.id, PID: capture.pid, StartedAt: capture.startedAt}
	if capture.recorder.record(strings.ReplaceAll(capture.process, "-", "_")+"_stop_call",
		slice6GuestRecoveryStopCallRef(partial)) != nil {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	output, commandErr, overflow := slice6DockerBounded(ctx, 128, nil,
		"stop", "--timeout", "10", capture.id)
	responseOK := bytes.Equal(output, []byte(capture.id+"\n"))
	clear(output)
	if commandErr != nil || overflow || ctx.Err() != nil || !responseOK {
		return slice6GuestRecoveryRawBinding{}, nil, errors.New("Guest A stop outcome unconfirmed")
	}
	capture.stopAdmitted = true
	return capture.verifyStopped(ctx, run, 0)
}

// B has no stop event in the 29-event E journal, but its final v2 stream must
// still prove a normal ordered shutdown and zero-drop seal before cleanup.
func slice6StopGuestRecoveryReplacementCapture(ctx context.Context, run slice6DockerRun,
	capture *slice6GuestRecoveryCapture) (slice6GuestRecoveryRawBinding, []phase6guestreceipt.Record, error) {
	if ctx == nil || ctx.Err() != nil || capture == nil || capture.recorder == nil ||
		capture.run == nil || run.id != capture.run.id || capture.stopAdmitted ||
		(capture.process != "product-b" && capture.process != "guest-b") ||
		capture.confirmStillRunning(ctx, run) != nil {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	output, commandErr, overflow := slice6DockerBounded(ctx, 128, nil,
		"stop", "--timeout", "10", capture.id)
	responseOK := bytes.Equal(output, []byte(capture.id+"\n"))
	clear(output)
	if commandErr != nil || overflow || ctx.Err() != nil || !responseOK {
		return slice6GuestRecoveryRawBinding{}, nil, errors.New("Guest B stop outcome unconfirmed")
	}
	// The E journal ends at guest_b_start_observed. B's later terminal
	// shutdown is still sealed, but it must not append A-only stop events.
	binding, records, err := capture.verifyStopped(ctx, run, 0)
	if err != nil {
		return slice6GuestRecoveryRawBinding{}, nil, err
	}
	capture.stopAdmitted = true
	return binding, records, nil
}

func slice6RemoveGuestRecoverySealedProcess(ctx context.Context, run slice6DockerRun,
	capture *slice6GuestRecoveryCapture, binding slice6GuestRecoveryRawBinding) error {
	if ctx == nil || ctx.Err() != nil || capture == nil || capture.run == nil ||
		binding.RunID != run.id || capture.run.id != run.id ||
		capture.process != binding.Process || capture.id != binding.ContainerID ||
		binding.File != slice6GuestRecoveryRawName(capture.process) ||
		binding.Role != capture.role || binding.PID != capture.pid ||
		binding.StartedAt != capture.startedAt || binding.ImageID != capture.image ||
		binding.ImageRef != capture.imageRef || binding.ProfileDigest != capture.profile ||
		binding.ConfigDigest != capture.config || binding.ExitCode != 0 ||
		!capture.stopAdmitted || capture.fileErr != nil || capture.output == nil ||
		capture.output.overflow || binding.Bytes != capture.output.written ||
		!guestRevokeFixtureDigestGate(binding.SHA256) || binding.Bytes < 1 {
		return phase6guestreceipt.ErrUnavailable
	}
	raw, err := capture.run.readFile(binding.File, phase6guestreceipt.MaxTotalBytes)
	if err != nil || len(raw) != binding.Bytes || slice6ReceiptSHA256(raw) != binding.SHA256 {
		clear(raw)
		return phase6guestreceipt.ErrUnavailable
	}
	clear(raw)
	output, commandErr, overflow := slice6DockerBounded(ctx, 128, nil, "rm", "-v", capture.id)
	confirmed := bytes.Equal(output, []byte(capture.id+"\n"))
	clear(output)
	if commandErr != nil || overflow || ctx.Err() != nil || !confirmed ||
		!slice6GuestRecoveryProductPriorAbsent(ctx, capture.id) {
		return errors.New("Guest E sealed PID1 exact removal unconfirmed")
	}
	return nil
}

func (capture *slice6GuestRecoveryCapture) verifyStopped(ctx context.Context, run slice6DockerRun,
	expectedExit int) (slice6GuestRecoveryRawBinding, []phase6guestreceipt.Record, error) {
	if capture == nil || ctx == nil || ctx.Err() != nil || run.id != capture.run.id ||
		capture.pid < 1 || capture.startedAt == "" || expectedExit < 0 || expectedExit > 255 ||
		(capture.recorder != nil && (capture.process == "guest-a" || capture.process == "product-a") && !capture.stopAdmitted) {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	select {
	case <-capture.done:
	case <-ctx.Done():
		capture.abort()
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	capture.finish.Do(func() {
		capture.fileErr = errors.Join(capture.file.Sync(), capture.file.Close())
	})
	defer capture.cancel()
	if capture.fileErr != nil || capture.run.check() != nil || capture.output.overflow ||
		capture.output.written < 1 || capture.output.written > phase6guestreceipt.MaxTotalBytes {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	if expectedExit == 0 && capture.waitErr != nil {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	if expectedExit != 0 {
		var exit *exec.ExitError
		if !errors.As(capture.waitErr, &exit) || exit.ExitCode() != expectedExit {
			return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
		}
	}
	output, err, overflow := slice6DockerBounded(ctx, 640, nil, "inspect", "--format",
		"{{.Id}} {{.Image}} {{.Config.Image}} {{index .Config.Labels \""+slice6RunLabel+"\"}} {{.HostConfig.LogConfig.Type}} {{.Config.Tty}} {{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}} {{.State.StartedAt}} {{.State.FinishedAt}}", capture.id)
	defer clear(output)
	fields := strings.Fields(string(output))
	if err != nil || overflow || len(fields) != 11 || fields[0] != capture.id ||
		fields[1] != capture.image || fields[2] != capture.imageRef || fields[3] != run.id ||
		fields[4] != "none" || fields[5] != "false" || fields[6] != "false" ||
		fields[7] != strconv.Itoa(expectedExit) || fields[8] != "false" ||
		fields[9] != capture.startedAt {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	started, startErr := time.Parse(time.RFC3339Nano, capture.startedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, fields[10])
	if startErr != nil || finishErr != nil || !finished.After(started) {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	partial := slice6GuestRecoveryRawBinding{Process: capture.process, RunID: run.id,
		ContainerID: capture.id, PID: capture.pid, StartedAt: capture.startedAt,
		FinishedAt: fields[10], ExitCode: expectedExit}
	if capture.recorder != nil && capture.stopAdmitted &&
		capture.recorder.record(strings.ReplaceAll(capture.process, "-", "_")+"_exit_observed",
			slice6GuestRecoveryExitObservedRef(partial)) != nil {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	name := slice6GuestRecoveryRawName(capture.process)
	document, err := capture.run.readFile(name, phase6guestreceipt.MaxTotalBytes)
	if err != nil || len(document) != capture.output.written {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	defer clear(document)
	records, err := phase6guestreceipt.VerifyV2(document, capture.role, capture.profile, capture.config)
	if err != nil {
		return slice6GuestRecoveryRawBinding{}, nil, err
	}
	binding := slice6GuestRecoveryRawBinding{Process: capture.process, Role: capture.role,
		File: name, RunID: run.id, ContainerID: capture.id, PID: capture.pid,
		StartedAt: capture.startedAt, FinishedAt: fields[10], ImageID: fields[1],
		ImageRef: fields[2], ProfileDigest: capture.profile, ConfigDigest: capture.config,
		SHA256: slice6ReceiptSHA256(document), Bytes: len(document), ExitCode: expectedExit,
		CaptureStartUTC:    capture.captureStarted.Format(time.RFC3339Nano),
		CaptureFinishUTC:   time.Now().UTC().Format(time.RFC3339Nano),
		StartInspectSHA256: capture.startInspectSHA256}
	if capture.recorder != nil && capture.stopAdmitted &&
		capture.recorder.record(strings.ReplaceAll(capture.process, "-", "_")+"_sealed",
			slice6GuestRecoverySealRef(binding)) != nil {
		return slice6GuestRecoveryRawBinding{}, nil, phase6guestreceipt.ErrUnavailable
	}
	return binding, records, nil
}
