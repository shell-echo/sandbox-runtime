//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktophandoff"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	"github.com/shell-echo/sandbox-runtime/internal/sessiontermination"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	desktopremote "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/remote"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	mediaMeasurementSessions = 20
	mediaMeasurementWindow   = 2 * time.Second
	inputProcessDeadline     = time.Second
)

type inputBatchResult struct {
	count     int64
	maxMicros int64
	err       error
}

func runDesktopEvidenceMeasurements(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	client := newGateProtectedClient(environment)
	// The earlier Desktop scenario client owns the low JTI sequence range.
	// Use a disjoint deterministic range so this evidence pass cannot replay
	// an admission token after the Provider restart.
	client.sequence = 10_000
	state := openDesktopMeasurementSession(t, client)
	state.open = desktopPrivateOpen(t, state.handoff, "desktop-media-measurement-bind")
	handoffExpiry, err := time.Parse(time.RFC3339Nano, state.handoff.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	state.open.AuthorityExpiresAt = handoffExpiry.Add(-time.Second).Format(time.RFC3339Nano)
	state.open.AuthorityDigest = desktophandoff.AuthorityDigest(state.open)
	state.open.RequestDigest = desktophandoff.RequestDigest(state.open)
	bindingSession, accepted := openDesktopMedia(t, ctx, environment, state.open)
	state.open = accepted
	bindingSession.CloseNow()
	waitForDesktopSessionProcesses(t, environment, 0, 10*time.Second)

	driver, httpClient, authority, attachment, policy := measuredDesktopDriver(t, ctx, environment, state)
	environment.stress = measureDesktopStress(t, ctx, environment, driver, authority, attachment, policy)
	environment.desktopMedia = measureDesktopMedia(t, ctx, environment, driver, httpClient, authority, attachment, policy)

	closeDesktopSession(t, environment, client, state.handoff, "desktop-close-measurement", "desktop-close-measurement-attempt", 7)
	waitForDesktopResources(t, environment, 0, 45*time.Second)
	environment.desktopMedia.DynamicContainersRemaining, _ = managedResourceCount(environment)
	environment.desktopMedia.EvidenceDigest = productphase6evidence.DesktopMediaEvidenceDigest(environment.desktopMedia)
	if environment.desktopMedia.DynamicContainersRemaining != 0 {
		t.Fatalf("Desktop measurement cleanup containers=%d", environment.desktopMedia.DynamicContainersRemaining)
	}
	t.Logf("phase6 Desktop stress: runs=%d inputs=%d failures=%d input_timeouts=%d", environment.stress.TotalRuns, environment.stress.TotalInputs, environment.stress.InputFailures, environment.stress.InputTimeouts)
	t.Logf("phase6 Desktop media: sessions=%d first_frame_p95_us=%d first_frame_max_us=%d packets=%d marker_frames=%d sequence_gaps=%d max_fps_milli=%d max_bitrate_bps=%d inputs=%d max_input_us=%d backpressure=%s/%s goroutines=%d/%d",
		environment.desktopMedia.Sessions, environment.desktopMedia.FirstFrameP95Microseconds, environment.desktopMedia.FirstFrameMaxMicroseconds,
		environment.desktopMedia.RTPPackets, environment.desktopMedia.RTPMarkerFrames, environment.desktopMedia.RTPSequenceGaps,
		environment.desktopMedia.MaxFPSMilli, environment.desktopMedia.MaxBitrateBPS, environment.desktopMedia.ConcurrentInputs,
		environment.desktopMedia.MaxInputRoundtripMicroseconds, environment.desktopMedia.BackpressureStage, environment.desktopMedia.BackpressureCause,
		environment.desktopMedia.GoroutinesBaseline, environment.desktopMedia.GoroutinesFinal)
}

func openDesktopMeasurementSession(t *testing.T, client *protectedClient) desktopGateState {
	t.Helper()
	now := time.Now().UTC()
	deadline, expires := now.Add(6*time.Minute), now.Add(5*time.Minute)
	const sessionID = "desktop-session-phase6-measurement"
	body := map[string]any{
		"operation_id": "desktop-open-measurement", "attempt_id": "desktop-open-measurement-attempt", "fencing_token": int64(6),
		"idempotency_key": "desktop-open-measurement-idempotency", "deadline_at": deadline.Format(time.RFC3339Nano),
		"expected_generation": int64(1), "desktop_session_id": sessionID,
		"capability_profile_id": "desktop-v1", "expires_at": expires.Format(time.RFC3339Nano),
	}
	status, document := client.do(t, protectedRequest{Method: http.MethodPost, Path: "/v1/sandboxes/" + gateSandboxID + "/desktop-sessions", Operation: admission.OperationOpenDesktopSession, SandboxID: gateSandboxID, OperationID: "desktop-open-measurement", AttemptID: "desktop-open-measurement-attempt", Fence: 6, Deadline: deadline, Body: body})
	if status != http.StatusAccepted {
		t.Fatalf("Desktop measurement session open status=%d body=%s", status, document)
	}
	var operation providerv1.Operation
	if json.Unmarshal(document, &operation) != nil || operation.OperationID != "desktop-open-measurement" || operation.Status != providerv1.OperationSucceeded {
		t.Fatalf("Desktop measurement session operation=%s", document)
	}
	status, document = client.do(t, protectedRequest{Method: http.MethodGet, Path: "/v1/operations/desktop-open-measurement/desktop-session", Operation: admission.OperationReadDesktopSession, SandboxID: gateSandboxID, OperationID: "desktop-open-measurement", AttemptID: "desktop-open-measurement-attempt", Fence: 6, Deadline: time.Now().UTC().Add(time.Minute)})
	if status != http.StatusOK {
		t.Fatalf("Desktop measurement handoff status=%d body=%s", status, document)
	}
	var result providerv1.DesktopSessionHandoff
	if json.Unmarshal(document, &result) != nil || result.DesktopSessionID != sessionID || result.InternalEndpointReference == "" || result.ConnectionGeneration < 1 {
		t.Fatalf("Desktop measurement handoff=%s", document)
	}
	return desktopGateState{client: client, handoff: result}
}

func measuredDesktopDriver(t *testing.T, ctx context.Context, environment *gateEnvironment, state desktopGateState) (*desktopremote.Driver, interface{ CloseIdleConnections() }, providerdesktop.MediaAuthority, providerdesktop.Attachment, desktopmedia.MediaPolicy) {
	t.Helper()
	store, err := providerpostgres.New(environment.providerDB.admin, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	references, err := providerpostgres.NewDesktopReferenceStore(store)
	if err != nil {
		t.Fatal(err)
	}
	record, err := references.Get(ctx, state.open.HandoffReference)
	if err != nil || record.Binding == nil {
		t.Fatalf("read measurement binding: %v", err)
	}
	key, err := os.ReadFile(environment.paths.bridgeKey)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal("read measurement bridge key")
	}
	binding := record.Binding
	mediaAuthority := providerdesktop.MediaAuthority{
		TenantBindingDigest: binding.TenantBindingDigest, ProviderRevisionID: binding.ProviderRevisionID,
		SandboxID: binding.SandboxID, DesktopSessionID: binding.DesktopSessionID,
		HandoffReference: binding.HandoffReference, HandoffReferenceDigest: desktophandoff.ReferenceDigest(binding.HandoffReference),
		AllocationReference: record.Receipt.Reference, ConnectionGeneration: binding.ConnectionGeneration,
		ConnectionEpoch: binding.ConnectionEpoch, ControllerFence: binding.ControllerFence,
		MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID,
		AuthorityExpiresAt: binding.AuthorityExpiresAt, HandoffExpiresAt: binding.HandoffExpiresAt,
	}
	attachment := providerdesktop.Attachment{DesktopSessionID: binding.DesktopSessionID, ConnectionGeneration: binding.ConnectionGeneration, MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID}
	httpClient := environment.tls.ca.client("desktop-role.phase6.test", mustLoadCertificateForDiagnostic(environment.tls.providerExecutorCert, environment.tls.providerExecutorKey))
	driver, err := desktopremote.New(desktopremote.Options{URL: fmt.Sprintf("wss://127.0.0.1:%d/executor", environment.ports.desktop), HTTPClient: httpClient, OperationTimeout: 20 * time.Second, BridgeKeyID: "provider-desktop-v2", ExecutorIdentity: "executor-desktop-1", BridgePrivateKey: ed25519.PrivateKey(key)})
	if err != nil {
		t.Fatal(err)
	}
	return driver, httpClient, mediaAuthority, attachment, binding.MediaPolicy
}

func measureDesktopStress(t *testing.T, ctx context.Context, environment *gateEnvironment, driver *desktopremote.Driver, authority providerdesktop.MediaAuthority, attachment providerdesktop.Attachment, policy desktopmedia.MediaPolicy) productphase6evidence.StressMeasurements {
	t.Helper()
	measurement := productphase6evidence.StressMeasurements{Harness: "phase6-desktop-mux-stress-v2", Runs50: 50, Runs100: 100, InputsPerRun: 5, TerminalCauses: []string{}}
	measurement.TotalRuns = measurement.Runs50 + measurement.Runs100
	measurement.TotalInputs = measurement.TotalRuns * measurement.InputsPerRun
	measurement.CommandDigest = productphase6evidence.StressCommandDigest(measurement)
	sequence := int64(1)
	for _, runs := range []int{measurement.Runs50, measurement.Runs100} {
		for run := 0; run < runs; run++ {
			session := openMeasuredMedia(t, ctx, driver, authority, attachment, policy)
			firstContext, cancelFirst := context.WithTimeout(ctx, 30*time.Second)
			frame, err := session.ReadVideoRTP(firstContext)
			cancelFirst()
			if err != nil || !validRTP(frame) {
				measurement.FirstFrameFailures++
				t.Fatalf("Desktop stress first frame batch=%d run=%d: %v", runs, run, err)
			}
			for input := 0; input < measurement.InputsPerRun; input++ {
				inputContext, cancelInput := context.WithTimeout(ctx, 1500*time.Millisecond)
				_, inputErr := session.HandleInput(inputContext, desktopmedia.Input{Sequence: sequence, Kind: "pointer", Event: "move", X: 123, Y: 234, ControlLeaseID: "phase6-measurement-lease", ControlFence: sequence})
				cancelInput()
				sequence++
				if inputErr != nil {
					measurement.InputFailures++
					var classified sessiontermination.Error
					if errors.As(inputErr, &classified) {
						measurement.TerminalCauses = append(measurement.TerminalCauses, classified.Record.String())
						if classified.Record.Cause == sessiontermination.CauseInputTimeout {
							measurement.InputTimeouts++
						}
					}
					t.Fatalf("Desktop stress input batch=%d run=%d input=%d: %v", runs, run, input, inputErr)
				}
			}
			_ = session.Close()
			waitForDesktopSessionProcesses(t, environment, 0, 10*time.Second)
		}
	}
	measurement.SessionExecRemaining, measurement.FFmpegRemaining = desktopSessionProcessCounts(environment)
	if measurement.SessionExecRemaining != 0 || measurement.FFmpegRemaining != 0 {
		measurement.CleanupFailures++
		t.Fatalf("Desktop stress cleanup exec=%d ffmpeg=%d", measurement.SessionExecRemaining, measurement.FFmpegRemaining)
	}
	measurement.EvidenceDigest = productphase6evidence.StressEvidenceDigest(measurement)
	return measurement
}

func measureDesktopMedia(t *testing.T, ctx context.Context, environment *gateEnvironment, driver *desktopremote.Driver, httpClient interface{ CloseIdleConnections() }, authority providerdesktop.MediaAuthority, attachment providerdesktop.Attachment, policy desktopmedia.MediaPolicy) productphase6evidence.DesktopMediaMeasurements {
	t.Helper()
	measurement := productphase6evidence.DesktopMediaMeasurements{Harness: "phase6-desktop-media-v2", Sessions: mediaMeasurementSessions, FirstFrameLimitMilliseconds: 30_000, WindowMilliseconds: mediaMeasurementWindow.Milliseconds(), FPSLimitMilli: int64(policy.MaxFPS * 1000), BitrateLimitBPS: int64(policy.MaxVideoBitrateKbps * 1000), InputProcessDeadlineMilliseconds: inputProcessDeadline.Milliseconds()}
	measurement.CommandDigest = productphase6evidence.DesktopMediaCommandDigest(measurement)
	latencies := make([]time.Duration, 0, measurement.Sessions)
	time.Sleep(250 * time.Millisecond)
	measurement.GoroutinesBaseline = stableGoroutineCount()
	sequence := int64(10_000)
	for sessionIndex := 0; sessionIndex < measurement.Sessions; sessionIndex++ {
		started := time.Now()
		session := openMeasuredMedia(t, ctx, driver, authority, attachment, policy)
		firstContext, cancelFirst := context.WithTimeout(ctx, 30*time.Second)
		first, err := session.ReadVideoRTP(firstContext)
		cancelFirst()
		if err != nil || !validRTP(first) {
			t.Fatalf("Desktop media first frame session=%d: %v", sessionIndex, err)
		}
		latencies = append(latencies, time.Since(started))

		inputDone := make(chan inputBatchResult, 1)
		firstInputSequence := sequence
		sequence += 10
		go measureConcurrentInputs(ctx, session, firstInputSequence, inputDone)
		windowStarted := time.Now()
		deadline := windowStarted.Add(mediaMeasurementWindow)
		packets, frames, bytes := int64(1), int64(0), int64(len(first))
		if first[1]&0x80 != 0 {
			frames++
		}
		previousSequence := binary.BigEndian.Uint16(first[2:4])
		firstTimestamp := binary.BigEndian.Uint32(first[4:8])
		lastTimestamp := firstTimestamp
		for time.Now().Before(deadline) {
			readContext, cancelRead := context.WithDeadline(ctx, deadline)
			packet, readErr := session.ReadVideoRTP(readContext)
			cancelRead()
			if readErr != nil {
				if errors.Is(readErr, context.DeadlineExceeded) {
					break
				}
				t.Fatalf("Desktop continuous RTP session=%d: %v", sessionIndex, readErr)
			}
			if !validRTP(packet) {
				t.Fatalf("Desktop invalid RTP session=%d", sessionIndex)
			}
			packetSequence := binary.BigEndian.Uint16(packet[2:4])
			if packetSequence != previousSequence+1 {
				measurement.RTPSequenceGaps++
			}
			previousSequence = packetSequence
			lastTimestamp = binary.BigEndian.Uint32(packet[4:8])
			packets++
			bytes += int64(len(packet))
			if packet[1]&0x80 != 0 {
				frames++
			}
		}
		inputResult := <-inputDone
		if inputResult.err != nil {
			t.Fatal(inputResult.err)
		}
		measurement.ConcurrentInputs += inputResult.count
		measurement.MaxInputRoundtripMicroseconds = max(measurement.MaxInputRoundtripMicroseconds, inputResult.maxMicros)
		elapsedMicros := time.Since(windowStarted).Microseconds()
		fpsMilli := int64(0)
		if frames > 1 && lastTimestamp > firstTimestamp {
			fpsMilli = (frames - 1) * 90_000 * 1000 / int64(lastTimestamp-firstTimestamp)
		}
		bitrateBPS := bytes * 8 * 1_000_000 / elapsedMicros
		measurement.MaxFPSMilli = max(measurement.MaxFPSMilli, fpsMilli)
		measurement.MaxBitrateBPS = max(measurement.MaxBitrateBPS, bitrateBPS)
		measurement.RTPPackets += packets
		measurement.RTPMarkerFrames += frames
		measurement.RTPBytes += bytes
		if fpsMilli <= 0 || fpsMilli > measurement.FPSLimitMilli || bitrateBPS > measurement.BitrateLimitBPS {
			t.Fatalf("Desktop media policy session=%d fps_milli=%d bitrate_bps=%d", sessionIndex, fpsMilli, bitrateBPS)
		}
		_ = session.Close()
		waitForDesktopSessionProcesses(t, environment, 0, 10*time.Second)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	measurement.FirstFrameP95Microseconds = latencies[(len(latencies)-1)*95/100].Microseconds()
	measurement.FirstFrameMaxMicroseconds = latencies[len(latencies)-1].Microseconds()
	if measurement.FirstFrameMaxMicroseconds > measurement.FirstFrameLimitMilliseconds*1000 || measurement.RTPSequenceGaps > measurement.AllowedPacketLoss || measurement.MaxInputRoundtripMicroseconds > measurement.InputProcessDeadlineMilliseconds*1000 {
		t.Fatalf("Desktop media bounds first_max_us=%d gaps=%d input_max_us=%d", measurement.FirstFrameMaxMicroseconds, measurement.RTPSequenceGaps, measurement.MaxInputRoundtripMicroseconds)
	}

	backpressureSession := openMeasuredMedia(t, ctx, driver, authority, attachment, policy)
	// Preserve the Provider-signed queue policy. A stopped consumer fills the
	// bounded queue naturally; changing MaxQueuedFrames would correctly fail
	// the media-policy authority binding before backpressure could be tested.
	time.Sleep(2 * time.Second)
	var terminal sessiontermination.Error
	for attempts := 0; attempts < 4; attempts++ {
		readContext, cancelRead := context.WithTimeout(ctx, 2*time.Second)
		_, readErr := backpressureSession.ReadVideoRTP(readContext)
		cancelRead()
		if readErr == nil {
			continue
		}
		if !errors.As(readErr, &terminal) {
			t.Fatalf("Desktop unclassified backpressure: %v", readErr)
		}
		break
	}
	measurement.BackpressureStage = string(terminal.Record.Stage)
	measurement.BackpressureCause = string(terminal.Record.Cause)
	if terminal.Record != (sessiontermination.Record{Stage: sessiontermination.StageMediaReader, Cause: sessiontermination.CauseBackpressure}) {
		t.Fatalf("Desktop backpressure=%s", terminal.Record.String())
	}
	_ = backpressureSession.Close()
	waitForDesktopSessionProcesses(t, environment, 0, 10*time.Second)

	recovery := openMeasuredMedia(t, ctx, driver, authority, attachment, policy)
	recoveryContext, cancelRecovery := context.WithTimeout(ctx, 30*time.Second)
	recoveryFrame, err := recovery.ReadVideoRTP(recoveryContext)
	cancelRecovery()
	if err != nil || !validRTP(recoveryFrame) {
		t.Fatalf("Desktop media recovery frame: %v", err)
	}
	inputStarted := time.Now()
	inputContext, cancelInput := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, err = recovery.HandleInput(inputContext, desktopmedia.Input{Sequence: sequence, Kind: "pointer", Event: "move", X: 123, Y: 234, ControlLeaseID: "phase6-measurement-lease", ControlFence: sequence})
	cancelInput()
	inputMicros := time.Since(inputStarted).Microseconds()
	if err != nil || inputMicros > inputProcessDeadline.Microseconds() {
		t.Fatalf("Desktop media recovery input latency_us=%d: %v", inputMicros, err)
	}
	measurement.ConcurrentInputs++
	measurement.MaxInputRoundtripMicroseconds = max(measurement.MaxInputRoundtripMicroseconds, inputMicros)
	measurement.Recovery = true
	_ = recovery.Close()
	waitForDesktopSessionProcesses(t, environment, 0, 10*time.Second)
	measurement.SessionExecRemaining, measurement.FFmpegRemaining = desktopSessionProcessCounts(environment)
	httpClient.CloseIdleConnections()
	measurement.GoroutinesFinal = waitForGoroutineCount(t, measurement.GoroutinesBaseline, 10*time.Second)
	measurement.EvidenceDigest = productphase6evidence.DesktopMediaEvidenceDigest(measurement)
	return measurement
}

func measureConcurrentInputs(ctx context.Context, session providerdesktop.MediaSession, sequence int64, done chan<- inputBatchResult) {
	result := inputBatchResult{}
	for index := 0; index < 10; index++ {
		started := time.Now()
		inputContext, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		_, err := session.HandleInput(inputContext, desktopmedia.Input{Sequence: sequence + int64(index), Kind: "pointer", Event: "move", X: 123, Y: 234, ControlLeaseID: "phase6-measurement-lease", ControlFence: sequence + int64(index)})
		cancel()
		micros := time.Since(started).Microseconds()
		result.maxMicros = max(result.maxMicros, micros)
		if err != nil || micros > inputProcessDeadline.Microseconds() {
			result.err = fmt.Errorf("Desktop concurrent input %d latency_us=%d: %v", index, micros, err)
			done <- result
			return
		}
		result.count++
	}
	done <- result
}

func openMeasuredMedia(t *testing.T, ctx context.Context, driver *desktopremote.Driver, authority providerdesktop.MediaAuthority, attachment providerdesktop.Attachment, policy desktopmedia.MediaPolicy) providerdesktop.MediaSession {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		session, err := driver.OpenMedia(ctx, authority, attachment, policy)
		if err == nil {
			return session
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Desktop measured media remained unavailable")
	return nil
}

func validRTP(packet []byte) bool { return len(packet) >= 12 && packet[0]>>6 == 2 }

func waitForDesktopSessionProcesses(t *testing.T, environment *gateEnvironment, wanted int, timeout time.Duration) {
	t.Helper()
	waitFor(t, timeout, fmt.Sprintf("Desktop session process count %d", wanted), func() bool {
		execCount, ffmpegCount := desktopSessionProcessCounts(environment)
		return execCount+ffmpegCount == wanted
	})
}

func desktopSessionProcessCounts(environment *gateEnvironment) (int, int) {
	output, err := exec.Command("docker", "ps", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4").Output()
	if err != nil {
		return -1, -1
	}
	execCount, ffmpegCount := 0, 0
	for _, identifier := range strings.Fields(string(output)) {
		processes, topErr := exec.Command("docker", "top", identifier, "-eo", "pid,ppid,user,args").Output()
		if topErr != nil {
			return -1, -1
		}
		for _, line := range strings.Split(string(processes), "\n") {
			if strings.Contains(line, "desktop-broker session") {
				execCount++
			}
			if strings.Contains(line, "/usr/bin/ffmpeg") {
				ffmpegCount++
			}
		}
	}
	return execCount, ffmpegCount
}

func stableGoroutineCount() int {
	previous := -1
	stable := 0
	for attempts := 0; attempts < 100 && stable < 3; attempts++ {
		runtime.GC()
		current := runtime.NumGoroutine()
		if current == previous {
			stable++
		} else {
			stable = 0
			previous = current
		}
		time.Sleep(20 * time.Millisecond)
	}
	return previous
}

func waitForGoroutineCount(t *testing.T, wanted int, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	last := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		last = stableGoroutineCount()
		if last == wanted {
			return last
		}
	}
	t.Fatalf("Desktop media goroutines baseline=%d final=%d", wanted, last)
	return last
}
