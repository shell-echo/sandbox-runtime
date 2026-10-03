//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var errSlice6CapacityMonitorClosed = errors.New("Slice 6 capacity monitor closed")

const slice6CapacityMonitorDiagnosticEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CAPACITY_MONITOR_DIAGNOSTIC"
const slice6CapacityStopDiagnosticEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CAPACITY_STOP_DIAGNOSTIC"
const slice6CapacityPerturbationDiagnosticEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CAPACITY_PERTURBATION_DIAGNOSTIC"

type slice6CapacityClass string

const (
	slice6CapacityInvalidInput      slice6CapacityClass = "invalid-input"
	slice6CapacityHostRead          slice6CapacityClass = "host-stat-read"
	slice6CapacityHostValue         slice6CapacityClass = "host-stat-value"
	slice6CapacityDockerExec        slice6CapacityClass = "docker-exec"
	slice6CapacityDockerOutputLimit slice6CapacityClass = "docker-output-limit"
	slice6CapacityDFSyntax          slice6CapacityClass = "df-syntax"
	slice6CapacityDFValue           slice6CapacityClass = "df-value"
	slice6CapacityHostThreshold     slice6CapacityClass = "host-threshold"
	slice6CapacityDockerThreshold   slice6CapacityClass = "docker-threshold"
	slice6CapacityBothThresholds    slice6CapacityClass = "both-thresholds"
	slice6CapacityParentCanceled    slice6CapacityClass = "parent-canceled"
	slice6CapacityParentDeadline    slice6CapacityClass = "parent-deadline"
	slice6CapacitySampleTimeout     slice6CapacityClass = "sample-timeout"
	slice6CapacityUnknown           slice6CapacityClass = "unknown"
)

// The failure carries only a closed stage/class and bounded numeric evidence.
// It deliberately does not unwrap raw Docker, df, path or environment errors.
type slice6CapacityFailure struct {
	stage, contextClass            string
	class                          slice6CapacityClass
	sample                         int
	duration, lastSuccessAge       time.Duration
	hostAvailable, dockerAvailable int64
	hostThreshold, dockerThreshold int64
}

func (failure *slice6CapacityFailure) Unwrap() []error {
	switch failure.class {
	case slice6CapacityParentCanceled:
		return []error{errSlice6Capacity, context.Canceled}
	case slice6CapacityParentDeadline, slice6CapacitySampleTimeout:
		return []error{errSlice6Capacity, context.DeadlineExceeded}
	default:
		return []error{errSlice6Capacity}
	}
}

func (failure *slice6CapacityFailure) Error() string {
	stage := failure.stage
	switch stage {
	case "input", "host", "docker", "df", "admission", "monitor":
	default:
		stage = "unknown"
	}
	class := failure.class
	switch class {
	case slice6CapacityInvalidInput, slice6CapacityHostRead, slice6CapacityHostValue,
		slice6CapacityDockerExec, slice6CapacityDockerOutputLimit,
		slice6CapacityDFSyntax, slice6CapacityDFValue,
		slice6CapacityHostThreshold, slice6CapacityDockerThreshold, slice6CapacityBothThresholds,
		slice6CapacityParentCanceled, slice6CapacityParentDeadline,
		slice6CapacitySampleTimeout, slice6CapacityUnknown:
	default:
		class = slice6CapacityUnknown
	}
	contextClass := failure.contextClass
	switch contextClass {
	case "active", "parent-canceled", "parent-deadline", "sample-timeout":
	default:
		contextClass = "unavailable"
	}
	sample := "unavailable"
	if failure.sample > 0 {
		sample = strconv.Itoa(failure.sample)
	}
	duration, lastSuccessAge := failure.duration, failure.lastSuccessAge
	if failure.sample == 0 {
		duration, lastSuccessAge = -1, -1
	}
	return fmt.Sprintf("Slice 6 capacity unavailable stage=%s class=%s sample=%s elapsed_ms=%s host_available=%s docker_available=%s host_threshold=%s docker_threshold=%s context=%s last_success_age_ms=%s",
		stage, class, sample, slice6CapacityDuration(duration),
		slice6CapacityMetric(failure.hostAvailable), slice6CapacityMetric(failure.dockerAvailable),
		slice6CapacityMetric(failure.hostThreshold), slice6CapacityMetric(failure.dockerThreshold),
		contextClass, slice6CapacityDuration(lastSuccessAge))
}

func slice6CapacityMetric(value int64) string {
	if value <= 0 {
		return "unavailable"
	}
	return strconv.FormatInt(value, 10)
}

func slice6CapacityDuration(value time.Duration) string {
	if value < 0 {
		return "unavailable"
	}
	return strconv.FormatInt(value.Milliseconds(), 10)
}

func slice6CapacityThresholdFailure(stage string, observation slice6CapacityObservation,
	host, docker int64) error {
	result := &slice6CapacityFailure{stage: stage, contextClass: "active",
		duration: -1, lastSuccessAge: -1,
		hostAvailable:   observation.hostPhysicalAvailableBytes,
		dockerAvailable: observation.dockerBackingAvailableBytes,
		hostThreshold:   host, dockerThreshold: docker}
	if host <= 0 || docker <= 0 || result.hostAvailable <= 0 || result.dockerAvailable <= 0 {
		result.class = slice6CapacityInvalidInput
		return result
	}
	hostLow, dockerLow := result.hostAvailable <= host, result.dockerAvailable <= docker
	switch {
	case hostLow && dockerLow:
		result.class = slice6CapacityBothThresholds
	case hostLow:
		result.class = slice6CapacityHostThreshold
	case dockerLow:
		result.class = slice6CapacityDockerThreshold
	default:
		return nil
	}
	return result
}

func slice6CapacityIncident(cause error, stage string, sample int, elapsed time.Duration,
	observation slice6CapacityObservation, hostThreshold, dockerThreshold int64,
	lastSuccess time.Time, parentState, sampleState error) error {
	var typed *slice6CapacityFailure
	failure := &slice6CapacityFailure{stage: stage, class: slice6CapacityUnknown}
	if errors.As(cause, &typed) {
		copy := *typed
		failure = &copy
	}
	if failure.stage == "" {
		failure.stage = stage
	}
	failure.sample, failure.duration = sample, elapsed
	failure.hostAvailable, failure.dockerAvailable = observation.hostPhysicalAvailableBytes, observation.dockerBackingAvailableBytes
	failure.hostThreshold, failure.dockerThreshold = hostThreshold, dockerThreshold
	failure.lastSuccessAge = -1
	if !lastSuccess.IsZero() {
		failure.lastSuccessAge = time.Since(lastSuccess)
	}
	failure.contextClass = "active"
	switch {
	case errors.Is(parentState, context.DeadlineExceeded):
		failure.class, failure.contextClass = slice6CapacityParentDeadline, "parent-deadline"
	case errors.Is(parentState, context.Canceled):
		failure.class, failure.contextClass = slice6CapacityParentCanceled, "parent-canceled"
	case errors.Is(sampleState, context.DeadlineExceeded):
		failure.class, failure.contextClass = slice6CapacitySampleTimeout, "sample-timeout"
	case sampleState != nil:
		failure.class = slice6CapacityUnknown
	}
	return failure
}

// slice6CapacityMonitor is a runtime safety interlock, not an observation of
// scenario success. A final gate must install it before launching writers and
// make stopProducers cancel every run-owned writer before resource cleanup.
type slice6CapacityMonitor struct {
	cancel    context.CancelCauseFunc
	done      chan struct{}
	triggered chan struct{}
	stopOnce  sync.Once
	mu        sync.Mutex
	reason    error
}

func startSlice6CapacityMonitor(parent context.Context, budget slice6CapacityBudget,
	interval, sampleTimeout time.Duration,
	sample func(context.Context) (slice6CapacityObservation, error),
	stopProducers func(error)) (*slice6CapacityMonitor, error) {
	if parent == nil || interval < 100*time.Millisecond || interval > time.Second ||
		sampleTimeout < interval || sampleTimeout > 2*time.Second || sample == nil || stopProducers == nil {
		return nil, &slice6CapacityFailure{stage: "input", class: slice6CapacityInvalidInput,
			duration: -1, lastSuccessAge: -1}
	}
	if parent.Err() != nil {
		return nil, slice6CapacityIncident(parent.Err(), "admission", 0, -1,
			slice6CapacityObservation{}, 0, 0, time.Time{}, parent.Err(), nil)
	}
	initialContext, cancelInitial := context.WithTimeout(parent, sampleTimeout)
	initialStarted := time.Now()
	initial, err := sample(initialContext)
	initialState, parentState := initialContext.Err(), parent.Err()
	cancelInitial()
	hostRequired, dockerRequired, _ := budget.required()
	if err != nil || initialState != nil || parentState != nil {
		return nil, slice6CapacityIncident(err, "admission", 1, time.Since(initialStarted),
			initial, hostRequired, dockerRequired, time.Time{}, parentState, initialState)
	}
	if admitted := budget.admit(initial); admitted != nil {
		return nil, slice6CapacityIncident(admitted, "admission", 1, time.Since(initialStarted),
			initial, hostRequired, dockerRequired, time.Time{}, parentState, initialState)
	}
	ctx, cancel := context.WithCancelCause(parent)
	monitor := &slice6CapacityMonitor{cancel: cancel, done: make(chan struct{}), triggered: make(chan struct{})}
	go func() {
		defer close(monitor.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		sampleNumber := 1
		lastSuccess := time.Now()
		hostStop, dockerStop, _ := budget.stopThresholds()
		for {
			select {
			case <-ctx.Done():
				if !errors.Is(context.Cause(ctx), errSlice6CapacityMonitorClosed) {
					monitor.stop(slice6CapacityIncident(context.Cause(ctx), "monitor", sampleNumber,
						0, slice6CapacityObservation{}, hostStop, dockerStop, lastSuccess, ctx.Err(), nil), stopProducers)
				}
				return
			case <-ticker.C:
				sampleNumber++
				pollContext, cancelPoll := context.WithTimeout(ctx, sampleTimeout)
				started := time.Now()
				observation, pollErr := sample(pollContext)
				// Read both statuses before our own cancelPoll: that cancel is not
				// evidence of a timeout or a caller cancellation.
				pollState, parentState := pollContext.Err(), ctx.Err()
				cancelPoll()
				if parentState != nil || ctx.Err() != nil {
					if !errors.Is(context.Cause(ctx), errSlice6CapacityMonitorClosed) {
						monitor.stop(slice6CapacityIncident(pollErr, "monitor", sampleNumber, time.Since(started),
							observation, hostStop, dockerStop, lastSuccess, ctx.Err(), pollState), stopProducers)
					}
					return
				}
				if pollErr != nil || pollState != nil {
					monitor.stop(slice6CapacityIncident(pollErr, "monitor", sampleNumber, time.Since(started),
						observation, hostStop, dockerStop, lastSuccess, parentState, pollState), stopProducers)
					return
				}
				if thresholdErr := budget.stopEarlyFailure(observation); thresholdErr != nil {
					monitor.stop(slice6CapacityIncident(thresholdErr, "monitor", sampleNumber, time.Since(started),
						observation, hostStop, dockerStop, lastSuccess, parentState, pollState), stopProducers)
					return
				}
				lastSuccess = time.Now()
			}
		}
	}()
	return monitor, nil
}

func (monitor *slice6CapacityMonitor) stop(reason error, stopProducers func(error)) {
	monitor.stopOnce.Do(func() {
		monitor.mu.Lock()
		monitor.reason = reason
		monitor.mu.Unlock()
		stopProducers(reason)
		close(monitor.triggered)
	})
}

func (monitor *slice6CapacityMonitor) Reason() error {
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	return monitor.reason
}

func (monitor *slice6CapacityMonitor) Close() {
	monitor.cancel(errSlice6CapacityMonitorClosed)
	<-monitor.done
}

// sampleSlice6RunningCapacity reads the physical host filesystem and the
// Docker backing filesystem from a known run-owned container. A Docker exec
// failure is a sampling failure, not proof that the observer disappeared;
// absence requires a separate exact ID/label readback. Ambiguous df is not
// interpreted as free space.
func sampleSlice6RunningCapacity(ctx context.Context, run slice6DockerRun, hostPath, containerID string) (slice6CapacityObservation, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(hostPath) || filepath.Clean(hostPath) != hostPath ||
		len(containerID) != 64 || !lowerHexSlice6(containerID) {
		return slice6CapacityObservation{}, &slice6CapacityFailure{stage: "input", class: slice6CapacityInvalidInput}
	}
	info, err := os.Lstat(hostPath)
	if err != nil {
		return slice6CapacityObservation{}, &slice6CapacityFailure{stage: "host", class: slice6CapacityHostRead}
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return slice6CapacityObservation{}, &slice6CapacityFailure{stage: "host", class: slice6CapacityHostValue}
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(hostPath, &stat); err != nil {
		return slice6CapacityObservation{}, &slice6CapacityFailure{stage: "host", class: slice6CapacityHostRead}
	}
	if stat.Bsize <= 0 || stat.Bavail == 0 || uint64(stat.Bavail) > math.MaxInt64/uint64(stat.Bsize) {
		return slice6CapacityObservation{}, &slice6CapacityFailure{stage: "host", class: slice6CapacityHostValue}
	}
	observation := slice6CapacityObservation{hostPhysicalAvailableBytes: int64(stat.Bavail) * int64(stat.Bsize)}
	document, err, overflow := slice6DockerBounded(ctx, 4096, nil, "exec", containerID, "df", "-B1", "/")
	defer clear(document)
	return slice6DockerCapacityObservation(observation, document, err, overflow)
}

func slice6DockerCapacityObservation(observation slice6CapacityObservation, document []byte,
	execErr error, overflow bool) (slice6CapacityObservation, error) {
	if overflow {
		return observation, &slice6CapacityFailure{stage: "docker", class: slice6CapacityDockerOutputLimit}
	}
	if execErr != nil {
		return observation, &slice6CapacityFailure{stage: "docker", class: slice6CapacityDockerExec}
	}
	available, err := parseSlice6DockerAvailable(document)
	if err != nil {
		return observation, err
	}
	observation.dockerBackingAvailableBytes = available
	return observation, nil
}

func parseSlice6DockerAvailable(document []byte) (int64, error) {
	if len(document) > 4096 {
		return 0, &slice6CapacityFailure{stage: "docker", class: slice6CapacityDockerOutputLimit}
	}
	if len(document) == 0 {
		return 0, &slice6CapacityFailure{stage: "df", class: slice6CapacityDFSyntax}
	}
	lines := strings.Split(strings.TrimSpace(string(document)), "\n")
	if len(lines) != 2 {
		return 0, &slice6CapacityFailure{stage: "df", class: slice6CapacityDFSyntax}
	}
	header, row := strings.Fields(lines[0]), strings.Fields(lines[1])
	if len(header) != 7 || (header[1] != "1-blocks" && header[1] != "1B-blocks") ||
		header[3] != "Available" ||
		header[5] != "Mounted" || header[6] != "on" ||
		len(row) != 6 || row[5] != "/" {
		return 0, &slice6CapacityFailure{stage: "df", class: slice6CapacityDFSyntax}
	}
	available, err := strconv.ParseInt(row[3], 10, 64)
	if err != nil || available <= 0 {
		return 0, &slice6CapacityFailure{stage: "df", class: slice6CapacityDFValue}
	}
	return available, nil
}

// Capacity loss is an emergency stop, not just cancellation of a Docker CLI.
// Only exact run-labeled, inspected writer containers are stopped; the
// read-only sampling container remains available until the monitor closes.
func slice6StopRunOwnedWriters(run slice6DockerRun, observerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return slice6StopRunOwnedWritersContext(ctx, run, observerID)
}

func slice6StopRunOwnedWritersContext(ctx context.Context, run slice6DockerRun, observerID string) error {
	return slice6StopRunOwnedWritersWith(ctx, run.id, observerID, slice6DockerWriterStopOps(run))
}

func slice6DockerWriterStopOps(run slice6DockerRun) slice6WriterStopOps {
	return slice6WriterStopOps{
		list:    func(ctx context.Context) ([]string, error) { return run.labeledIDs(ctx, "container") },
		inspect: slice6InspectWriterForStop,
		stop: func(ctx context.Context, id string) error {
			output, err, overflow := slice6DockerBounded(ctx, 256, nil, "stop", "-t", "1", id)
			defer clear(output)
			if err != nil || overflow || strings.TrimSpace(string(output)) != id {
				return errors.New("exact capacity writer stop unconfirmed")
			}
			return nil
		},
		kill: func(ctx context.Context, id string) error {
			output, err, overflow := slice6DockerBounded(ctx, 256, nil, "kill", id)
			defer clear(output)
			if err != nil || overflow || strings.TrimSpace(string(output)) != id {
				return errors.New("exact capacity writer kill unconfirmed")
			}
			return nil
		},
	}
}

type slice6WriterStopState struct {
	exists, running bool
	owner           string
}

type slice6WriterStopOps struct {
	list    func(context.Context) ([]string, error)
	inspect func(context.Context, string) (slice6WriterStopState, error)
	stop    func(context.Context, string) error
	kill    func(context.Context, string) error
}

func slice6InspectWriterForStop(ctx context.Context, id string) (slice6WriterStopState, error) {
	if len(id) != 64 || !lowerHexSlice6(id) {
		return slice6WriterStopState{}, errors.New("capacity writer identity invalid")
	}
	format := fmt.Sprintf("{{.Id}}|{{index .Config.Labels %q}}|{{.State.Running}}", slice6RunLabel)
	output, err, overflow := slice6DockerBounded(ctx, 256, nil, "inspect", "--format", format, id)
	defer clear(output)
	missing := "error: no such object: " + id + "\n"
	if !overflow && err != nil && (string(output) == missing || string(output) == "\n"+missing) {
		return slice6WriterStopState{}, nil
	}
	if err != nil || overflow {
		return slice6WriterStopState{}, errors.New("capacity writer state ambiguous")
	}
	parts := strings.Split(strings.TrimSuffix(string(output), "\n"), "|")
	if len(parts) != 3 || parts[0] != id || (parts[2] != "true" && parts[2] != "false") {
		return slice6WriterStopState{}, errors.New("capacity writer state malformed")
	}
	return slice6WriterStopState{exists: true, owner: parts[1], running: parts[2] == "true"}, nil
}

func slice6StopRunOwnedWritersWith(ctx context.Context, runID, observerID string, ops slice6WriterStopOps) error {
	if ctx == nil || ctx.Err() != nil || len(runID) != 32 || !lowerHexSlice6(runID) ||
		len(observerID) != 64 || !lowerHexSlice6(observerID) ||
		ops.list == nil || ops.inspect == nil || ops.stop == nil || ops.kill == nil {
		return errors.New("capacity writer stop authority invalid")
	}
	var failures []error
	inspectOwned := func(id string) (slice6WriterStopState, error) {
		if len(id) != 64 || !lowerHexSlice6(id) {
			return slice6WriterStopState{}, errors.New("capacity inventory identity invalid")
		}
		state, err := ops.inspect(ctx, id)
		if err != nil || state.exists && state.owner != runID {
			return slice6WriterStopState{}, errors.New("capacity writer ownership observation ambiguous")
		}
		return state, nil
	}
	for pass := 0; pass < 2; pass++ {
		ids, err := ops.list(ctx)
		if err != nil {
			failures = append(failures, errors.New("capacity run-owned writer inventory unavailable"))
		} else {
			for _, id := range ids {
				if id == observerID {
					continue
				}
				state, inspectErr := inspectOwned(id)
				if inspectErr != nil {
					failures = append(failures, inspectErr)
					continue
				}
				if !state.exists || !state.running {
					continue
				}
				stopErr := ops.stop(ctx, id)
				state, inspectErr = inspectOwned(id)
				if inspectErr != nil {
					failures = append(failures, inspectErr)
					continue
				}
				if stopErr != nil && state.exists {
					failures = append(failures, stopErr)
				}
				if !state.exists || !state.running {
					continue
				}
				killErr := ops.kill(ctx, id)
				state, inspectErr = inspectOwned(id)
				if inspectErr != nil {
					failures = append(failures, inspectErr)
					continue
				}
				if state.exists && state.running {
					failures = append(failures, errors.New("capacity writer remained active after stop/kill"))
				} else if killErr != nil {
					failures = append(failures, killErr)
				}
			}
		}
		if pass == 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
			timer.Stop()
		}
	}
	ids, err := ops.list(ctx)
	if err != nil {
		failures = append(failures, errors.New("capacity final writer inventory unavailable"))
	} else {
		for _, id := range ids {
			if id == observerID {
				continue
			}
			state, inspectErr := inspectOwned(id)
			if inspectErr != nil {
				failures = append(failures, inspectErr)
			} else if state.exists && state.running {
				failures = append(failures, errors.New("capacity final run-owned writer still active"))
			}
		}
	}
	return errors.Join(failures...)
}

func slice6StartCapacityObserver(ctx context.Context, run slice6DockerRun) (string, error) {
	output, err, overflow := slice6DockerBounded(ctx, 256, nil,
		"run", "-d", "--pull=never", "--network=none", "--restart=no",
		"--name", "sr-p6-capacity-monitor-"+run.id, "--label", run.label(),
		"--log-driver=none", "--user=65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--memory=67108864", "--cpus=0.2",
		"--pids-limit=16", slice6CapacityImage, "sleep", "1500")
	defer clear(output)
	id := strings.TrimSpace(string(output))
	if err != nil || overflow || len(id) != 64 || !lowerHexSlice6(id) {
		return "", errors.New("capacity observer process start unconfirmed")
	}
	raw, err := run.docker(ctx, "inspect", id)
	var found []struct {
		ID     string `json:"Id"`
		Config struct{ Labels map[string]string }
		State  struct{ Running bool }
	}
	if err != nil || json.Unmarshal(raw, &found) != nil || len(found) != 1 ||
		found[0].ID != id || found[0].Config.Labels[slice6RunLabel] != run.id ||
		!found[0].State.Running {
		return "", errors.New("capacity observer identity unavailable")
	}
	return id, nil
}

func TestSlice6CapacityStopContinuesAcrossVanishedAndFailedWriters(t *testing.T) {
	runID := strings.Repeat("a", 32)
	observer := strings.Repeat("f", 64)
	vanished, failing := strings.Repeat("1", 64), strings.Repeat("2", 64)
	live, foreign := strings.Repeat("3", 64), strings.Repeat("4", 64)
	for _, test := range []struct {
		name      string
		ids       []string
		states    map[string]slice6WriterStopState
		wantError bool
	}{
		{"enumerated target vanished", []string{vanished, live}, map[string]slice6WriterStopState{
			vanished: {}, live: {exists: true, running: true, owner: runID},
		}, false},
		{"one failed, other run untouched", []string{failing, live, foreign}, map[string]slice6WriterStopState{
			failing: {exists: true, running: true, owner: runID},
			live:    {exists: true, running: true, owner: runID},
			foreign: {exists: true, running: true, owner: strings.Repeat("b", 32)},
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stopped []string
			var killed []string
			ops := slice6WriterStopOps{
				list: func(context.Context) ([]string, error) { return append([]string(nil), test.ids...), nil },
				inspect: func(_ context.Context, id string) (slice6WriterStopState, error) {
					return test.states[id], nil
				},
				stop: func(_ context.Context, id string) error {
					stopped = append(stopped, id)
					if id == failing {
						return errors.New("target-specific stop failure")
					}
					state := test.states[id]
					state.running = false
					test.states[id] = state
					return nil
				},
				kill: func(_ context.Context, id string) error {
					killed = append(killed, id)
					return errors.New("target-specific kill failure")
				},
			}
			err := slice6StopRunOwnedWritersWith(t.Context(), runID, observer, ops)
			if (err != nil) != test.wantError || test.states[live].running || !slices.Contains(stopped, live) ||
				slices.Contains(stopped, foreign) || slices.Contains(killed, foreign) ||
				slices.Contains(stopped, vanished) ||
				test.wantError && (!slices.Contains(stopped, failing) || !slices.Contains(killed, failing) ||
					!test.states[foreign].running) {
				t.Fatalf("multi-target stop err=%v stopped=%v killed=%v", err, stopped, killed)
			}
		})
	}
}

func TestSlice6CapacityStopCatchesBoundedLateWriter(t *testing.T) {
	runID := strings.Repeat("a", 32)
	observer, first, late := strings.Repeat("f", 64), strings.Repeat("1", 64), strings.Repeat("2", 64)
	states := map[string]slice6WriterStopState{
		first: {exists: true, running: true, owner: runID},
		late:  {exists: true, running: true, owner: runID},
	}
	listed := 0
	var stopped []string
	ops := slice6WriterStopOps{
		list: func(context.Context) ([]string, error) {
			listed++
			if listed == 1 {
				return []string{first}, nil
			}
			return []string{first, late}, nil
		},
		inspect: func(_ context.Context, id string) (slice6WriterStopState, error) { return states[id], nil },
		stop: func(_ context.Context, id string) error {
			stopped = append(stopped, id)
			state := states[id]
			state.running = false
			states[id] = state
			return nil
		},
		kill: func(context.Context, string) error { return errors.New("unexpected kill") },
	}
	if err := slice6StopRunOwnedWritersWith(t.Context(), runID, observer, ops); err != nil ||
		listed != 3 || !slices.Contains(stopped, first) || !slices.Contains(stopped, late) {
		t.Fatalf("late writer stop err=%v lists=%d stopped=%v", err, listed, stopped)
	}
}

func TestSlice6CapacityStopRetainsAmbiguousInspectAndStopsOthers(t *testing.T) {
	runID := strings.Repeat("a", 32)
	observer, ambiguous, live := strings.Repeat("f", 64), strings.Repeat("1", 64), strings.Repeat("2", 64)
	running := true
	var stopped []string
	ops := slice6WriterStopOps{
		list: func(context.Context) ([]string, error) { return []string{ambiguous, live}, nil },
		inspect: func(_ context.Context, id string) (slice6WriterStopState, error) {
			if id == ambiguous {
				return slice6WriterStopState{}, errors.New("ambiguous daemon response")
			}
			return slice6WriterStopState{exists: true, owner: runID, running: running}, nil
		},
		stop: func(_ context.Context, id string) error {
			stopped = append(stopped, id)
			running = false
			return nil
		},
		kill: func(context.Context, string) error { return errors.New("unexpected kill") },
	}
	if err := slice6StopRunOwnedWritersWith(t.Context(), runID, observer, ops); err == nil ||
		running || !slices.Equal(stopped, []string{live}) {
		t.Fatalf("ambiguous inspect did not preserve failure and stop later writer: stopped=%v", stopped)
	}
}

func TestSlice6CapacityMonitorStopsOnThresholdAndSampleLoss(t *testing.T) {
	budget := slice6TopologyBudget(0)
	hostRequired, dockerRequired, err := budget.required()
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"threshold", "sample loss"} {
		t.Run(failure, func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			stops := 0
			monitor, err := startSlice6CapacityMonitor(t.Context(), budget, 100*time.Millisecond, 200*time.Millisecond,
				func(context.Context) (slice6CapacityObservation, error) {
					mu.Lock()
					defer mu.Unlock()
					calls++
					if calls == 1 {
						return slice6CapacityObservation{hostRequired + 1, dockerRequired + 1}, nil
					}
					if failure == "sample loss" {
						return slice6CapacityObservation{}, errors.New("docker exec unavailable")
					}
					return slice6CapacityObservation{1, dockerRequired + 1}, nil
				}, func(error) {
					mu.Lock()
					stops++
					mu.Unlock()
				})
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-monitor.triggered:
			case <-time.After(time.Second):
				t.Fatal("capacity monitor did not stop producers")
			}
			monitor.Close()
			mu.Lock()
			defer mu.Unlock()
			if calls != 2 || stops != 1 || monitor.Reason() == nil {
				t.Fatalf("capacity monitor did not stop exactly once: samples=%d stops=%d reason=%v", calls, stops, monitor.Reason())
			}
		})
	}
}

func TestSlice6CapacityMonitorRejectsBadAdmissionAndClosesWithoutStop(t *testing.T) {
	budget := slice6TopologyBudget(0)
	if _, err := startSlice6CapacityMonitor(t.Context(), budget, 100*time.Millisecond, 200*time.Millisecond,
		func(context.Context) (slice6CapacityObservation, error) { return slice6CapacityObservation{}, nil },
		func(error) {}); err == nil {
		t.Fatal("inadequate initial capacity admitted")
	}
	stopped := make(chan error, 1)
	monitor, err := startSlice6CapacityMonitor(t.Context(), budget, time.Second, time.Second,
		func(context.Context) (slice6CapacityObservation, error) {
			return slice6CapacityObservation{math.MaxInt64, math.MaxInt64}, nil
		}, func(reason error) { stopped <- reason })
	if err != nil {
		t.Fatal(err)
	}
	monitor.Close()
	select {
	case <-stopped:
		t.Fatal("normal monitor close stopped producers")
	default:
	}
}

func TestSlice6CapacityMonitorParentCancellationStopsProducers(t *testing.T) {
	parent, cancelParent := context.WithCancel(t.Context())
	stopped := make(chan error, 1)
	monitor, err := startSlice6CapacityMonitor(parent, slice6TopologyBudget(0), time.Second, time.Second,
		func(context.Context) (slice6CapacityObservation, error) {
			return slice6CapacityObservation{math.MaxInt64, math.MaxInt64}, nil
		}, func(reason error) { stopped <- reason })
	if err != nil {
		t.Fatal(err)
	}
	cancelParent()
	select {
	case reason := <-stopped:
		if !errors.Is(reason, context.Canceled) {
			t.Fatalf("parent cancellation reason = %v", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not stop producers")
	}
	monitor.Close()
	if !errors.Is(monitor.Reason(), context.Canceled) {
		t.Fatal("parent cancellation reason was not retained")
	}
}

func TestSlice6CapacityMonitorCanceledAdmissionIsNotInvalidInput(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := startSlice6CapacityMonitor(parent, slice6TopologyBudget(0), time.Second, 2*time.Second,
		func(context.Context) (slice6CapacityObservation, error) {
			t.Fatal("canceled admission sampled")
			return slice6CapacityObservation{}, nil
		},
		func(error) { t.Fatal("canceled admission stopped producers") })
	var failure *slice6CapacityFailure
	if !errors.As(err, &failure) || failure.class != slice6CapacityParentCanceled ||
		!errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "elapsed_ms=unavailable") {
		t.Fatalf("canceled admission class = %v", err)
	}
}

func TestSlice6CapacityFailureClassesAreBounded(t *testing.T) {
	budget := slice6TopologyBudget(0)
	host, docker, err := budget.required()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		observation slice6CapacityObservation
		class       slice6CapacityClass
	}{
		{"host", slice6CapacityObservation{host, docker + 1}, slice6CapacityHostThreshold},
		{"docker", slice6CapacityObservation{host + 1, docker}, slice6CapacityDockerThreshold},
		{"both", slice6CapacityObservation{host, docker}, slice6CapacityBothThresholds},
		{"invalid", slice6CapacityObservation{0, docker + 1}, slice6CapacityInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := budget.admit(test.observation)
			var typed *slice6CapacityFailure
			if !errors.Is(failure, errSlice6Capacity) || !errors.As(failure, &typed) || typed.class != test.class {
				t.Fatalf("admission class = %v", failure)
			}
			for _, forbidden := range []string{"/private/", "docker.sock", "error: ", "<nil>"} {
				if strings.Contains(failure.Error(), forbidden) {
					t.Fatal("unsafe capacity diagnostic")
				}
			}
		})
	}
	stopHost, stopDocker, err := budget.stopThresholds()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		observation slice6CapacityObservation
		class       slice6CapacityClass
	}{
		{slice6CapacityObservation{stopHost, stopDocker + 1}, slice6CapacityHostThreshold},
		{slice6CapacityObservation{stopHost + 1, stopDocker}, slice6CapacityDockerThreshold},
	} {
		var typed *slice6CapacityFailure
		if !errors.As(budget.stopEarlyFailure(test.observation), &typed) || typed.class != test.class {
			t.Fatal("stop threshold class lost")
		}
	}
}

func TestSlice6CapacityIncidentKeepsFirstClassAndContext(t *testing.T) {
	for _, test := range []struct {
		name       string
		cause      error
		parent     error
		sample     error
		class      slice6CapacityClass
		contextErr error
	}{
		{"typed docker", &slice6CapacityFailure{stage: "docker", class: slice6CapacityDockerExec}, nil, nil, slice6CapacityDockerExec, nil},
		{"parent canceled", errors.New("raw daemon path"), context.Canceled, nil, slice6CapacityParentCanceled, context.Canceled},
		{"parent deadline", nil, context.DeadlineExceeded, context.DeadlineExceeded, slice6CapacityParentDeadline, context.DeadlineExceeded},
		{"sample timeout", nil, nil, context.DeadlineExceeded, slice6CapacitySampleTimeout, context.DeadlineExceeded},
		{"unknown", errors.New("raw daemon path"), nil, nil, slice6CapacityUnknown, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			incident := slice6CapacityIncident(test.cause, "monitor", 3, time.Second,
				slice6CapacityObservation{9, 11}, 7, 8, time.Now().Add(-time.Second), test.parent, test.sample)
			var typed *slice6CapacityFailure
			if !errors.Is(incident, errSlice6Capacity) || !errors.As(incident, &typed) || typed.class != test.class ||
				(test.contextErr != nil && !errors.Is(incident, test.contextErr)) ||
				strings.Contains(incident.Error(), "raw daemon path") || typed.sample != 3 || typed.hostAvailable != 9 {
				t.Fatalf("capacity incident lost bounded class/metadata: %v", incident)
			}
		})
	}
}

func TestSlice6CapacitySampleFailureClasses(t *testing.T) {
	host := slice6CapacityObservation{hostPhysicalAvailableBytes: 99}
	for _, test := range []struct {
		name     string
		document []byte
		execErr  error
		overflow bool
		class    slice6CapacityClass
	}{
		{"exec", nil, errors.New("raw daemon diagnostic"), false, slice6CapacityDockerExec},
		{"output", nil, nil, true, slice6CapacityDockerOutputLimit},
		{"syntax", []byte("unrecognized df"), nil, false, slice6CapacityDFSyntax},
		{"value", []byte("Filesystem 1-blocks Used Available Use% Mounted on\noverlay 1000 100 9223372036854775808 10% /\n"), nil, false, slice6CapacityDFValue},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation, err := slice6DockerCapacityObservation(host, test.document, test.execErr, test.overflow)
			var failure *slice6CapacityFailure
			if !errors.As(err, &failure) || failure.class != test.class ||
				observation.hostPhysicalAvailableBytes != 99 || observation.dockerBackingAvailableBytes != 0 ||
				strings.Contains(err.Error(), "raw daemon diagnostic") {
				t.Fatalf("unsafe Docker sample classification: %v", err)
			}
		})
	}
	root := t.TempDir()
	badID := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, path string
		class      slice6CapacityClass
	}{
		{"read", filepath.Join(root, "missing"), slice6CapacityHostRead},
		{"value", filepath.Join(root, "regular"), slice6CapacityHostValue},
	} {
		if test.name == "value" {
			if err := os.WriteFile(test.path, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := sampleSlice6RunningCapacity(t.Context(), slice6DockerRun{}, test.path, badID)
		var failure *slice6CapacityFailure
		if !errors.As(err, &failure) || failure.class != test.class {
			t.Fatalf("host %s classification = %v", test.name, err)
		}
	}
	_, err := parseSlice6DockerAvailable(make([]byte, 4097))
	var failure *slice6CapacityFailure
	if !errors.As(err, &failure) || failure.class != slice6CapacityDockerOutputLimit {
		t.Fatalf("parser output overflow class = %v", err)
	}
}

func TestSlice6CapacityMonitorSampleTimeoutAndCloseRace(t *testing.T) {
	budget := slice6TopologyBudget(0)
	ready := slice6CapacityObservation{math.MaxInt64, math.MaxInt64}
	for _, test := range []struct {
		name      string
		closeOnly bool
		class     slice6CapacityClass
	}{
		{"sample-timeout", false, slice6CapacitySampleTimeout},
		{"normal-close", true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			var calls int
			var stopped int
			monitor, err := startSlice6CapacityMonitor(t.Context(), budget, 100*time.Millisecond, 150*time.Millisecond,
				func(ctx context.Context) (slice6CapacityObservation, error) {
					calls++
					if calls == 1 {
						return ready, nil
					}
					close(entered)
					<-ctx.Done()
					return slice6CapacityObservation{}, ctx.Err()
				}, func(error) { stopped++ })
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("monitor sample did not begin")
			}
			if test.closeOnly {
				monitor.Close()
				if stopped != 0 || monitor.Reason() != nil {
					t.Fatal("normal Close became an emergency stop")
				}
				return
			}
			select {
			case <-monitor.triggered:
			case <-time.After(time.Second):
				t.Fatal("sample timeout did not stop")
			}
			monitor.Close()
			monitor.Close()
			var typed *slice6CapacityFailure
			if stopped != 1 || !errors.As(monitor.Reason(), &typed) || typed.class != test.class ||
				!errors.Is(monitor.Reason(), context.DeadlineExceeded) {
				t.Fatalf("sample timeout class/once-only stop lost: %v", monitor.Reason())
			}
		})
	}
}

func TestSlice6DockerAvailableParser(t *testing.T) {
	valid := []byte("Filesystem 1-blocks Used Available Use% Mounted on\noverlay 1000 100 900 10% /\n")
	if value, err := parseSlice6DockerAvailable(valid); err != nil || value != 900 {
		t.Fatalf("valid Docker backing sample = %d, %v", value, err)
	}
	gnu := []byte("Filesystem 1B-blocks Used Available Use% Mounted on\noverlay 1000 100 900 10% /\n")
	if value, err := parseSlice6DockerAvailable(gnu); err != nil || value != 900 {
		t.Fatalf("valid GNU Docker backing sample = %d, %v", value, err)
	}
	for _, document := range [][]byte{
		nil,
		[]byte("Filesystem 1-blocks Used Available Use% Mounted on\noverlay 1000 100 0 10% /"),
		[]byte("Filesystem 1-blocks Used Available Use% Mounted on\noverlay 1000 100 900 10% /tmp"),
		[]byte("Filesystem 1-blocks Used Available Use% Mounted on\noverlay 1000 100 900 10% /\nextra"),
		[]byte("Filesystem 1-blocks Used Available Use% Mounted on\noverlay 1000 100 nope 10% /"),
		[]byte("Filesystem 1-blocks Used Available Use% Mounted on\noverlay 1000 100 9223372036854775808 10% /"),
	} {
		if _, err := parseSlice6DockerAvailable(document); err == nil {
			t.Fatalf("ambiguous Docker backing sample admitted: %q", document)
		}
	}
}

// This opt-in diagnostic verifies that the interlock can sample the real
// Docker backing filesystem via a run-owned container. It does not launch a
// reviewed role or satisfy any of the 16 release scenarios.
func TestSlice6RunningCapacityMonitorRealDockerDiagnostic(t *testing.T) {
	if os.Getenv(slice6CapacityMonitorDiagnosticEnv) != "1" {
		t.Skip("set " + slice6CapacityMonitorDiagnosticEnv + "=1 for real Docker capacity monitor diagnostic")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact capacity-monitor diagnostic cleanup: %v", err)
		}
	})
	container, err := run.docker(ctx, "run", "-d", "--pull=never", "--network", "none",
		"--name", "sr-p6-capacity-monitor-"+run.id, "--label", run.label(),
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", "64m", "--pids-limit", "16", slice6CapacityImage, "sleep", "30")
	containerID := strings.TrimSpace(string(container))
	if err != nil || len(containerID) != 64 || !lowerHexSlice6(containerID) {
		t.Fatal("real capacity-monitor diagnostic container did not start")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	sample := func(ctx context.Context) (slice6CapacityObservation, error) {
		return sampleSlice6RunningCapacity(ctx, run, root, containerID)
	}
	stopped := make(chan error, 1)
	monitor, err := startSlice6CapacityMonitor(ctx, slice6TopologyBudget(0), 500*time.Millisecond, 2*time.Second,
		sample, func(reason error) { stopped <- reason })
	if err != nil {
		t.Fatal("real Docker capacity-monitor admission failed")
	}
	select {
	case reason := <-stopped:
		t.Fatalf("real Docker capacity monitor stopped producers: %v", reason)
	case <-time.After(1200 * time.Millisecond):
	}
	monitor.Close()
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("exact capacity-monitor diagnostic cleanup: %v", err)
	}
	ids, err := run.labeledIDs(ctx, "container")
	if err != nil || len(ids) != 0 {
		t.Fatal("capacity-monitor diagnostic container retained")
	}
}

// This opt-in no-issuer drill runs the production sampling cadence through
// bounded container churn, then deliberately loses one sample to check the
// exact-run writer stop. It is not a reproduction of an earlier unknown loss.
func TestSlice6CapacitySamplingPerturbationNoIssuerDocker(t *testing.T) {
	if os.Getenv(slice6CapacityPerturbationDiagnosticEnv) != "1" {
		t.Skip("set " + slice6CapacityPerturbationDiagnosticEnv + "=1 for no-issuer perturbation drill")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("no-issuer capacity perturbation run label=%s", run.label())
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("exact no-issuer perturbation cleanup: %v", err)
		}
	})
	observerID, err := slice6StartCapacityObserver(ctx, run)
	if err != nil {
		t.Fatal("fixed capacity observer unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal("host sample root unavailable")
	}
	var forceLoss atomic.Bool
	stopResult := make(chan error, 1)
	monitor, err := startSlice6CapacityMonitor(ctx, slice6GuestStorageCapacityBudget(0),
		time.Second, 2*time.Second,
		func(sampleContext context.Context) (slice6CapacityObservation, error) {
			if forceLoss.Load() {
				return slice6CapacityObservation{}, &slice6CapacityFailure{stage: "docker", class: slice6CapacityDockerExec}
			}
			return sampleSlice6RunningCapacity(sampleContext, run, root, observerID)
		}, func(error) {
			stopContext, release := context.WithTimeout(context.Background(), 45*time.Second)
			defer release()
			stopResult <- slice6StopRunOwnedWritersContext(stopContext, run, observerID)
		})
	if err != nil {
		t.Fatal("no-issuer capacity admission failed")
	}
	defer monitor.Close()
	select {
	case <-time.After(2200 * time.Millisecond):
	case <-monitor.triggered:
		t.Fatalf("idle capacity sampling failed: %v", monitor.Reason())
	}
	startWriter := func(index int) string {
		t.Helper()
		output, startErr, overflow := slice6DockerBounded(ctx, 256, nil,
			"run", "-d", "--pull=never", "--network=none", "--restart=no",
			"--name", fmt.Sprintf("sr-p6-capacity-perturb-%02d-%s", index, run.id),
			"--label", run.label(), "--log-driver=none", "--user=65532:65532",
			"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
			"--memory=67108864", "--pids-limit=16", slice6CapacityImage, "sleep", "1500")
		id := strings.TrimSpace(string(output))
		clear(output)
		if startErr != nil || overflow || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("bounded read-only perturbation start unconfirmed")
		}
		state, inspectErr := slice6InspectWriterForStop(ctx, id)
		if inspectErr != nil || !state.exists || !state.running || state.owner != run.id {
			t.Fatal("perturbation exact owner/running readback failed")
		}
		return id
	}
	for index := 0; index < 10; index++ {
		id := startWriter(index)
		output, removeErr, overflow := slice6DockerBounded(ctx, 256, nil, "rm", "-f", "-v", id)
		confirmed := strings.TrimSpace(string(output)) == id
		clear(output)
		if removeErr != nil || overflow || !confirmed {
			t.Fatal("exact read-only perturbation removal unconfirmed")
		}
		if reason := monitor.Reason(); reason != nil {
			t.Fatalf("capacity monitor stopped during bounded perturbations: %v", reason)
		}
	}
	first, second := startWriter(10), startWriter(11)
	forceLoss.Store(true)
	select {
	case <-monitor.triggered:
	case <-time.After(10 * time.Second):
		t.Fatal("deliberate sample loss did not stop exact-run writers")
	}
	monitor.Close()
	select {
	case stopErr := <-stopResult:
		if stopErr != nil {
			t.Fatalf("exact-run emergency writer stop failed: %v", stopErr)
		}
	default:
		t.Fatal("emergency stop result missing")
	}
	var failure *slice6CapacityFailure
	if !errors.As(monitor.Reason(), &failure) || failure.class != slice6CapacityDockerExec {
		t.Fatalf("deliberate Docker sample-loss class lost: %v", monitor.Reason())
	}
	for _, id := range []string{first, second} {
		state, inspectErr := slice6InspectWriterForStop(ctx, id)
		if inspectErr != nil || !state.exists || state.running || state.owner != run.id {
			t.Fatal("exact-run writer was not observed stopped")
		}
	}
	t.Log("idle and ten create/remove perturbations stayed healthy; deliberate sample loss stopped two exact-run read-only writers")
}

// This no-issuer drill deletes one enumerated writer concurrently, then proves
// another exact-run writer stops while an independent run keeps running.
func TestSlice6CapacityLossStopsRealDockerWriter(t *testing.T) {
	if os.Getenv(slice6CapacityStopDiagnosticEnv) != "1" {
		t.Skip("set " + slice6CapacityStopDiagnosticEnv + "=1 for no-issuer Docker stop drill")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("capacity stop drill exact zero cleanup: %v", err)
		}
	})
	observerID, err := slice6StartCapacityObserver(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	otherRun, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if err := otherRun.cleanup(cleanup); err != nil {
			t.Errorf("foreign capacity run cleanup: %v", err)
		}
	})
	startWriter := func(owner slice6DockerRun, suffix string) string {
		t.Helper()
		raw, startErr := owner.docker(ctx, "run", "-d", "--pull=never", "--network=none", "--restart=no",
			"--name", "sr-p6-capacity-writer-"+suffix+"-"+owner.id, "--label", owner.label(),
			"--log-driver=none", "--user=65532:65532", "--read-only", "--cap-drop=ALL",
			"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
			slice6CapacityImage, "sleep", "30")
		id := strings.TrimSpace(string(raw))
		if startErr != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("capacity stop drill writer start unconfirmed")
		}
		return id
	}
	vanishedID := startWriter(run, "vanish")
	writerID := startWriter(run, "live")
	foreignID := startWriter(otherRun, "foreign")
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	var samples int
	var stopErr error
	ops := slice6DockerWriterStopOps(run)
	list := ops.list
	deleted := false
	ops.list = func(ctx context.Context) ([]string, error) {
		ids, err := list(ctx)
		if err != nil || deleted {
			return ids, err
		}
		if !slices.Contains(ids, vanishedID) {
			return nil, errors.New("concurrent-delete target missing from run inventory")
		}
		deleted = true
		if _, err := run.docker(ctx, "rm", "-f", "-v", vanishedID); err != nil {
			return nil, errors.New("enumerated writer concurrent deletion unavailable")
		}
		ordered := []string{vanishedID}
		for _, id := range ids {
			if id != vanishedID {
				ordered = append(ordered, id)
			}
		}
		return ordered, nil
	}
	monitor, err := startSlice6CapacityMonitor(ctx, slice6GuestStorageCapacityBudget(0),
		100*time.Millisecond, 2*time.Second,
		func(sampleContext context.Context) (slice6CapacityObservation, error) {
			samples++
			if samples == 2 {
				return slice6CapacityObservation{}, errSlice6Capacity
			}
			return sampleSlice6RunningCapacity(sampleContext, run, root, observerID)
		}, func(error) { stopErr = slice6StopRunOwnedWritersWith(ctx, run.id, observerID, ops) })
	if err != nil {
		t.Fatal("capacity stop drill admission failed")
	}
	select {
	case <-monitor.triggered:
	case <-time.After(15 * time.Second):
		t.Fatal("capacity stop drill did not trigger")
	}
	monitor.Close()
	if stopErr != nil || monitor.Reason() == nil || !deleted {
		t.Fatalf("capacity stop drill stop=%v reason=%v", stopErr, monitor.Reason())
	}
	if vanished, inspectErr := slice6InspectWriterForStop(ctx, vanishedID); inspectErr != nil || vanished.exists {
		t.Fatal("first enumerated writer was not confirmed deleted")
	}
	for _, probe := range []struct {
		id   string
		want bool
	}{{writerID, false}, {observerID, true}, {foreignID, true}} {
		raw, inspectErr := run.docker(ctx, "inspect", probe.id)
		var found []struct{ State struct{ Running bool } }
		if inspectErr != nil || json.Unmarshal(raw, &found) != nil || len(found) != 1 ||
			found[0].State.Running != probe.want {
			t.Fatal("capacity stop drill writer/observer stop order unconfirmed")
		}
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatal("capacity stop drill exact cleanup failed")
	}
	if err := otherRun.cleanup(ctx); err != nil {
		t.Fatal("foreign capacity run exact cleanup failed")
	}
}
