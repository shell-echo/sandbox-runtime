//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

var errSlice6CapacityMonitorClosed = errors.New("Slice 6 capacity monitor closed")

const slice6CapacityMonitorDiagnosticEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CAPACITY_MONITOR_DIAGNOSTIC"
const slice6CapacityStopDiagnosticEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CAPACITY_STOP_DIAGNOSTIC"

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
	if parent == nil || parent.Err() != nil || interval < 100*time.Millisecond || interval > time.Second ||
		sampleTimeout < interval || sampleTimeout > 2*time.Second || sample == nil || stopProducers == nil {
		return nil, errSlice6Capacity
	}
	initialContext, cancelInitial := context.WithTimeout(parent, sampleTimeout)
	initial, err := sample(initialContext)
	cancelInitial()
	if err != nil || budget.admit(initial) != nil {
		return nil, errSlice6Capacity
	}
	ctx, cancel := context.WithCancelCause(parent)
	monitor := &slice6CapacityMonitor{cancel: cancel, done: make(chan struct{}), triggered: make(chan struct{})}
	go func() {
		defer close(monitor.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				if !errors.Is(context.Cause(ctx), errSlice6CapacityMonitorClosed) {
					monitor.stop(context.Cause(ctx), stopProducers)
				}
				return
			case <-ticker.C:
				pollContext, cancelPoll := context.WithTimeout(ctx, sampleTimeout)
				observation, pollErr := sample(pollContext)
				cancelPoll()
				if ctx.Err() != nil {
					if !errors.Is(context.Cause(ctx), errSlice6CapacityMonitorClosed) {
						monitor.stop(context.Cause(ctx), stopProducers)
					}
					return
				}
				if pollErr != nil || budget.stopEarly(observation) {
					if pollErr == nil {
						pollErr = errSlice6Capacity
					}
					monitor.stop(pollErr, stopProducers)
					return
				}
			}
		}
	}()
	return monitor, nil
}

func (monitor *slice6CapacityMonitor) stop(reason error, stopProducers func(error)) {
	monitor.stopOnce.Do(func() {
		stopProducers(reason)
		monitor.mu.Lock()
		monitor.reason = reason
		monitor.mu.Unlock()
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
// Docker backing filesystem from a known run-owned container. Loss of that
// container or an ambiguous df response is a monitor failure, not free space.
func sampleSlice6RunningCapacity(ctx context.Context, run slice6DockerRun, hostPath, containerID string) (slice6CapacityObservation, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(hostPath) || filepath.Clean(hostPath) != hostPath ||
		len(containerID) != 64 || !lowerHexSlice6(containerID) {
		return slice6CapacityObservation{}, errSlice6Capacity
	}
	info, err := os.Lstat(hostPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return slice6CapacityObservation{}, errSlice6Capacity
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(hostPath, &stat); err != nil || stat.Bsize <= 0 || stat.Bavail == 0 ||
		uint64(stat.Bavail) > math.MaxInt64/uint64(stat.Bsize) {
		return slice6CapacityObservation{}, errSlice6Capacity
	}
	document, err := run.docker(ctx, "exec", containerID, "df", "-B1", "/")
	if err != nil {
		return slice6CapacityObservation{}, errSlice6Capacity
	}
	available, err := parseSlice6DockerAvailable(document)
	if err != nil {
		return slice6CapacityObservation{}, err
	}
	return slice6CapacityObservation{hostPhysicalAvailableBytes: int64(stat.Bavail) * int64(stat.Bsize),
		dockerBackingAvailableBytes: available}, nil
}

func parseSlice6DockerAvailable(document []byte) (int64, error) {
	if len(document) == 0 || len(document) > 4096 {
		return 0, errSlice6Capacity
	}
	lines := strings.Split(strings.TrimSpace(string(document)), "\n")
	if len(lines) != 2 {
		return 0, errSlice6Capacity
	}
	header, row := strings.Fields(lines[0]), strings.Fields(lines[1])
	if len(header) != 7 || (header[1] != "1-blocks" && header[1] != "1B-blocks") ||
		header[3] != "Available" ||
		header[5] != "Mounted" || header[6] != "on" ||
		len(row) != 6 || row[5] != "/" {
		return 0, errSlice6Capacity
	}
	available, err := strconv.ParseInt(row[3], 10, 64)
	if err != nil || available <= 0 {
		return 0, errSlice6Capacity
	}
	return available, nil
}

// Capacity loss is an emergency stop, not just cancellation of a Docker CLI.
// Only exact run-labeled, inspected writer containers are stopped; the
// read-only sampling container remains available until the monitor closes.
func slice6StopRunOwnedWriters(run slice6DockerRun, observerID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ids, err := run.labeledIDs(ctx, "container")
	if err != nil {
		return err
	}
	var writers []string
	for _, id := range ids {
		if id == observerID {
			continue
		}
		raw, inspectErr := run.docker(ctx, "inspect", id)
		var found []struct {
			ID     string `json:"Id"`
			Config struct{ Labels map[string]string }
			State  struct{ Running bool }
		}
		if inspectErr != nil || json.Unmarshal(raw, &found) != nil || len(found) != 1 ||
			found[0].ID != id || found[0].Config.Labels[slice6RunLabel] != run.id {
			return errors.New("capacity stop writer ownership changed")
		}
		if found[0].State.Running {
			writers = append(writers, id)
		}
	}
	if len(writers) == 0 {
		return nil
	}
	arguments := append([]string{"stop", "-t", "1"}, writers...)
	_, stopErr, overflow := slice6DockerBounded(ctx, 8192, nil, arguments...)
	if stopErr != nil || overflow {
		arguments = append([]string{"kill"}, writers...)
		if _, killErr, killOverflow := slice6DockerBounded(ctx, 8192, nil, arguments...); killErr != nil || killOverflow {
			return errors.New("capacity loss could not stop exact run-owned writers")
		}
	}
	for _, id := range writers {
		raw, inspectErr := run.docker(ctx, "inspect", id)
		var found []struct {
			ID    string `json:"Id"`
			State struct{ Running bool }
		}
		if inspectErr != nil || json.Unmarshal(raw, &found) != nil || len(found) != 1 ||
			found[0].ID != id || found[0].State.Running {
			return errors.New("capacity loss writer stop not observed")
		}
	}
	return nil
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

// This no-issuer drill kills no unrelated process: a lost sample forces an
// exact run-labeled writer to stop before the normal zero-resource cleanup.
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
	writerRaw, err := run.docker(ctx, "run", "-d", "--pull=never", "--network=none", "--restart=no",
		"--name", "sr-p6-capacity-writer-"+run.id, "--label", run.label(),
		"--log-driver=none", "--user=65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
		slice6CapacityImage, "sleep", "30")
	writerID := strings.TrimSpace(string(writerRaw))
	if err != nil || len(writerID) != 64 || !lowerHexSlice6(writerID) {
		t.Fatal("capacity stop drill writer start unconfirmed")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	var samples int
	var stopErr error
	monitor, err := startSlice6CapacityMonitor(ctx, slice6GuestStorageCapacityBudget(0),
		100*time.Millisecond, 2*time.Second,
		func(sampleContext context.Context) (slice6CapacityObservation, error) {
			samples++
			if samples == 2 {
				return slice6CapacityObservation{}, errSlice6Capacity
			}
			return sampleSlice6RunningCapacity(sampleContext, run, root, observerID)
		}, func(error) { stopErr = slice6StopRunOwnedWriters(run, observerID) })
	if err != nil {
		t.Fatal("capacity stop drill admission failed")
	}
	select {
	case <-monitor.triggered:
	case <-time.After(15 * time.Second):
		t.Fatal("capacity stop drill did not trigger")
	}
	monitor.Close()
	if stopErr != nil || monitor.Reason() == nil {
		t.Fatalf("capacity stop drill stop=%v reason=%v", stopErr, monitor.Reason())
	}
	for _, probe := range []struct {
		id   string
		want bool
	}{{writerID, false}, {observerID, true}} {
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
}
