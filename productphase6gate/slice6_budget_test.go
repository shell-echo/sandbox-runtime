//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	slice6GiB              = int64(1 << 30)
	slice6CapacityProbeEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_CAPACITY_PREFLIGHT"
	slice6CapacityImage    = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"
)

var errSlice6Capacity = errors.New("Slice 6 physical/Docker capacity budget not established")

// This is a per-stage operating guard, not a Docker/DB volume quota. Retained
// bytes are already consumed and are inventory only. Docker writes are also
// charged to host physical growth because Docker Desktop has sparse backing.
type slice6CapacityBudget struct {
	retainedBytes, hostLocalPeakBytes, dockerPeakBytes int64
	runtimeWriteBytes, stopLagBytes                    int64
	cleanupEvidenceBytes, sharedHostReserveBytes       int64
	dockerReserveBytes, pollBurstBytes                 int64
}

type slice6CapacityObservation struct {
	hostPhysicalAvailableBytes, dockerBackingAvailableBytes int64
}

func (b slice6CapacityBudget) required() (host, docker int64, err error) {
	if b.retainedBytes < 0 {
		return 0, 0, errSlice6Capacity
	}
	host, err = slice6Sum(b.hostLocalPeakBytes, b.dockerPeakBytes, b.runtimeWriteBytes,
		b.stopLagBytes, b.cleanupEvidenceBytes, b.sharedHostReserveBytes)
	if err != nil {
		return 0, 0, err
	}
	docker, err = slice6Sum(b.dockerPeakBytes, b.runtimeWriteBytes, b.stopLagBytes, b.dockerReserveBytes)
	return host, docker, err
}

func (b slice6CapacityBudget) admit(observation slice6CapacityObservation) error {
	host, docker, err := b.required()
	if err != nil {
		return &slice6CapacityFailure{stage: "admission", class: slice6CapacityInvalidInput}
	}
	return slice6CapacityThresholdFailure("admission", observation, host, docker)
}

// stopEarly applies after a stage has begun. It leaves room for one measured
// polling burst, writes in the bounded stop delay, cleanup receipts and the
// shared-host reserve. The caller must stop producers before run-owned cleanup.
func (b slice6CapacityBudget) stopEarly(observation slice6CapacityObservation) bool {
	return b.stopEarlyFailure(observation) != nil
}

func (b slice6CapacityBudget) stopEarlyFailure(observation slice6CapacityObservation) error {
	host, docker, err := b.stopThresholds()
	if err != nil {
		return &slice6CapacityFailure{stage: "monitor", class: slice6CapacityInvalidInput}
	}
	return slice6CapacityThresholdFailure("monitor", observation, host, docker)
}

func (b slice6CapacityBudget) stopThresholds() (int64, int64, error) {
	host, hostErr := slice6Sum(b.pollBurstBytes, b.stopLagBytes,
		b.cleanupEvidenceBytes, b.sharedHostReserveBytes)
	docker, dockerErr := slice6Sum(b.pollBurstBytes, b.stopLagBytes, b.dockerReserveBytes)
	if hostErr != nil || dockerErr != nil {
		return 0, 0, errSlice6Capacity
	}
	return host, docker, nil
}

func slice6Sum(values ...int64) (int64, error) {
	var total int64
	for _, value := range values {
		if value < 0 || total > math.MaxInt64-value {
			return 0, errSlice6Capacity
		}
		total += value
	}
	return total, nil
}

// The topology estimate includes bounded test-input/time growth for three
// PostgreSQL databases including WAL/temp, Vault, Valkey, recording, all 78
// static role logs plus external/dynamic logs, and writable layers. Only
// tmpfs/log rotation are hard limits; DB/volume figures require active
// monitoring and early stop.
func slice6TopologyBudget(retainedBytes int64) slice6CapacityBudget {
	return slice6CapacityBudget{retainedBytes: retainedBytes,
		hostLocalPeakBytes: 1 * slice6GiB, dockerPeakBytes: 1 * slice6GiB,
		runtimeWriteBytes: 10 * slice6GiB, stopLagBytes: 1 * slice6GiB,
		cleanupEvidenceBytes: slice6GiB / 2, sharedHostReserveBytes: 8 * slice6GiB,
		dockerReserveBytes: 4 * slice6GiB, pollBurstBytes: slice6GiB / 4}
}

// The existing 10 GiB growth estimate does not separately identify Guest
// workspace/state/inputs. Until that estimate is decomposed, admit their
// three candidate logical budgets as an explicit conservative increment,
// rather than silently assuming they were already included. This is still
// neither a named-volume hard quota nor a proof for arbitrary deep paths.
func slice6GuestStorageCapacityBudget(retainedBytes int64) slice6CapacityBudget {
	budget := slice6TopologyBudget(retainedBytes)
	budget.runtimeWriteBytes += 3*slice6GiB + 2*(1<<20)
	return budget
}

func TestSlice6GuestStorageCapacityIncrementIsNotDoubleCounted(t *testing.T) {
	baseline := slice6TopologyBudget(0)
	guest := slice6GuestStorageCapacityBudget(0)
	baselineHost, baselineDocker, err := baseline.required()
	guestHost, guestDocker, guestErr := guest.required()
	if err != nil || guestErr != nil || guestHost-baselineHost != 3*slice6GiB+2*(1<<20) ||
		guestDocker-baselineDocker != 3*slice6GiB+2*(1<<20) ||
		guest.runtimeWriteBytes != 13*slice6GiB+2*(1<<20) {
		t.Fatal("Guest named-volume candidate budget omitted or counted twice")
	}
}

func TestSlice6CapacityBudgetSeparatesHostAndDocker(t *testing.T) {
	budget := slice6TopologyBudget(12 * slice6GiB)
	host, docker, err := budget.required()
	if err != nil || host != 21*slice6GiB+slice6GiB/2 || docker != 16*slice6GiB {
		t.Fatalf("unexpected two-sided requirement: %d %d %v", host, docker, err)
	}
	if budget.admit(slice6CapacityObservation{hostPhysicalAvailableBytes: host + 1,
		dockerBackingAvailableBytes: docker + 1}) != nil {
		t.Fatal("adequate separate host/Docker capacity rejected")
	}
	if budget.admit(slice6CapacityObservation{hostPhysicalAvailableBytes: host,
		dockerBackingAvailableBytes: math.MaxInt64}) == nil {
		t.Fatal("Docker virtual capacity masked exhausted physical host")
	}
	if budget.admit(slice6CapacityObservation{hostPhysicalAvailableBytes: math.MaxInt64,
		dockerBackingAvailableBytes: docker}) == nil {
		t.Fatal("host capacity masked exhausted Docker backing filesystem")
	}
	if budget.stopEarly(slice6CapacityObservation{hostPhysicalAvailableBytes: 10 * slice6GiB,
		dockerBackingAvailableBytes: 100 * slice6GiB}) {
		t.Fatal("normal reserve level triggered early stop")
	}
	if !budget.stopEarly(slice6CapacityObservation{hostPhysicalAvailableBytes: 9 * slice6GiB,
		dockerBackingAvailableBytes: 100 * slice6GiB}) {
		t.Fatal("bounded stop-delay reserve threshold was not triggered")
	}
	bad := budget
	bad.runtimeWriteBytes = math.MaxInt64
	if bad.admit(slice6CapacityObservation{math.MaxInt64, math.MaxInt64}) == nil {
		t.Fatal("overflowing budget admitted")
	}
}

// This opt-in precheck reads actual free capacity without filling a disk. A
// fresh run label permits exact cleanup if Docker committed a failed probe.
func TestSlice6CapacityPreflightRealHostAndDocker(t *testing.T) {
	if os.Getenv(slice6CapacityProbeEnv) != "1" {
		t.Skip("set " + slice6CapacityProbeEnv + "=1 for the real capacity precheck")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("capacity probe exact cleanup: %v", err)
		}
	})
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	var host unix.Statfs_t
	if err := unix.Statfs(root, &host); err != nil || host.Bsize <= 0 || host.Bavail == 0 ||
		uint64(host.Bavail) > math.MaxInt64/uint64(host.Bsize) {
		t.Fatal("host physical filesystem free capacity unavailable")
	}
	name := "sr-p6-capacity-" + run.id
	output, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--pull=never", "--network", "none",
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", "64m", "--pids-limit", "16", "--name", name, "--label", run.label(),
		slice6CapacityImage, "df", "-B1", "/").CombinedOutput()
	if err != nil {
		t.Fatalf("Docker backing capacity probe: %v: %.512s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "1-blocks") {
		t.Fatal("unexpected Docker capacity probe format")
	}
	fields := strings.Fields(lines[1])
	if len(fields) != 6 {
		t.Fatal("unexpected Docker backing capacity row")
	}
	dockerAvailable, err := strconv.ParseInt(fields[3], 10, 64)
	if err != nil || dockerAvailable <= 0 {
		t.Fatal("Docker backing free capacity unavailable")
	}
	observation := slice6CapacityObservation{hostPhysicalAvailableBytes: int64(host.Bavail) * int64(host.Bsize),
		dockerBackingAvailableBytes: dockerAvailable}
	budget := slice6TopologyBudget(0) // retained inventory is reported separately before full admission.
	if err := budget.admit(observation); err != nil {
		t.Fatalf("current measured space does not admit the draft topology budget: %v", err)
	}
	hostRequired, dockerRequired, _ := budget.required()
	t.Logf("host available=%d required=%d; Docker backing available=%d required=%d; no disk-fill test",
		observation.hostPhysicalAvailableBytes, hostRequired, observation.dockerBackingAvailableBytes, dockerRequired)
}
