//go:build integration

package docker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/client"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	browserdocker "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	networkdocker "github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
)

const browserCrashChildConfigEnv = "SANDBOX_RUNTIME_BROWSER_BOUND_CRASH_CHILD_CONFIG"
const browserCrashOutputChildEnv = "SANDBOX_RUNTIME_BROWSER_CRASH_OUTPUT_CHILD"

type browserCrashChildConfig struct {
	Mode, RuntimeDSN, Checkpoint string
	Plan                         sandboxidentity.Plan
	Allocation, Competitor       providerbrowser.Allocation
	Driver                       browserdocker.Options
	Network                      networkdocker.Options
}

type browserCrashCheckpoint struct {
	Stage string
	PID   int
}

// This adds two actual OS-process crash boundaries to the existing real
// PostgreSQL/high-UID Docker component. It is not provider serve v3 evidence.
func runBrowserBoundProcessCrashComponent(t *testing.T, ctx context.Context, api *client.Client,
	ledger *providerpostgres.BrowserBoundIdentityRepository,
	runtime *browserapplication.BrowserIdentityRuntime,
	sessions *providerpostgres.BrowserRepository, plan sandboxidentity.Plan,
	driverOptions browserdocker.Options, networkOptions networkdocker.Options,
	runtimeDSN, uplink string, base providerbrowser.OpenRequest, token string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	private := t.TempDir()
	driverOptions.Clock = nil // the child installs its own clock; no function crosses the process boundary
	config := browserCrashChildConfig{RuntimeDSN: runtimeDSN, Plan: plan,
		Driver: driverOptions, Network: networkOptions}
	newAllocation := func(suffix, digestLetter string) (providerbrowser.Allocation, providerbrowser.Record) {
		t.Helper()
		now := time.Now().UTC()
		request := base
		request.OperationID = "operation-crash-" + suffix + "-" + token
		request.BrowserSessionID = "browser-crash-" + suffix + "-" + token
		request.AttemptID = "attempt-crash-" + suffix + "-" + token
		request.IdempotencyKey = "key-crash-" + suffix + "-" + token
		request.RequestDigest = testIdentityDigest(digestLetter)
		request.Deadline, request.ExpiresAt = now.Add(4*time.Minute), now.Add(4*time.Minute)
		reserved, reserveErr := sessions.ReserveOpen(ctx, request, now)
		if reserveErr != nil {
			t.Fatal(reserveErr)
		}
		allocation := providerbrowser.Allocation{Request: providerbrowser.AllocationRequest{
			SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
			OperationID: request.OperationID, AttemptID: request.AttemptID,
			FencingToken: request.FencingToken, ExpectedGeneration: request.ExpectedGeneration,
			RequestDigest: request.RequestDigest, NetworkPolicyReference: driverOptions.NetworkPolicyReference,
			ExpiresAt: request.ExpiresAt}, AllocatedAt: reserved.Record.AcceptedAt}
		return allocation, reserved.Record
	}
	completed, completedRecord := newAllocation("completed", "2")
	config.Allocation = completed
	config.Mode = "after_finished_dispatch"
	config.Checkpoint = filepath.Join(private, "finished.checkpoint")
	crashBrowserChildAtCheckpoint(t, ctx, executable, private, config, "after_finished_dispatch")
	before, err := inspectTopology(ctx, api, completed.Request, uplink)
	if err != nil {
		t.Fatal(err)
	}
	beforeIDs := browserOwnedResourceIDs(t, ctx, api, plan.Namespace, plan.ControllerID)
	config.Mode, config.Checkpoint = "recover_finished", ""
	runBrowserCrashChildToCompletion(t, ctx, executable, private, config)
	if after, inspectErr := inspectTopology(ctx, api, completed.Request, uplink); inspectErr != nil || after != before ||
		!reflect.DeepEqual(browserOwnedResourceIDs(t, ctx, api, plan.Namespace, plan.ControllerID), beforeIDs) {
		t.Fatalf("replacement PID changed completed-dispatch Docker identity: %v", inspectErr)
	}
	if held, readErr := ledger.Reservations(ctx); readErr != nil || len(held) != 1 || held[0].Status != sandboxidentity.Active {
		t.Fatalf("replacement PID did not recover exact Active ticket: %+v, %v", held, readErr)
	}
	terminalNow := time.Now().UTC()
	failed, err := providerbrowser.Transition(completedRecord, providerbrowser.StatusFailed, terminalNow, nil)
	if err != nil {
		t.Fatalf("transition completed Browser record: %v", err)
	}
	if err := sessions.UpdateOpenAt(ctx, failed, providerbrowser.StatusAccepted, terminalNow); err != nil {
		t.Fatalf("persist terminal completed Browser record: %v", err)
	}
	if err := runtime.RetireUnallocated(ctx, failed); err != nil {
		t.Fatalf("finished-dispatch terminal cleanup: %v", err)
	}
	assertResourcesAbsent(t, ctx, api, before)
	if held, readErr := ledger.Reservations(ctx); readErr != nil || len(held) != 0 {
		t.Fatalf("finished-dispatch cleanup retained UID: %+v, %v", held, readErr)
	}
	if remaining := browserOwnedResourceIDs(t, ctx, api, plan.Namespace, plan.ControllerID); len(remaining) != 0 {
		t.Fatalf("finished-dispatch cleanup retained owned Docker resources: %v", remaining)
	}

	unknown, unknownRecord := newAllocation("network", "3")
	config.Allocation = unknown
	config.Mode = "after_network_acquire"
	config.Checkpoint = filepath.Join(private, "network.checkpoint")
	crashBrowserChildAtCheckpoint(t, ctx, executable, private, config, "after_network_acquire")
	unknownIDs := browserOwnedResourceIDs(t, ctx, api, plan.Namespace, plan.ControllerID)
	if !slices.ContainsFunc(unknownIDs, func(id string) bool { return strings.HasPrefix(id, "container:") }) ||
		!slices.ContainsFunc(unknownIDs, func(id string) bool { return strings.HasPrefix(id, "network:") }) {
		t.Fatalf("real network/gateway side effect not observed after crash: %v", unknownIDs)
	}
	if held, readErr := ledger.Reservations(ctx); readErr != nil || len(held) != 1 ||
		held[0].Status != sandboxidentity.Creating || held[0].Claim.OperationID != unknown.Request.OperationID ||
		held[0].Slot != plan.Slots[0] {
		t.Fatalf("unproved Docker outcome did not retain exact Creating capacity: %+v, %v", held, readErr)
	}
	competitor := base
	competitor.SandboxID = "sandbox-competitor-" + token
	competitor.BrowserSessionID = "browser-competitor-" + token
	competitor.OperationID = "operation-competitor-" + token
	competitor.AttemptID = "attempt-competitor-" + token
	competitor.IdempotencyKey = "key-competitor-" + token
	competitor.RequestDigest = testIdentityDigest("4")
	competitor.Deadline = time.Now().UTC().Add(4 * time.Minute)
	competitor.ExpiresAt = competitor.Deadline
	if err := sessions.SynchronizeSandboxAuthority(ctx, providerbrowser.SandboxAuthority{
		SandboxID: competitor.SandboxID, ProviderRevisionID: competitor.ProviderRevisionID,
		Ready: true, Generation: 1, LeaseExpiresAt: competitor.ExpiresAt.Add(time.Minute),
		FencingToken: 1, CapabilityProfileID: providerbrowser.CapabilityProfileID,
		NetworkPolicyReference: driverOptions.NetworkPolicyReference}); err != nil {
		t.Fatal(err)
	}
	competing, err := sessions.ReserveOpen(ctx, competitor, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	config.Competitor = providerbrowser.Allocation{Request: providerbrowser.AllocationRequest{
		SandboxID: competitor.SandboxID, BrowserSessionID: competitor.BrowserSessionID,
		OperationID: competitor.OperationID, AttemptID: competitor.AttemptID,
		FencingToken: competitor.FencingToken, ExpectedGeneration: competitor.ExpectedGeneration,
		RequestDigest: competitor.RequestDigest, NetworkPolicyReference: driverOptions.NetworkPolicyReference,
		ExpiresAt: competitor.ExpiresAt}, AllocatedAt: competing.Record.AcceptedAt}
	config.Mode, config.Checkpoint = "deny_unknown", ""
	runBrowserCrashChildToCompletion(t, ctx, executable, private, config)
	if !reflect.DeepEqual(browserOwnedResourceIDs(t, ctx, api, plan.Namespace, plan.ControllerID), unknownIDs) {
		t.Fatal("replacement PID dispatched or changed unproved Docker resources")
	}
	terminalNow = time.Now().UTC()
	unknownTerminal, err := providerbrowser.Transition(unknownRecord, providerbrowser.StatusOutcomeUnknown, terminalNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.UpdateOpenAt(ctx, unknownTerminal, providerbrowser.StatusAccepted, terminalNow); err != nil {
		t.Fatal(err)
	}
	if err := runtime.RetireUnallocated(ctx, unknownTerminal); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
		t.Fatalf("unproved terminal Creating was released: %v", err)
	}
	if held, readErr := ledger.Reservations(ctx); readErr != nil || len(held) != 1 || held[0].Status != sandboxidentity.Creating {
		t.Fatalf("unknown result did not retain capacity after terminal reconciliation: %+v, %v", held, readErr)
	}
	// Teardown is operator/test-owned, not application recovery of an unknown
	// daemon outcome. The disposable PostgreSQL ledger remains Creating.
	if err := cleanupIntegrationResources(ctx, api, plan.Namespace, plan.ControllerID); err != nil ||
		len(browserOwnedResourceIDs(t, ctx, api, plan.Namespace, plan.ControllerID)) != 0 {
		t.Fatalf("exact unknown-outcome test resource teardown: %v", err)
	}
}

func browserOwnedResourceIDs(t *testing.T, ctx context.Context, api *client.Client, namespace, controller string) []string {
	t.Helper()
	filters := make(client.Filters).Add("label", managedLabel+"=true").
		Add("label", namespaceLabel+"="+namespace).Add("label", controllerLabel+"="+controller)
	containers, err := api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		t.Fatal(err)
	}
	networks, err := api.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil {
		t.Fatal(err)
	}
	result := make([]string, 0, len(containers.Items)+len(networks.Items))
	for _, value := range containers.Items {
		result = append(result, "container:"+value.ID)
	}
	for _, value := range networks.Items {
		result = append(result, "network:"+value.ID)
	}
	slices.Sort(result)
	return result
}

func crashBrowserChildAtCheckpoint(t *testing.T, ctx context.Context, executable, directory string,
	config browserCrashChildConfig, stage string) {
	t.Helper()
	path := writeBrowserCrashChildConfig(t, directory, config)
	child := exec.CommandContext(ctx, executable, "-test.run=^TestBrowserBoundCrashChild$")
	child.Env = append(os.Environ(), browserCrashChildConfigEnv+"="+path)
	if err := waitBrowserCrashCheckpoint(ctx, child, config.Checkpoint, stage, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	t.Logf("Browser application subprocess reached %s and died by SIGKILL; replacement must read durable state", stage)
}

// Output is deliberately discarded: a failing child must not race an
// unbounded bytes.Buffer read or leak private process diagnostics into a gate.
func waitBrowserCrashCheckpoint(ctx context.Context, child *exec.Cmd, checkpointPath, stage string, budget time.Duration) error {
	child.Stdout, child.Stderr = io.Discard, io.Discard
	if err := child.Start(); err != nil {
		return fmt.Errorf("start Browser crash child: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	finished := false
	defer func() {
		if !finished {
			_ = child.Process.Kill()
			<-done
		}
	}()
	deadline := time.NewTimer(budget)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-done:
			finished = true
			if err == nil {
				return fmt.Errorf("Browser child exited before %s checkpoint", stage)
			}
			return fmt.Errorf("Browser child exited before %s checkpoint: %w", stage, err)
		case <-deadline.C:
			return fmt.Errorf("Browser child did not reach %s checkpoint before bounded deadline", stage)
		case <-tick.C:
			raw, err := os.ReadFile(checkpointPath)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			var checkpoint browserCrashCheckpoint
			if err != nil || json.Unmarshal(raw, &checkpoint) != nil || checkpoint.Stage != stage || checkpoint.PID != child.Process.Pid {
				return errors.New("Browser child checkpoint mismatch")
			}
			if err := child.Process.Kill(); err != nil {
				return fmt.Errorf("kill Browser child at checkpoint: %w", err)
			}
			waitErr := <-done
			finished = true
			if child.ProcessState == nil {
				return errors.New("Browser child process state is unavailable after SIGKILL")
			}
			status, ok := child.ProcessState.Sys().(syscall.WaitStatus)
			if waitErr == nil || !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				return errors.New("Browser child did not die by SIGKILL")
			}
			return nil
		}
	}
}

func TestBrowserCrashCheckpointBoundedOutput(t *testing.T) {
	if os.Getenv(browserCrashOutputChildEnv) == "child" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("private-child-output"), 1<<16))
		time.Sleep(5 * time.Second)
		return
	}
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestBrowserCrashCheckpointBoundedOutput$")
	child.Env = append(os.Environ(), browserCrashOutputChildEnv+"=child")
	err := waitBrowserCrashCheckpoint(t.Context(), child, filepath.Join(t.TempDir(), "absent.checkpoint"),
		"bounded-output-regression", time.Second)
	if err == nil || !strings.Contains(err.Error(), "bounded deadline") || strings.Contains(err.Error(), "private-child-output") {
		t.Fatalf("unbounded or unredacted child failure: %v", err)
	}
}

func runBrowserCrashChildToCompletion(t *testing.T, ctx context.Context, executable, directory string,
	config browserCrashChildConfig) {
	t.Helper()
	path := writeBrowserCrashChildConfig(t, directory, config)
	child := exec.CommandContext(ctx, executable, "-test.run=^TestBrowserBoundCrashChild$")
	child.Env = append(os.Environ(), browserCrashChildConfigEnv+"="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("replacement Browser process %s failed: %v: %.512s", config.Mode, err, output)
	}
}

func writeBrowserCrashChildConfig(t *testing.T, directory string, config browserCrashChildConfig) string {
	t.Helper()
	path := filepath.Join(directory, "child-"+config.Mode+".json")
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type browserCrashBeforeCommit struct {
	*providerpostgres.BrowserBoundIdentityRepository
	checkpoint string
}

func (value *browserCrashBeforeCommit) CompleteCreate(_ context.Context, _ sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	return sandboxidentity.Reservation{}, browserCrashBlock(value.checkpoint, "after_finished_dispatch")
}

type browserCrashAfterNetwork struct {
	browserdocker.RestrictedNetwork
	checkpoint string
}

func (value *browserCrashAfterNetwork) Acquire(ctx context.Context, request browserdocker.NetworkRequest) (browserdocker.NetworkAttachment, error) {
	attachment, err := value.RestrictedNetwork.Acquire(ctx, request)
	if err != nil {
		return attachment, err
	}
	return attachment, browserCrashBlock(value.checkpoint, "after_network_acquire")
}

func browserCrashBlock(path, stage string) error {
	temporary := path + ".writing"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(file).Encode(browserCrashCheckpoint{Stage: stage, PID: os.Getpid()}); err != nil {
		_ = file.Close()
		return err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return err
	}
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	<-timer.C // parent must kill after observing the durable checkpoint
	return errors.New("Browser crash checkpoint was not terminated")
}

type browserForbidDispatch struct {
	*browserdocker.Driver
	attempts int
}

func (value *browserForbidDispatch) AllocateBound(context.Context, providerbrowser.Allocation,
	sandboxidentity.Reservation) (providerbrowser.AllocationReceipt, error) {
	value.attempts++
	return providerbrowser.AllocationReceipt{}, errors.New("replacement PID attempted a second Docker dispatch")
}

func TestBrowserBoundCrashChild(t *testing.T) {
	path := os.Getenv(browserCrashChildConfigEnv)
	if path == "" {
		t.Skip("component subprocess only")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 32<<10 {
		t.Fatal("bounded Browser crash child configuration unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config browserCrashChildConfig
	var trailing any
	if decoder.Decode(&config) != nil || decoder.Decode(&trailing) != io.EOF {
		t.Fatal("Browser crash child configuration invalid")
	}
	switch config.Mode {
	case "after_finished_dispatch", "after_network_acquire", "recover_finished", "deny_unknown":
	default:
		t.Fatal("Browser crash child mode invalid")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, config.RuntimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := providerpostgres.New(pool, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := providerpostgres.NewBrowserBoundIdentityRepository(ctx, store, config.Plan)
	if err != nil {
		t.Fatal(err)
	}
	network, err := networkdocker.New(ctx, config.Network)
	if err != nil {
		t.Fatal(err)
	}
	defer network.Close()
	var restricted browserdocker.RestrictedNetwork = network
	if config.Mode == "after_network_acquire" {
		restricted = &browserCrashAfterNetwork{RestrictedNetwork: network, checkpoint: config.Checkpoint}
	}
	verifier, err := realProvenanceVerifier()
	if err != nil {
		t.Fatal(err)
	}
	config.Driver.Clock = browserdocker.ClockFunc(time.Now)
	authority, err := config.Plan.ProjectRuntimeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := browserdocker.NewBound(ctx, config.Driver, verifier, restricted, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	var selected browserapplication.BrowserIdentityLifecycleLedger = ledger
	if config.Mode == "after_finished_dispatch" {
		selected = &browserCrashBeforeCommit{BrowserBoundIdentityRepository: ledger, checkpoint: config.Checkpoint}
	}
	var bound browserapplication.BoundBrowserRuntime = driver
	var forbidden *browserForbidDispatch
	if config.Mode == "recover_finished" || config.Mode == "deny_unknown" {
		forbidden = &browserForbidDispatch{Driver: driver}
		bound = forbidden
	}
	runtime, err := browserapplication.NewBrowserIdentityRuntime(selected, bound, browserapplication.ClockFunc(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	switch config.Mode {
	case "after_finished_dispatch", "after_network_acquire":
		if _, err := runtime.Allocate(ctx, config.Allocation); err == nil {
			t.Fatal("crash boundary returned without SIGKILL")
		}
		t.Fatal("crash boundary failed before checkpoint")
	case "recover_finished":
		receipt, err := runtime.Allocate(ctx, config.Allocation)
		if err != nil || receipt.Validate() != nil || !receipt.Matches(config.Allocation.Request) || forbidden.attempts != 0 {
			t.Fatalf("replacement did not use finished proof: %v, dispatches %d", err, forbidden.attempts)
		}
	case "deny_unknown":
		if _, err := runtime.Allocate(ctx, config.Allocation); !errors.Is(err, providerbrowser.ErrAllocationUnknown) {
			t.Fatalf("unproved Creating recovered: %v", err)
		}
		if _, err := runtime.Allocate(ctx, config.Competitor); !errors.Is(err, providerbrowser.ErrBrowserUnsupported) {
			t.Fatalf("competing request reused held UID: %v", err)
		}
		if forbidden.attempts != 0 {
			t.Fatalf("replacement dispatched unproved work %d times", forbidden.attempts)
		}
	default:
		t.Fatal(fmt.Errorf("unexpected Browser crash action"))
	}
}
