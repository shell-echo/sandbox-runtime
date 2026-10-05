package coordinator

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/memory"
)

func originalTestDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

type testCodingOriginalRepository struct {
	*testCodingBoundRepository
	plan        codingidentity.Plan
	policy      string
	original    []byte
	cancel      context.CancelFunc
	driftTicket bool
}

func (r *testCodingOriginalRepository) BeginCodingFirstCreateWithAuthority(ctx context.Context,
	operationID string) (codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox,
	dockercontrol.CodingCreateAuthority, error) {
	ticket, running, provisioning, err := r.testCodingBoundRepository.BeginCodingFirstCreate(ctx, operationID)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
			dockercontrol.CodingCreateAuthority{}, err
	}
	ticket.PlanDigest, err = r.plan.Digest()
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
			dockercontrol.CodingCreateAuthority{}, err
	}
	authority, err := dockercontrol.NewCodingCreateAuthority(ctx, ticket, running,
		provisioning, r.plan, r.policy, r.plan.OwnerPrincipalDigest, running.ObservedAt)
	if err != nil {
		return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
			dockercontrol.CodingCreateAuthority{}, err
	}
	r.original, err = dockercontrol.EncodeCodingCreateAuthority(authority)
	if r.driftTicket {
		ticket.SpecDigest = originalTestDigest("0")
	}
	if r.cancel != nil {
		r.cancel()
	}
	return ticket, running, provisioning, authority, err
}

type testCodingOriginalDriver struct {
	*testCodingDispatchDriver
	mu        sync.Mutex
	originals [][]byte
}

func (d *testCodingOriginalDriver) DispatchCodingCreateAuthority(ctx context.Context,
	authority dockercontrol.CodingCreateAuthority) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	document, err := dockercontrol.EncodeCodingCreateAuthority(authority)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.originals = append(d.originals, document)
	d.mu.Unlock()
	return nil
}

func newOriginalCoordinator(t *testing.T, now time.Time) (*Coordinator,
	*testCodingOriginalRepository, *testCodingOriginalDriver, *testClock) {
	t.Helper()
	clock := &testClock{now: now}
	base := memory.NewRepository()
	t.Cleanup(func() { _ = base.Close() })
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: originalTestDigest("d"), OwnerDeployment: "provider-runtime",
		OwnerPrincipalDigest: originalTestDigest("f"), Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: originalTestDigest("2"), ImageDigest: originalTestDigest("3"),
		ImageConfigDigest: originalTestDigest("4"), NetworkMode: "none",
		Limits:   codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64},
		Capacity: codingidentity.LocalCandidateCapacity,
		Slots: []codingidentity.Slot{
			{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000,
				InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace",
				OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001,
				InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace",
				OutputsVolume: "coding-0001-outputs"}}}
	bound := &testCodingBoundRepository{Repository: base, clock: clock,
		digest: validRequest(now).RequestDigest}
	repo := &testCodingOriginalRepository{testCodingBoundRepository: bound,
		plan: plan, policy: originalTestDigest("e")}
	driver := &testCodingOriginalDriver{testCodingDispatchDriver: &testCodingDispatchDriver{}}
	service, err := NewWithCodingOriginalAuthority(repo, driver, clock)
	if err != nil {
		t.Fatal(err)
	}
	return service, repo, driver, clock
}

func TestCodingOriginalCoordinatorDispatchesExactOnceAndReadbackNeverReplays(t *testing.T) {
	service, repo, driver, clock := newOriginalCoordinator(t, time.Now().UTC())
	request := codingRequest(clock.Now())
	if _, err := service.AcceptCreate(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _ = service.ReconcileOperation(context.Background(), request.OperationID)
		}()
	}
	wait.Wait()
	driver.mu.Lock()
	count := len(driver.originals)
	var sent []byte
	if count == 1 {
		sent = driver.originals[0]
	}
	driver.mu.Unlock()
	if count != 1 || !bytes.Equal(sent, repo.original) {
		t.Fatalf("dispatcher did not receive exact original bytes once: count=%d", count)
	}
	if _, err := service.ReconcileOperation(t.Context(), request.OperationID); !errors.Is(err, ErrUnknownRuntime) {
		t.Fatalf("committed first permit replayed instead of readback: %v", err)
	}
	driver.mu.Lock()
	count = len(driver.originals)
	driver.mu.Unlock()
	if count != 1 || driver.legacyCreates != 0 || driver.legacyInspects != 0 ||
		driver.dispatches != 0 {
		t.Fatal("v3 used a legacy create/inspect/ticket dispatcher")
	}
}

func TestCodingOriginalCoordinatorRejectsLegacyAndExpiredOrCancelledPermit(t *testing.T) {
	service, repo, _, _ := newOriginalCoordinator(t, time.Now().UTC())
	if _, err := NewWithCodingOriginalAuthority(repo, &testCodingDispatchDriver{},
		&testClock{now: time.Now().UTC()}); !errors.Is(err, ErrInvalidCoordinator) {
		t.Fatalf("legacy-only dispatcher entered v3 composition: %v", err)
	}
	_ = service
	for name, offset := range map[string]time.Duration{"expired": -31 * time.Second,
		"cancelled": 0} {
		t.Run(name, func(t *testing.T) {
			service, repo, driver, clock := newOriginalCoordinator(t, time.Now().UTC().Add(offset))
			request := codingRequest(clock.Now())
			if _, err := service.AcceptCreate(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			if name == "cancelled" {
				repo.cancel = cancel
			} else {
				defer cancel()
			}
			if _, err := service.ReconcileOperation(ctx, request.OperationID); err == nil {
				t.Fatal("unusable original returned success")
			}
			driver.mu.Lock()
			count := len(driver.originals)
			driver.mu.Unlock()
			if count != 0 {
				t.Fatal("expired or cancelled original reached dispatcher")
			}
		})
	}
}

func TestCodingOriginalCoordinatorRejectsReturnedTupleDriftBeforeDispatch(t *testing.T) {
	service, repo, driver, clock := newOriginalCoordinator(t, time.Now().UTC())
	repo.driftTicket = true
	request := codingRequest(clock.Now())
	if _, err := service.AcceptCreate(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReconcileOperation(t.Context(), request.OperationID); !errors.Is(err, ErrInvalidCoordinator) {
		t.Fatalf("returned ticket/authority drift was dispatched: %v", err)
	}
	driver.mu.Lock()
	count := len(driver.originals)
	driver.mu.Unlock()
	if count != 0 {
		t.Fatal("tuple-drifted original reached physical dispatcher")
	}
}

type codingTrapRepository struct {
	repository.Repository
	operation lifecycle.Operation
	sandbox   lifecycle.Sandbox
}

func (r *codingTrapRepository) GetOperation(context.Context, string) (lifecycle.Operation, error) {
	return r.operation, nil
}

func (r *codingTrapRepository) GetSandbox(context.Context, string) (lifecycle.Sandbox, error) {
	return r.sandbox, nil
}

func (r *codingTrapRepository) BeginCodingFirstCreateWithAuthority(context.Context, string) (
	codingidentity.Reservation, lifecycle.Operation, lifecycle.Sandbox,
	dockercontrol.CodingCreateAuthority, error) {
	return codingidentity.Reservation{}, lifecycle.Operation{}, lifecycle.Sandbox{},
		dockercontrol.CodingCreateAuthority{}, errors.New("trap first permit")
}

type codingTrapDriver struct{ calls int }

func (d *codingTrapDriver) Create(context.Context, lifecycle.Sandbox) error {
	d.calls++
	return nil
}

func (d *codingTrapDriver) Inspect(context.Context, string) (RuntimeObservation, error) {
	d.calls++
	return RuntimeObservation{State: RuntimeAbsent}, nil
}

func (d *codingTrapDriver) Remove(context.Context, string) error  { d.calls++; return nil }
func (d *codingTrapDriver) Suspend(context.Context, string) error { d.calls++; return nil }
func (d *codingTrapDriver) Resume(context.Context, string) error  { d.calls++; return nil }
func (d *codingTrapDriver) DispatchCodingCreateAuthority(context.Context,
	dockercontrol.CodingCreateAuthority) error {
	d.calls++
	return nil
}

func TestCodingOriginalCoordinatorNeverRoutesOtherLifecycleToLegacyDriver(t *testing.T) {
	repo := &codingTrapRepository{sandbox: lifecycle.Sandbox{ID: "coding-sandbox-1"}}
	driver := &codingTrapDriver{}
	service, err := NewWithCodingOriginalAuthority(repo, driver,
		&testClock{now: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, operationType := range []lifecycle.OperationType{
		lifecycle.OperationCreate, lifecycle.OperationTerminate,
		lifecycle.OperationSuspend, lifecycle.OperationResume,
		lifecycle.OperationExtendLease,
	} {
		repo.operation = lifecycle.Operation{ID: "coding-operation-1",
			SandboxID: repo.sandbox.ID, Type: operationType,
			State: lifecycle.OperationAccepted}
		if operationType == lifecycle.OperationCreate {
			repo.operation.State = lifecycle.OperationRunning
		}
		if _, err := service.ReconcileOperation(t.Context(), repo.operation.ID); !errors.Is(err, ErrUnknownRuntime) {
			t.Fatalf("%s used legacy lifecycle path: %v", operationType, err)
		}
	}
	if driver.calls != 0 {
		t.Fatalf("v3 called a legacy optional driver method %d times", driver.calls)
	}
}
