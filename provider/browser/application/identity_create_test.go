package application

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
)

type identityLedgerFixture struct {
	mu                       sync.Mutex
	plan                     sandboxidentity.Plan
	state                    sandboxidentity.State
	events                   []string
	loseBegin, loseComplete  bool
	failCompleteBeforeCommit bool
	loseCleanup              bool
	releasedTicket           sandboxidentity.Reservation
	retiredReceipt           browser.AllocationReceipt
}

func (f *identityLedgerFixture) Plan() sandboxidentity.Plan { return f.plan }
func (f *identityLedgerFixture) ReserveAuthorized(_ context.Context, allocation browser.Allocation,
	specs map[string]string) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "Reserve")
	request := allocation.Request
	claim := sandboxidentity.Claim{SandboxID: request.SandboxID, SessionID: request.BrowserSessionID,
		OperationID: request.OperationID, AttemptID: request.AttemptID, RequestDigest: request.RequestDigest,
		Generation: request.ExpectedGeneration, Fence: request.FencingToken}
	return f.state.Reserve(f.plan, claim, specs)
}
func (f *identityLedgerFixture) BeginCreateAuthorized(_ context.Context, _ browser.Allocation,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "BeginCreate")
	result, err := f.state.BeginCreate(f.plan, ticket)
	if err == nil && f.loseBegin {
		return sandboxidentity.Reservation{}, errors.New("lost BeginCreate response")
	}
	return result, err
}
func (f *identityLedgerFixture) CompleteCreate(_ context.Context,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "CompleteCreate")
	if f.failCompleteBeforeCommit {
		return sandboxidentity.Reservation{}, errors.New("PostgreSQL unavailable before CompleteCreate commit")
	}
	result, err := f.state.CompleteCreate(f.plan, ticket)
	if err == nil && f.loseComplete {
		return sandboxidentity.Reservation{}, errors.New("lost CompleteCreate response")
	}
	return result, err
}
func (f *identityLedgerFixture) status() sandboxidentity.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.state.Reservations) == 0 {
		return ""
	}
	return f.state.Reservations[0].Status
}
func (f *identityLedgerFixture) Reservations(context.Context) ([]sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "Reservations")
	return append([]sandboxidentity.Reservation(nil), f.state.Reservations...), nil
}
func (f *identityLedgerFixture) BeginCleanupAuthorized(_ context.Context, receipt browser.AllocationReceipt,
	ticket sandboxidentity.Reservation) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "BeginCleanup")
	cleaning, err := f.state.BeginCleanup(f.plan, ticket)
	if err == nil {
		f.retiredReceipt = receipt
	}
	return cleaning, err
}
func (f *identityLedgerFixture) CompleteCleanupAuthorized(ctx context.Context, ticket sandboxidentity.Reservation,
	check func(context.Context, sandboxidentity.Reservation) error) error {
	if err := check(ctx, ticket); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "CompleteCleanup")
	err := f.state.CompleteCleanup(f.plan, ticket)
	if err == nil {
		f.releasedTicket = ticket
	}
	if err == nil && f.loseCleanup {
		return errors.New("lost CompleteCleanup response")
	}
	return err
}
func (f *identityLedgerFixture) CompletedRetirement(_ context.Context,
	receipt browser.AllocationReceipt) (sandboxidentity.Reservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.releasedTicket.Status != sandboxidentity.Cleaning || receipt != f.retiredReceipt {
		return sandboxidentity.Reservation{}, sandboxidentity.ErrConflict
	}
	return f.releasedTicket, nil
}
func (f *identityLedgerFixture) CompletedTerminalRetirement(_ context.Context, record browser.Record) (
	sandboxidentity.Reservation, browser.AllocationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.releasedTicket.Status != sandboxidentity.Cleaning ||
		f.releasedTicket.Claim.OperationID != record.Request.OperationID ||
		f.retiredReceipt.Validate() != nil {
		return sandboxidentity.Reservation{}, browser.AllocationReceipt{}, sandboxidentity.ErrConflict
	}
	return f.releasedTicket, f.retiredReceipt, nil
}

func (f *identityLedgerFixture) RetireUnallocated(_ context.Context, record browser.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "RetireUnallocated")
	for _, ticket := range f.state.Reservations {
		if ticket.Claim.OperationID != record.Request.OperationID {
			continue
		}
		if ticket.Status != sandboxidentity.Reserved {
			return sandboxidentity.ErrInProgress
		}
		cleaning, err := f.state.BeginCleanup(f.plan, ticket)
		if err != nil {
			return err
		}
		return f.state.CompleteCleanup(f.plan, cleaning)
	}
	return nil
}

type boundCreatorFixture struct {
	mu            sync.Mutex
	authority     sandboxidentity.RuntimeAuthority
	ledger        *identityLedgerFixture
	receipt       browser.AllocationReceipt
	completed     bool
	allocateCalls int
	recoverCalls  int
	allocateErr   error
	cleanupCalls  int
	absenceCalls  int
	finalizeCalls int
	attachCalls   int
	cleanupErr    error
	absenceErr    error
	finalizeErr   error
	closing       bool
}

type blockedBoundCreator struct {
	*boundCreatorFixture
	entered chan struct{}
	release chan struct{}
}

func (b *blockedBoundCreator) AllocateBound(ctx context.Context, allocation browser.Allocation,
	ticket sandboxidentity.Reservation) (browser.AllocationReceipt, error) {
	close(b.entered)
	select {
	case <-b.release:
	case <-ctx.Done():
		return browser.AllocationReceipt{}, ctx.Err()
	}
	return b.boundCreatorFixture.AllocateBound(ctx, allocation, ticket)
}

func (f *boundCreatorFixture) RuntimeAuthority() sandboxidentity.RuntimeAuthority { return f.authority }
func (f *boundCreatorFixture) Ready(context.Context) error                        { return nil }
func (f *boundCreatorFixture) DesiredSpecDigests(browser.Allocation) (map[string]string, error) {
	return map[string]string{f.authority.Slots[0].ID: testIdentityDigest("c")}, nil
}
func (f *boundCreatorFixture) AllocateBound(_ context.Context, _ browser.Allocation,
	ticket sandboxidentity.Reservation) (browser.AllocationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ledger.status() != sandboxidentity.Creating || ticket.Status != sandboxidentity.Creating {
		return browser.AllocationReceipt{}, errors.New("Docker called before durable Creating CAS")
	}
	f.ledger.mu.Lock()
	f.ledger.events = append(f.ledger.events, "AllocateBound")
	f.ledger.mu.Unlock()
	f.allocateCalls++
	if f.allocateErr != nil {
		return browser.AllocationReceipt{}, f.allocateErr
	}
	f.completed = true
	return f.receipt, nil
}
func (f *boundCreatorFixture) CompletedBound(_ context.Context, _ browser.Allocation,
	ticket sandboxidentity.Reservation) (browser.AllocationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.completed || ticket.Status != sandboxidentity.Creating {
		return browser.AllocationReceipt{}, browser.ErrAllocationUnknown
	}
	return f.receipt, nil
}
func (f *boundCreatorFixture) CompletedTerminalBound(_ context.Context, record browser.Record,
	ticket sandboxidentity.Reservation) (browser.AllocationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.completed || record.Allocation != nil ||
		(ticket.Status != sandboxidentity.Creating && ticket.Status != sandboxidentity.Active &&
			ticket.Status != sandboxidentity.Cleaning) ||
		ticket.Claim.OperationID != record.Request.OperationID {
		return browser.AllocationReceipt{}, browser.ErrAllocationUnknown
	}
	return f.receipt, nil
}
func (f *boundCreatorFixture) RecoverBound(_ context.Context, _ browser.Allocation,
	ticket sandboxidentity.Reservation) (browser.AllocationReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ledger.status() != sandboxidentity.Active || ticket.Status != sandboxidentity.Active {
		return browser.AllocationReceipt{}, errors.New("recovery not Active")
	}
	f.recoverCalls++
	return f.receipt, nil
}
func (f *boundCreatorFixture) ObserveBound(_ context.Context, receipt browser.AllocationReceipt,
	ticket sandboxidentity.Reservation) (browser.AllocationObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing || ticket.Status != sandboxidentity.Active {
		return browser.AllocationObservation{}, browser.ErrAllocationUnknown
	}
	return browser.AllocationObservation{Receipt: receipt, State: browser.AllocationRunning,
		ObservedAt: receipt.AllocatedAt}, nil
}
func (f *boundCreatorFixture) AttachBound(_ context.Context, _ browser.AllocationReceipt,
	ticket sandboxidentity.Reservation) (browser.Stream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing || ticket.Status != sandboxidentity.Active {
		return nil, browser.ErrAllocationUnknown
	}
	f.attachCalls++
	return identityStream{}, nil
}
func (f *boundCreatorFixture) CleanupBound(_ context.Context, _ browser.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ticket.Status != sandboxidentity.Cleaning {
		return browser.ErrAllocationUnknown
	}
	f.cleanupCalls++
	f.closing = true
	return f.cleanupErr
}
func (f *boundCreatorFixture) ConfirmAbsentBound(_ context.Context, _ browser.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closing || ticket.Status != sandboxidentity.Cleaning {
		return browser.ErrAllocationUnknown
	}
	f.absenceCalls++
	return f.absenceErr
}
func (f *boundCreatorFixture) FinalizeCleanupBound(_ context.Context, _ browser.AllocationReceipt,
	ticket sandboxidentity.Reservation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closing || ticket.Status != sandboxidentity.Cleaning {
		return browser.ErrAllocationUnknown
	}
	f.finalizeCalls++
	return f.finalizeErr
}

type identityStream struct{}

func (identityStream) Read(context.Context, []byte) (int, error)  { return 0, nil }
func (identityStream) Write(context.Context, []byte) (int, error) { return 0, nil }
func (identityStream) Close() error                               { return nil }

func testIdentityDigest(letter string) string { return "sha256:" + strings.Repeat(letter, 64) }

func newIdentityCreateFixture(t *testing.T) (*BrowserIdentityCreateCoordinator,
	*identityLedgerFixture, *boundCreatorFixture, browser.Allocation) {
	t.Helper()
	plan := sandboxidentity.Plan{ProfileDigest: testIdentityDigest("a"), OwnerDeployment: "provider-browser-runtime",
		OwnerPrincipalDigest: testIdentityDigest("b"), Namespace: "browser-test", ServiceName: "postgres",
		ServiceIdentityDigest: testIdentityDigest("d"), TrustEdgeID: "provider-browser-postgres",
		EgressPolicyID: "browser-egress", BrokerDeployment: "broker-browser",
		BrokerRoleEdgeID: "broker-role-browser", BrokerExternalEdgeID: "broker-external-browser",
		MaterialBindingID: "browser-runtime-dsn", DatabaseName: "provider_browser",
		RuntimeRole: "browser_runtime", ControllerID: "controller-1", Template: "browser-sandbox-runtime",
		TemplateDigest: testIdentityDigest("e"), Capacity: 1,
		Slots: []sandboxidentity.Slot{{ID: "browser-0000", WorkloadUID: 20000, WorkloadGID: 30000,
			GatewayUID: 20001, GatewayGID: 30001}}}
	state, err := sandboxidentity.NewState(plan)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := plan.ProjectRuntimeAuthority()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)
	allocation := browser.Allocation{Request: browser.AllocationRequest{SandboxID: "sandbox-1",
		BrowserSessionID: "session-1", OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 1, ExpectedGeneration: 1, RequestDigest: testIdentityDigest("f"),
		NetworkPolicyReference: "browser-egress", ExpiresAt: now.Add(5 * time.Minute)}, AllocatedAt: now}
	receipt := browser.AllocationReceipt{Reference: "ref:browser/" + strings.Repeat("a", 32),
		SandboxID: allocation.Request.SandboxID, BrowserSessionID: allocation.Request.BrowserSessionID,
		OperationID: allocation.Request.OperationID, AttemptID: allocation.Request.AttemptID,
		FencingToken: 1, ExpectedGeneration: 1, ConnectionGeneration: 1,
		AllocatedAt: now, ExpiresAt: allocation.Request.ExpiresAt}
	ledger := &identityLedgerFixture{plan: plan, state: state}
	creator := &boundCreatorFixture{authority: authority, ledger: ledger, receipt: receipt}
	coordinator, err := NewBrowserIdentityCreateCoordinator(ledger, creator, ClockFunc(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, ledger, creator, allocation
}

func TestBrowserIdentityCoordinatorOrdersCASBeforeDockerAndRecoversActive(t *testing.T) {
	coordinator, ledger, creator, allocation := newIdentityCreateFixture(t)
	receipt, err := coordinator.Allocate(t.Context(), allocation)
	if err != nil || receipt != creator.receipt || ledger.status() != sandboxidentity.Active {
		t.Fatalf("coordinated Browser allocation = %#v, %v, %s", receipt, err, ledger.status())
	}
	ledger.mu.Lock()
	events := append([]string(nil), ledger.events...)
	ledger.mu.Unlock()
	want := []string{"Reserve", "BeginCreate", "AllocateBound", "CompleteCreate"}
	if !slices.Equal(events, want) {
		t.Fatalf("CAS/side-effect order = %v", events)
	}
	recovered, err := coordinator.Allocate(t.Context(), allocation)
	if err != nil || recovered != receipt || creator.allocateCalls != 1 || creator.recoverCalls != 1 {
		t.Fatalf("Active retry = %#v, %v, create=%d recover=%d", recovered, err, creator.allocateCalls, creator.recoverCalls)
	}
}

func TestBrowserIdentityCoordinatorRetainsAmbiguousCreating(t *testing.T) {
	for name, configure := range map[string]func(*identityLedgerFixture, *boundCreatorFixture){
		"BeginCreate response lost": func(ledger *identityLedgerFixture, _ *boundCreatorFixture) { ledger.loseBegin = true },
		"Docker outcome unknown": func(_ *identityLedgerFixture, creator *boundCreatorFixture) {
			creator.allocateErr = errors.New("lost Docker create response")
		},
	} {
		t.Run(name, func(t *testing.T) {
			coordinator, ledger, creator, allocation := newIdentityCreateFixture(t)
			configure(ledger, creator)
			if _, err := coordinator.Allocate(t.Context(), allocation); !errors.Is(err, browser.ErrAllocationUnknown) ||
				ledger.status() != sandboxidentity.Creating {
				t.Fatalf("ambiguous create = %v, status %s", err, ledger.status())
			}
			calls := creator.allocateCalls
			if _, err := coordinator.Allocate(t.Context(), allocation); !errors.Is(err, browser.ErrAllocationUnknown) ||
				creator.allocateCalls != calls {
				t.Fatalf("Creating replay = %v, create calls %d", err, creator.allocateCalls)
			}
		})
	}
}

func TestBrowserIdentityCoordinatorRecoversLostCompleteCASResponse(t *testing.T) {
	coordinator, ledger, creator, allocation := newIdentityCreateFixture(t)
	ledger.loseComplete = true
	if _, err := coordinator.Allocate(t.Context(), allocation); !errors.Is(err, browser.ErrAllocationUnknown) ||
		ledger.status() != sandboxidentity.Active || creator.allocateCalls != 1 {
		t.Fatalf("lost Active response = %v, status %s", err, ledger.status())
	}
	if _, err := coordinator.Allocate(t.Context(), allocation); err != nil || creator.allocateCalls != 1 || creator.recoverCalls != 1 {
		t.Fatalf("Active retry did not use read-only recovery: %v", err)
	}
}

func TestBrowserIdentityCoordinatorRecoversFinishedDispatchBeforePostgresCommit(t *testing.T) {
	coordinator, ledger, creator, allocation := newIdentityCreateFixture(t)
	ledger.failCompleteBeforeCommit = true
	if _, err := coordinator.Allocate(t.Context(), allocation); !errors.Is(err, browser.ErrAllocationUnknown) ||
		ledger.status() != sandboxidentity.Creating || creator.allocateCalls != 1 {
		t.Fatalf("pre-commit failure = %v, state %s, dispatches %d", err, ledger.status(), creator.allocateCalls)
	}
	ledger.failCompleteBeforeCommit = false
	receipt, err := coordinator.Allocate(t.Context(), allocation)
	if err != nil || receipt != creator.receipt || ledger.status() != sandboxidentity.Active ||
		creator.allocateCalls != 1 {
		t.Fatalf("durably finished dispatch was not reconciled without replay: %+v, %v, %s, %d",
			receipt, err, ledger.status(), creator.allocateCalls)
	}
}

func TestBrowserIdentityCoordinatorNeverTakesOverInFlightCreating(t *testing.T) {
	_, ledger, creator, allocation := newIdentityCreateFixture(t)
	blocked := &blockedBoundCreator{boundCreatorFixture: creator,
		entered: make(chan struct{}), release: make(chan struct{})}
	coordinator, err := NewBrowserIdentityCreateCoordinator(ledger, blocked,
		ClockFunc(func() time.Time { return allocation.AllocatedAt }))
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := coordinator.Allocate(t.Context(), allocation)
		result <- err
	}()
	<-blocked.entered
	if ledger.status() != sandboxidentity.Creating {
		t.Fatal("dispatch barrier did not retain Creating")
	}
	if _, err := coordinator.Allocate(t.Context(), allocation); !errors.Is(err, browser.ErrAllocationUnknown) ||
		creator.allocateCalls != 0 {
		t.Fatalf("in-flight Creating was taken over: %v, dispatches %d", err, creator.allocateCalls)
	}
	close(blocked.release)
	if err := <-result; err != nil || ledger.status() != sandboxidentity.Active || creator.allocateCalls != 1 {
		t.Fatalf("original dispatch completion = %v, %s, %d", err, ledger.status(), creator.allocateCalls)
	}
}

func TestBrowserIdentityCoordinatorRejectsAuthorityDrift(t *testing.T) {
	_, ledger, creator, _ := newIdentityCreateFixture(t)
	creator.authority.Slots[0].WorkloadUID++
	if _, err := NewBrowserIdentityCreateCoordinator(ledger, creator, ClockFunc(time.Now)); !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("drifted driver authority = %v", err)
	}
}

func TestBrowserIdentityCoordinatorConcurrentClaimHasOneCreator(t *testing.T) {
	coordinator, ledger, creator, allocation := newIdentityCreateFixture(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := coordinator.Allocate(context.Background(), allocation)
			results <- err
		}()
	}
	close(start)
	first, second := <-results, <-results
	for _, err := range []error{first, second} {
		if err != nil && !errors.Is(err, browser.ErrAllocationUnknown) {
			t.Fatalf("concurrent claim error = %v", err)
		}
	}
	if creator.allocateCalls != 1 || ledger.status() != sandboxidentity.Active {
		t.Fatalf("concurrent claim created %d times, status %s", creator.allocateCalls, ledger.status())
	}
}

func TestBrowserIdentityRuntimeFencesAttachAndCompletesExactCleanup(t *testing.T) {
	_, ledger, creator, allocation := newIdentityCreateFixture(t)
	runtime, err := NewBrowserIdentityRuntime(ledger, creator, ClockFunc(func() time.Time { return allocation.AllocatedAt }))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtime.Allocate(t.Context(), allocation)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtime.Observe(t.Context(), receipt)
	if err != nil || observation.State != browser.AllocationRunning {
		t.Fatalf("runtime observation = %#v, %v", observation, err)
	}
	stream, err := runtime.Attach(t.Context(), receipt)
	if err != nil || stream.Close() != nil {
		t.Fatalf("runtime attach = %v", err)
	}
	if err := runtime.Cleanup(t.Context(), receipt); err != nil || ledger.status() != "" {
		t.Fatalf("runtime cleanup = %v, status %s", err, ledger.status())
	}
	if creator.cleanupCalls != 1 || creator.absenceCalls != 1 || creator.finalizeCalls != 1 {
		t.Fatalf("cleanup/absence/finalize calls = %d/%d/%d", creator.cleanupCalls, creator.absenceCalls, creator.finalizeCalls)
	}
	if _, err := runtime.Attach(t.Context(), receipt); !errors.Is(err, browser.ErrAllocationUnknown) || creator.attachCalls != 1 {
		t.Fatalf("late attach after cleanup = %v, calls %d", err, creator.attachCalls)
	}
}

func TestBrowserIdentityRuntimeKeepsCleaningOnAbsentOrCASFailure(t *testing.T) {
	for name, configure := range map[string]func(*identityLedgerFixture, *boundCreatorFixture){
		"absence failed": func(_ *identityLedgerFixture, creator *boundCreatorFixture) {
			creator.absenceErr = errors.New("network still present")
		},
		"CompleteCleanup response lost": func(ledger *identityLedgerFixture, _ *boundCreatorFixture) {
			ledger.loseCleanup = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, ledger, creator, allocation := newIdentityCreateFixture(t)
			configure(ledger, creator)
			runtime, err := NewBrowserIdentityRuntime(ledger, creator, ClockFunc(func() time.Time { return allocation.AllocatedAt }))
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := runtime.Allocate(t.Context(), allocation)
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.Cleanup(t.Context(), receipt); !errors.Is(err, browser.ErrAllocationUnknown) || creator.finalizeCalls != 0 {
				t.Fatalf("uncertain cleanup = %v, finalize calls %d", err, creator.finalizeCalls)
			}
			if name == "absence failed" {
				if ledger.status() != sandboxidentity.Cleaning {
					t.Fatalf("absence failure freed slot: %s", ledger.status())
				}
				creator.absenceErr = nil
				if err := runtime.Cleanup(t.Context(), receipt); err != nil || ledger.status() != "" {
					t.Fatalf("fenced cleanup retry = %v, status %s", err, ledger.status())
				}
			} else {
				if ledger.status() != "" {
					t.Fatalf("lost response did not commit cleanup: %s", ledger.status())
				}
				if err := runtime.Cleanup(t.Context(), receipt); err != nil || creator.finalizeCalls != 1 {
					t.Fatalf("lost-response cleanup completion = %v, finalize calls %d", err, creator.finalizeCalls)
				}
			}
		})
	}
}

func TestBrowserIdentityRuntimeRetriesFailedFinalizeAfterRelease(t *testing.T) {
	_, ledger, creator, allocation := newIdentityCreateFixture(t)
	runtime, err := NewBrowserIdentityRuntime(ledger, creator, ClockFunc(func() time.Time { return allocation.AllocatedAt }))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtime.Allocate(t.Context(), allocation)
	if err != nil {
		t.Fatal(err)
	}
	creator.finalizeErr = errors.New("local tombstone sync failed")
	if err := runtime.Cleanup(t.Context(), receipt); !errors.Is(err, browser.ErrAllocationUnknown) || ledger.status() != "" {
		t.Fatalf("failed finalization must retain released proof: %v, %s", err, ledger.status())
	}
	creator.finalizeErr = nil
	if err := runtime.Cleanup(t.Context(), receipt); err != nil || creator.finalizeCalls != 2 || creator.cleanupCalls != 1 {
		t.Fatalf("finalization retry = %v, finalize/cleanup calls %d/%d", err, creator.finalizeCalls, creator.cleanupCalls)
	}
}

func TestBrowserIdentityRuntimeOldFinalizeDoesNotCleanReusedSlot(t *testing.T) {
	_, ledger, creator, allocation := newIdentityCreateFixture(t)
	ledger.loseCleanup = true
	runtime, err := NewBrowserIdentityRuntime(ledger, creator, ClockFunc(func() time.Time { return allocation.AllocatedAt }))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := runtime.Allocate(t.Context(), allocation)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Cleanup(t.Context(), receipt); !errors.Is(err, browser.ErrAllocationUnknown) {
		t.Fatalf("lost cleanup response = %v", err)
	}
	newClaim := sandboxidentity.Claim{SandboxID: "sandbox-new", SessionID: "session-new",
		OperationID: "operation-new", AttemptID: "attempt-new", RequestDigest: testIdentityDigest("f"),
		Generation: 1, Fence: 1}
	ledger.mu.Lock()
	newTicket, err := ledger.state.Reserve(ledger.plan, newClaim,
		map[string]string{ledger.plan.Slots[0].ID: testIdentityDigest("c")})
	ledger.mu.Unlock()
	if err != nil || newTicket.Slot != ledger.plan.Slots[0] {
		t.Fatalf("new claim did not reuse released slot: %+v, %v", newTicket, err)
	}
	if err := runtime.Cleanup(t.Context(), receipt); err != nil {
		t.Fatalf("old finalization after slot reuse = %v", err)
	}
	ledger.mu.Lock()
	remaining := append([]sandboxidentity.Reservation(nil), ledger.state.Reservations...)
	ledger.mu.Unlock()
	if len(remaining) != 1 || remaining[0] != newTicket || creator.cleanupCalls != 1 || creator.finalizeCalls != 1 {
		t.Fatalf("old finalization mutated new slot: %+v, cleanup/finalize %d/%d",
			remaining, creator.cleanupCalls, creator.finalizeCalls)
	}
}
