package application

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/sandboxidentity"
	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/repository/memory"
)

// This is an application/ledger-port interleaving, not PostgreSQL, process
// restart, Docker, or fsynced completion evidence. The existing fixture's
// completed flag stands for a returned, exact finished-dispatch proof.
type interleavedBrowserCreator struct {
	*boundCreatorFixture
	entered, release chan struct{}
	dispatches       atomic.Int32
	finish           bool
}

func (c *interleavedBrowserCreator) AllocateBound(ctx context.Context, allocation browser.Allocation,
	ticket sandboxidentity.Reservation) (browser.AllocationReceipt, error) {
	if c.dispatches.Add(1) != 1 {
		return browser.AllocationReceipt{}, errors.New("second allocation dispatch")
	}
	close(c.entered)
	select {
	case <-c.release:
	case <-ctx.Done():
		return browser.AllocationReceipt{}, ctx.Err()
	}
	if !c.finish {
		return browser.AllocationReceipt{}, browser.ErrAllocationUnknown
	}
	return c.boundCreatorFixture.AllocateBound(ctx, allocation, ticket)
}

func awaitBrowserInterleaving(t *testing.T, event <-chan struct{}, name string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-event:
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestBrowserTerminalIntentDuringCreateRetainsIdentityUntilProof(t *testing.T) {
	for _, terminal := range []string{"cancel", "expiry"} {
		for _, finished := range []bool{false, true} {
			name := terminal + "_without_proof"
			if finished {
				name = terminal + "_finished_before_commit"
			}
			t.Run(name, func(t *testing.T) {
				_, ledger, base, _ := newIdentityCreateFixture(t)
				// Vertical uses a real context deadline as well as its injected
				// clock, so the opening deadline must initially be in the future.
				now := time.Now().UTC()
				clock := &testClock{now: now}
				request := browserRequest(now)
				base.receipt.BrowserSessionID = request.BrowserSessionID
				base.receipt.AllocatedAt = now
				base.receipt.ExpiresAt = request.ExpiresAt
				allocation := browser.Allocation{AllocatedAt: now, Request: browser.AllocationRequest{
					SandboxID: request.SandboxID, BrowserSessionID: request.BrowserSessionID,
					OperationID: request.OperationID, AttemptID: request.AttemptID,
					ExpectedGeneration: request.ExpectedGeneration, FencingToken: request.FencingToken,
					RequestDigest: request.RequestDigest, ExpiresAt: request.ExpiresAt,
					NetworkPolicyReference: browserSandbox(now).Network.PolicyReference,
				}}
				creator := &interleavedBrowserCreator{boundCreatorFixture: base,
					entered: make(chan struct{}), release: make(chan struct{}), finish: finished}
				// A simulated finished dispatch must remain Creating until the
				// terminal reconciliation gets its own successful ledger commit.
				ledger.failCompleteBeforeCommit = finished
				authority := memory.NewRepository()
				newVertical := func() (*Vertical, *BrowserIdentityRuntime) {
					t.Helper()
					runtime, err := NewBrowserIdentityRuntime(ledger, creator, clock)
					if err != nil {
						t.Fatal(err)
					}
					vertical, err := NewVertical(authority, runtime,
						sandboxReader{sandbox: browserSandbox(now)}, browserProfile(), clock)
					if err != nil {
						t.Fatal(err)
					}
					return vertical, runtime
				}
				vertical, _ := newVertical()
				openContext, stopOpen := context.WithCancel(t.Context())
				var release sync.Once
				done := make(chan struct{})
				openResult := make(chan error, 1)
				go func() {
					_, err := vertical.Open(openContext, request)
					openResult <- err
					close(done)
				}()
				t.Cleanup(func() {
					release.Do(func() { close(creator.release) })
					stopOpen()
					awaitBrowserInterleaving(t, done, "original Open shutdown")
				})
				awaitBrowserInterleaving(t, creator.entered, "Creating dispatch barrier")
				tickets, err := ledger.Reservations(t.Context())
				if err != nil || len(tickets) != 1 || tickets[0].Status != sandboxidentity.Creating {
					t.Fatalf("dispatch did not hold Creating: %+v, %v", tickets, err)
				}
				creating := tickets[0]
				wantStatus := browser.StatusCancelled
				if terminal == "cancel" {
					operation, err := vertical.Cancel(t.Context(), request.OperationID)
					if !errors.Is(err, browser.ErrAllocationUnknown) || operation.Status != wantStatus {
						t.Fatalf("in-flight cancellation = %+v, %v", operation, err)
					}
				} else {
					clock.Set(now.Add(6 * time.Minute))
					wantStatus = browser.StatusFailed
					operation, err := vertical.Reconcile(t.Context(), request.OperationID)
					if err != nil || operation.Status != wantStatus {
						t.Fatalf("in-flight expiry = %+v, %v", operation, err)
					}
				}
				assertTerminal := func(v *Vertical, runtime *BrowserIdentityRuntime) {
					t.Helper()
					record, err := authority.GetOpen(t.Context(), request.OperationID)
					if err != nil || record.Status != wantStatus || record.Allocation != nil {
						t.Fatalf("terminal record revived or attached: %+v, %v", record, err)
					}
					if _, err := v.GetHandoff(t.Context(), request.OperationID); err == nil {
						t.Fatal("terminal creation acquired a user handoff")
					}
					if _, err := runtime.Attach(t.Context(), base.receipt); !errors.Is(err, browser.ErrAllocationUnknown) {
						t.Fatalf("terminal creation attached: %v", err)
					}
					if creator.dispatches.Load() != 1 {
						t.Fatalf("creation dispatched %d times", creator.dispatches.Load())
					}
				}
				assertHeld := func(want sandboxidentity.Status) {
					t.Helper()
					tickets, err := ledger.Reservations(t.Context())
					if err != nil || len(tickets) != 1 || tickets[0].Status != want || !tickets[0].SameIdentity(creating) {
						t.Fatalf("identity/capacity changed: %+v, %v", tickets, err)
					}
				}
				replacement, runtime := newVertical()
				if _, err := replacement.Recover(t.Context()); !errors.Is(err, browser.ErrAllocationUnknown) {
					t.Fatalf("in-flight terminal recovery = %v", err)
				}
				assertHeld(sandboxidentity.Creating)
				assertTerminal(replacement, runtime)
				competitor := allocation
				competitor.AllocatedAt = clock.Now()
				competitor.Request.SandboxID = "sandbox-competitor"
				competitor.Request.BrowserSessionID = "session-competitor"
				competitor.Request.OperationID = "operation-competitor"
				competitor.Request.AttemptID = "attempt-competitor"
				competitor.Request.ExpiresAt = clock.Now().Add(5 * time.Minute)
				if _, err := runtime.Allocate(t.Context(), competitor); !errors.Is(err, browser.ErrBrowserUnsupported) {
					t.Fatalf("held identity did not exclude competitor: %v", err)
				}
				assertHeld(sandboxidentity.Creating)
				assertTerminal(replacement, runtime)

				release.Do(func() { close(creator.release) })
				awaitBrowserInterleaving(t, done, "original Open completion")
				if err := <-openResult; err == nil {
					t.Fatal("original Open succeeded after terminal intent")
				}
				assertHeld(sandboxidentity.Creating)
				assertTerminal(replacement, runtime)
				if !finished {
					if _, err := replacement.Recover(t.Context()); !errors.Is(err, browser.ErrAllocationUnknown) {
						t.Fatalf("missing proof was inferred after dispatch returned: %v", err)
					}
					assertHeld(sandboxidentity.Creating)
					base.mu.Lock()
					cleanup, absence, finalize := base.cleanupCalls, base.absenceCalls, base.finalizeCalls
					base.mu.Unlock()
					if cleanup != 0 || absence != 0 || finalize != 0 {
						t.Fatalf("unproved creation cleaned/released: %d/%d/%d", cleanup, absence, finalize)
					}
					return
				}
				ledger.failCompleteBeforeCommit = false
				base.absenceErr = errors.New("owned network still present")
				if _, err := replacement.Recover(t.Context()); !errors.Is(err, browser.ErrAllocationUnknown) {
					t.Fatalf("failed absence was accepted: %v", err)
				}
				assertHeld(sandboxidentity.Cleaning)
				assertTerminal(replacement, runtime)
				base.absenceErr = nil
				if _, err := replacement.Recover(t.Context()); err != nil || ledger.status() != "" {
					t.Fatalf("exact terminal cleanup = %v, state %s", err, ledger.status())
				}
				assertTerminal(replacement, runtime)
				base.mu.Lock()
				cleanup, absence, finalize, attaches := base.cleanupCalls, base.absenceCalls, base.finalizeCalls, base.attachCalls
				base.mu.Unlock()
				if cleanup != 2 || absence != 2 || finalize != 1 || attaches != 0 {
					t.Fatalf("terminal cleanup/proof/finalize/attach = %d/%d/%d/%d", cleanup, absence, finalize, attaches)
				}
			})
		}
	}
}
