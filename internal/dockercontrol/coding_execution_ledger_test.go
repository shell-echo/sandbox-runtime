//go:build darwin || linux

package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
)

func executionTestDigest(v string) string { return "sha256:" + strings.Repeat(v, 64) }
func executionTestBinding(t *testing.T) executionBinding {
	t.Helper()
	slots := []codingidentity.Slot{}
	for i := range 2 {
		id := fmt.Sprintf("coding-%04d", i)
		slots = append(slots, codingidentity.Slot{ID: id, WorkloadUID: 57000 + uint32(i), WorkloadGID: 58000 + uint32(i),
			InputsVolume: id + "-inputs", WorkspaceVolume: id + "-workspace", OutputsVolume: id + "-outputs"})
	}
	template, err := phase6security.NewCodingCandidateExecutionTemplate("linux/arm64/v8",
		executionTestDigest("b"), digest([]byte(executionFixturePolicy)), slots)
	if err != nil {
		t.Fatal(err)
	}
	d, err := template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	b := executionBinding{Storage: controlstorage.Binding{Layout: controlstorage.NewLayout(), Namespace: strings.Repeat("a", 32), StorageID: "control-execution-" + strings.Repeat("a", 32),
		ProfileDigest: executionTestDigest("d"), TemplateDigest: d, ControlPrincipalDigest: executionTestDigest("e"), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())},
		Template: template, DaemonDigest: executionTestDigest("1"), DaemonEnvironmentDigest: executionTestDigest("2"), EndpointScopeDigest: executionTestDigest("3"), ControlPolicyDigest: executionTestDigest("4")}
	daemon, err := projectCodingDaemonInfo(codingInfoFixture(), b.EndpointScopeDigest)
	if err != nil {
		t.Fatal(err)
	}
	b.DaemonDigest, b.DaemonEnvironmentDigest = daemon.IdentityDigest, daemon.EnvironmentDigest
	if err := b.validate(); err != nil {
		t.Fatal(err)
	}
	return b
}
func executionTestRoot(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}
func executionTestLedger(t *testing.T) (*executionLedger, string, executionCreate) {
	t.Helper()
	b := executionTestBinding(t)
	p := executionTestRoot(t)
	l, err := initializeExecutionLedger(t.Context(), p, b, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.close(context.Background()) })
	now := time.Now().UTC()
	a := executionCreate{Protocol: executionReceiptProtocol, BindingDigest: b.digest(), AllocationID: "codingalloc-" + strings.Repeat("a", 64), SlotID: "coding-0000", SandboxID: "sandbox", ProviderRevisionID: "revision", TenantDigest: executionTestDigest("5"), OperationID: "create", AttemptID: "create-attempt", RequestDigest: executionTestDigest("6"), Generation: 1, Fence: 1, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second), OperationDeadline: now.Add(time.Minute)}
	return l, p, a
}

// A synthetic projection for state-machine tests ONLY. It does not inspect a
// Docker daemon, image, volume, mount, archive or source-built workload.
type executionTestCollector func(context.Context, executionBinding, executionCreate, uint64, string) (executionCompletionObservation, error)

func (f executionTestCollector) observeExecutionCreate(c context.Context, b executionBinding, a executionCreate, r uint64, d string) (executionCompletionObservation, error) {
	return f(c, b, a, r, d)
}
func executionTestObservation(ctx context.Context, b executionBinding, a executionCreate, r uint64, d string) (executionCompletionObservation, error) {
	fixture, err := newExecutionObserverFixture(b, a)
	if err != nil {
		return executionCompletionObservation{}, err
	}
	defer fixture.observer.CloseContext(context.Background())
	return fixture.observer.observeExecutionCreate(ctx, b, a, r, d)
}

func executionTestCreate(t *testing.T, l *executionLedger, a executionCreate) {
	t.Helper()
	if err := l.create(t.Context(), a, func(context.Context, executionResources) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
func executionTestComplete(t *testing.T, l *executionLedger, a executionCreate) {
	t.Helper()
	executionTestCreate(t, l, a)
	if err := l.completeCreate(t.Context(), a, executionTestCollector(executionTestObservation)); err != nil {
		t.Fatal(err)
	}
}
func executionTestClaim(l *executionLedger, a executionCreate) executionClaim {
	now := time.Now().UTC()
	completion := executionTestDigest("f")
	if i := l.current.allocation(a.digest()); i >= 0 && l.current.Allocations[i].Completion != nil {
		completion = l.current.Allocations[i].Completion.digest()
	}
	return executionClaim{Protocol: executionReceiptProtocol, BindingDigest: l.binding.digest(), CreateDigest: a.digest(), CompletionDigest: completion, TenantDigest: a.TenantDigest, ProviderRevisionID: a.ProviderRevisionID, AcceptedAt: now, ExpiresAt: now.Add(30 * time.Second),
		Request: providerexec.Request{SandboxID: a.SandboxID, OperationID: "exec", AttemptID: "exec-attempt", FencingToken: 2, ExpectedGeneration: 1, IdempotencyKey: "exec-key", RequestDigest: executionTestDigest("d"), Deadline: now.Add(time.Minute), Command: []string{"/bin/true"}, WorkingDirectory: "/workspace", ResultRetention: time.Hour, CaptureStdout: true, CaptureStderr: true}}
}
func executionTestRetire(l *executionLedger, a executionCreate) executionRetirement {
	now := time.Now().UTC()
	return executionRetirement{BindingDigest: l.binding.digest(), CreateDigest: a.digest(), OperationID: "terminate", Generation: 2, Fence: 3, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second)}
}
func executionTestState(t *testing.T, l *executionLedger) executionState {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	s, err := l.store.ReadState(t.Context(), l.key)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decodeExecutionState(s.Data, l.binding, l.clock().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func executionNoop(context.Context, executionClaim, executionResources) error { return nil }

func TestCodingExecutionLedgerDurableUnknownAndRestart(t *testing.T) {
	l, p, a := executionTestLedger(t)
	if err := l.create(t.Context(), a, func(_ context.Context, r executionResources) error {
		s := executionTestState(t, l)
		if len(s.Allocations) != 1 || s.Allocations[0].CreateStatus != executionUnknown || r != a.resources(l.binding) {
			t.Fatal("effect preceded durable bound Unknown")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c := executionTestClaim(l, a)
	if l.execute(t.Context(), c, executionNoop) == nil {
		t.Fatal("callback return became completion")
	}
	if err := l.completeCreate(t.Context(), a, executionTestCollector(executionTestObservation)); err != nil {
		t.Fatal(err)
	}
	c = executionTestClaim(l, a)
	calls := 0
	if err := l.execute(t.Context(), c, func(_ context.Context, got executionClaim, _ executionResources) error {
		calls++
		s := executionTestState(t, l)
		if len(s.Executions) != 1 || s.Executions[0].Status != executionUnknown || s.Executions[0].Claim.digest() != c.digest() {
			t.Fatal("exec effect preceded durable exact Unknown")
		}
		got.Request.Command[0] = "mutated"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if l.execute(t.Context(), c, executionNoop) == nil || l.closeClaim(t.Context(), c) == nil {
		t.Fatal("Unknown replayed or downgraded")
	}
	second := c.clone()
	second.Request.OperationID = "second"
	second.Request.IdempotencyKey = "second"
	if l.execute(t.Context(), second, executionNoop) == nil {
		t.Fatal("second possible execution")
	}
	if l.current.Executions[0].Claim.Request.Command[0] != "/bin/true" || calls != 1 {
		t.Fatal("callback changed retained claim")
	}
	r := executionTestRetire(l, a)
	if err := l.retire(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	if l.cleanup(t.Context(), a, r, func(context.Context, executionResources) error { t.Fatal("cleanup with Unknown"); return nil }) == nil {
		t.Fatal("released Unknown")
	}
	if err := l.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	reopened, err := openExecutionLedger(t.Context(), p, l.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close(context.Background())
	if reopened.execute(t.Context(), c, executionNoop) == nil || reopened.closeClaim(t.Context(), c) == nil || reopened.cleanup(t.Context(), a, r, func(context.Context, executionResources) error { return nil }) == nil {
		t.Fatal("reopen forgot occupancy")
	}
	if executionTestState(t, reopened).Executions[0].Status != executionUnknown {
		t.Fatal("Unknown lost")
	}
}

func TestCodingExecutionLedgerClosureAndRetirementWinBeforeLateArrival(t *testing.T) {
	t.Run("claim", func(t *testing.T) {
		l, _, a := executionTestLedger(t)
		executionTestComplete(t, l, a)
		c := executionTestClaim(l, a)
		if err := l.closeClaim(t.Context(), c); err != nil {
			t.Fatal(err)
		}
		if err := l.closeClaim(t.Context(), c); err != nil {
			t.Fatal("exact closure retry", err)
		}
		if l.execute(t.Context(), c, func(context.Context, executionClaim, executionResources) error { t.Fatal("late effect"); return nil }) == nil {
			t.Fatal("late claim admitted")
		}
		changed := c.clone()
		changed.Request.Command = []string{"/bin/false"}
		if l.closeClaim(t.Context(), changed) == nil {
			t.Fatal("claim collision accepted")
		}
		later := c.clone()
		later.Request.OperationID = "expired"
		later.Request.IdempotencyKey = "expired"
		l.clock = func() time.Time { return c.ExpiresAt.Add(time.Hour) }
		if err := l.closeClaim(t.Context(), later); err != nil {
			t.Fatal("exact expired claim cannot close", err)
		}
	})
	t.Run("before create", func(t *testing.T) {
		l, _, a := executionTestLedger(t)
		r := executionTestRetire(l, a)
		sameGeneration := r
		sameGeneration.Generation = a.Generation
		if l.retire(t.Context(), a, sameGeneration) == nil {
			t.Fatal("same-generation retirement admitted")
		}
		sameOperation := r
		sameOperation.OperationID = a.OperationID
		if l.retire(t.Context(), a, sameOperation) == nil {
			t.Fatal("create operation used as retirement")
		}
		if err := l.retire(t.Context(), a, r); err != nil {
			t.Fatal(err)
		}
		if l.create(t.Context(), a, func(context.Context, executionResources) error { t.Fatal("late create effect"); return nil }) == nil {
			t.Fatal("closed create admitted")
		}
		if s := executionTestState(t, l); s.Allocations[0].CreateStatus != executionClosedBeforeEffect {
			t.Fatal("missing closure")
		}
	})
	t.Run("completed then cleanup", func(t *testing.T) {
		l, _, a := executionTestLedger(t)
		executionTestComplete(t, l, a)
		c := executionTestClaim(l, a)
		r := executionTestRetire(l, a)
		if err := l.retire(t.Context(), a, r); err != nil {
			t.Fatal(err)
		}
		if l.execute(t.Context(), c, executionNoop) == nil {
			t.Fatal("late exec after retirement")
		}
		calls := 0
		physical := func(context.Context, executionResources) error {
			calls++
			if !executionTestState(t, l).Allocations[0].CleanupUnknown {
				t.Fatal("cleanup effect before Unknown")
			}
			return nil
		}
		if err := l.cleanup(t.Context(), a, r, physical); err != nil {
			t.Fatal(err)
		}
		if l.cleanup(t.Context(), a, r, physical) == nil || calls != 1 {
			t.Fatal("cleanup replayed")
		}
		if !executionTestState(t, l).Allocations[0].CleanupUnknown {
			t.Fatal("callback success released capacity")
		}
	})
}

func TestCodingExecutionLedgerRetirementDoesNotWaitForCommandAndCloseRetainsOwner(t *testing.T) {
	l, p, a := executionTestLedger(t)
	executionTestComplete(t, l, a)
	c := executionTestClaim(l, a)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- l.execute(t.Context(), c, func(context.Context, executionClaim, executionResources) error { close(entered); <-release; return nil })
	}()
	<-entered
	// Ensure release even if a later assertion fails; no writer is abandoned.
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		select {
		case <-done:
		default:
		}
	}()
	r := executionTestRetire(l, a)
	if err := l.retire(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	if l.cleanup(t.Context(), a, r, func(context.Context, executionResources) error { t.Error("cleanup entered"); return nil }) == nil {
		t.Fatal("live callback cleaned")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(l.close(cancelled), context.Canceled) {
		t.Fatal("close did not preserve bounded wait")
	}
	if other, err := openExecutionLedger(t.Context(), p, l.binding); err == nil {
		other.close(t.Context())
		t.Fatal("lock released before callback drained")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := l.close(t.Context()); err != nil {
		t.Fatal(err)
	}
	other, err := openExecutionLedger(t.Context(), p, l.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer other.close(context.Background())
	if other.cleanup(t.Context(), a, r, func(context.Context, executionResources) error { return nil }) == nil {
		t.Fatal("local drain released Unknown")
	}
}

func TestCodingExecutionLedgerCompletionRequiresCurrentNewObservation(t *testing.T) {
	for _, mode := range []string{"old protocol", "three volumes", "source revision", "source digest", "resident", "retirement during observe", "reopen"} {
		t.Run(mode, func(t *testing.T) {
			l, p, a := executionTestLedger(t)
			executionTestCreate(t, l, a)
			if mode == "reopen" {
				if err := l.close(t.Context()); err != nil {
					t.Fatal(err)
				}
				var err error
				l, err = openExecutionLedger(t.Context(), p, l.binding)
				if err != nil {
					t.Fatal(err)
				}
				defer l.close(context.Background())
			}
			collector := executionTestCollector(func(ctx context.Context, b executionBinding, a executionCreate, rev uint64, d string) (executionCompletionObservation, error) {
				o, err := executionTestObservation(ctx, b, a, rev, d)
				switch mode {
				case "old protocol":
					o.Protocol = "sandbox-runtime.coding-receipts.v1"
				case "three volumes":
					o.Resources.Volumes[3] = ""
				case "source revision":
					o.SourceRevision++
				case "source digest":
					o.SourceStateDigest = executionTestDigest("f")
				case "resident":
					o.ResidentID = ""
				case "retirement during observe":
					if err := l.retire(ctx, a, executionTestRetire(l, a)); err != nil {
						t.Fatal(err)
					}
				case "reopen":
					t.Fatal("restart manufactured create-return authority")
				}
				return o, err
			})
			if l.completeCreate(t.Context(), a, collector) == nil {
				t.Fatal("invalid completion accepted")
			}
			if executionTestState(t, l).Allocations[0].Completion != nil {
				t.Fatal("completion retained")
			}
		})
	}
}

func TestCodingExecutionLedgerUncertainWriteNeverDispatchesOrReplays(t *testing.T) {
	for _, stage := range []string{"before-state", "after-state"} {
		t.Run(stage, func(t *testing.T) {
			l, p, a := executionTestLedger(t)
			executionTestComplete(t, l, a)
			c := executionTestClaim(l, a)
			l.fault = func(at string) error {
				if at == stage {
					return errors.New("injected publication uncertainty")
				}
				return nil
			}
			if l.execute(t.Context(), c, func(context.Context, executionClaim, executionResources) error {
				t.Fatal("effect after uncertain publication")
				return nil
			}) == nil {
				t.Fatal("uncertainty hidden")
			}
			if l.execute(t.Context(), c, executionNoop) == nil {
				t.Fatal("poisoned owner reused")
			}
			if err := l.close(t.Context()); err != nil {
				t.Fatal(err)
			}
			reopened, err := openExecutionLedger(t.Context(), p, l.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.close(context.Background())
			s := executionTestState(t, reopened)
			if stage == "after-state" {
				if len(s.Executions) != 1 || s.Executions[0].Status != executionUnknown || reopened.execute(t.Context(), c, executionNoop) == nil {
					t.Fatal("durable Unknown lost")
				}
			} else if len(s.Executions) != 0 {
				t.Fatal("pre-publication failure changed state")
			}
		})
	}
}

func TestCodingExecutionLedgerRejectsMissingStateBindingDriftAndNoncanonicalState(t *testing.T) {
	b := executionTestBinding(t)
	p := executionTestRoot(t)
	s, err := controlstorage.Initialize(t.Context(), p, b.Storage, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if l, err := openExecutionLedger(t.Context(), p, b); err == nil {
		l.close(t.Context())
		t.Fatal("missing state implicitly initialized")
	}
	l, _, a := executionTestLedger(t)
	executionTestComplete(t, l, a)
	c := executionTestClaim(l, a)
	for _, change := range []func(*executionClaim){func(c *executionClaim) { c.BindingDigest = executionTestDigest("f") }, func(c *executionClaim) { c.CompletionDigest = executionTestDigest("f") }, func(c *executionClaim) { c.Request.ExpectedGeneration++ }, func(c *executionClaim) { c.TenantDigest = executionTestDigest("f") }, func(c *executionClaim) { c.Request.Environment = map[string]string{"X": "value"} }, func(c *executionClaim) { c.AcceptedAt = c.AcceptedAt.Add(time.Hour) }, func(c *executionClaim) { c.Request.FencingToken = 0 }} {
		bad := c.clone()
		change(&bad)
		if l.execute(t.Context(), bad, executionNoop) == nil {
			t.Fatal("binding/request drift admitted")
		}
	}
	base := l.current.clone()
	encoded, _ := json.Marshal(base)
	for _, raw := range [][]byte{append([]byte(" "), encoded...), bytes.Replace(encoded, []byte(executionReceiptProtocol), []byte("old"), 1), append(append([]byte{}, encoded[:len(encoded)-1]...), []byte(`,"unknown":true}`)...)} {
		if _, err := decodeExecutionState(raw, l.binding, time.Now().UTC()); err == nil {
			t.Fatal("noncanonical state accepted")
		}
	}
	for _, change := range []func(*executionState){func(s *executionState) { s.Allocations[0].HighFence = ^uint64(0) }, func(s *executionState) { s.Allocations[0].CleanupUnknown = true }, func(s *executionState) { s.Allocations[0].Completion.Resources.Volumes[3] = "old" }, func(s *executionState) { s.Allocations = append(s.Allocations, s.Allocations[0]) }} {
		bad := base.clone()
		change(&bad)
		if bad.validate(l.binding, time.Now().UTC()) == nil {
			t.Fatal("invalid restored state accepted")
		}
	}
	changed := a
	changed.Generation++
	if changed.resources(l.binding) == a.resources(l.binding) {
		t.Fatal("generation reused physical names")
	}
	b2 := l.binding.clone()
	b2.Storage.Namespace = strings.Repeat("b", 32)
	b2.Storage.StorageID = "control-execution-" + b2.Storage.Namespace
	if a.resources(b2) == a.resources(l.binding) {
		t.Fatal("namespace reused physical names")
	}
}

func TestCodingExecutionLedgerRejectsOldNamespacesWithoutMigration(t *testing.T) {
	for _, protocol := range []string{"sandbox-runtime.coding-isolated-receipts.v1", "sandbox-runtime.coding-isolated-receipts.v2"} {
		t.Run(protocol, func(t *testing.T) {
			l, root, _ := executionTestLedger(t)
			b, key := l.binding, l.key
			old := l.current.clone()
			old.Protocol = protocol
			raw, _ := json.Marshal(old)
			if err := l.store.CompareState(t.Context(), key, l.snapshot, raw); err != nil {
				t.Fatal(err)
			}
			if err := l.close(t.Context()); err != nil {
				t.Fatal(err)
			}
			if reopened, err := openExecutionLedger(t.Context(), root, b); err == nil {
				reopened.close(t.Context())
				t.Fatal("old namespace reopened")
			}
			if initialized, err := initializeExecutionLedger(t.Context(), root, b, func(context.Context) error { return nil }); err == nil {
				initialized.close(t.Context())
				t.Fatal("populated namespace initialized as new")
			}
			store, err := controlstorage.Open(root, b.Storage)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			after, err := store.ReadState(t.Context(), key)
			if err != nil || !after.Found || !bytes.Equal(after.Data, raw) {
				t.Fatal("old state modified by failed admission")
			}
		})
	}
}

func TestCodingExecutionLedgerCapacityRetainsClosureHistory(t *testing.T) {
	l, _, a := executionTestLedger(t)
	executionTestComplete(t, l, a)
	c := executionTestClaim(l, a)
	for i := range l.binding.Template.Storage.MaxExecutionRecords {
		next := c.clone()
		next.Request.OperationID = fmt.Sprintf("op-%d", i)
		next.Request.IdempotencyKey = next.Request.OperationID
		if err := l.closeClaim(t.Context(), next); err != nil {
			t.Fatal(i, err)
		}
	}
	if l.closeClaim(t.Context(), c) == nil || l.execute(t.Context(), c, executionNoop) == nil {
		t.Fatal("record cap bypassed")
	}
	if len(executionTestState(t, l).Executions) != 64 {
		t.Fatal("history pruned")
	}
	if err := l.retire(t.Context(), a, executionTestRetire(l, a)); err != nil {
		t.Fatal("claim history consumed allocation closure", err)
	}
}

func TestCodingExecutionLedgerClosedClaimAdvancesFence(t *testing.T) {
	l, _, a := executionTestLedger(t)
	executionTestComplete(t, l, a)
	older := executionTestClaim(l, a)
	newer := older.clone()
	newer.Request.OperationID = "newer"
	newer.Request.IdempotencyKey = "newer"
	newer.Request.FencingToken = 3
	if err := l.closeClaim(t.Context(), newer); err != nil {
		t.Fatal(err)
	}
	if l.execute(t.Context(), older, func(context.Context, executionClaim, executionResources) error {
		t.Fatal("stale fence effect")
		return nil
	}) == nil {
		t.Fatal("closed newer claim failed to fence late older request")
	}
	if executionTestState(t, l).Allocations[0].HighFence != 3 {
		t.Fatal("closure lost fence")
	}
	r := executionTestRetire(l, a)
	if err := l.retire(t.Context(), a, r); err != nil {
		t.Fatal(err)
	}
	postRetirement := newer.clone()
	postRetirement.Request.OperationID = "post-retirement"
	postRetirement.Request.IdempotencyKey = "post-retirement"
	postRetirement.Request.FencingToken = 4
	if l.closeClaim(t.Context(), postRetirement) == nil {
		t.Fatal("claim advanced past retirement fence")
	}
	if err := l.closeClaim(t.Context(), older); err != nil {
		t.Fatal("older exact closure rejected", err)
	}
	if executionTestState(t, l).Allocations[0].HighFence != 3 {
		t.Fatal("late closure lowered retirement fence")
	}
}
