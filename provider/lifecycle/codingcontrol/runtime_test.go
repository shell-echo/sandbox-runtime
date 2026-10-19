package codingcontrol

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type runtimeFixture struct {
	now      time.Time
	snapshot RuntimeSnapshot
	calls    int
	read     func(context.Context)
	err      error
	deadline time.Time
}

func (f *runtimeFixture) Now() time.Time { return f.now }
func (f *runtimeFixture) ReadCodingRuntime(ctx context.Context, id string) (RuntimeSnapshot, error) {
	f.calls++
	f.deadline, _ = ctx.Deadline()
	if f.read != nil {
		f.read(ctx)
	}
	return f.snapshot, f.err
}

func newRuntimeFixture() (*runtimeFixture, providerexec.Request, Expected) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	expected := Expected{digest("a"), digest("b"), digest("c")}
	sb := lifecycle.Sandbox{ID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "order-1", WorkspaceID: "workspace-1", ProviderRevisionID: "revision-1",
		RuntimeProfile: "sandbox-runtime-coding-shell-v1", Network: lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone}, SandboxSlotKey: "primary",
		DesiredState: lifecycle.DesiredReady, ObservedState: lifecycle.ObservedReady, Generation: 1, ObservedGeneration: 1,
		LeaseExpiresAt: now.Add(5 * time.Minute), CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Minute)}
	f := &runtimeFixture{now: now, snapshot: RuntimeSnapshot{Sandbox: sb, Lease: lifecycle.Lease{SandboxID: sb.ID, Generation: 1, FencingToken: 7, ExpiresAt: sb.LeaseExpiresAt},
		ProfileDigest: expected.ProfileDigest, ControlPolicyDigest: expected.ControlPolicyDigest, ProviderPrincipalDigest: expected.ProviderPrincipalDigest, ObservedAt: now}}
	r := providerexec.Request{SandboxID: sb.ID, OperationID: "exec-one", AttemptID: "attempt-one", IdempotencyKey: "exec-key", RequestDigest: digest("d"),
		FencingToken: 7, ExpectedGeneration: 1, Deadline: now.Add(time.Minute), Command: []string{"/bin/echo", "hello"}, WorkingDirectory: "/workspace", ResultRetention: time.Minute}
	return f, r, expected
}

func TestExecPreflightIsOneReadWithoutExecutionAuthority(t *testing.T) {
	for _, highFence := range []bool{false, true} {
		f, r, expected := newRuntimeFixture()
		p, err := NewExecPreflight(f, f, expected)
		if err != nil {
			t.Fatal(err)
		}
		if highFence {
			r.FencingToken++
		}
		before := f.snapshot
		if err := p.CheckSupport(t.Context(), r); err != nil || f.calls != 1 || f.snapshot != before || !f.deadline.Equal(r.Deadline) {
			t.Fatalf("preflight: %v, calls=%d, deadline=%v", err, f.calls, f.deadline)
		}
		for _, exposed := range []bool{implementsExecutor(p), implementsObserver(p), implementsCanceler(p), implementsCleaner(p)} {
			if exposed {
				t.Fatal("read-only checker exposed a runtime execution port")
			}
		}
	}
}

func implementsExecutor(v any) bool { _, ok := v.(providerexec.Executor); return ok }
func implementsObserver(v any) bool { _, ok := v.(providerexec.Observer); return ok }
func implementsCanceler(v any) bool { _, ok := v.(providerexec.Canceler); return ok }
func implementsCleaner(v any) bool  { _, ok := v.(providerexec.ResultCleaner); return ok }

func TestExecPreflightRejectsUnsupportedOrInvalidBeforeReading(t *testing.T) {
	for _, name := range []string{"environment", "secret", "grant", "stdin", "bad command", "zero generation", "negative fence", "deadline", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f, r, expected := newRuntimeFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch name {
			case "environment":
				r.Environment = map[string]string{"USER_INPUT": "envref:one"}
			case "secret":
				r.SecretReferenceIDs = []string{"secret-one"}
			case "grant":
				r.SecretGrantID, r.SecretGrantDigest = "grant:one", expected.ProfileDigest
			case "stdin":
				r.StdinReference = "ref:stdin:one"
			case "bad command":
				r.Command = nil
			case "zero generation":
				r.ExpectedGeneration = 0
			case "negative fence":
				r.FencingToken = -1
			case "deadline":
				r.Deadline = f.now
			case "cancelled":
				cancel()
			}
			p, err := NewExecPreflight(f, f, expected)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckSupport(ctx, r); err == nil || f.calls != 0 {
				t.Fatalf("unsupported request reached PG: %v, calls=%d", err, f.calls)
			}
		})
	}
}

func TestExecPreflightRejectsSubstitutionAndExpiryDuringRead(t *testing.T) {
	for _, name := range []string{"profile", "policy", "peer", "sandbox", "generation", "overflow generation", "low fence", "overflow fence", "terminating", "not ready", "lease identity", "lease expiry", "expired after read", "deadline after read", "cancelled after read", "rollback", "cached snapshot", "future snapshot", "read error"} {
		t.Run(name, func(t *testing.T) {
			f, r, expected := newRuntimeFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch name {
			case "profile":
				f.snapshot.ProfileDigest = expected.ControlPolicyDigest
			case "policy":
				f.snapshot.ControlPolicyDigest = expected.ProfileDigest
			case "peer":
				f.snapshot.ProviderPrincipalDigest = expected.ProfileDigest
			case "sandbox":
				f.snapshot.Sandbox.ID = "other-sandbox"
			case "generation":
				r.ExpectedGeneration++
			case "overflow generation":
				f.snapshot.Sandbox.Generation, f.snapshot.Sandbox.ObservedGeneration, f.snapshot.Lease.Generation = math.MaxUint64, math.MaxUint64, math.MaxUint64
			case "low fence":
				r.FencingToken--
			case "overflow fence":
				f.snapshot.Lease.FencingToken = math.MaxUint64
			case "terminating":
				f.snapshot.Sandbox.DesiredState = lifecycle.DesiredTerminated
			case "not ready":
				f.snapshot.Sandbox.ObservedState = lifecycle.ObservedProvisioning
			case "lease identity":
				f.snapshot.Lease.SandboxID = "other-sandbox"
			case "lease expiry":
				f.snapshot.Lease.ExpiresAt = f.snapshot.Lease.ExpiresAt.Add(time.Second)
			case "expired after read":
				f.snapshot.Sandbox.LeaseExpiresAt, f.snapshot.Lease.ExpiresAt = f.now.Add(time.Second), f.now.Add(time.Second)
				f.read = func(context.Context) { f.now = f.snapshot.Lease.ExpiresAt }
			case "deadline after read":
				f.read = func(context.Context) { f.now = r.Deadline }
			case "cancelled after read":
				f.read = func(context.Context) { cancel() }
			case "rollback":
				f.read = func(context.Context) { f.now = f.now.Add(-time.Second) }
			case "cached snapshot":
				f.snapshot.ObservedAt = f.now.Add(-time.Nanosecond)
			case "future snapshot":
				f.snapshot.ObservedAt = f.now.Add(time.Nanosecond)
			case "read error":
				f.err = errors.New("private database diagnostics must not escape")
			}
			p, err := NewExecPreflight(f, f, expected)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckSupport(ctx, r); err == nil || f.calls != 1 || (f.err != nil && err != ErrRuntimePreflight) {
				t.Fatalf("unsafe snapshot accepted or leaked error: %v, calls=%d", err, f.calls)
			}
		})
	}
}

func TestExecPreflightNilDependenciesAndParentDeadline(t *testing.T) {
	f, r, expected := newRuntimeFixture()
	var nilFixture *runtimeFixture
	if p, err := NewExecPreflight(nilFixture, f, expected); err == nil || p != nil {
		t.Fatal("typed nil reader accepted")
	}
	if p, err := NewExecPreflight(f, nilFixture, expected); err == nil || p != nil {
		t.Fatal("typed nil clock accepted")
	}
	p, err := NewExecPreflight(f, f, expected)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	if err := p.CheckSupport(ctx, r); err != nil || !f.deadline.Equal(deadline) {
		t.Fatalf("parent deadline not preserved: %v %v", err, f.deadline)
	}
	if p.CheckSupport(nil, r) == nil || ((*ExecPreflight)(nil)).CheckSupport(ctx, r) == nil {
		t.Fatal("nil entry accepted")
	}
}
