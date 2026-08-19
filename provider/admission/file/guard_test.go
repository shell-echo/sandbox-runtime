package file_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	admissionfile "github.com/shell-echo/sandbox-runtime/provider/admission/file"
)

func TestGuardRejectsReplayAndStaleFencingAcrossRestart(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	path := filepath.Join(t.TempDir(), "state", "admission.json")
	guard, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	first := guardRequest("jti-first", 4, clock.Now().Add(time.Minute))
	if decision, err := guard.Reserve(context.Background(), first); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("first Reserve = %v, %v", decision, err)
	}
	if decision, err := guard.Reserve(context.Background(), first); err != nil || decision != admission.MutationGuardReplayed {
		t.Fatalf("replayed Reserve = %v, %v", decision, err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if decision, err := reopened.Reserve(context.Background(), first); err != nil || decision != admission.MutationGuardReplayed {
		t.Fatalf("replayed after restart = %v, %v", decision, err)
	}
	if decision, err := reopened.Reserve(context.Background(), guardRequest("jti-stale", 3, clock.Now().Add(time.Minute))); err != nil || decision != admission.MutationGuardStaleFencing {
		t.Fatalf("stale fencing Reserve = %v, %v", decision, err)
	}
	if decision, err := reopened.Reserve(context.Background(), guardRequest("jti-new", 5, clock.Now().Add(time.Minute))); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("advanced fencing Reserve = %v, %v", decision, err)
	}
}

func TestGuardScopesFencingToProviderRevisionSandboxAndOperation(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	guard, err := admissionfile.NewGuard(filepath.Join(t.TempDir(), "admission.json"), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	first := guardRequest("jti-one", 2, clock.Now().Add(time.Minute))
	if decision, err := guard.Reserve(context.Background(), first); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("first Reserve = %v, %v", decision, err)
	}
	otherSandbox := guardRequest("jti-two", 1, clock.Now().Add(time.Minute))
	otherSandbox.SandboxID = "sandbox-two"
	if decision, err := guard.Reserve(context.Background(), otherSandbox); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("other sandbox Reserve = %v, %v", decision, err)
	}
	otherRevision := guardRequest("jti-three", 1, clock.Now().Add(time.Minute))
	otherRevision.ProviderRevisionID = "provider-revision-two"
	if decision, err := guard.Reserve(context.Background(), otherRevision); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("other revision Reserve = %v, %v", decision, err)
	}
	stale := guardRequest("jti-four", 1, clock.Now().Add(time.Minute))
	if decision, err := guard.Reserve(context.Background(), stale); err != nil || decision != admission.MutationGuardStaleFencing {
		t.Fatalf("same scope stale Reserve = %v, %v", decision, err)
	}
}

func TestGuardPrunesExpiredEntriesBeforeAndAfterRestart(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	path := filepath.Join(t.TempDir(), "admission.json")
	guard, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	request := guardRequest("jti-expired", 1, clock.Now().Add(time.Minute))
	if decision, err := guard.Reserve(context.Background(), request); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("Reserve = %v, %v", decision, err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}

	clock.Set(clock.Now().Add(time.Minute))
	reopened, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	last, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer last.Close()
	request.ExpiresAt = clock.Now().Add(time.Minute)
	if decision, err := last.Reserve(context.Background(), request); err != nil || decision != admission.MutationGuardAccepted {
		t.Fatalf("Reserve after expiry = %v, %v", decision, err)
	}
}

func TestGuardStateDoesNotStoreRawAdmissionInputs(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	path := filepath.Join(t.TempDir(), "admission.json")
	guard, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	request := guardRequest("raw-jti-value-never-persisted", 1, clock.Now().Add(time.Minute))
	request.ProviderRevisionID = "provider-revision-secret"
	request.SandboxID = "sandbox-secret"
	request.OperationID = "operation-secret"
	request.AttemptID = "attempt-secret"
	if _, err := guard.Reserve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"raw-jti-value-never-persisted", "provider-revision-secret", "sandbox-secret", "operation-secret", "attempt-secret"} {
		if strings.Contains(string(data), raw) {
			t.Fatalf("guard state contains raw admission input %q: %s", raw, data)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
}

func TestGuardRejectsConcurrentOwnerAndCorruptState(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	path := filepath.Join(t.TempDir(), "admission.json")
	first, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admissionfile.NewGuard(path, clock); err == nil {
		t.Fatal("NewGuard accepted a concurrent owner")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"version":1,"replays":[],"fences":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := admissionfile.NewGuard(path, clock); err == nil {
		t.Fatal("NewGuard accepted duplicate JSON state keys")
	}
}

func TestGuardRejectsInsecureOrOversizedPersistedState(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	path := filepath.Join(t.TempDir(), "admission.json")
	validEmptyState := []byte(`{"version":1,"replays":[],"fences":[]}`)
	if err := os.WriteFile(path, validEmptyState, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := admissionfile.NewGuard(path, clock); err == nil {
		t.Fatal("NewGuard accepted an insecure state-file mode")
	}

	var state strings.Builder
	state.WriteString(`{"version":1,"replays":[`)
	for index := range 4097 {
		if index > 0 {
			state.WriteByte(',')
		}
		_, _ = fmt.Fprintf(&state, `{"jti_fingerprint":"%064x","expires_at":"1970-01-01T00:17:40Z"}`, index+1)
	}
	state.WriteString(`],"fences":[]}`)
	if err := os.WriteFile(path, []byte(state.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := admissionfile.NewGuard(path, clock); err == nil {
		t.Fatal("NewGuard accepted state beyond the replay entry capacity")
	}
}

func TestGuardFailsClosedForInvalidOrUnavailableState(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	path := filepath.Join(t.TempDir(), "state", "admission.json")
	guard, err := admissionfile.NewGuard(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := guard.Reserve(ctx, guardRequest("jti-cancelled", 1, clock.Now().Add(time.Minute))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Reserve error = %v", err)
	}
	invalid := guardRequest("jti-invalid", 1, clock.Now().Add(time.Minute))
	invalid.ExpiresAt = clock.Now()
	if _, err := guard.Reserve(context.Background(), invalid); err == nil {
		t.Fatal("Reserve accepted an expired request")
	}

	directory := filepath.Dir(path)
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := guard.Reserve(context.Background(), guardRequest("jti-unavailable", 1, clock.Now().Add(time.Minute))); err == nil {
		t.Fatal("Reserve accepted an unavailable durable state path")
	}
}

func TestGuardReservesExactlyOnceUnderConcurrency(t *testing.T) {
	clock := newTestClock(time.Unix(1_000, 0).UTC())
	guard, err := admissionfile.NewGuard(filepath.Join(t.TempDir(), "admission.json"), clock)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	request := guardRequest("jti-concurrent", 1, clock.Now().Add(time.Minute))
	const workers = 32
	decisions := make(chan admission.MutationGuardDecision, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			decision, err := guard.Reserve(context.Background(), request)
			decisions <- decision
			errors <- err
		}()
	}
	group.Wait()
	close(decisions)
	close(errors)

	accepted := 0
	replayed := 0
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Reserve error = %v", err)
		}
	}
	for decision := range decisions {
		switch decision {
		case admission.MutationGuardAccepted:
			accepted++
		case admission.MutationGuardReplayed:
			replayed++
		default:
			t.Fatalf("concurrent Reserve decision = %v", decision)
		}
	}
	if accepted != 1 || replayed != workers-1 {
		t.Fatalf("accepted = %d, replayed = %d", accepted, replayed)
	}
}

func guardRequest(jti string, fencingToken int64, expiresAt time.Time) admission.MutationGuardRequest {
	return admission.MutationGuardRequest{
		ProviderRevisionID: "provider-revision-one",
		SandboxID:          "sandbox-one",
		OperationID:        "operation-one",
		AttemptID:          "attempt-one",
		FencingToken:       fencingToken,
		JTIFingerprint:     sha256.Sum256([]byte(jti)),
		ExpiresAt:          expiresAt,
	}
}

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
}

func (c *testClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

var _ admission.Clock = (*testClock)(nil)
