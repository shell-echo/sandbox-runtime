//go:build integration && (darwin || linux)

package dockercontrol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

// Explicit fixture metadata only: these Profile/principal/policy digests do not
// grant public admission. The candidate template is source-owned; the daemon is
// read live. Positive full Profile/operator command admission is still absent.
func TestSourceExecutionFixtureInput(t *testing.T) {
	if os.Getenv("CONTROL_SOURCE_FIXTURE_INPUT") != "1" {
		t.Skip("explicit fixture opt-in")
	}
	api, err := client.New(client.FromEnv, client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	ns := os.Getenv("CONTROL_SOURCE_NAMESPACE")
	b := executionTestBinding(t)
	b.Storage.Namespace, b.Storage.StorageID = ns, "control-execution-"+ns
	b.Storage.UID, b.Storage.GID = 57010, 57011
	daemon, err := ObserveCodingDaemon(t.Context(), api, b.EndpointScopeDigest)
	if err != nil {
		t.Fatal(err)
	}
	b.DaemonDigest, b.DaemonEnvironmentDigest = daemon.IdentityDigest, daemon.EnvironmentDigest
	s := controlStorageBinding{Storage: b.Storage, SourceSealDigest: os.Getenv("CONTROL_SOURCE_SEAL"), SourceSocket: "/run/host-services/docker.proxy.sock",
		EndpointScopeDigest: b.EndpointScopeDigest, Daemon: daemon, ControlID: strings.Repeat("f", 64), ControlName: b.Storage.StorageID, ControlImageID: os.Getenv("CONTROL_SOURCE_IMAGE")}
	s.Backend = controlstorage.DedicatedBackend{Protocol: controlstorage.DedicatedBackendProtocol, Device: "/dev/loop7", Bytes: controlstorage.DedicatedBackendBytes,
		BackingFile: "/var/lib/docker/volumes/" + s.backingVolume() + "/_data/receipt.ext4"}
	if bindExecutionSource(codingBoundUnixEndpoint{path: controlStorageSocketTarget, scopeDigest: b.EndpointScopeDigest}, b, s) != nil {
		t.Fatal("fixture join")
	}
	raw, _ := json.Marshal(struct {
		Binding                      controlStorageBinding
		Execution                    executionBinding
		Backing, Filesystem, Control map[string]string
	}{s, b, s.labels("backing"), s.labels("filesystem"), s.labels("control")})
	fmt.Println("SOURCE_FIXTURE_INPUT=" + string(raw))
}

func sourceExecutionCreate(b executionBinding) executionCreate {
	now := time.Now().UTC()
	return executionCreate{Protocol: executionReceiptProtocol, BindingDigest: b.digest(), AllocationID: "codingalloc-" + strings.Repeat("a", 64), SlotID: b.Template.Slots[0].Data.ID,
		SandboxID: "sandbox", ProviderRevisionID: "revision", TenantDigest: executionTestDigest("5"), OperationID: "create", AttemptID: "create-attempt", RequestDigest: executionTestDigest("6"),
		Generation: 1, Fence: 1, IssuedAt: now, ExpiresAt: now.Add(30 * time.Second), OperationDeadline: now.Add(time.Minute)}
}

func TestSourceExecutionLedgerReal(t *testing.T) {
	if os.Getenv("CONTROL_SOURCE_LEDGER_REAL") != "1" {
		t.Skip("explicit source ledger fixture")
	}
	if os.Geteuid() != 57010 || os.Getegid() != 57011 {
		t.Fatal("actual principal drift")
	}
	var input struct {
		Binding                      controlStorageBinding
		Execution                    executionBinding
		Backing, Filesystem, Control map[string]string
	}
	if json.Unmarshal([]byte(os.Getenv("CONTROL_SOURCE_LEDGER_INPUT")), &input) != nil {
		t.Fatal("fixture input")
	}
	source, b := input.Binding, input.Execution
	source.ControlID = os.Getenv("CONTROL_SOURCE_CONTAINER")
	endpoint := codingBoundUnixEndpoint{path: controlStorageSocketTarget, scopeDigest: b.EndpointScopeDigest}
	action := os.Getenv("CONTROL_SOURCE_ACTION")
	if action == "missing-state" {
		s, err := openSourceBoundControlStorage(t.Context(), endpoint, source, true)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		for _, init := range []bool{false, true} {
			if l, err := openSourceExecutionLedger(t.Context(), endpoint, b, source, init); err == nil {
				_ = l.close(context.Background())
				t.Fatal("missing state repaired/reset")
			}
		}
		s, err = openSourceBoundControlStorage(t.Context(), endpoint, source, false)
		if err != nil {
			t.Fatal("failed ledger load leaked source owner", err)
		}
		snap, err := s.ReadState(t.Context(), b.digest()[7:39])
		if err != nil || snap.Found {
			t.Fatal("missing state was changed")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("SOURCE_LEDGER_MISSING_STATE_PRESERVED")
		return
	}
	init := !strings.HasPrefix(action, "reopen-")
	l, err := openSourceExecutionLedger(t.Context(), endpoint, b, source, init)
	if err != nil {
		t.Fatal("source ledger open", err)
	}
	defer func() {
		if err := l.close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	assertState := func(count int) {
		t.Helper()
		s := executionTestState(t, l)
		if len(s.Allocations) != count || len(s.Executions) != 0 {
			t.Fatal("unexpected durable record count")
		}
		if count == 1 && (s.Allocations[0].CreateStatus != executionUnknown || s.Allocations[0].Completion != nil) {
			t.Fatal("Unknown became completion")
		}
	}
	noEffect := func(context.Context, executionResources) error { t.Fatal("forbidden effect callback"); return nil }
	switch action {
	case "init-unknown":
		a := sourceExecutionCreate(b)
		calls := 0
		if err := l.create(t.Context(), a, func(_ context.Context, r executionResources) error {
			calls++
			assertState(1)
			if r != a.resources(b) {
				t.Fatal("unbound resource tuple")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Fatal("effect probe count")
		}
		assertState(1)
		if err := l.completeCreate(t.Context(), a, nil); err == nil {
			t.Fatal("callback return became completion")
		}
		fmt.Println("SOURCE_LEDGER_DURABLE_UNKNOWN_PASS")
	case "reopen-unknown":
		assertState(1)
		a := l.current.Allocations[0].Create
		if len(l.createReturned) != 0 {
			t.Fatal("ephemeral create return survived process")
		}
		if err := l.create(t.Context(), a, noEffect); err == nil {
			t.Fatal("Unknown replayed")
		}
		if err := l.execute(t.Context(), executionTestClaim(l, a), executionNoop); err == nil {
			t.Fatal("Unknown admitted exec")
		}
		called := false
		collector := executionTestCollector(func(context.Context, executionBinding, executionCreate, uint64, string) (executionCompletionObservation, error) {
			called = true
			return executionCompletionObservation{}, nil
		})
		if err := l.completeCreate(t.Context(), a, collector); err == nil || called {
			t.Fatal("reopen re-observed Unknown as completion")
		}
		assertState(1)
		fmt.Println("SOURCE_LEDGER_REOPEN_UNKNOWN_HELD")
	case "reopen-empty":
		assertState(0)
		fmt.Println("SOURCE_LEDGER_REOPEN_EMPTY_PASS")
	case "before-state", "after-state":
		a := sourceExecutionCreate(b)
		l.fault = func(stage string) error {
			if stage == action {
				return errors.New("bounded ledger interruption")
			}
			return nil
		}
		if err := l.create(t.Context(), a, noEffect); !errors.Is(err, controlstorage.ErrUncertain) || !l.poisoned {
			t.Fatal("uncertain ledger write did not close", err)
		}
		if err := l.create(t.Context(), a, noEffect); err == nil {
			t.Fatal("poisoned ledger replay")
		}
		fmt.Println("SOURCE_LEDGER_UNCERTAIN_NO_DISPATCH " + action)
	case "close-drain":
		a := sourceExecutionCreate(b)
		entered := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- l.create(t.Context(), a, func(context.Context, executionResources) error { close(entered); <-release; return nil })
		}()
		select {
		case <-entered:
		case err := <-done:
			t.Fatal("callback never entered", err)
		case <-time.After(15 * time.Second):
			t.Fatal("callback entry timeout")
		}
		released := false
		defer func() {
			if !released {
				close(release)
				<-done
			}
		}()
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		if err := l.close(canceled); !errors.Is(err, context.Canceled) {
			t.Fatal("close released in-flight owner", err)
		}
		if !l.closing || l.store.Check(t.Context()) != nil {
			t.Fatal("canceled close lost its live source owner")
		}
		other, err := openSourceExecutionLedger(t.Context(), endpoint, b, source, false)
		if err == nil {
			_ = other.close(context.Background())
			t.Fatal("second owner acquired during drain")
		}
		if err := l.create(t.Context(), a, noEffect); err == nil {
			t.Fatal("closing ledger admitted work")
		}
		close(release)
		released = true
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := l.close(t.Context()); err != nil {
			t.Fatal(err)
		}
		l, err = openSourceExecutionLedger(t.Context(), endpoint, b, source, false)
		if err != nil {
			t.Fatal("owner not released after drain", err)
		}
		assertState(1)
		fmt.Println("SOURCE_LEDGER_DRAIN_RETAINS_OWNER_PASS")
	case "hold-drift":
		scan := bufio.NewScanner(os.Stdin)
		fmt.Println("SOURCE_LEDGER_HOLD_READY")
		if !scan.Scan() || scan.Text() != "check" {
			t.Fatal("fixture coordination lost")
		}
		a := sourceExecutionCreate(b)
		if err := l.create(t.Context(), a, noEffect); err == nil {
			t.Fatal("new stopped consumer accepted")
		}
		if !l.store.(*sourceBoundControlStorage).poisoned || len(l.current.Allocations) != 0 {
			t.Fatal("drift did not poison source owner before ledger write")
		}
		fmt.Println("SOURCE_LEDGER_DRIFT_REFUSED")
		if !scan.Scan() || scan.Text() != "retry" {
			t.Fatal("fixture retry lost")
		}
		fresh := sourceExecutionCreate(b)
		if fresh.validate(b, time.Now().UTC()) != nil {
			t.Fatal("retry authority expired before check")
		}
		if err := l.create(t.Context(), fresh, noEffect); err == nil || !l.store.(*sourceBoundControlStorage).poisoned {
			t.Fatal("source owner poison was reset")
		}
		if len(l.current.Allocations) != 0 {
			t.Fatal("drift wrote allocation")
		}
		fmt.Println("SOURCE_LEDGER_POISON_RETAINED")
	default:
		t.Fatal("unknown fixture action")
	}
}
