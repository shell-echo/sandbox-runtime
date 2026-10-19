//go:build integration && (darwin || linux)

package dockercontrol

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
)

// Operator-side fixture metadata, not a runtime authorization constructor.
func TestSourceCompositionFixtureInput(t *testing.T) {
	if os.Getenv("CONTROL_SOURCE_FIXTURE_INPUT") != "1" {
		t.Skip("explicit fixture opt-in")
	}
	api, e := client.New(client.FromEnv, client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	ns := os.Getenv("CONTROL_SOURCE_NAMESPACE")
	b := controlStorageBinding{Storage: controlstorage.Binding{Layout: controlstorage.NewLayout(), Namespace: ns, StorageID: "control-execution-" + ns, ProfileDigest: executionTestDigest("b"), TemplateDigest: executionTestDigest("c"), ControlPrincipalDigest: executionTestDigest("d"), UID: 57010, GID: 57011}, SourceSealDigest: os.Getenv("CONTROL_SOURCE_SEAL"), SourceSocket: "/run/host-services/docker.proxy.sock", EndpointScopeDigest: executionTestDigest("e"), ControlID: strings.Repeat("f", 64), ControlName: "control-execution-" + ns, ControlImageID: os.Getenv("CONTROL_SOURCE_IMAGE")}
	b.Backend = controlstorage.DedicatedBackend{Protocol: controlstorage.DedicatedBackendProtocol, Device: "/dev/loop7", Bytes: controlstorage.DedicatedBackendBytes, BackingFile: "/var/lib/docker/volumes/" + b.backingVolume() + "/_data/receipt.ext4"}
	b.Daemon, e = ObserveCodingDaemon(t.Context(), api, b.EndpointScopeDigest)
	if e != nil || b.validate() != nil {
		t.Fatal("invalid observed fixture input", e)
	}
	d, _ := json.Marshal(struct {
		Binding                      controlStorageBinding
		Backing, Filesystem, Control map[string]string
	}{b, b.labels("backing"), b.labels("filesystem"), b.labels("control")})
	fmt.Println("SOURCE_FIXTURE_INPUT=" + string(d))
}

// Executed as the actual high-UID process inside the exact inventoried Control
// container. All source and Store observations use real Linux FDs and ioctl.
func TestSourceCompositionReal(t *testing.T) {
	if os.Getenv("CONTROL_SOURCE_REAL") != "1" {
		t.Skip("explicit Linux source fixture")
	}
	if os.Geteuid() != 57010 || os.Getegid() != 57011 {
		t.Fatal("wrong actual principal")
	}
	var b controlStorageBinding
	if json.Unmarshal([]byte(os.Getenv("CONTROL_SOURCE_BINDING")), &b) != nil {
		t.Fatal("fixture binding missing")
	}
	b.ControlID = os.Getenv("CONTROL_SOURCE_CONTAINER")
	endpoint := codingBoundUnixEndpoint{path: controlStorageSocketTarget, scopeDigest: b.EndpointScopeDigest}
	action := os.Getenv("CONTROL_SOURCE_ACTION")
	if action == "refuse" || action == "wrong-seal" {
		if action == "wrong-seal" {
			b.SourceSealDigest = executionTestDigest("0")
		}
		s, e := openSourceBoundControlStorage(t.Context(), endpoint, b, false)
		if e == nil {
			_ = s.Close()
			t.Fatal("unsafe composition accepted")
		}
		fmt.Println("COMPOSITION_REFUSED")
		return
	}
	s, e := openSourceBoundControlStorage(t.Context(), endpoint, b, action == "init")
	if e != nil {
		o, oe := openControlStorageUnixObserver(endpoint, b, nil)
		t.Logf("private admission stage: endpoint=%v", oe)
		if oe == nil {
			defer o.api.Close()
			d, de := ObserveCodingDaemon(t.Context(), o.api, b.EndpointScopeDigest)
			t.Logf("daemon equal=%t error=%v", d == b.Daemon, de)
			_, ie := readControlStorageInventory(t.Context(), o.api, b)
			t.Logf("inventory error=%v", ie)
		}
		t.Fatal("real composed admission", e)
	}
	defer func() {
		if e := s.Close(); e != nil {
			t.Error("close", e)
		}
	}()
	key := strings.Repeat("1", 32)
	payload := bytes.Repeat([]byte("source-bound-persistence\n"), 4096)
	switch action {
	case "init":
		if e := s.Put(t.Context(), controlstorage.State, key, payload); e != nil {
			t.Fatal(e)
		}
		state, e := s.ReadState(t.Context(), key)
		if e != nil || !state.Found || !bytes.Equal(state.Data, payload) {
			t.Fatal("new state mismatch", e)
		}
		if e := s.CompareState(t.Context(), key, state, payload); e != nil {
			t.Fatal("owner CAS", e)
		}
		if e := s.CompareState(t.Context(), key, state, payload); e == nil {
			t.Fatal("stale CAS accepted")
		}
		if e := s.Put(t.Context(), controlstorage.Class("browser"), key, payload); e == nil {
			t.Fatal("unallocated scope accepted")
		}
		fmt.Println("COMPOSED_INITIALIZE_WRITE_CAS_PASS")
	case "reopen":
		state, e := s.ReadState(t.Context(), key)
		if e != nil || !state.Found || !bytes.Equal(state.Data, payload) {
			t.Fatal("persisted state mismatch", e)
		}
		fmt.Println("COMPOSED_REOPEN_PASS")
	case "quota":
		// Sixty-four one-byte allocation records reach the actual class object
		// limit without a memory-heavy synthetic counter or oversized stress file.
		for i := 0; i < 64; i++ {
			if e := s.Put(t.Context(), controlstorage.AllocationEvidence, fmt.Sprintf("%032x", i+100), []byte("x")); e != nil {
				t.Fatal(i, e)
			}
		}
		if e := s.Put(t.Context(), controlstorage.AllocationEvidence, fmt.Sprintf("%032x", 164), []byte("x")); !errors.Is(e, controlstorage.ErrCapacity) {
			t.Fatal("logical object quota", e)
		}
		if e := s.Check(t.Context()); e != nil {
			t.Fatal("quota refusal damaged store", e)
		}
		fmt.Println("COMPOSED_LOGICAL_OBJECT_QUOTA_PASS")
	case "hold-reject", "hold-source-reject", "hold-pass":
		fmt.Println("SOURCE_HOLD_READY")
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() || scanner.Text() != "check" {
			t.Fatal("fixture coordination lost")
		}
		if action == "hold-source-reject" && s.observer.store.Check() == nil {
			t.Fatal("retained source replacement accepted by Store")
		}
		e := s.Check(t.Context())
		if action == "hold-pass" && e != nil {
			t.Fatal(e)
		}
		if action != "hold-pass" && e == nil {
			t.Fatal("changed source/inventory accepted")
		}
		fmt.Println("COMPOSED_HOLD_RESULT_PASS")
	default:
		t.Fatal("unknown fixture action")
	}
}
