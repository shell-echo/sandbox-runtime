//go:build integration && (darwin || linux)

package dockercontrol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// The only composer of the held complete-profile branch is test-only. The
// operator review output does not create this authority in production code.
func profileSourceFixture(t *testing.T, api *client.Client, file string) controlStorageBinding {
	t.Helper()
	data, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	r, e := phase6security.ReviewControlSourceProfile(data)
	if e != nil {
		t.Fatal("complete canonical Profile", e)
	}
	ns := r.Source.Intent.Namespace
	b := controlStorageBinding{profileSource: &r, Storage: controlstorage.Binding{Layout: controlstorage.NewLayout(), Namespace: ns, StorageID: "control-execution-" + ns, ProfileDigest: r.ProfileDigest, TemplateDigest: r.TemplateDigest, ControlPrincipalDigest: r.Control.PrincipalDigest, UID: r.Control.UID, GID: r.Control.GID}, SourceSealDigest: r.Source.SealDigest, SourceSocket: r.Source.Intent.SocketSource, EndpointScopeDigest: executionTestDigest("e"), ControlID: strings.Repeat("f", 64), ControlName: "control-execution-" + ns, ControlImageID: sourceControlImageID(r.Control)}
	if r, err := phase6security.ReviewControlBootstrap(data); err == nil && phase6security.ControlObservesSource(r.Bootstrap.Target) {
		for _, service := range r.Services {
			if service.Launch.Target == r.Bootstrap.Target {
				copy := service
				b.sourceService = &copy
			}
		}
	}
	b.Backend = controlstorage.DedicatedBackend{Protocol: controlstorage.DedicatedBackendProtocol, Device: r.Source.Intent.SelectedDevice, Bytes: r.Source.Intent.SealedImageBytes, BackingFile: "/var/lib/docker/volumes/" + b.backingVolume() + "/_data/receipt.ext4"}
	b.Daemon, e = ObserveCodingDaemon(t.Context(), api, b.EndpointScopeDigest)
	if e != nil || b.validate() != nil {
		t.Fatal("observed fixture input", e)
	}
	return b
}
func TestProfileSourceFixtureInput(t *testing.T) {
	if os.Getenv("CONTROL_PROFILE_METADATA") != "1" {
		t.Skip("explicit held fixture")
	}
	api, e := client.New(client.FromEnv, client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	if os.Getenv("CONTROL_PROFILE_PRESEAL") == "1" {
		data, e := os.ReadFile(os.Getenv("CONTROL_PROFILE_OUTPUT"))
		if e != nil {
			t.Fatal(e)
		}
		var intent phase6security.ControlSourceIntentV1
		if json.Unmarshal(data, &intent) != nil {
			t.Fatal("intent")
		}
		digest, e := intent.Digest()
		if e != nil {
			t.Fatal(e)
		}
		ns := intent.Namespace
		b := controlStorageBinding{Storage: controlstorage.Binding{Namespace: ns, ControlPrincipalDigest: intent.PrincipalDigest}, profileSource: &phase6security.ControlSourceReview{Source: phase6security.ControlSourceAccessV1{Intent: intent, IntentDigest: digest}}, Backend: controlstorage.DedicatedBackend{Protocol: controlstorage.DedicatedBackendProtocol, Device: intent.SelectedDevice, Bytes: intent.SealedImageBytes, BackingFile: "/var/lib/docker/volumes/control-backing-" + ns + "/_data/receipt.ext4"}}
		out, _ := json.Marshal(struct{ Backing map[string]string }{b.labels("backing")})
		fmt.Println("PROFILE_SOURCE_INPUT=" + string(out))
		return
	}
	b := profileSourceFixture(t, api, os.Getenv("CONTROL_PROFILE_OUTPUT"))
	type input struct {
		Name   string
		Mount  phase6security.Mount
		Labels map[string]string
	}
	type net struct {
		Name    string
		Network phase6security.ControlSourceNetwork
		Labels  map[string]string
	}
	inputs := []input{}
	nets := []net{}
	for _, m := range b.profileSource.Control.Mounts {
		if m.Kind != "daemon_socket" && m.Kind != "control_source" && m.Kind != "persistent_ledger" {
			inputs = append(inputs, input{b.profileVolume(m), m, b.labels("input:" + m.StorageID)})
		}
	}
	for _, n := range b.profileSource.Networks {
		nets = append(nets, net{b.profileNetwork(n.Network.Name), n, b.labels("network:" + n.Network.Name)})
	}
	data, _ := json.Marshal(struct {
		Binding                      controlStorageBinding
		Review                       phase6security.ControlSourceReview
		Backing, Filesystem, Control map[string]string
		Inputs                       []input
		Networks                     []net
	}{b, *b.profileSource, b.labels("backing"), b.labels("filesystem"), b.labels("control"), inputs, nets})
	fmt.Println("PROFILE_SOURCE_INPUT=" + string(data))
}
func TestProfileSourceReal(t *testing.T) {
	if os.Getenv("CONTROL_PROFILE_REAL") != "1" {
		t.Skip("explicit high-UID Linux fixture")
	}
	if os.Geteuid() != 57010 || os.Getegid() != 57011 {
		t.Fatal("actual principal")
	}
	// Bootstrap the read-only socket client; complete static authority is then
	// derived from canonical Profile bytes, never caller-selected binding JSON.
	api, e := client.New(client.WithHost("unix://"+controlStorageSocketTarget), client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	b := profileSourceFixture(t, api, phase6security.Slice6PrivateConfigDirectory+"/profile.json")
	b.ControlID = os.Getenv("CONTROL_SOURCE_CONTAINER")
	endpoint := codingBoundUnixEndpoint{path: controlStorageSocketTarget, scopeDigest: b.EndpointScopeDigest}
	action := os.Getenv("CONTROL_SOURCE_ACTION")
	owner, e := openSourceBoundControlStorage(t.Context(), endpoint, b, action == "init")
	if action == "refuse" {
		if e == nil {
			_ = owner.Close()
			t.Fatal("unsafe complete shape accepted")
		}
		fmt.Println("PROFILE_SOURCE_REFUSED")
		return
	}
	if e != nil {
		// Private fixture diagnostics preserve the failed stage without raw daemon
		// output in the public API. This branch never weakens the actual predicate.
		c, ce := api.ContainerInspect(t.Context(), b.ControlID, client.ContainerInspectOptions{})
		back, be := api.VolumeInspect(t.Context(), b.backingVolume(), client.VolumeInspectOptions{})
		t.Logf("inspect=%v backing=%v profile_shape=%t", ce, be, safeProfileSourceControlAccess(c.Container, b, back.Volume))
		vs, _ := api.VolumeList(t.Context(), client.VolumeListOptions{})
		_, oe := readControlProfileStagingObjects(t.Context(), api, b, c.Container, vs.Items)
		t.Logf("objects=%v", oe)
		t.Fatal("held composed admission", e)
	}
	defer owner.Close()
	key := strings.Repeat("7", 32)
	payload := []byte("complete-profile-source-mode")
	if action == "init" {
		if e := owner.Put(t.Context(), controlstorage.State, key, payload); e != nil {
			t.Fatal(e)
		}
	}
	state, e := owner.ReadState(t.Context(), key)
	if e != nil || !state.Found || !bytes.Equal(state.Data, payload) {
		t.Fatal("persistent state", e)
	}
	if e := owner.Check(t.Context()); e != nil {
		t.Fatal(e)
	}
	fmt.Println("PROFILE_SOURCE_PERSISTENCE_PASS " + action)
}

// Unsafe permission variants are created but NEVER started. Inspecting these
// real daemon objects exercises exact projection without granting a process the
// broader device/group/socket authority under test.
func TestProfileSourceRefusalInspect(t *testing.T) {
	if os.Getenv("CONTROL_PROFILE_INSPECT") != "1" {
		t.Skip("explicit stopped negative fixture")
	}
	api, e := client.New(client.FromEnv, client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	b := profileSourceFixture(t, api, os.Getenv("CONTROL_PROFILE_OUTPUT"))
	b.ControlID = os.Getenv("CONTROL_SOURCE_CONTAINER")
	c, e := api.ContainerInspect(t.Context(), b.ControlID, client.ContainerInspectOptions{})
	if e != nil || c.Container.State.Running {
		t.Fatal("negative must be stopped", e)
	}
	expected := os.Getenv("CONTROL_EXPECT_CONFIGURED") == "1"
	if safeProfileSourceConfiguredAccess(c.Container, b) != expected {
		t.Fatal("actual configured permissions disagree with expected result", expected)
	}
	fmt.Println("PROFILE_SOURCE_STOPPED_CONFIGURATION_PASS", expected)
}
