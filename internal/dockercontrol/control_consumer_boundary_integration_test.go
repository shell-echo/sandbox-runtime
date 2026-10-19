//go:build integration && (darwin || linux)

package dockercontrol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/controlstorage"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func boundaryFixture(t *testing.T, api *client.Client, file string) (controlStorageBinding, []byte) {
	t.Helper()
	b := profileSourceFixture(t, api, file)
	data, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	v, e := phase6security.ReviewControlConsumerBoundary(data)
	if e != nil {
		t.Fatal(e)
	}
	b.boundary = &v
	b.ControlID = os.Getenv("CONTROL_SOURCE_CONTAINER")
	if b.ControlID == "" {
		b.ControlID = strings.Repeat("f", 64)
	}
	return b, data
}
func TestControlBoundaryFixtureInput(t *testing.T) {
	if os.Getenv("CONTROL_BOUNDARY_METADATA") != "1" {
		t.Skip("explicit diagnostic")
	}
	api, e := client.New(client.FromEnv, client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	b, _ := boundaryFixture(t, api, os.Getenv("CONTROL_PROFILE_OUTPUT"))
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
	type peer struct {
		Name             string
		Principal        phase6security.Principal
		Mounts           []input
		Network, Address string
		Labels           map[string]string
	}
	inputs := []input{}
	nets := []net{}
	peers := []peer{}
	for _, m := range b.profileSource.Control.Mounts {
		if m.Kind != "daemon_socket" && m.Kind != "control_source" && m.Kind != "persistent_ledger" {
			inputs = append(inputs, input{b.profileVolume(m), m, b.labels("input:" + m.StorageID)})
		}
	}
	for _, n := range b.profileSource.Networks {
		nets = append(nets, net{b.profileNetwork(n.Network.Name), n, b.labels("network:" + n.Network.Name)})
	}
	for _, p := range b.boundary.Consumers {
		if p.Name == b.profileSource.Control.Name {
			continue
		}
		v := peer{Name: sourceObjectName("peer", b.Storage.Namespace, p.Name), Principal: p, Network: "none", Labels: b.labels("peer:" + p.Name)}
		for _, m := range b.boundary.Mounts(p) {
			v.Mounts = append(v.Mounts, input{b.profileVolume(m), m, b.labels("input:" + m.StorageID)})
		}
		for _, end := range b.boundary.Endpoints {
			if end.ProviderDeployment == p.Name {
				v.Network = b.profileNetwork(end.Network)
				for _, n := range b.profileSource.Networks {
					if n.Network.Name == end.Network {
						v.Address = strings.TrimSuffix(n.Address, ".3") + ".2"
					}
				}
			}
		}
		peers = append(peers, v)
	}
	out, _ := json.Marshal(struct {
		Binding                      controlStorageBinding
		Review                       phase6security.ControlSourceReview
		Boundary                     phase6security.ControlConsumerBoundary
		Backing, Filesystem, Control map[string]string
		Inputs                       []input
		Networks                     []net
		Peers                        []peer
	}{b, *b.profileSource, *b.boundary, b.labels("backing"), b.labels("filesystem"), b.labels("control"), inputs, nets, peers})
	fmt.Println("PROFILE_SOURCE_INPUT=" + string(out))
}
func TestControlOperatorKeyFixture(t *testing.T) {
	dir := os.Getenv("CONTROL_OPERATOR_KEY_OUTPUT")
	if dir == "" {
		t.Skip("explicit test key ceremony")
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for name, data := range map[string][]byte{"operator.key": key, "control-operator.pub": pub} {
		f, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		_, e = f.Write(data)
		_ = f.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	d := sha256.Sum256(pub)
	fmt.Println("OPERATOR_KEY_PIN=sha256:" + hex.EncodeToString(d[:]))
}
func fixtureStoreContents(t *testing.T) string {
	t.Helper()
	names, e := os.ReadDir(controlStorageTarget)
	if e != nil {
		t.Fatal(e)
	}
	out := map[string]string{}
	for _, n := range names {
		data, e := os.ReadFile(filepath.Join(controlStorageTarget, n.Name()))
		if e != nil {
			t.Fatal(e)
		}
		d := sha256.Sum256(data)
		out[n.Name()] = hex.EncodeToString(d[:])
	}
	return executionDigest("fixture-store-bytes", out)
}
func TestControlBoundaryReal(t *testing.T) {
	if os.Getenv("CONTROL_BOUNDARY_REAL") != "1" {
		t.Skip("explicit high UID diagnostic fixture")
	}
	if os.Geteuid() != 57010 || os.Getegid() != 57011 {
		t.Fatal("actual principal")
	}
	api, e := client.New(client.WithHost("unix://"+controlStorageSocketTarget), client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	b, doc := boundaryFixture(t, api, "/run/phase6/config/profile.json")
	endpoint := codingBoundUnixEndpoint{path: controlStorageSocketTarget, scopeDigest: b.EndpointScopeDigest}
	action := os.Getenv("CONTROL_SOURCE_ACTION")
	before := fixtureStoreContents(t)
	if action == "tampered-boundary" {
		b.boundary.Consumers = b.boundary.Consumers[:1]
	}
	// Public test key bytes come from the host; a separate binary commitment is
	// required. This test-only pipe is NOT a new file in closed private_config.
	pub, e := hex.DecodeString(os.Getenv("CONTROL_OPERATOR_PUBLIC_HEX"))
	if e != nil {
		t.Fatal(e)
	}
	input, output, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := output.Write(pub); e != nil {
		t.Fatal(e)
	}
	_ = output.Close()
	prepared, e := prepareControlAdmission(t.Context(), endpoint, b, doc, input)
	if action == "refuse" || action == "tampered-boundary" {
		if e == nil {
			_ = prepared.Close()
			t.Fatal("unsafe boundary accepted")
		}
		if before != fixtureStoreContents(t) {
			t.Fatal("refusal wrote Store")
		}
		fmt.Println("BOUNDARY_REFUSED_UNCHANGED")
		return
	}
	if e != nil {
		t.Fatal("prepare", e)
	}
	defer prepared.Close()
	request, e := prepared.Request()
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println("OPERATOR_REQUEST=" + string(request))
	in := bufio.NewReaderSize(os.Stdin, 4096)
	reply, e := in.ReadBytes('\n')
	if e != nil || len(reply) > 2049 {
		t.Fatal("bounded reply", e)
	}
	reply = bytes.TrimSuffix(reply, []byte{'\n'})
	owner, e := prepared.Open(t.Context(), reply, action == "init" || action == "bad-signature")
	if action == "bad-signature" || action == "post-sign-drift" {
		if e == nil {
			_ = owner.Close()
			t.Fatal("unsafe operator accepted")
		}
		if before != fixtureStoreContents(t) {
			t.Fatal("signature refusal wrote Store")
		}
		fmt.Println("OPERATOR_REFUSED_UNCHANGED")
		return
	}
	if e != nil {
		t.Fatal("open", e)
	}
	defer owner.Close()
	if _, e := prepared.Open(t.Context(), reply, false); e == nil {
		t.Fatal("session replay")
	}
	if action == "live-drift" {
		before = fixtureStoreContents(t)
		fmt.Println("BOUNDARY_OPENED")
		if _, e := in.ReadBytes('\n'); e != nil {
			t.Fatal(e)
		}
		if owner.Check(t.Context()) == nil || owner.Put(t.Context(), controlstorage.State, strings.Repeat("7", 32), []byte("unsafe")) == nil {
			t.Fatal("live drift accepted")
		}
		if before != fixtureStoreContents(t) {
			t.Fatal("live drift wrote Store")
		}
		fmt.Println("LIVE_DRIFT_REFUSED_UNCHANGED")
		return
	}
	key := strings.Repeat("7", 32)
	payload := []byte("operator-boundary-component")
	if action == "init" {
		if e := owner.Put(t.Context(), controlstorage.State, key, payload); e != nil {
			t.Fatal(e)
		}
	}
	state, e := owner.ReadState(t.Context(), key)
	if e != nil || !state.Found || !bytes.Equal(state.Data, payload) {
		t.Fatal("state", e)
	}
	if e := owner.Check(t.Context()); e != nil {
		t.Fatal(e)
	}
	fmt.Println("OPERATOR_BOUNDARY_PERSISTENCE_PASS " + action)
}

// Separate process on the operator host. It re-derives the Profile and re-reads
// the full Docker graph; the private test key is never copied into a container.
func TestControlBoundaryOperatorSign(t *testing.T) {
	if os.Getenv("CONTROL_OPERATOR_SIGN") != "1" {
		t.Skip("explicit test operator")
	}
	api, e := client.New(client.FromEnv, client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	b, _ := boundaryFixture(t, api, os.Getenv("CONTROL_PROFILE_OUTPUT"))
	data, e := os.ReadFile(os.Getenv("CONTROL_OPERATOR_REQUEST"))
	if e != nil {
		t.Fatal(e)
	}
	var r controlOperatorRequest
	if json.Unmarshal(data, &r) != nil {
		t.Fatal("request")
	}
	canon, _ := json.Marshal(r)
	if !bytes.Equal(data, canon) {
		t.Fatal("canonical request")
	}
	ctx, cancel := context.WithTimeout(t.Context(), maxCodingInventoryDuration)
	defer cancel()
	inv, e := readControlStorageInventory(ctx, api, b)
	if e != nil {
		t.Fatal("host independent graph", e)
	}
	vol, e := readSourceVolumeBinding(ctx, api, b)
	if e != nil {
		t.Fatal(e)
	}
	if r.Protocol != controlOperatorProtocol || r.Scope != "held-control-consumer-component" || r.ProfileBytes != b.boundary.ProfileBytesDigest || r.Profile != b.Storage.ProfileDigest || r.Namespace != b.Storage.Namespace || r.Intent != b.profileSource.Source.IntentDigest || r.Seal != b.SourceSealDigest || r.Inventory != inv || r.Volumes != vol || r.Root != os.Getenv("CONTROL_OBSERVED_ROOT") || !codingArchiveRuntimeID.MatchString(r.Run) || !codingArchiveRuntimeID.MatchString(r.Challenge) || r.Issued > time.Now().Unix() || r.Expires <= time.Now().Unix() || r.Expires-r.Issued > 120 {
		t.Fatal("operator observed binding disagreement")
	}
	key, e := os.ReadFile(os.Getenv("CONTROL_OPERATOR_KEY"))
	if e != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal("test private key")
	}
	reply := controlOperatorReply{operatorRequestDigest(r), ed25519.Sign(ed25519.PrivateKey(key), operatorBytes(r))}
	raw, _ := json.Marshal(reply)
	fmt.Println("OPERATOR_REPLY=" + string(raw))
}
func TestControlBoundaryProbeReal(t *testing.T) {
	if os.Getenv("CONTROL_BOUNDARY_PROBE") != "1" {
		t.Skip("explicit second physical read")
	}
	api, e := client.New(client.WithHost("unix://"+controlStorageSocketTarget), client.WithAPIVersion("1.55"))
	if e != nil {
		t.Fatal(e)
	}
	defer api.Close()
	b, _ := boundaryFixture(t, api, "/run/phase6/config/profile.json")
	vol, e := readSourceVolumeBinding(t.Context(), api, b)
	if e != nil {
		t.Fatal(e)
	}
	p, e := controlstorage.ProbeSourceBound(t.Context(), controlStorageTarget, b.Storage, b.Backend, b.SourceSealDigest, vol)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	root, e := p.Observe(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println("OPERATOR_PHYSICAL_ROOT=" + root)
}
