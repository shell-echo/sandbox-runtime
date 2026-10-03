//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6GuestFixtureAdmissionNoIssuerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_FIXTURE_ADMISSION_NO_ISSUER"
const slice6GuestFixtureBarrierNoIssuerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_FIXTURE_BARRIER_NO_ISSUER"

// Only tests the finite task's Docker create/inspect admission against the
// source-bound Profile. The PostgreSQL network peer is a no-secret Alpine
// placeholder; neither SQL nor Vault nor the fixture process is started.
func slice6GuestFixtureAdmissionNoIssuer(t *testing.T, ctx context.Context, run slice6DockerRun,
	static slice6VaultStaticInputs, composed slice6VaultComposedInputs,
	plan slice6ProductRuntimeLaunchPlan, socketVolumes map[string]string) {
	t.Helper()
	if os.Getenv(slice6VaultTrustSwitchEnv) == "1" {
		t.Fatal("Guest fixture admission probe must not enable the issuer gate")
	}
	fixtureRoot := os.Getenv(slice6GuestFixtureSourceRootEnv)
	fixtureRevision := os.Getenv(slice6GuestFixtureSourceRevisionEnv)
	if err := slice6VerifyGuestFixtureSourceDelta(ctx, static.sourceRoot, static.sourceRevision,
		fixtureRoot, fixtureRevision); err != nil {
		t.Fatal("no-issuer Guest fixture source pairing unavailable")
	}
	artifact, err := slice6BuildGuestBindingFixture(t, ctx, fixtureRoot, fixtureRevision)
	if err != nil || slice6ApproveGuestBindingFixture(&artifact,
		os.Getenv(slice6GuestBindingFixtureExpectedDigestEnv)) != nil {
		t.Fatal("no-issuer Guest fixture artifact is not externally approved")
	}
	if phase6security.VerifySlice6DesiredFinalExternalProfile(composed.Profile) != nil ||
		len(socketVolumes) != 74 || plan.ServiceNetwork.Name != "service-product-postgres" {
		t.Fatal("no-issuer Guest fixture Profile authority unavailable")
	}
	anchors := slice6PrepareTrustAnchorVolumes(t, ctx, run, composed)
	material, materialErr := composed.Profile.Slice6MaterialSocketForOwner("product-runtime")
	signer, _, _, _, _, signerErr := composed.Profile.PostgresClientSignerForOwner("product-runtime")
	if materialErr != nil || signerErr != nil || material.SocketStorageID == signer.SocketStorageID ||
		socketVolumes[signer.SocketStorageID] == "" {
		t.Fatal("no-issuer Guest fixture socket authority unavailable")
	}
	materialVolume := "sr-p6-socket-" + material.SocketStorageID + "-" + run.id
	created, err := run.docker(ctx, "volume", "create", "--label", run.label(), materialVolume)
	if err != nil || strings.TrimSpace(string(created)) != materialVolume {
		t.Fatal("no-issuer Guest fixture material placeholder volume unavailable")
	}
	socketVolumes[material.SocketStorageID] = materialVolume
	for _, volume := range []string{"sr-p6-config-product-runtime-" + run.id,
		materialVolume, socketVolumes[signer.SocketStorageID]} {
		if err := slice6VerifyGuestFixtureVolume(ctx, run, volume); err != nil {
			t.Fatal("no-issuer Guest fixture same-run volume admission failed")
		}
	}
	network, err := createSlice6ProfileNetwork(ctx, run, plan.ServiceNetwork)
	if err != nil {
		t.Fatal("no-issuer Guest fixture PostgreSQL bridge create failed")
	}
	postgresIP, err := phase6security.Slice6DesiredServiceEndpointAddress(plan.ServiceNetwork.Name, "postgres")
	if err != nil {
		t.Fatal("no-issuer Guest fixture external peer address unavailable")
	}
	postgresName := "sr-p6-guest-fixture-admission-peer-" + run.id
	peer, err := run.docker(ctx, "create", "--pull=never", "--name", postgresName,
		"--label", run.label(), "--log-driver=none", "--network", network.NetworkID,
		"--ip", postgresIP, "--restart=no", "--user=65534:65534", "--read-only",
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		slice6PinnedAlpineImage, "sleep", "300")
	peerID := strings.TrimSpace(string(peer))
	if err != nil || len(peerID) != 64 || !lowerHexSlice6(peerID) {
		t.Fatal("no-issuer Guest fixture placeholder peer create failed")
	}
	if _, err := run.docker(ctx, "start", peerID); err != nil {
		t.Fatal("no-issuer Guest fixture placeholder peer start failed")
	}
	observed, err := run.docker(ctx, "network", "inspect", plan.ServiceNetwork.Name)
	withoutProduct := plan.ServiceNetwork
	withoutProduct.Principals = nil
	if err != nil || slice6VerifyMigrationPostgresBridge(observed, withoutProduct,
		network.NetworkID, peerID, postgresIP) != nil {
		t.Fatal("no-issuer Guest fixture placeholder bridge did not match source topology")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal("no-issuer Guest fixture seccomp source unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompDocument, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompDocument)
	clear(seccompDocument)
	if err != nil || plan.Principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		t.Fatal("no-issuer Guest fixture seccomp source drift")
	}
	private, ok := phase6security.Slice6PrivateConfigMount("product-runtime")
	if !ok || private.Target != phase6security.Slice6PrivateConfigDirectory {
		t.Fatal("no-issuer Guest fixture private Product mount unavailable")
	}
	anchorArgs, err := slice6AnchorMountArguments(composed.Profile, "product-runtime", anchors)
	if err != nil {
		t.Fatal("no-issuer Guest fixture anchor mount inventory unavailable")
	}
	name := "sr-p6-guest-binding-fixture-" + run.id
	args := []string{"create", "-i", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network", network.NetworkID, "--ip", plan.SourceAddress,
		"--restart=no", "--user", fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(plan.Principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(plan.Principal.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(plan.Principal.Resources.PIDs, 10),
		"--mount", "type=bind,src=" + artifact.Path + ",dst=/phase6-guest-binding-fixture,readonly",
		"--mount", "type=volume,src=sr-p6-config-product-runtime-" + run.id + ",dst=" + private.Target + ",readonly",
		"--mount", "type=volume,src=" + materialVolume + ",dst=" + material.SocketDirectory + ",readonly",
		"--mount", "type=volume,src=" + socketVolumes[signer.SocketStorageID] + ",dst=" + signer.SocketDirectory + ",readonly"}
	args = append(args, anchorArgs...)
	args = append(args, "--entrypoint=/phase6-guest-binding-fixture", slice6PinnedAlpineImage,
		"--config", private.Target+"/"+phase6security.Slice6StartupConfigFile,
		"phase6-guest-binding-fixture")
	fixture, err := run.docker(ctx, args...)
	fixtureID := strings.TrimSpace(string(fixture))
	if err != nil || len(fixtureID) != 64 || !lowerHexSlice6(fixtureID) {
		t.Fatal("no-issuer Guest fixture finite container create failed")
	}
	if err := slice6VerifyGuestFixtureContainer(ctx, run, fixtureID, network.NetworkID, plan.ServiceNetwork.Name,
		plan.SourceAddress, composed.Profile, plan.Principal, artifact, socketVolumes, anchors,
		seccomp, material.SocketDirectory, signer.SocketDirectory, private.Target); err != nil {
		t.Fatalf("no-issuer Guest fixture created-container admission failed: %v", err)
	}
	var state []struct {
		State struct{ Running bool }
	}
	stateDocument, stateErr := run.docker(ctx, "inspect", fixtureID)
	if stateErr != nil || json.Unmarshal(stateDocument, &state) != nil || len(state) != 1 || state[0].State.Running {
		t.Fatal("no-issuer Guest fixture unexpectedly started")
	}
	t.Log("no-issuer source-bound Guest fixture finite container create/inspect admitted; SQL/Vault/fixture execution remain unproved")
}

// Mechanism evidence only: pinned Alpine substitutes for the Guest fixture.
// It confirms Docker's attached stdin can remain closed while the exact
// running endpoint is inspected, and that early exit/cancellation send no data.
func TestSlice6GuestFixtureStdinBarrierNoIssuerDocker(t *testing.T) {
	if os.Getenv(slice6GuestFixtureBarrierNoIssuerEnv) != "1" {
		t.Skip("set " + slice6GuestFixtureBarrierNoIssuerEnv + " for the no-issuer Docker stdin mechanism probe")
	}
	if os.Getenv(slice6VaultTrustSwitchEnv) == "1" {
		t.Fatal("stdin mechanism probe cannot enable the issuer gate")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("no-issuer stdin barrier exact Docker cleanup: %v", err)
		}
	})
	networkName := "sr-p6-fixture-barrier-" + run.id
	created, err := run.docker(ctx, "network", "create", "--driver=bridge", "--internal",
		"--opt=com.docker.network.bridge.gateway_mode_ipv4=isolated",
		"--subnet=172.31.250.0/24", "--label", run.label(), networkName)
	networkID := strings.TrimSpace(string(created))
	if err != nil || len(networkID) != 64 || !lowerHexSlice6(networkID) {
		t.Fatal("no-issuer stdin barrier isolated network unavailable")
	}
	for index, scenario := range []struct {
		name, script string
		cancel       bool
		earlyExit    bool
	}{
		{"accepted", `read -r value; test "$value" = admitted && printf 'accepted\n'`, false, false},
		{"early-exit", `exit 7`, false, true},
		{"cancel", `read -r value; test "$value" = admitted && printf 'accepted\n'`, true, false},
	} {
		ip := fmt.Sprintf("172.31.250.%d", index+3)
		name := "sr-p6-fixture-barrier-" + scenario.name + "-" + run.id
		created, err := run.docker(ctx, "create", "-i", "--pull=never", "--name", name,
			"--label", run.label(), "--log-driver=none", "--network", networkID, "--ip", ip,
			"--restart=no", "--user=65534:65534", "--read-only", "--cap-drop=ALL",
			"--security-opt", "no-new-privileges:true", "--entrypoint=/bin/sh",
			slice6PinnedAlpineImage, "-ec", scenario.script)
		id := strings.TrimSpace(string(created))
		if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
			t.Fatal("no-issuer stdin barrier finite container unavailable")
		}
		caseContext, caseCancel := context.WithCancel(ctx)
		command := exec.CommandContext(caseContext, "docker", "start", "-ai", id)
		stdin, err := command.StdinPipe()
		if err != nil {
			caseCancel()
			t.Fatal("no-issuer stdin barrier attached pipe unavailable")
		}
		output := &slice6BoundedOutput{limit: 4096}
		command.Stdout, command.Stderr = output, output
		if err := command.Start(); err != nil {
			stdin.Close()
			caseCancel()
			t.Fatal("no-issuer stdin barrier attached start unavailable")
		}
		completed := make(chan error, 1)
		go func() { completed <- command.Wait() }()
		admit := func() error {
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) && caseContext.Err() == nil {
				document, err := run.docker(caseContext, "inspect", id)
				var inspected []struct {
					State           struct{ Running bool }
					NetworkSettings struct {
						Networks map[string]slice6GuestFixtureRunningEndpoint
					}
				}
				if err != nil || json.Unmarshal(document, &inspected) != nil || len(inspected) != 1 {
					return errors.New("no-issuer barrier inspect unavailable")
				}
				if inspected[0].State.Running {
					return slice6ValidateGuestFixtureRunningNetwork(inspected[0].NetworkSettings.Networks,
						networkID, networkName, ip)
				}
				if scenario.earlyExit {
					return errors.New("no-issuer barrier process exited before admission")
				}
				time.Sleep(100 * time.Millisecond)
			}
			return errors.New("no-issuer barrier process did not become ready")
		}
		if scenario.cancel {
			if err := admit(); err != nil {
				t.Fatal("no-issuer cancellation case never reached running state")
			}
			caseCancel()
		}
		var wrote bool
		barrierErr := slice6DeliverGuestFixtureInput(caseContext, func() error {
			if caseContext.Err() != nil {
				return caseContext.Err()
			}
			return admit()
		}, slice6ObservedWriteCloser{WriteCloser: stdin, wrote: &wrote}, []byte("admitted\n"))
		stdin.Close()
		if scenario.earlyExit || scenario.cancel {
			if barrierErr == nil || wrote {
				t.Fatal("no-issuer failed admission released the payload")
			}
			caseCancel()
			select {
			case <-completed:
			case <-time.After(5 * time.Second):
				t.Fatal("no-issuer failed admission Docker attach did not terminate")
			}
			continue
		}
		if barrierErr != nil || !wrote {
			t.Fatal("no-issuer admitted container did not receive canonical stdin")
		}
		select {
		case err := <-completed:
			if err != nil {
				t.Fatal("no-issuer admitted finite task did not exit cleanly")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no-issuer admitted finite task did not finish")
		}
		output.mu.Lock()
		got := bytes.Clone(output.buffer.Bytes())
		clear(output.buffer.Bytes())
		oversized := output.overflow
		output.mu.Unlock()
		if oversized || !bytes.Equal(got, []byte("accepted\n")) {
			clear(got)
			t.Fatal("no-issuer admitted finite task returned unexpected bounded output")
		}
		clear(got)
		caseCancel()
	}
	t.Log("pinned no-secret container confirmed start/inspect/stdin barrier, early exit and cancellation; no fixture, SQL or Vault execution")
}

type slice6ObservedWriteCloser struct {
	io.WriteCloser
	wrote *bool
}

func (writer slice6ObservedWriteCloser) Write(payload []byte) (int, error) {
	*writer.wrote = true
	return writer.WriteCloser.Write(payload)
}
