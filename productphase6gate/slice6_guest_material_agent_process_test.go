//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

// Component evidence only. A distinct material-agent PID1 obtains its own
// credential, reads Vault KVv2 through the live Guest TLS signer and serves
// one exact owner-side resolve before draining and removing both sockets.
func slice6RunGuestMaterialAgentStartup(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, serverID, publicKeyDigest string,
	socketVolumes, anchorFiles map[string]string) {
	t.Helper()
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil ||
		len(publicKeyDigest) != len("sha256:")+64 || len(socketVolumes) != 67 {
		t.Fatal("Guest material-agent final source authority unavailable")
	}
	var agent, owner phase6security.Principal
	for _, principal := range profile.Principals {
		switch principal.Name {
		case "guest-agent":
			agent = principal
		case "guest-runtime":
			owner = principal
		}
	}
	if agent.Name != "guest-agent" || agent.Kind != "material_agent" || owner.Name != "guest-runtime" ||
		agent.ImageLocation != "local" || agent.ImageReference != agent.ImageDigest ||
		agent.UID == 0 || agent.GID == 0 || !agent.ReadOnlyRootFilesystem || !agent.NoNewPrivileges ||
		!slices.Equal(agent.DroppedCapabilities, []string{"ALL"}) ||
		!slices.Equal(agent.Networks, []string{"network-guest-agent", "service-guest-agent-vault"}) {
		t.Fatal("Guest material-agent immutable identity or network drift")
	}
	material, err := profile.Slice6MaterialSocketForOwner(owner.Name)
	issuer, _, _, issuerErr := profile.CredentialIssuerSocketForClient(agent.Name)
	tls, _, _, tlsErr := profile.TLSAgentForSubject(agent.Name)
	var delivery, consume phase6security.Slice6BreakGlassSocketBinding
	for _, binding := range profile.BreakGlassSockets {
		if binding.TargetAgent == agent.Name {
			if binding.Kind == "delivery" {
				delivery = binding
			} else if binding.Kind == "consume" {
				consume = binding
			}
		}
	}
	allowedSockets := map[string]bool{
		material.SocketStorageID: false, issuer.SocketStorageID: true, tls.SocketStorageID: true,
		delivery.SocketStorageID: false, consume.SocketStorageID: true,
	}
	if err != nil || issuerErr != nil || tlsErr != nil || len(allowedSockets) != 5 ||
		delivery.ID == "" || consume.ID == "" {
		t.Fatal("Guest material-agent socket authority drift")
	}
	var dedicated, service phase6security.Network
	for _, network := range profile.Networks {
		switch network.Name {
		case "network-guest-agent":
			dedicated = network
		case "service-guest-agent-vault":
			service = network
		}
	}
	if dedicated.Name == "" || service.Name == "" || !dedicated.Internal || !service.Internal ||
		!slices.Equal(dedicated.Principals, []string{agent.Name}) ||
		!slices.Equal(service.Principals, []string{agent.Name}) ||
		!slices.Equal(service.ExternalServices, []string{"vault"}) {
		t.Fatal("Guest material-agent isolated topology drift")
	}
	createdDedicated, err := createSlice6ProfileNetwork(ctx, run, dedicated)
	if err != nil {
		t.Fatal("create Guest material-agent dedicated network")
	}
	createdService, err := createSlice6ProfileNetwork(ctx, run, service)
	if err != nil {
		t.Fatal("create Guest material-agent Vault service bridge")
	}
	vaultIP, err := phase6security.Slice6DesiredServiceEndpointAddress(service.Name, "vault")
	agentIP, agentIPErr := phase6security.Slice6DesiredServiceEndpointAddress(service.Name, agent.Name)
	if err != nil || agentIPErr != nil {
		t.Fatal("Guest material-agent fixed service addresses unavailable")
	}
	if _, err := run.docker(ctx, "network", "connect", "--ip", vaultIP,
		"--alias", "vault.sandbox-runtime.test", createdService.NetworkID, serverID); err != nil {
		t.Fatal("connect real Vault to exact Guest material bridge")
	}
	serviceWithVault := service
	serviceWithVault.Principals = nil
	if observed, err := observeSlice6ProfileNetworkWithExternal(ctx, run, createdService.NetworkID,
		serviceWithVault, serverID); err != nil || len(observed.Endpoints) != 1 ||
		observed.Endpoints[0].IPv4Address != vaultIP {
		t.Fatal("Guest material bridge initial Vault membership drift")
	}
	config, err := slice6BuildGuestMaterialAgentConfig(composed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	key, err := slice6ReadPrivateSigningKey(composed.CredentialKeys["credential-guest-agent"])
	if err != nil {
		t.Fatal("Guest material-agent source-bound credential key unavailable")
	}
	defer clear(key)
	privateMount, needed := phase6security.Slice6PrivateConfigMount(agent.Name)
	if !needed || privateMount.Target != "/run/phase6/config" {
		t.Fatal("Guest material-agent private Profile mount unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	seccompBytes, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompBytes)
	if err != nil || agent.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		t.Fatal("Guest material-agent seccomp source drift")
	}
	nonce, err := phase6security.NewSlice6RunID()
	if err != nil {
		t.Fatal(err)
	}
	name := "sr-p6-guest-material-live-" + run.id
	arguments := []string{"create", "-i", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network", createdService.NetworkID, "--ip", agentIP,
		"--restart=no", "--user", fmt.Sprintf("%d:%d", agent.UID, agent.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(agent.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(agent.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(agent.Resources.PIDs, 10),
		"--mount", "type=volume,src=sr-p6-config-" + agent.Name + "-" + run.id + ",dst=" + privateMount.Target + ",readonly"}
	anchors, err := slice6AnchorMountArguments(profile, agent.Name, anchorFiles)
	if err != nil {
		t.Fatal("Guest material-agent trust-anchor mounts unavailable")
	}
	arguments = append(arguments, anchors...)
	socketCount := 0
	for _, mount := range agent.Mounts {
		if mount.Kind != "private_socket" {
			continue
		}
		readonly, known := allowedSockets[mount.StorageID]
		volume := socketVolumes[mount.StorageID]
		if !known || volume == "" || mount.ReadOnly != readonly {
			t.Fatal("Guest material-agent private socket mount drift")
		}
		value := "type=volume,src=" + volume + ",dst=" + mount.Target
		if readonly {
			value += ",readonly"
		}
		arguments = append(arguments, "--mount", value)
		socketCount++
	}
	if socketCount != len(allowedSockets) {
		t.Fatal("Guest material-agent socket mount count drift")
	}
	const imageTarget = "workload-material-agent"
	arguments = append(arguments, "-e", "SR_PHASE6_FD_RUN_ID="+run.id,
		"-e", "SR_PHASE6_FD_TARGET="+imageTarget, "-e", "SR_PHASE6_FD_NONCE="+nonce,
		agent.ImageReference)
	created, err := run.docker(ctx, arguments...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create real Guest material-agent process")
	}
	inspectDocument, err := run.docker(ctx, "inspect", id)
	var containers []struct {
		Image  string `json:"Image"`
		Config struct {
			Image, User string
			Entrypoint  []string
		} `json:"Config"`
		HostConfig struct {
			ReadonlyRootfs, Privileged  bool
			NetworkMode                 string
			NanoCpus, Memory, PidsLimit int64
		} `json:"HostConfig"`
	}
	if err != nil || json.Unmarshal(inspectDocument, &containers) != nil || len(containers) != 1 ||
		containers[0].Image != agent.ImageDigest || containers[0].Config.Image != agent.ImageReference ||
		containers[0].Config.User != fmt.Sprintf("%d:%d", agent.UID, agent.GID) ||
		!slices.Equal(containers[0].Config.Entrypoint, []string{"/bin/sh", "-ec", phase6fdloader.FixedEntrypointCommand}) ||
		!containers[0].HostConfig.ReadonlyRootfs || containers[0].HostConfig.Privileged ||
		containers[0].HostConfig.NetworkMode != createdService.NetworkID ||
		containers[0].HostConfig.NanoCpus != agent.Resources.CPUMillis*1_000_000 ||
		containers[0].HostConfig.Memory != agent.Resources.MemoryBytes ||
		containers[0].HostConfig.PidsLimit != agent.Resources.PIDs {
		t.Fatal("Guest material-agent created-container authority or isolation drift")
	}
	envelope := phase6fdloader.Envelope{Protocol: phase6fdloader.ProtocolID, RunID: run.id,
		Target: imageTarget, ContainerID: id, Nonce: nonce, Config: bytes.Clone(config),
		Files: []phase6fdloader.PrivateFile{{FD: 3, Data: bytes.Clone(key)}}}
	defer envelope.Destroy()
	input, err := json.Marshal(envelope)
	if err != nil || envelope.Validate(phase6fdloader.Expected{RunID: run.id, Target: imageTarget,
		Nonce: nonce, ContainerHostname: id[:12]}) != nil {
		t.Fatal("Guest material-agent FD envelope invalid")
	}
	defer clear(input)
	type result struct {
		output []byte
		err    error
	}
	completed := make(chan result, 1)
	startup := bytes.Clone(input)
	go func() {
		command := exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
		command.Stdin = bytes.NewReader(startup)
		output, startErr := command.CombinedOutput()
		clear(startup)
		completed <- result{output, startErr}
	}()
	deadline := time.Now().Add(90 * time.Second)
	running := false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		state, _ := run.docker(ctx, "inspect", "--format", "{{.State.Running}}", id)
		if strings.TrimSpace(string(state)) == "true" {
			running = true
			break
		}
		select {
		case done := <-completed:
			stage := slice6ControllerFailureStage(done.output)
			category := slice6MaterialFailureCategory(done.output)
			clear(done.output)
			t.Fatalf("Guest material-agent exited before network join: stage=%s category=%s exit=%v", stage, category, done.err)
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !running {
		t.Fatal("Guest material-agent did not enter running state")
	}
	prefix, err := netip.ParsePrefix(dedicated.IPv4Subnet)
	if err != nil || prefix.Bits() != 24 || !prefix.Addr().Is4() {
		t.Fatal("Guest material-agent dedicated subnet drift")
	}
	address := prefix.Addr().As4()
	address[3] = 2
	if _, err := run.docker(ctx, "network", "connect", "--ip", netip.AddrFrom4(address).String(),
		createdDedicated.NetworkID, id); err != nil {
		t.Fatal("connect Guest material-agent to exact dedicated network")
	}
	if _, err := observeSlice6ProfileNetwork(ctx, run, createdDedicated.NetworkID, dedicated,
		map[string]string{agent.Name: id}); err != nil {
		t.Fatal("Guest material-agent dedicated network membership drift")
	}
	serviceInspect, inspectErr := run.docker(ctx, "network", "inspect", createdService.NetworkID)
	if inspectErr != nil {
		t.Fatal("Guest material-agent/Vault bridge inspect unavailable")
	}
	if _, err := phase6security.ObserveDockerNetworkWithExternal(serviceInspect, service,
		map[string]string{agent.Name: id}, map[string]string{"vault": serverID}); err != nil {
		t.Fatal("Guest material-agent/Vault bridge membership drift")
	}
	ready := false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if _, probeErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", agent.UID, agent.GID),
			id, "/bin/sh", "-ec", "test -S "+material.SocketPath+" && test -S "+delivery.SocketPath); probeErr == nil {
			ready = true
			break
		}
		select {
		case done := <-completed:
			stage := slice6ControllerFailureStage(done.output)
			category := slice6MaterialFailureCategory(done.output)
			clear(done.output)
			t.Fatalf("Guest material-agent exited before listeners: stage=%s category=%s exit=%v", stage, category, done.err)
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !ready {
		state, _ := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", id)
		select {
		case done := <-completed:
			stage := slice6ControllerFailureStage(done.output)
			category := slice6MaterialFailureCategory(done.output)
			clear(done.output)
			t.Fatalf("Guest material-agent listener timeout: state=%q stage=%s category=%s exit=%v", strings.TrimSpace(string(state)), stage, category, done.err)
		default:
			t.Fatalf("Guest material-agent listener timeout: state=%q attached start still pending", strings.TrimSpace(string(state)))
		}
	}
	observerDir, err := os.MkdirTemp(".", ".sr-guest-material-observer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(observerDir); err != nil {
			t.Errorf("remove exact Guest material observer build: %v", err)
		}
	})
	observer, err := filepath.Abs(filepath.Join(observerDir, "observer"))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", observer, "./productphase6gate/testdata/guestmaterialobserver")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixed owner-side Guest material observer: %v: %.256s", err, output)
	}
	access, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		t.Fatal(err)
	}
	var binding secretref.Binding
	for _, item := range access {
		if item.Agent == agent.Name && len(item.Bindings) == 1 {
			binding = item.Bindings[0]
		}
	}
	if binding.Validate() != nil || binding.Purpose != secretref.PurposeGuestSigningKey {
		t.Fatal("Guest owner-side exact material binding unavailable")
	}
	request, err := json.Marshal(struct {
		SocketPath              string            `json:"socket_path"`
		AgentUID                uint32            `json:"agent_uid"`
		AgentGID                uint32            `json:"agent_gid"`
		OwnerUID                uint32            `json:"owner_uid"`
		OwnerGID                uint32            `json:"owner_gid"`
		Binding                 secretref.Binding `json:"binding"`
		ExpectedPublicKeyDigest string            `json:"expected_public_key_digest"`
	}{SocketPath: material.SocketPath, ExpectedPublicKeyDigest: publicKeyDigest,
		AgentUID: agent.UID, AgentGID: agent.GID, OwnerUID: owner.UID, OwnerGID: owner.GID, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(request)
	observerArgs := []string{"run", "--rm", "-i", "--pull=never", "--name", "sr-p6-guest-material-observe-" + run.id,
		"--label", run.label(), "--network=none", "--user", fmt.Sprintf("%d:%d", owner.UID, owner.GID),
		"--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--memory=64m", "--cpus=0.2", "--pids-limit=16",
		"--mount", "type=volume,src=" + socketVolumes[material.SocketStorageID] + ",dst=" + material.SocketDirectory + ",readonly",
		"--mount", "type=bind,src=" + observer + ",dst=/observer,readonly",
		"--entrypoint=/observer", agent.ImageReference}
	command := exec.CommandContext(ctx, "docker", observerArgs...)
	command.Stdin = bytes.NewReader(request)
	output, observeErr := command.CombinedOutput()
	if observeErr != nil || string(output) != "guest-material-resolved=exact-vault-key\n" {
		t.Fatalf("Guest owner-side Vault-backed material resolve failed: %v: %.256s", observeErr, output)
	}
	t.Log("real Guest material-agent PID1 obtained a scoped credential, used the distinct signer for Vault mTLS, and served the exact KVv2 Guest key to a cross-UID/GID owner-only observer")
	if _, err := run.docker(ctx, "stop", "--time", "10", id); err != nil {
		t.Fatal("stop Guest material-agent")
	}
	select {
	case done := <-completed:
		stage := slice6ControllerFailureStage(done.output)
		clear(done.output)
		if done.err != nil {
			t.Fatalf("Guest material-agent did not drain cleanly: stage=%s exit=%v", stage, done.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Guest material-agent did not drain")
	}
	if _, err := run.docker(ctx, "rm", id); err != nil {
		t.Fatal("remove stopped Guest material-agent")
	}
	if _, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-guest-material-clean-"+run.id,
		"--label", run.label(), "--network=none", "--user", fmt.Sprintf("%d:%d", agent.UID, agent.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--mount", "type=volume,src="+socketVolumes[material.SocketStorageID]+",dst="+material.SocketDirectory+",readonly",
		"--mount", "type=volume,src="+socketVolumes[delivery.SocketStorageID]+",dst="+delivery.SocketDirectory+",readonly",
		"--entrypoint=/bin/sh", agent.ImageReference, "-ec",
		"test ! -e "+material.SocketPath+" && test ! -e "+delivery.SocketPath); err != nil {
		t.Fatal("Guest material and break-glass listener exact socket cleanup unproved")
	}
	t.Log("real Guest material-agent clean drain removed both exact listeners; online break-glass delivery/consume remains unproved")
}

// The only surfaced error detail is a fixed, reviewed category. Captured
// process output may contain sensitive arguments and is never logged raw.
func slice6MaterialFailureCategory(output []byte) string {
	for _, category := range []string{"profile", "identity", "dependency", "endpoint", "bridge", "edge",
		"signer-binding", "server-anchor", "client-anchor", "server-anchor-bytes",
		"client-anchor-bytes", "anchor-roots", "signer-socket", "signer-bootstrap"} {
		if bytes.Contains(output, []byte("vault-mtls-"+category+":")) {
			return category
		}
	}
	return "unclassified"
}
