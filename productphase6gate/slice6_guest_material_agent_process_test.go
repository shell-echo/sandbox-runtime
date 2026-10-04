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
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type slice6MaterialRunResult struct {
	output []byte
	err    error
}

// E-only convergence is emitted after the existing stop/drain/remove/socket
// guard has completed; a deferred failure cleanup never marks this success.
type slice6EMaterialOutcome struct {
	RunID, ProfileDigest, AgentDeployment, ContainerID, ExitClass string
	PhysicalConverged                                             bool
}

func (outcome slice6EMaterialOutcome) validForRun(runID, profileDigest, agent string) bool {
	wantExit := "stopped"
	if agent == "product-migration-agent" {
		wantExit = "natural_exit"
	}
	return outcome.RunID == runID && outcome.ProfileDigest == profileDigest &&
		outcome.AgentDeployment == agent && len(outcome.ContainerID) == 64 &&
		lowerHexSlice6(outcome.ContainerID) && outcome.ExitClass == wantExit && outcome.PhysicalConverged
}

// Component evidence only. A distinct material-agent PID1 obtains its own
// credential, reads Vault KVv2 through the live Guest TLS signer and serves
// one exact owner-side resolve before draining and removing both sockets.
func slice6RunGuestMaterialAgentStartup(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, serverID, publicKeyDigest string,
	socketVolumes, anchorFiles map[string]string,
	onReady func(phase6security.Slice6BreakGlassSocketBinding), outcome ...*slice6EMaterialOutcome) error {
	return slice6RunRuntimeMaterialAgentStartup(t, ctx, run, composed, serverID, publicKeyDigest,
		"", "guest-agent", "guest-runtime", "guest", 67, socketVolumes, anchorFiles,
		func(binding phase6security.Slice6BreakGlassSocketBinding) error {
			if onReady != nil {
				onReady(binding)
			}
			return nil
		}, outcome...)
}

func slice6RunRuntimeMaterialAgentStartup(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, serverID, expectedDigest, expectedDSNDigest,
	agentDeployment, ownerDeployment, label string, expectedSockets int,
	socketVolumes, anchorFiles map[string]string,
	onReady func(phase6security.Slice6BreakGlassSocketBinding) error,
	outcome ...*slice6EMaterialOutcome) (resultErr error) {
	t.Helper()
	if len(outcome) > 1 {
		return errors.New("ambiguous E material outcome")
	}
	profile := composed.Profile
	migration := agentDeployment == "product-migration-agent"
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil ||
		len(socketVolumes) != expectedSockets ||
		(agentDeployment != "guest-agent" && agentDeployment != "product-runtime-agent" && !migration) ||
		(agentDeployment == "guest-agent" && (len(expectedDigest) != len("sha256:")+64 ||
			ownerDeployment != "guest-runtime" || label != "guest" || expectedSockets != 67)) ||
		(agentDeployment == "product-runtime-agent" && (len(expectedDigest) != len("sha256:")+64 ||
			ownerDeployment != "product-runtime" || label != "product-material" || expectedSockets != 70)) ||
		(migration && (expectedDigest != "" || expectedDSNDigest != "" ||
			ownerDeployment != "product-migration-job" || label != "product-migration-material" || expectedSockets != 73)) {
		t.Fatal("runtime material-agent final source authority unavailable")
	}
	var agent, owner phase6security.Principal
	for _, principal := range profile.Principals {
		switch principal.Name {
		case agentDeployment:
			agent = principal
		case ownerDeployment:
			owner = principal
		}
	}
	if agent.Name != agentDeployment || agent.Kind != "material_agent" || owner.Name != ownerDeployment ||
		agent.ImageLocation != "local" || agent.ImageReference != agent.ImageDigest ||
		agent.UID == 0 || agent.GID == 0 || !agent.ReadOnlyRootFilesystem || !agent.NoNewPrivileges ||
		!slices.Equal(agent.DroppedCapabilities, []string{"ALL"}) ||
		!slices.Equal(agent.Networks, []string{"network-" + agentDeployment, "service-" + agentDeployment + "-vault"}) {
		t.Fatal("runtime material-agent immutable identity or network drift")
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
	}
	if !migration {
		allowedSockets[delivery.SocketStorageID] = false
		allowedSockets[consume.SocketStorageID] = true
	}
	if err != nil || issuerErr != nil || tlsErr != nil || len(allowedSockets) != map[bool]int{true: 3, false: 5}[migration] ||
		(migration && (delivery.ID != "" || consume.ID != "")) ||
		(!migration && (delivery.ID == "" || consume.ID == "")) {
		t.Fatal("Guest material-agent socket authority drift")
	}
	var dedicated, service phase6security.Network
	for _, network := range profile.Networks {
		switch network.Name {
		case "network-" + agentDeployment:
			dedicated = network
		case "service-" + agentDeployment + "-vault":
			service = network
		}
	}
	if dedicated.Name == "" || service.Name == "" || !dedicated.Internal || !service.Internal ||
		!slices.Equal(dedicated.Principals, []string{agent.Name}) ||
		!slices.Equal(service.Principals, []string{agent.Name}) ||
		!slices.Equal(service.ExternalServices, []string{"vault"}) {
		t.Fatal("Guest material-agent isolated topology drift")
	}
	createdDedicated, err := run.resolveProfileNetwork(ctx, dedicated)
	if err != nil {
		t.Fatal("create Guest material-agent dedicated network")
	}
	createdService, err := run.resolveProfileNetwork(ctx, service)
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
	var role secretref.Role
	var purposes []secretref.Purpose
	if agentDeployment == "guest-agent" {
		role = secretref.RoleGuest
		purposes = []secretref.Purpose{secretref.PurposeGuestSigningKey}
	} else if migration {
		role = secretref.RoleProduct
		purposes = []secretref.Purpose{secretref.PurposePostgresMigrationDSN}
	} else {
		role = secretref.RoleProduct
		purposes = []secretref.Purpose{secretref.PurposeIdentityKeyRing, secretref.PurposePostgresRuntimeDSN}
	}
	config, err := slice6BuildRuntimeMaterialAgentConfig(composed, agentDeployment, ownerDeployment, role, purposes)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	key, err := slice6ReadPrivateSigningKey(composed.CredentialKeys["credential-"+agentDeployment])
	if err != nil {
		t.Fatal("Guest material-agent source-bound credential key unavailable")
	}
	defer clear(key)
	if agentDeployment == "guest-agent" {
		slice6ProbeGuestSignerAsMaterialAgent(t, ctx, run, agent, tls, socketVolumes[tls.SocketStorageID], rootForSlice6GuestProbe(t))
	}
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
	name := "sr-p6-" + label + "-live-" + run.id
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
	completed := make(chan slice6MaterialRunResult, 1)
	startup := bytes.Clone(input)
	go func() {
		command := exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
		command.Stdin = bytes.NewReader(startup)
		output, startErr := command.CombinedOutput()
		clear(startup)
		completed <- slice6MaterialRunResult{output, startErr}
	}()
	completionConsumed := false
	stopRequired := true
	runtimeCleanup := slice6RuntimeMaterialCleanupSequence(
		func(cleanup context.Context, arguments ...string) error {
			_, err := run.docker(cleanup, arguments...)
			return err
		}, run.id, id, label, agent.ImageReference, agent.UID, agent.GID,
		material.SocketPath, material.SocketDirectory, socketVolumes[material.SocketStorageID],
		delivery.SocketPath, delivery.SocketDirectory, socketVolumes[delivery.SocketStorageID],
		completed, &completionConsumed, &stopRequired)
	// Arm before readiness checks: testing.T.Fatal/Goexit must not strand an
	// already-created agent or leave active nonterminal ledger records.
	guard := slice6MaterialCleanupGuard{sequence: runtimeCleanup}
	defer guard.Finish(&resultErr, func(err error) {
		t.Errorf("failure-path runtime material-agent cleanup: %v", err)
	})
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
			completionConsumed = true
			stage := slice6ControllerFailureStage(done.output)
			category := slice6MaterialFailureCategory(done.output)
			bootstrapMS := slice6MaterialBootstrapMillis(done.output)
			clear(done.output)
			t.Fatalf("Guest material-agent exited before network join: stage=%s category=%s bootstrap_ms=%d exit=%v", stage, category, bootstrapMS, done.err)
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
		probe := "test -S " + material.SocketPath
		if !migration {
			probe += " && test -S " + delivery.SocketPath
		}
		if _, probeErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", agent.UID, agent.GID),
			id, "/bin/sh", "-ec", probe); probeErr == nil {
			ready = true
			break
		}
		select {
		case done := <-completed:
			completionConsumed = true
			stage := slice6ControllerFailureStage(done.output)
			category := slice6MaterialFailureCategory(done.output)
			bootstrapMS := slice6MaterialBootstrapMillis(done.output)
			clear(done.output)
			t.Fatalf("Guest material-agent exited before listeners: stage=%s category=%s bootstrap_ms=%d exit=%v", stage, category, bootstrapMS, done.err)
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !ready {
		state, _ := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", id)
		select {
		case done := <-completed:
			completionConsumed = true
			stage := slice6ControllerFailureStage(done.output)
			category := slice6MaterialFailureCategory(done.output)
			bootstrapMS := slice6MaterialBootstrapMillis(done.output)
			clear(done.output)
			t.Fatalf("Guest material-agent listener timeout: state=%q stage=%s category=%s bootstrap_ms=%d exit=%v", strings.TrimSpace(string(state)), stage, category, bootstrapMS, done.err)
		default:
			t.Fatalf("Guest material-agent listener timeout: state=%q attached start still pending", strings.TrimSpace(string(state)))
		}
	}
	if onReady != nil {
		if callbackErr := onReady(delivery); callbackErr != nil {
			return callbackErr
		}
	}
	if agentDeployment == "guest-agent" {
		observerDir := run.privateSibling(t, rootForSlice6GuestProbe(t), ".sr-guest-material-observer-")
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
		var activeConfig slice6MaterialAgentConfig
		if json.Unmarshal(config, &activeConfig) != nil ||
			activeConfig.Role != secretref.RoleGuest || activeConfig.MaxResolutions != 0 ||
			len(activeConfig.Bindings) != 1 || activeConfig.Bindings[0] != binding ||
			activeConfig.ExpectedClientUID != owner.UID || activeConfig.ExpectedClientGID != owner.GID {
			t.Fatal("Guest observer and live material-agent authorization inputs disagree")
		}
		request, err := json.Marshal(struct {
			SocketPath              string            `json:"socket_path"`
			AgentUID                uint32            `json:"agent_uid"`
			AgentGID                uint32            `json:"agent_gid"`
			OwnerUID                uint32            `json:"owner_uid"`
			OwnerGID                uint32            `json:"owner_gid"`
			Binding                 secretref.Binding `json:"binding"`
			ExpectedPublicKeyDigest string            `json:"expected_public_key_digest"`
		}{SocketPath: material.SocketPath, ExpectedPublicKeyDigest: expectedDigest,
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
			stage, resolveMS := slice6GuestMaterialObservationFailure(output)
			clear(output)
			t.Fatalf("Guest owner-side Vault-backed material resolve failed: stage=%s resolve_ms=%d exit=%v", stage, resolveMS, observeErr)
		}
		t.Log("real Guest material-agent PID1 obtained a scoped credential, used the distinct signer for Vault mTLS, and served the exact KVv2 Guest key to a cross-UID/GID owner-only observer")
	} else if !migration {
		slice6ObserveProductIdentityMaterial(t, ctx, run, profile, agent, owner, material,
			config, expectedDigest, expectedDSNDigest, socketVolumes[material.SocketStorageID], root)
	}
	if migration {
		// A one-shot migration agent exits after its sole resolution. If the
		// dependent callback failed, the deferred path still stops it first.
		stopRequired = false
	}
	resultErr = guard.Complete()
	if resultErr != nil {
		return resultErr
	}
	if len(outcome) == 1 && outcome[0] != nil {
		exitClass := "stopped"
		if migration {
			exitClass = "natural_exit"
		}
		*outcome[0] = slice6EMaterialOutcome{RunID: run.id,
			ProfileDigest: profile.ProfileDigest, AgentDeployment: agent.Name,
			ContainerID: id, ExitClass: exitClass, PhysicalConverged: true}
	}
	t.Logf("real %s material-agent clean drain removed its exact listeners", label)
	return nil
}

// The runtime agent must be gone before its signer and the controllers begin
// terminal cleanup, including when a dependent callback fails or calls Goexit.
// Only fixed failure categories leave this helper; Docker output is discarded.
type slice6MaterialCleanupGuard struct {
	sequence *slice6CleanupSequence
	complete bool
}

func (guard *slice6MaterialCleanupGuard) Complete() error {
	guard.complete = true
	return guard.sequence.Run()
}

func (guard *slice6MaterialCleanupGuard) Finish(resultErr *error, report func(error)) {
	if guard.complete {
		return
	}
	if cleanupErr := guard.sequence.Run(); cleanupErr != nil {
		if *resultErr != nil {
			*resultErr = errors.Join(*resultErr, cleanupErr)
		} else {
			report(cleanupErr)
		}
	}
}

func slice6RuntimeMaterialCleanupSequence(docker func(context.Context, ...string) error,
	runID, id, label, image string, uid, gid uint32,
	materialPath, materialDirectory, materialVolume,
	deliveryPath, deliveryDirectory, deliveryVolume string,
	completed <-chan slice6MaterialRunResult, completionConsumed, stopRequired *bool) *slice6CleanupSequence {
	drainBudget := 30 * time.Second
	if label == "product-migration-material" {
		// Preserve the prior bounded abort budget for the one-shot listener.
		drainBudget = 20 * time.Second
	}
	return &slice6CleanupSequence{stages: []slice6CleanupStage{
		{"stop-material-agent", func(ctx context.Context) error {
			if !*stopRequired {
				return nil
			}
			if err := docker(ctx, "stop", "--timeout", "10", id); err != nil {
				return errors.New("runtime material-agent stop unconfirmed")
			}
			return nil
		}},
		{"drain-material-agent", func(ctx context.Context) error {
			if *completionConsumed {
				return nil
			}
			select {
			case done := <-completed:
				*completionConsumed = true
				clear(done.output)
				if done.err != nil {
					return errors.New("runtime material-agent drain unconfirmed")
				}
				return nil
			case <-time.After(drainBudget):
				return errors.New("runtime material-agent drain timed out")
			case <-ctx.Done():
				return errors.New("runtime material-agent cleanup deadline ended")
			}
		}},
		{"remove-material-agent", func(ctx context.Context) error {
			if err := docker(ctx, "rm", "-f", id); err != nil {
				return errors.New("runtime material-agent removal unconfirmed")
			}
			return nil
		}},
		{"verify-material-sockets", func(ctx context.Context) error {
			arguments := []string{"run", "--rm", "--pull=never", "--name", "sr-p6-" + label + "-clean-" + runID,
				"--label", slice6RunLabel + "=" + runID, "--network=none", "--user", fmt.Sprintf("%d:%d", uid, gid),
				"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
				"--mount", "type=volume,src=" + materialVolume + ",dst=" + materialDirectory + ",readonly"}
			probe := "test ! -e " + materialPath
			if deliveryPath != "" {
				arguments = append(arguments, "--mount", "type=volume,src="+deliveryVolume+",dst="+deliveryDirectory+",readonly")
				probe += " && test ! -e " + deliveryPath
			}
			arguments = append(arguments, "--entrypoint=/bin/sh", image, "-ec", probe)
			if err := docker(ctx, arguments...); err != nil {
				return errors.New("runtime material-agent exact socket cleanup unconfirmed")
			}
			return nil
		}},
	}}
}

func TestSlice6RuntimeMaterialFailureCleanupIsSingleShot(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	cancel()
	var commands []string
	completed := make(chan slice6MaterialRunResult, 1)
	completed <- slice6MaterialRunResult{output: []byte("private process output")}
	consumed, stopRequired := false, true
	sequence := slice6RuntimeMaterialCleanupSequence(func(ctx context.Context, args ...string) error {
		if parent.Err() == nil || ctx.Err() != nil {
			t.Error("material cleanup inherited the canceled business context")
		}
		commands = append(commands, args[0])
		if args[0] == "stop" {
			return errors.New("private Docker diagnostic")
		}
		return nil
	}, strings.Repeat("a", 32), strings.Repeat("b", 64), "product-material", "image", 20041, 30041,
		"/material.sock", "/material", "material-volume", "/delivery.sock", "/delivery", "delivery-volume", completed,
		&consumed, &stopRequired)
	callback := errors.New("original callback failure")
	guard := &slice6MaterialCleanupGuard{sequence: sequence}
	var reported error
	got := func() (resultErr error) {
		defer guard.Finish(&resultErr, func(err error) { reported = err })
		return callback
	}()
	if !errors.Is(got, callback) || strings.Contains(got.Error(), "private Docker diagnostic") ||
		!slices.Equal(commands, []string{"stop", "rm", "run"}) || reported != nil {
		t.Fatal("material failure lost its first error, leaked a diagnostic or skipped cleanup")
	}
	if sequence.Run() == nil || len(commands) != 3 {
		t.Fatal("material cleanup retried after its first execution")
	}
}

func TestSlice6RuntimeMaterialCleanupSurvivesGoexit(t *testing.T) {
	var commands []string
	completed := make(chan slice6MaterialRunResult, 1)
	completed <- slice6MaterialRunResult{}
	consumed, stopRequired := false, true
	sequence := slice6RuntimeMaterialCleanupSequence(func(ctx context.Context, args ...string) error {
		commands = append(commands, args[0])
		return nil
	}, strings.Repeat("a", 32), strings.Repeat("b", 64), "product-material", "image", 20041, 30041,
		"/material.sock", "/material", "material-volume", "/delivery.sock", "/delivery", "delivery-volume", completed,
		&consumed, &stopRequired)
	guard := &slice6MaterialCleanupGuard{sequence: sequence}
	finished := make(chan error, 1)
	go func() {
		var resultErr error
		defer func() { finished <- resultErr }()
		defer guard.Finish(&resultErr, func(err error) { resultErr = err })
		runtime.Goexit()
	}()
	select {
	case err := <-finished:
		if err != nil || !slices.Equal(commands, []string{"stop", "rm", "run"}) {
			t.Fatal("Goexit skipped the runtime material cleanup order")
		}
	case <-time.After(time.Second):
		t.Fatal("Goexit did not reach runtime material cleanup")
	}
}

func TestSlice6RuntimeMaterialPreReadyCompletionDoesNotDrainTwice(t *testing.T) {
	completed := make(chan slice6MaterialRunResult, 1)
	// The readiness loop consumed and classified the first exit already.
	consumed, stopRequired := true, true
	var commands []string
	sequence := slice6RuntimeMaterialCleanupSequence(func(ctx context.Context, args ...string) error {
		commands = append(commands, args[0])
		return nil
	}, strings.Repeat("a", 32), strings.Repeat("b", 64), "product-material", "image", 20041, 30041,
		"/material.sock", "/material", "material-volume", "/delivery.sock", "/delivery", "delivery-volume", completed,
		&consumed, &stopRequired)
	guard := &slice6MaterialCleanupGuard{sequence: sequence}
	started := time.Now()
	var resultErr error
	guard.Finish(&resultErr, func(err error) { resultErr = err })
	if resultErr != nil || time.Since(started) > time.Second ||
		!slices.Equal(commands, []string{"stop", "rm", "run"}) {
		t.Fatal("pre-ready process exit waited for an already-consumed completion or skipped cleanup")
	}
}

func TestSlice6GuestCleanupOnlyFailureRemainsObservable(t *testing.T) {
	completed := make(chan slice6MaterialRunResult, 1)
	completed <- slice6MaterialRunResult{}
	consumed, stopRequired := false, true
	sequence := slice6RuntimeMaterialCleanupSequence(func(ctx context.Context, args ...string) error {
		if args[0] == "stop" {
			return errors.New("private Docker diagnostic")
		}
		return nil
	}, strings.Repeat("a", 32), strings.Repeat("b", 64), "guest", "image", 20035, 30035,
		"/material.sock", "/material", "material-volume", "/delivery.sock", "/delivery", "delivery-volume", completed,
		&consumed, &stopRequired)
	guard := &slice6MaterialCleanupGuard{sequence: sequence}
	guestFailure := slice6PreserveFirstFailure(nil, guard.Complete())
	if guestFailure == nil || strings.Contains(guestFailure.Error(), "private Docker diagnostic") {
		t.Fatal("Guest cleanup-only error was lost or disclosed a raw diagnostic")
	}
}

// The observer has a finite, reviewed diagnostic vocabulary. Never include
// Docker output or provider errors in gate logs: they can contain private paths.
func slice6GuestMaterialObservationFailure(output []byte) (string, int64) {
	pattern := regexp.MustCompile(`^guest-material-observation stage=(input|identity-or-binding|parent-layout|socket-layout|client-init|resolve-canceled|resolve-deadline|resolve-revoked|resolve-expired|resolve-unavailable|material-binding|material-window|material-size|public-digest) resolve_ms=(-1|[0-9]{1,6})\n$`)
	match := pattern.FindSubmatch(output)
	if match == nil {
		return "unclassified", -1
	}
	millis, err := strconv.ParseInt(string(match[2]), 10, 64)
	if err != nil || millis > 30000 {
		return "unclassified", -1
	}
	return string(match[1]), millis
}

func TestSlice6GuestMaterialObservationFailure(t *testing.T) {
	for _, tc := range []struct {
		output, stage string
		millis        int64
	}{
		{"guest-material-observation stage=parent-layout resolve_ms=-1\n", "parent-layout", -1},
		{"guest-material-observation stage=resolve-unavailable resolve_ms=15001\n", "resolve-unavailable", 15001},
		{"guest-material-observation stage=resolve-unavailable-unavailable resolve_ms=6\n", "unclassified", -1},
		{"guest-material-observation stage=resolve-deadline resolve_ms=30001\n", "unclassified", -1},
		{"guest-material-observation stage=other resolve_ms=1\n", "unclassified", -1},
		{"secret\nguest-material-observation stage=socket-layout resolve_ms=-1\n", "unclassified", -1},
	} {
		stage, millis := slice6GuestMaterialObservationFailure([]byte(tc.output))
		if stage != tc.stage || millis != tc.millis {
			t.Fatalf("observer diagnostic classified as %s/%d; want %s/%d", stage, millis, tc.stage, tc.millis)
		}
	}
}

// The only surfaced error detail is a fixed, reviewed category. Captured
// process output may contain sensitive arguments and is never logged raw.
func slice6MaterialFailureCategory(output []byte) string {
	for _, category := range []string{"authority", "signer-unavailable", "context-ended", "chain", "leaf",
		"signer-identity", "signer-challenge", "issuer", "deadline", "other"} {
		if bytes.Contains(output, []byte("vault-mtls-signer-bootstrap-"+category+":")) {
			return "signer-bootstrap/" + category
		}
	}
	for _, category := range []string{"profile", "identity", "dependency", "endpoint", "bridge", "edge",
		"signer-binding", "server-anchor", "client-anchor", "server-anchor-bytes",
		"client-anchor-bytes", "anchor-roots", "signer-socket", "signer-bootstrap"} {
		if bytes.Contains(output, []byte("vault-mtls-"+category+":")) {
			return category
		}
	}
	return "unclassified"
}

func slice6MaterialBootstrapMillis(output []byte) int64 {
	marker := []byte("bootstrap_ms=")
	index := bytes.Index(output, marker)
	if index < 0 {
		return -1
	}
	remaining := output[index+len(marker):]
	end := bytes.IndexByte(remaining, ':')
	if end < 1 || end > 6 {
		return -1
	}
	value, err := strconv.ParseInt(string(remaining[:end]), 10, 64)
	if err != nil || value < 0 || value > 120000 {
		return -1
	}
	return value
}

func TestSlice6MaterialFailureClassificationIsFinite(t *testing.T) {
	output := []byte("secret/private/path stage vault-mtls: vault-mtls-signer-bootstrap-leaf: bootstrap_ms=1234: unavailable")
	if category := slice6MaterialFailureCategory(output); category != "signer-bootstrap/leaf" ||
		slice6MaterialBootstrapMillis(output) != 1234 {
		t.Fatalf("fixed failure classification drift: %q", category)
	}
	if category := slice6MaterialFailureCategory([]byte("vault-mtls-secret/private/path: unavailable")); category != "unclassified" {
		t.Fatalf("unreviewed failure category leaked: %q", category)
	}
}

var slice6GuestSignerProbePattern = regexp.MustCompile(`^signer_probe=(ok|input|identity|socket|snapshot|certificate|key|sign) snapshot_ms=(-1|[0-9]{1,6}) certificate_ms=(-1|[0-9]{1,6}) sign_ms=(-1|[0-9]{1,6}) leaf_mask=[0-9a-f]{3} duration_ms=(-1|[0-9]{1,9}) max_ttl_ms=(-1|[0-9]{1,9})\n$`)

func rootForSlice6GuestProbe(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func slice6ProbeGuestSignerAsMaterialAgent(t *testing.T, ctx context.Context, run slice6DockerRun,
	agent phase6security.Principal, binding phase6security.TLSAgentBinding, volume, root string) {
	t.Helper()
	if volume == "" || agent.TLS == nil || binding.SubjectUID != agent.UID || binding.SubjectGID != agent.GID {
		t.Fatal("Guest signer diagnostic has no source-bound socket identity")
	}
	directory := run.privateSibling(t, root, ".sr-guest-signer-observer-")
	binary, err := filepath.Abs(filepath.Join(directory, "observer"))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", binary, "./productphase6gate/testdata/guestsignerobserver")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixed Guest signer observer: %v: %.256s", err, output)
	}
	request, err := json.Marshal(struct {
		SocketPath    string   `json:"socket_path"`
		SignerUID     uint32   `json:"signer_uid"`
		SignerGID     uint32   `json:"signer_gid"`
		SubjectUID    uint32   `json:"subject_uid"`
		SubjectGID    uint32   `json:"subject_gid"`
		ExpectedURI   string   `json:"expected_uri"`
		ExpectedDNS   []string `json:"expected_dns"`
		ExpectedUsage []string `json:"expected_usage"`
		MaxTTLSeconds int64    `json:"max_ttl_seconds"`
	}{binding.SocketPath, binding.AgentUID, binding.AgentGID, binding.SubjectUID, binding.SubjectGID,
		agent.TLS.URI, agent.TLS.DNSNames, agent.TLS.Usages, agent.TLS.TTLSeconds})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(request)
	command := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--pull=never",
		"--name", "sr-p6-guest-signer-observe-"+run.id, "--label", run.label(), "--network=none",
		"--user", fmt.Sprintf("%d:%d", agent.UID, agent.GID), "--read-only", "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--memory=64m", "--cpus=0.2", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst="+binding.SocketDirectory+",readonly",
		"--mount", "type=bind,src="+binary+",dst=/observer,readonly",
		"--entrypoint=/observer", agent.ImageReference)
	command.Stdin = bytes.NewReader(request)
	output, probeErr := command.CombinedOutput()
	if len(output) > 256 || !slice6GuestSignerProbePattern.Match(output) {
		t.Fatal("Guest signer diagnostic returned noncanonical or oversized output")
	}
	if probeErr != nil {
		t.Logf("NON-RELEASE Guest signer same-UID/GID diagnostic: %s", strings.TrimSpace(string(output)))
		return
	}
	if !bytes.HasPrefix(output, []byte("signer_probe=ok ")) {
		t.Fatal("Guest signer diagnostic exited successfully without a complete round trip")
	}
	t.Logf("Guest signer same-UID/GID snapshot/certificate/challenge round trip: %s", strings.TrimSpace(string(output)))
}
