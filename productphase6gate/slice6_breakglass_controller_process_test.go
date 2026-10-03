//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const slice6BreakGlassProcessEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_BREAK_GLASS_PROCESS"

type slice6BreakGlassActorDocument struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
}

type slice6BreakGlassConfigDocument struct {
	Protocol              string                          `json:"protocol"`
	SecurityProfilePath   string                          `json:"security_profile_path"`
	SecurityProfileDigest string                          `json:"security_profile_digest"`
	LedgerPath            string                          `json:"ledger_path"`
	AuditPath             string                          `json:"audit_path"`
	MaxTTLSeconds         int                             `json:"max_ttl_seconds"`
	Actors                []slice6BreakGlassActorDocument `json:"actors"`
}

func slice6BuildBreakGlassControllerInput(composed slice6VaultComposedInputs) ([]byte, ed25519.PrivateKey, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6FinalGateProfile(profile) != nil || len(profile.BreakGlassKeyAuthority.Actors) != 11 {
		return nil, nil, fmt.Errorf("break-glass Profile authority unavailable")
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount("break-glass-controller")
	if err != nil {
		return nil, nil, err
	}
	auditPath, err := phase6security.Slice6BreakGlassAuditPath()
	if err != nil {
		return nil, nil, err
	}
	config := slice6BreakGlassConfigDocument{Protocol: "sandbox-runtime.break-glass-controller-config.v2",
		SecurityProfilePath:   "/run/phase6/config/" + phase6security.Slice6ProfileConfigFile,
		SecurityProfileDigest: profile.ProfileDigest, LedgerPath: ledgerPath, AuditPath: auditPath,
		MaxTTLSeconds: 900}
	for _, binding := range profile.BreakGlassKeyAuthority.Actors {
		var public ed25519.PublicKey
		if binding.Kind == "target" {
			private, readErr := slice6ReadPrivateSigningKey(composed.CredentialKeys[binding.KeyID])
			if readErr != nil {
				return nil, nil, readErr
			}
			public = bytes.Clone(private.Public().(ed25519.PublicKey))
			clear(private)
		} else {
			path := composed.BreakGlassKeys[binding.KeyID]
			info, statErr := os.Lstat(path)
			if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 || info.Size() != ed25519.PublicKeySize {
				return nil, nil, fmt.Errorf("unsafe break-glass actor public source")
			}
			public, err = os.ReadFile(path)
			if err != nil {
				return nil, nil, err
			}
		}
		if phase6security.Slice6BreakGlassPublicKeyDigest(public) != binding.PublicKeyDigest {
			clear(public)
			return nil, nil, fmt.Errorf("break-glass actor source digest drift")
		}
		kind := binding.Kind
		if kind == "target" {
			kind = breakglass.ActorTarget
		}
		config.Actors = append(config.Actors, slice6BreakGlassActorDocument{ID: binding.ID, Kind: kind,
			PublicKey: base64.RawURLEncoding.EncodeToString(public)})
		clear(public)
	}
	private, err := slice6ReadPrivateSigningKey(composed.BreakGlassKeys[profile.BreakGlassKeyAuthority.ControllerKeyID])
	if err != nil {
		return nil, nil, err
	}
	if phase6security.Slice6BreakGlassPublicKeyDigest(private.Public().(ed25519.PublicKey)) !=
		profile.BreakGlassKeyAuthority.ControllerPublicKeyDigest {
		clear(private)
		return nil, nil, fmt.Errorf("break-glass controller signing source drift")
	}
	document, err := json.Marshal(config)
	if err != nil || len(document) > 1<<20 {
		clear(private)
		return nil, nil, fmt.Errorf("break-glass controller config unavailable")
	}
	return document, private, nil
}

func slice6RunBreakGlassControllerStartup(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, socketVolumes map[string]string, onReady func(restart func())) {
	t.Helper()
	profile := composed.Profile
	if len(socketVolumes) != 65 || phase6security.VerifySlice6BreakGlassBoundaries(profile) != nil {
		t.Fatal("complete break-glass socket supply unavailable")
	}
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == "break-glass-controller" {
			principal = candidate
			break
		}
	}
	if principal.Name == "" || principal.ImageLocation != "local" ||
		principal.ImageReference != principal.ImageDigest || principal.UID == 0 || principal.GID == 0 ||
		!principal.ReadOnlyRootFilesystem || !principal.NoNewPrivileges ||
		!slices.Equal(principal.DroppedCapabilities, []string{"ALL"}) {
		t.Fatal("break-glass controller principal drift")
	}
	var network phase6security.Network
	for _, candidate := range profile.Networks {
		if candidate.Name == "network-break-glass-controller" {
			network = candidate
		}
	}
	if network.Name == "" || !network.Internal || network.GatewayModeIPv4 != "isolated" ||
		!slices.Equal(network.Principals, []string{"break-glass-controller"}) || len(network.ExternalServices) != 0 {
		t.Fatal("break-glass controller isolated network drift")
	}
	createdNetwork, err := createSlice6ProfileNetwork(ctx, run, network)
	if err != nil {
		t.Fatal(err)
	}
	config, key, err := slice6BuildBreakGlassControllerInput(composed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	defer clear(key)
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccompPath := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	seccompBytes, err := os.ReadFile(seccompPath)
	if err != nil {
		t.Fatal(err)
	}
	seccompDigest := sha256.Sum256(seccompBytes)
	if principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		t.Fatal("break-glass controller seccomp digest drift")
	}
	_, ledgerPath, _ := phase6security.Slice6ControllerLedgerMount(principal.Name)
	privateMount, needed := phase6security.Slice6PrivateConfigMount(principal.Name)
	if !needed || privateMount.Target != "/run/phase6/config" {
		t.Fatal("break-glass controller private-config mount drift")
	}
	nonce, err := phase6security.NewSlice6RunID()
	if err != nil {
		t.Fatal(err)
	}
	name := "sr-p6-break-glass-live-" + run.id
	arguments := []string{"create", "-i", "--pull=never", "--name", name,
		"--label", run.label(), "--log-driver=none", "--network", createdNetwork.NetworkID,
		"--restart=no", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccompPath,
		"--read-only", "--memory", strconv.FormatInt(principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(principal.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(principal.Resources.PIDs, 10),
		"--mount", "type=volume,src=sr-p6-config-" + principal.Name + "-" + run.id + ",dst=" + privateMount.Target + ",readonly",
		"--mount", "type=volume,src=sr-p6-ledger-" + principal.Name + "-" + run.id + ",dst=" + filepath.Dir(ledgerPath)}
	control := phase6security.Slice6BreakGlassSocketBinding{}
	serverSockets := 0
	for _, binding := range profile.BreakGlassSockets {
		if binding.ServerDeployment != principal.Name {
			continue
		}
		if socketVolumes[binding.SocketStorageID] == "" {
			t.Fatal("break-glass controller socket volume omitted")
		}
		arguments = append(arguments, "--mount", "type=volume,src="+socketVolumes[binding.SocketStorageID]+",dst="+binding.SocketDirectory)
		if binding.Kind == "control" {
			control = binding
		}
		serverSockets++
	}
	if serverSockets != 8 || control.ID == "" {
		t.Fatal("break-glass controller endpoint count drift")
	}
	arguments = append(arguments, "-e", "SR_PHASE6_FD_RUN_ID="+run.id,
		"-e", "SR_PHASE6_FD_TARGET=break-glass-controller", "-e", "SR_PHASE6_FD_NONCE="+nonce,
		principal.ImageReference)
	created, err := run.docker(ctx, arguments...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create real break-glass controller failed")
	}
	verifyCreated := func(containerID string) {
		inspect, err := run.docker(ctx, "inspect", containerID)
		var containers []struct {
			Image  string `json:"Image"`
			Config struct {
				Image, User string
				Entrypoint  []string
			} `json:"Config"`
			HostConfig struct {
				ReadonlyRootfs, Privileged bool
				NetworkMode                string
			} `json:"HostConfig"`
			Mounts []struct {
				Type        string
				Source      string
				Name        string
				Destination string
				RW          bool
			} `json:"Mounts"`
		}
		if err != nil || json.Unmarshal(inspect, &containers) != nil || len(containers) != 1 ||
			containers[0].Image != principal.ImageDigest || containers[0].Config.Image != principal.ImageReference ||
			containers[0].Config.User != fmt.Sprintf("%d:%d", principal.UID, principal.GID) ||
			!slices.Equal(containers[0].Config.Entrypoint, []string{"/bin/sh", "-ec", phase6fdloader.FixedEntrypointCommand}) ||
			!containers[0].HostConfig.ReadonlyRootfs || containers[0].HostConfig.Privileged ||
			containers[0].HostConfig.NetworkMode != createdNetwork.NetworkID || len(containers[0].Mounts) != 10 {
			t.Fatal("break-glass controller created-container identity or mount count drift")
		}
		expectedMounts := map[string]struct {
			name string
			rw   bool
		}{
			privateMount.Target:      {"sr-p6-config-" + principal.Name + "-" + run.id, false},
			filepath.Dir(ledgerPath): {"sr-p6-ledger-" + principal.Name + "-" + run.id, true},
		}
		for _, binding := range profile.BreakGlassSockets {
			if binding.ServerDeployment == principal.Name {
				expectedMounts[binding.SocketDirectory] = struct {
					name string
					rw   bool
				}{socketVolumes[binding.SocketStorageID], true}
			}
		}
		if len(expectedMounts) != 10 {
			t.Fatal("break-glass controller expected mount inventory drift")
		}
		for _, mount := range containers[0].Mounts {
			wanted, found := expectedMounts[mount.Destination]
			if !found || mount.Type != "volume" || mount.Name != wanted.name || mount.RW != wanted.rw {
				t.Fatal("break-glass controller effective mount drift")
			}
			delete(expectedMounts, mount.Destination)
		}
		if len(expectedMounts) != 0 {
			t.Fatal("break-glass controller omitted a required mount")
		}
	}
	verifyCreated(id)
	envelope := phase6fdloader.Envelope{Protocol: phase6fdloader.ProtocolID, RunID: run.id,
		Target: "break-glass-controller", ContainerID: id, Nonce: nonce,
		Config: bytes.Clone(config), Files: []phase6fdloader.PrivateFile{{FD: 3, Data: bytes.Clone(key)}}}
	defer envelope.Destroy()
	encoded, err := json.Marshal(envelope)
	if err != nil || envelope.Validate(phase6fdloader.Expected{RunID: run.id, Target: envelope.Target,
		Nonce: nonce, ContainerHostname: id[:12]}) != nil {
		t.Fatal("break-glass controller sealed FD envelope invalid")
	}
	defer clear(encoded)
	type startResult struct {
		output []byte
		err    error
	}
	startAndAwait := func(containerID string, document []byte) chan startResult {
		completed := make(chan startResult, 1)
		startupInput := bytes.Clone(document)
		go func() {
			command := exec.CommandContext(ctx, "docker", "start", "-a", "-i", containerID)
			command.Stdin = bytes.NewReader(startupInput)
			output, startErr := command.CombinedOutput()
			clear(startupInput)
			completed <- startResult{output: output, err: startErr}
		}()
		deadline := time.Now().Add(30 * time.Second)
		ready := false
		for time.Now().Before(deadline) && ctx.Err() == nil {
			probe := "set -eu; test -s " + ledgerPath
			for _, binding := range profile.BreakGlassSockets {
				if binding.ServerDeployment == principal.Name {
					probe += "; test -S " + binding.SocketPath
				}
			}
			if _, probeErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID), containerID,
				"/bin/sh", "-ec", probe); probeErr == nil {
				ready = true
				break
			}
			select {
			case result := <-completed:
				t.Fatalf("real break-glass controller exited before eight listeners: %v: %.256s", result.err, result.output)
			case <-time.After(250 * time.Millisecond):
			}
		}
		if !ready {
			t.Fatal("real break-glass controller eight listeners and ledger not ready")
		}
		if _, err := observeSlice6ProfileNetwork(ctx, run, createdNetwork.NetworkID, network,
			map[string]string{principal.Name: containerID}); err != nil {
			t.Fatal("real break-glass controller network membership drift")
		}
		return completed
	}
	stopAndDrain := func(containerID string, completed chan startResult) {
		if _, err := run.docker(ctx, "stop", "--time", "10", containerID); err != nil {
			t.Fatal("stop real break-glass controller")
		}
		select {
		case result := <-completed:
			if result.err != nil {
				t.Fatalf("break-glass controller did not exit cleanly: %v: %.256s", result.err, result.output)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("break-glass controller did not drain after stop")
		}
	}
	completed := startAndAwait(id, encoded)
	seed := slice6ExerciseBreakGlassControlChain(t, ctx, run, composed, control, socketVolumes[control.SocketStorageID])
	stopAndDrain(id, completed)
	slice6InspectStoppedBreakGlassController(t, ctx, run, profile, principal, ledgerPath, socketVolumes)
	if _, err := run.docker(ctx, "rm", id); err != nil {
		t.Fatal("remove first break-glass controller before replacement")
	}
	previousNonce, previousID := nonce, id
	startReplacement := func() (string, chan startResult) {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			t.Fatal(err)
		}
		newNonce := hex.EncodeToString(random[:])
		replaced := false
		for index, argument := range arguments {
			if argument == "SR_PHASE6_FD_NONCE="+previousNonce {
				arguments[index] = "SR_PHASE6_FD_NONCE=" + newNonce
				replaced = true
			}
		}
		if !replaced || newNonce == previousNonce {
			t.Fatal("break-glass replacement nonce did not change")
		}
		created, createErr := run.docker(ctx, arguments...)
		containerID := strings.TrimSpace(string(created))
		if createErr != nil || len(containerID) != 64 || !lowerHexSlice6(containerID) || containerID == previousID {
			t.Fatal("create independent replacement break-glass controller")
		}
		verifyCreated(containerID)
		envelope := phase6fdloader.Envelope{Protocol: phase6fdloader.ProtocolID, RunID: run.id,
			Target: "break-glass-controller", ContainerID: containerID, Nonce: newNonce,
			Config: bytes.Clone(config), Files: []phase6fdloader.PrivateFile{{FD: 3, Data: bytes.Clone(key)}}}
		defer envelope.Destroy()
		input, marshalErr := json.Marshal(envelope)
		if marshalErr != nil || envelope.Validate(phase6fdloader.Expected{RunID: run.id,
			Target: envelope.Target, Nonce: newNonce, ContainerHostname: containerID[:12]}) != nil {
			t.Fatal("replacement controller FD envelope invalid")
		}
		defer clear(input)
		ready := startAndAwait(containerID, input)
		previousNonce, previousID = newNonce, containerID
		return containerID, ready
	}
	replacementID, replacementCompleted := startReplacement()
	slice6ExerciseBreakGlassRestart(t, ctx, run, composed, control, socketVolumes[control.SocketStorageID], seed)
	// The replay record has a one-minute lifetime. Check it immediately
	// across the restart, then run the slower Guest dependency chain while
	// the replacement controller remains live for delivery/consume.
	currentID, currentCompleted := replacementID, replacementCompleted
	restart := func() {
		stopAndDrain(currentID, currentCompleted)
		slice6InspectStoppedBreakGlassController(t, ctx, run, profile, principal, ledgerPath, socketVolumes)
		if _, err := run.docker(ctx, "rm", currentID); err != nil {
			t.Fatal("remove consumed-capability controller before replacement")
		}
		currentID, currentCompleted = startReplacement()
	}
	if onReady != nil {
		onReady(restart)
	}
	stopAndDrain(currentID, currentCompleted)
	slice6InspectStoppedBreakGlassController(t, ctx, run, profile, principal, ledgerPath, socketVolumes)
	if _, err := run.docker(ctx, "rm", currentID); err != nil {
		t.Fatal("remove replacement break-glass controller")
	}
	t.Log("real source-bound break-glass controller accepted signed submit/two approvals/issue, rejected same-JTI distinct-request replay, then a fresh replacement PID1 recovered persistent ledger/replay state and accepted a new request; Guest delivery/consume evidence is reported separately")
}

func slice6InspectStoppedBreakGlassController(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, principal phase6security.Principal, ledgerPath string,
	socketVolumes map[string]string) {
	t.Helper()
	auditPath, err := phase6security.Slice6BreakGlassAuditPath()
	if err != nil {
		t.Fatal(err)
	}
	arguments := []string{"run", "--rm", "--pull=never", "--name", "sr-p6-break-glass-stopped-" + run.id,
		"--label", run.label(), "--log-driver=none", "--network=none", "--restart=no",
		"--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID), "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--read-only", "--memory=64m", "--cpus=0.1",
		"--pids-limit=16", "--mount", "type=volume,src=sr-p6-ledger-" + principal.Name + "-" + run.id +
			",dst=" + filepath.Dir(ledgerPath) + ",readonly"}
	probe := "set -eu; test -s " + ledgerPath + "; test -s " + auditPath
	serverSockets := 0
	for _, binding := range profile.BreakGlassSockets {
		if binding.ServerDeployment != principal.Name {
			continue
		}
		volume := socketVolumes[binding.SocketStorageID]
		if volume == "" {
			t.Fatal("stopped controller socket volume missing")
		}
		arguments = append(arguments, "--mount", "type=volume,src="+volume+",dst="+binding.SocketDirectory+",readonly")
		probe += "; test ! -e " + binding.SocketPath
		serverSockets++
	}
	if serverSockets != 8 {
		t.Fatal("stopped controller endpoint count drift")
	}
	arguments = append(arguments, "--entrypoint=/bin/sh", principal.ImageReference, "-ec", probe)
	if output, err := run.docker(ctx, arguments...); err != nil {
		t.Fatalf("stopped controller persisted state or eight socket cleanup failed: %v: %.256s", err, output)
	}
}

type slice6BreakGlassRestartSeed struct {
	request    breakglass.AccessRequest
	replayJTI  string
	acceptedAt time.Time
}

func slice6ExerciseBreakGlassControlChain(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, control phase6security.Slice6BreakGlassSocketBinding, volume string) slice6BreakGlassRestartSeed {
	t.Helper()
	requesterKey, err := slice6ReadPrivateSigningKey(filepath.Join(composed.BreakGlassSignerDirectory, "break-glass-requester-a.key"))
	if err != nil {
		t.Fatal(err)
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	materialAccess, err := phase6security.BuildSlice6DesiredMaterialAccess(composed.Profile)
	if err != nil {
		t.Fatal("break-glass target material binding unavailable")
	}
	var guestBindingDigest string
	for _, access := range materialAccess {
		if access.Agent == "guest-agent" && len(access.Bindings) == 1 &&
			access.Bindings[0].Purpose == secretref.PurposeGuestSigningKey {
			guestBindingDigest = access.Bindings[0].Digest()
		}
	}
	if guestBindingDigest == "" {
		t.Fatal("break-glass Guest binding unavailable")
	}
	request, err := breakglass.NewSignedAccessRequest(breakglass.AccessRequest{
		Protocol: breakglass.ProtocolID, RequestID: "bgreq_" + run.id, RequesterID: "requester-a",
		TargetAgentID: "guest-agent", Role: secretref.RoleGuest, Purpose: secretref.PurposeGuestSigningKey,
		BindingDigest: guestBindingDigest, TenantID: secretref.SystemTenant,
		Operation: "material.resolve", ReasonDigest: digest("slice6-break-glass-reason-" + run.id),
		TicketDigest: digest("slice6-break-glass-ticket-" + run.id), RequestedTTLSeconds: 60,
		Deadline: time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano),
		JTI:      base64.RawURLEncoding.EncodeToString(random[:]),
	}, requesterKey)
	if err != nil {
		clear(requesterKey)
		t.Fatal(err)
	}
	replay := request
	replayID := sha256.Sum256([]byte("replay:" + run.id))
	replay.RequestID = "bgreq_" + hex.EncodeToString(replayID[:16])
	replay.Deadline = time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano)
	replay, err = breakglass.NewSignedAccessRequest(replay, requesterKey)
	clear(requesterKey)
	if err != nil || replay.RequestID == request.RequestID || replay.RequestDigest == request.RequestDigest ||
		replay.JTI != request.JTI {
		t.Fatal("distinct signed request did not preserve replay nonce")
	}
	if result := slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, volume, "submit",
		breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType, Request: &request}, true); result.Revision != 1 || result.Capability != nil {
		t.Fatal("signed requester submit did not create revision 1")
	}
	slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, volume, "replay",
		breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType, Request: &replay}, false)
	for index, approver := range []string{"approver-a", "approver-b"} {
		key, readErr := slice6ReadPrivateSigningKey(filepath.Join(composed.BreakGlassSignerDirectory,
			"break-glass-"+approver+".key"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		approval, signErr := breakglass.NewSignedApproval(breakglass.Approval{RequestID: request.RequestID,
			RequestDigest: request.RequestDigest, Revision: int64(index + 1), ApproverID: approver,
			Deadline: time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano),
			JTI:      slice6FreshBreakGlassJTI(t)}, key)
		clear(key)
		if signErr != nil {
			t.Fatal(signErr)
		}
		result := slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, volume,
			approver, breakglass.WireRequest{Protocol: breakglass.ProtocolID,
				Type: breakglass.ApproveType, Approval: &approval}, true)
		if result.Revision != int64(index+2) || result.Capability != nil {
			t.Fatal("two-person approval revision drift")
		}
	}
	operatorKey, err := slice6ReadPrivateSigningKey(filepath.Join(composed.BreakGlassSignerDirectory,
		"break-glass-operator-a.key"))
	if err != nil {
		t.Fatal(err)
	}
	issue, err := breakglass.NewSignedCommand(breakglass.Command{Type: breakglass.CommandIssue,
		RequestID: request.RequestID, Revision: 3, ActorID: "operator-a",
		Deadline: time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano),
		JTI:      slice6FreshBreakGlassJTI(t)}, operatorKey)
	clear(operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt := time.Now()
	issued := slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, volume, "issue",
		breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.IssueType, Command: &issue}, true)
	if issued.Revision != 0 || issued.Capability == nil ||
		issued.Capability.RequestID != request.RequestID ||
		issued.Capability.RequestDigest != request.RequestDigest ||
		issued.Capability.TargetAgentID != request.TargetAgentID ||
		issued.Capability.BindingDigest != request.BindingDigest || issued.Capability.MaxUses != 1 {
		t.Fatal("issued break-glass capability drift")
	}
	return slice6BreakGlassRestartSeed{request: request, replayJTI: issue.JTI, acceptedAt: acceptedAt}
}

func slice6ExerciseBreakGlassRestart(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, control phase6security.Slice6BreakGlassSocketBinding, volume string,
	seed slice6BreakGlassRestartSeed) {
	t.Helper()
	if seed.request.RequestID == "" || seed.replayJTI == "" || seed.replayJTI == seed.request.JTI || seed.acceptedAt.IsZero() {
		t.Fatal("replacement controller replay seed invalid")
	}
	key, err := slice6ReadPrivateSigningKey(filepath.Join(composed.BreakGlassSignerDirectory,
		"break-glass-requester-a.key"))
	if err != nil {
		t.Fatal(err)
	}
	replayed := seed.request
	replayID := sha256.Sum256([]byte("restart-replay:" + run.id))
	replayed.RequestID = "bgreq_" + hex.EncodeToString(replayID[:16])
	replayed.JTI = seed.replayJTI
	replayed.Deadline = time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano)
	replayed, err = breakglass.NewSignedAccessRequest(replayed, key)
	if err != nil {
		clear(key)
		t.Fatal(err)
	}
	fresh := seed.request
	freshID := sha256.Sum256([]byte("restart-fresh:" + run.id))
	fresh.RequestID = "bgreq_" + hex.EncodeToString(freshID[:16])
	fresh.JTI = slice6FreshBreakGlassJTI(t)
	fresh.Deadline = time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano)
	fresh, err = breakglass.NewSignedAccessRequest(fresh, key)
	clear(key)
	if err != nil || replayed.RequestID == seed.request.RequestID ||
		fresh.RequestID == seed.request.RequestID || fresh.RequestID == replayed.RequestID ||
		fresh.JTI == replayed.JTI {
		t.Fatal("replacement controller fresh and replay requests not distinct")
	}
	beforeReplay := time.Since(seed.acceptedAt)
	if beforeReplay < 0 || beforeReplay >= 50*time.Second {
		t.Fatalf("break-glass restart replay precondition expired before attempt: elapsed_ms=%d", beforeReplay.Milliseconds())
	}
	slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, volume, "restart-replay",
		breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType, Request: &replayed}, false)
	afterReplay := time.Since(seed.acceptedAt)
	if afterReplay < 0 || afterReplay >= time.Minute {
		t.Fatalf("break-glass restart replay observation exceeded nonce retention: elapsed_ms=%d", afterReplay.Milliseconds())
	}
	t.Logf("real break-glass replacement rejected persisted nonce within one-minute retention: elapsed_ms=%d", afterReplay.Milliseconds())
	result := slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, volume, "restart-submit",
		breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType, Request: &fresh}, true)
	if result.Revision != 1 || result.Capability != nil {
		t.Fatal("replacement controller did not accept fresh signed request")
	}
}

func slice6FreshBreakGlassJTI(t *testing.T) string {
	t.Helper()
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(random[:])
}

// Component evidence only: the actual Guest material-agent accepts delivery,
// signs the online consume, and uses its live Vault-backed material resolver.
func slice6ExerciseGuestBreakGlassDelivery(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, delivery phase6security.Slice6BreakGlassSocketBinding,
	socketVolumes map[string]string, restartController func()) {
	t.Helper()
	if restartController == nil {
		t.Fatal("live Guest break-glass controller restart unavailable")
	}
	var control phase6security.Slice6BreakGlassSocketBinding
	for _, candidate := range composed.Profile.BreakGlassSockets {
		if candidate.Kind == "control" {
			control = candidate
		}
	}
	if control.ID == "" || delivery.Kind != "delivery" || delivery.TargetAgent != "guest-agent" ||
		socketVolumes[control.SocketStorageID] == "" || socketVolumes[delivery.SocketStorageID] == "" {
		t.Fatal("Guest break-glass control/delivery socket binding unavailable")
	}
	access, err := phase6security.BuildSlice6DesiredMaterialAccess(composed.Profile)
	if err != nil {
		t.Fatal("Guest break-glass material binding unavailable")
	}
	var bindingDigest string
	for _, item := range access {
		if item.Agent == "guest-agent" && len(item.Bindings) == 1 &&
			item.Bindings[0].Purpose == secretref.PurposeGuestSigningKey {
			bindingDigest = item.Bindings[0].Digest()
		}
	}
	if bindingDigest == "" {
		t.Fatal("Guest break-glass exact material binding unavailable")
	}
	requesterKey, err := slice6ReadPrivateSigningKey(filepath.Join(composed.BreakGlassSignerDirectory,
		"break-glass-requester-a.key"))
	if err != nil {
		t.Fatal(err)
	}
	requestIDHash := sha256.Sum256([]byte("live-delivery:" + run.id))
	digest := func(label string) string {
		sum := sha256.Sum256([]byte(label + ":" + run.id))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	request, err := breakglass.NewSignedAccessRequest(breakglass.AccessRequest{
		Protocol: breakglass.ProtocolID, RequestID: "bgreq_" + hex.EncodeToString(requestIDHash[:16]),
		RequesterID: "requester-a", TargetAgentID: "guest-agent", Role: secretref.RoleGuest,
		Purpose: secretref.PurposeGuestSigningKey, BindingDigest: bindingDigest,
		TenantID: secretref.SystemTenant, Operation: "material.resolve",
		ReasonDigest: digest("live-guest-reason"), TicketDigest: digest("live-guest-ticket"),
		RequestedTTLSeconds: 120, Deadline: time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano),
		JTI: slice6FreshBreakGlassJTI(t),
	}, requesterKey)
	clear(requesterKey)
	if err != nil {
		t.Fatal("sign distinct live Guest break-glass request")
	}
	controlVolume := socketVolumes[control.SocketStorageID]
	if result := slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, controlVolume,
		"live-submit", breakglass.WireRequest{Protocol: breakglass.ProtocolID,
			Type: breakglass.SubmitType, Request: &request}, true); result.Revision != 1 {
		t.Fatal("live Guest break-glass request did not begin at revision 1")
	}
	for index, approver := range []string{"approver-a", "approver-b"} {
		key, readErr := slice6ReadPrivateSigningKey(filepath.Join(composed.BreakGlassSignerDirectory,
			"break-glass-"+approver+".key"))
		if readErr != nil {
			t.Fatal(readErr)
		}
		approval, signErr := breakglass.NewSignedApproval(breakglass.Approval{
			RequestID: request.RequestID, RequestDigest: request.RequestDigest,
			Revision: int64(index + 1), ApproverID: approver,
			Deadline: time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano),
			JTI:      slice6FreshBreakGlassJTI(t),
		}, key)
		clear(key)
		if signErr != nil {
			t.Fatal("sign live Guest break-glass approval")
		}
		result := slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, controlVolume,
			"live-"+approver, breakglass.WireRequest{Protocol: breakglass.ProtocolID,
				Type: breakglass.ApproveType, Approval: &approval}, true)
		if result.Revision != int64(index+2) {
			t.Fatal("live Guest two-approver revision drift")
		}
	}
	operatorKey, err := slice6ReadPrivateSigningKey(filepath.Join(composed.BreakGlassSignerDirectory,
		"break-glass-operator-a.key"))
	if err != nil {
		t.Fatal(err)
	}
	issue, err := breakglass.NewSignedCommand(breakglass.Command{
		Type: breakglass.CommandIssue, RequestID: request.RequestID, Revision: 3,
		ActorID: "operator-a", Deadline: time.Now().Add(45 * time.Second).UTC().Format(time.RFC3339Nano),
		JTI: slice6FreshBreakGlassJTI(t),
	}, operatorKey)
	clear(operatorKey)
	if err != nil {
		t.Fatal("sign live Guest break-glass issue")
	}
	issued := slice6FiniteBreakGlassControlTask(t, ctx, run, composed, control, controlVolume,
		"live-issue", breakglass.WireRequest{Protocol: breakglass.ProtocolID,
			Type: breakglass.IssueType, Command: &issue}, true)
	if issued.Capability == nil {
		t.Fatal("live Guest break-glass capability absent")
	}
	capability := *issued.Capability
	if capability.RequestID != request.RequestID || capability.RequestDigest != request.RequestDigest ||
		capability.TargetAgentID != "guest-agent" || capability.Role != secretref.RoleGuest ||
		capability.Purpose != secretref.PurposeGuestSigningKey || capability.BindingDigest != bindingDigest ||
		capability.TenantID != secretref.SystemTenant || capability.Operation != "material.resolve" ||
		capability.MaxUses != 1 {
		t.Fatal("live Guest break-glass issued authority drift")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, capability.ExpiresAt)
	if err != nil || time.Until(expiresAt) < 60*time.Second {
		t.Fatal("live Guest break-glass capability expiry precondition failed")
	}
	before := slice6ReadLiveBreakGlassLedger(t, ctx, run, composed.Profile)
	slice6AssertGuestBreakGlassRecord(t, before, capability, breakglass.StateIssued, 0)
	deliveryVolume := socketVolumes[delivery.SocketStorageID]
	slice6FiniteBreakGlassDeliveryTask(t, ctx, run, composed, delivery, deliveryVolume,
		"live-deliver", capability, true)
	after := slice6ReadLiveBreakGlassLedger(t, ctx, run, composed.Profile)
	slice6AssertGuestBreakGlassRecord(t, after, capability, breakglass.StateConsumed, 1)
	if after.AuditCount != before.AuditCount+1 || after.Revision != before.Revision+1 ||
		after.AuditHead == before.AuditHead {
		t.Fatal("online Guest consume did not commit exactly one controller audit/ledger transition")
	}
	restartController()
	recovered := slice6ReadLiveBreakGlassLedger(t, ctx, run, composed.Profile)
	slice6AssertGuestBreakGlassRecord(t, recovered, capability, breakglass.StateConsumed, 1)
	if recovered.Revision != after.Revision || recovered.AuditCount != after.AuditCount ||
		recovered.AuditHead != after.AuditHead {
		t.Fatal("replacement controller did not recover exact consumed-capability ledger")
	}
	if time.Until(expiresAt) < 15*time.Second {
		t.Fatal("live Guest break-glass capability expired before replay attempt")
	}
	slice6FiniteBreakGlassDeliveryTask(t, ctx, run, composed, delivery, deliveryVolume,
		"live-redeliver", capability, false)
	replayed := slice6ReadLiveBreakGlassLedger(t, ctx, run, composed.Profile)
	slice6AssertGuestBreakGlassRecord(t, replayed, capability, breakglass.StateConsumed, 1)
	if replayed.Revision != recovered.Revision || replayed.AuditCount != recovered.AuditCount ||
		replayed.AuditHead != recovered.AuditHead || !time.Now().Before(expiresAt) {
		t.Fatal("same-capability replay denial lacked a live single-use ledger witness")
	}
	t.Log("real Guest agent consumed one delivered break-glass capability and resolved exact Vault material; a new controller PID1 recovered consumed/1 and denied before-expiry redelivery with unchanged ledger")
}

func slice6ReadLiveBreakGlassLedger(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile) breakglass.Ledger {
	t.Helper()
	var controller phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == "break-glass-controller" {
			controller = candidate
		}
	}
	if controller.UID == 0 || controller.GID == 0 {
		t.Fatal("live break-glass controller principal unavailable")
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount("break-glass-controller")
	if err != nil {
		t.Fatal(err)
	}
	name := "sr-p6-break-glass-live-" + run.id
	document, err := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", controller.UID, controller.GID), name,
		"/bin/sh", "-ec", "test -s "+ledgerPath+" && cat "+ledgerPath)
	if err != nil || len(document) < 1 || len(document) > 8<<20 {
		clear(document)
		t.Fatal("live break-glass persisted ledger unavailable")
	}
	defer clear(document)
	var ledger breakglass.Ledger
	if json.Unmarshal(document, &ledger) != nil || ledger.Schema != breakglass.LedgerSchema ||
		ledger.Revision < 1 || ledger.AuditCount < 1 || ledger.AuditHead == "" {
		t.Fatal("live break-glass persisted ledger invalid")
	}
	return ledger
}

func slice6AssertGuestBreakGlassRecord(t *testing.T, ledger breakglass.Ledger,
	capability breakglass.Capability, state string, uses int) {
	t.Helper()
	count := 0
	for _, record := range ledger.Requests {
		if record.Request.RequestID != capability.RequestID {
			continue
		}
		count++
		if record.Request.RequestDigest != capability.RequestDigest ||
			record.Request.TargetAgentID != capability.TargetAgentID ||
			record.Request.BindingDigest != capability.BindingDigest ||
			record.CapabilityID != capability.CapabilityID || record.State != state ||
			record.Uses != uses || record.ExpiresAt != capability.ExpiresAt {
			t.Fatal("live Guest break-glass ledger record did not bind exact capability/state")
		}
	}
	if count != 1 {
		t.Fatal("live Guest break-glass ledger request cardinality drift")
	}
}

type slice6FiniteBreakGlassResult struct {
	Status     string                 `json:"status"`
	Revision   int64                  `json:"revision"`
	Capability *breakglass.Capability `json:"capability"`
}

func slice6FiniteBreakGlassControlTask(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, control phase6security.Slice6BreakGlassSocketBinding,
	volume, label string, wire breakglass.WireRequest, wantOK bool) slice6FiniteBreakGlassResult {
	t.Helper()
	if control.Kind != "control" {
		t.Fatal("finite control task received a non-control socket")
	}
	return slice6FiniteBreakGlassTask(t, ctx, run, composed, control, volume, label, &wire, nil, wantOK)
}

func slice6FiniteBreakGlassDeliveryTask(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, delivery phase6security.Slice6BreakGlassSocketBinding,
	volume, label string, capability breakglass.Capability, wantOK bool) slice6FiniteBreakGlassResult {
	t.Helper()
	if delivery.Kind != "delivery" || delivery.TargetAgent != capability.TargetAgentID {
		t.Fatal("finite delivery task received a non-target socket")
	}
	return slice6FiniteBreakGlassTask(t, ctx, run, composed, delivery, volume, label, nil, &capability, wantOK)
}

func slice6FiniteBreakGlassTask(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, binding phase6security.Slice6BreakGlassSocketBinding,
	volume, label string, wire *breakglass.WireRequest, capability *breakglass.Capability,
	wantOK bool) slice6FiniteBreakGlassResult {
	t.Helper()
	operation, target := "deliver", binding.TargetAgent
	if wire != nil && capability == nil && binding.Kind == "control" {
		operation, target = wire.Type, ""
	} else if wire != nil || capability == nil || binding.Kind != "delivery" {
		t.Fatal("finite break-glass task operation/socket mismatch")
	}
	type operatorInput struct {
		Protocol     string                  `json:"protocol"`
		Operation    string                  `json:"operation"`
		SocketPath   string                  `json:"socket_path"`
		ExpectedUID  uint32                  `json:"expected_uid"`
		ExpectedGID  uint32                  `json:"expected_gid"`
		DirectoryGID uint32                  `json:"directory_gid"`
		TargetAgent  string                  `json:"target_agent"`
		Request      *breakglass.WireRequest `json:"request"`
		Capability   *breakglass.Capability  `json:"capability"`
	}
	document, err := json.Marshal(operatorInput{Protocol: "sandbox-runtime.phase6-break-glass-operator-input.v1",
		Operation: operation, SocketPath: binding.SocketPath,
		ExpectedUID: binding.ServerUID, ExpectedGID: binding.ServerGID, DirectoryGID: binding.ClientGID,
		TargetAgent: target, Request: wire, Capability: capability})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(document)
	var task phase6security.Slice6BreakGlassOperatorTask
	for _, candidate := range composed.Profile.BreakGlassOperatorTasks {
		if candidate.ID == binding.ClientTaskID {
			task = candidate
		}
	}
	if task.ID == "" || task.Mount.StorageID != binding.SocketStorageID ||
		task.ExecutableArtifactID != composed.Profile.BreakGlassExecutableArtifact.ID {
		t.Fatal("finite operator socket task drift")
	}
	name := "sr-p6-break-glass-" + label + "-" + run.id
	created, err := run.docker(ctx, "create", "-i", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network=none", "--restart=no", "--user", fmt.Sprintf("%d:%d", task.UID, task.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--memory", strconv.FormatInt(task.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(task.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.Itoa(task.PIDs),
		"--mount", "type=bind,src="+composed.BreakGlassOperatorBinary+",dst="+task.Executable+",readonly",
		"--mount", "type=volume,src="+volume+",dst="+task.Mount.Target+",readonly",
		"--entrypoint="+task.Executable, task.ImageReference)
	id := slice6CanonicalCreatedID(created, err)
	if id == "" {
		t.Fatalf("create finite break-glass task: %s", slice6DockerCreateFailure(ctx, created, err))
	}
	inspect, err := run.docker(ctx, "inspect", id)
	var observed []struct {
		Image  string `json:"Image"`
		Config struct {
			User       string
			Entrypoint []string
		} `json:"Config"`
		HostConfig struct {
			NetworkMode                string
			ReadonlyRootfs, Privileged bool
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string
			Source      string
			Name        string
			Destination string
			RW          bool
		} `json:"Mounts"`
	}
	if err != nil || json.Unmarshal(inspect, &observed) != nil || len(observed) != 1 ||
		observed[0].Image != phase6security.Slice6BreakGlassCarrierIndexDigest ||
		observed[0].Config.User != fmt.Sprintf("%d:%d", task.UID, task.GID) ||
		!slices.Equal(observed[0].Config.Entrypoint, []string{task.Executable}) ||
		observed[0].HostConfig.NetworkMode != "none" || !observed[0].HostConfig.ReadonlyRootfs ||
		observed[0].HostConfig.Privileged || len(observed[0].Mounts) != 2 {
		t.Fatal("finite break-glass task created-container policy drift")
	}
	seenBinary, seenSocket := false, false
	for _, mount := range observed[0].Mounts {
		if mount.RW {
			t.Fatal("finite break-glass task gained a writable mount")
		}
		if mount.Type == "bind" && mount.Source == composed.BreakGlassOperatorBinary && mount.Destination == task.Executable {
			seenBinary = true
		}
		if mount.Type == "volume" && mount.Name == volume && mount.Destination == task.Mount.Target {
			seenSocket = true
		}
	}
	if !seenBinary || !seenSocket {
		t.Fatal("finite break-glass task mount source or target drift")
	}
	readback := filepath.Join(filepath.Dir(composed.ProfilePath), "break-glass-mounted-"+label+"-"+run.id)
	if _, err := run.docker(ctx, "cp", id+":"+task.Executable, readback); err != nil {
		t.Fatal("read finite task mounted executable before signed request")
	}
	mountedInfo, err := os.Lstat(readback)
	if err != nil || !mountedInfo.Mode().IsRegular() || mountedInfo.Mode().Perm() != 0o555 ||
		mountedInfo.Size() != composed.Profile.BreakGlassExecutableArtifact.BinaryBytes {
		t.Fatal("finite task mounted executable mode or size drift")
	}
	mounted, err := os.ReadFile(readback)
	if err != nil {
		t.Fatal(err)
	}
	mountedDigest := sha256.Sum256(mounted)
	clear(mounted)
	if "sha256:"+hex.EncodeToString(mountedDigest[:]) != composed.Profile.BreakGlassExecutableArtifact.BinaryDigest {
		t.Fatal("finite task mounted executable digest drift")
	}
	start := exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
	start.Stdin = bytes.NewReader(document)
	response, err := start.CombinedOutput()
	var result slice6FiniteBreakGlassResult
	if wantOK {
		if err != nil || json.Unmarshal(bytes.TrimSpace(response), &result) != nil || result.Status != "ok" {
			t.Fatalf("finite signed %s through real controller failed: %v (output bytes %d)", label, err, len(response))
		}
	} else if err == nil || string(bytes.TrimSpace(response)) != "break-glass operator unavailable" {
		t.Fatalf("finite signed %s was not denied: %v (output bytes %d)", label, err, len(response))
	}
	if _, err := run.docker(ctx, "rm", id); err != nil {
		t.Fatal("remove finite one-shot task")
	}
	return result
}
