//go:build phase6slice6gate

package productphase6gate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6GuestLiveRevokeEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_GUEST_LIVE_REVOKE"
const slice6GuestRevokeFixtureProtocol = "sandbox-runtime.phase6-guest-revoke-fixture.v1"
const slice6GuestRevokeAdmissionProtocol = "sandbox-runtime.phase6-guest-revoke-admission.v1"
const slice6GuestRevokeInteractiveDockerEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_REVOKE_INTERACTIVE_DOCKER"

type slice6GuestRevokeFixtureInput struct {
	Protocol           string                           `json:"protocol"`
	Operation          string                           `json:"operation"`
	RunID              string                           `json:"run_id"`
	ProfileDigest      string                           `json:"profile_digest"`
	ExecutableDigest   string                           `json:"executable_digest"`
	ProductContainerID string                           `json:"product_container_id"`
	InitialBinding     slice6GuestBindingFixtureReceipt `json:"initial_binding"`
}

type slice6GuestRevokeFixtureReceipt struct {
	Protocol            string  `json:"protocol"`
	RunID               string  `json:"run_id"`
	ProfileDigest       string  `json:"profile_digest"`
	ExecutableDigest    string  `json:"executable_digest"`
	ProductContainerID  string  `json:"product_container_id"`
	GuestID             string  `json:"guest_id"`
	BindingGeneration   int64   `json:"binding_generation"`
	MutationOutcome     string  `json:"mutation_outcome"`
	BeforeConnected     bool    `json:"before_connected"`
	BindingExpiresAt    string  `json:"binding_expires_at"`
	AfterRevoked        bool    `json:"after_revoked"`
	NonceCleared        bool    `json:"nonce_cleared"`
	PostgresBackendPID  int32   `json:"postgres_backend_pid"`
	PostgresBackendPIDs []int32 `json:"postgres_backend_pids"`
}

type slice6GuestRevokeAdmission struct {
	Protocol           string `json:"protocol"`
	RunID              string `json:"run_id"`
	ProfileDigest      string `json:"profile_digest"`
	ExecutableDigest   string `json:"executable_digest"`
	ProductContainerID string `json:"product_container_id"`
	GuestID            string `json:"guest_id"`
	PostgresBackendPID int32  `json:"postgres_backend_pid"`
}

func slice6RunGuestRevokeInteraction(ctx context.Context, id string, input []byte,
	onAdmitted func(slice6GuestRevokeAdmission) error) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || len(id) != 64 || !lowerHexSlice6(id) ||
		len(input) == 0 || len(input) > 4096 || onAdmitted == nil {
		return nil, errors.New("live revoke interaction authority invalid")
	}
	command := exec.CommandContext(ctx, "docker", "start", "-ai", id)
	stdin, inputErr := command.StdinPipe()
	stdout, outputErr := command.StdoutPipe()
	command.Stderr = io.Discard
	if inputErr != nil || outputErr != nil || command.Start() != nil {
		if stdin != nil {
			stdin.Close()
		}
		return nil, errors.New("live revoke task interactive start unavailable")
	}
	waited := false
	defer func() {
		stdin.Close()
		if !waited {
			command.Process.Kill()
			command.Wait()
		}
	}()
	if _, err := stdin.Write(append(bytes.Clone(input), '\n')); err != nil {
		return nil, errors.New("live revoke task input delivery unavailable")
	}
	reader := bufio.NewReader(io.LimitReader(stdout, 4097))
	admissionLine, err := reader.ReadBytes('\n')
	var admission slice6GuestRevokeAdmission
	if err != nil || len(admissionLine) < 2 || len(admissionLine) > 513 ||
		json.Unmarshal(admissionLine[:len(admissionLine)-1], &admission) != nil {
		return nil, errors.New("live revoke task connection admission unavailable")
	}
	canonical, err := json.Marshal(admission)
	if err != nil || !bytes.Equal(canonical, admissionLine[:len(admissionLine)-1]) ||
		admission.Protocol != slice6GuestRevokeAdmissionProtocol ||
		admission.PostgresBackendPID < 1 || !guestRevokeFixtureDigestGate(admission.ProfileDigest) ||
		!guestRevokeFixtureDigestGate(admission.ExecutableDigest) {
		return nil, errors.New("live revoke task connection admission malformed")
	}
	if err := onAdmitted(admission); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(stdin, "continue:"+admission.RunID+"\n"); err != nil || stdin.Close() != nil {
		return nil, errors.New("live revoke task one-shot continuation unavailable")
	}
	final, err := reader.ReadBytes('\n')
	if err != nil || len(final) < 2 || len(final) > 2049 {
		return nil, errors.New("live revoke task final receipt unavailable")
	}
	remainder, err := io.ReadAll(reader)
	if err != nil || len(remainder) != 0 {
		return nil, errors.New("live revoke task emitted unexpected output")
	}
	if err := command.Wait(); err != nil {
		waited = true
		return nil, errors.New("live revoke task did not exit cleanly")
	}
	waited = true
	return final, nil
}

func guestRevokeFixtureDigestGate(value string) bool {
	return len(value) == 71 && strings.HasPrefix(value, "sha256:") && lowerHexSlice6(value[7:])
}

func TestSlice6GuestRevokeInteractiveDockerNoIssuer(t *testing.T) {
	if os.Getenv(slice6GuestRevokeInteractiveDockerEnv) != "1" {
		t.Skip("set " + slice6GuestRevokeInteractiveDockerEnv + "=1 for no-issuer Docker stdin handshake")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := run.cleanup(cleanup); err != nil {
			t.Errorf("interactive Docker drill exact cleanup: %v", err)
		}
	})
	admission := slice6GuestRevokeAdmission{Protocol: slice6GuestRevokeAdmissionProtocol,
		RunID: run.id, ProfileDigest: "sha256:" + strings.Repeat("a", 64),
		ExecutableDigest:   "sha256:" + strings.Repeat("b", 64),
		ProductContainerID: strings.Repeat("c", 64), GuestID: "gst-diagnostic", PostgresBackendPID: 42}
	encoded, err := json.Marshal(admission)
	if err != nil {
		t.Fatal(err)
	}
	script := "read -r first; printf '%s\\n' \"$ADMISSION\"; read -r ack; " +
		"test \"$ack\" = \"continue:$RUN_ID\"; read -r extra && exit 9; printf '{\"ok\":true}\\n'"
	created, err := run.docker(ctx, "create", "-i", "--pull=never", "--network=none", "--restart=no",
		"--name", "sr-p6-revoke-interactive-"+run.id, "--label", run.label(),
		"--log-driver=none", "--user=65532:65532", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges:true", "--memory=67108864", "--pids-limit=16",
		"-e", "ADMISSION="+string(encoded), "-e", "RUN_ID="+run.id,
		"--entrypoint=/bin/sh", slice6PinnedAlpineImage, "-ec", script)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("interactive Docker drill create unavailable")
	}
	final, err := slice6RunGuestRevokeInteraction(ctx, id, []byte(`{"diagnostic":true}`),
		func(got slice6GuestRevokeAdmission) error {
			if got != admission {
				return errors.New("interactive Docker admission mismatch")
			}
			return nil
		})
	if err != nil || string(final) != "{\"ok\":true}\n" {
		t.Fatalf("interactive Docker handshake failed: %v final=%q", err, final)
	}
}

// A failed Docker command is never a negative readiness observation. BusyBox
// may return exit 1 for a genuine HTTP 503, so the bounded headers and exact
// exit code must agree.
func slice6ParseGuestReadyProbe(output []byte, commandErr error, overflow bool) (int, error) {
	if overflow || len(output) == 0 || len(output) > 4096 {
		return 0, errors.New("Guest readiness HTTP probe unavailable")
	}
	status := 0
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "HTTP/") {
			if status != 0 || !(strings.HasPrefix(line, "HTTP/1.1 ") || strings.HasPrefix(line, "HTTP/1.0 ")) {
				return 0, errors.New("Guest readiness HTTP status ambiguous")
			}
			fields := strings.Fields(line)
			if len(fields) < 2 || (fields[1] != "204" && fields[1] != "503") {
				return 0, errors.New("Guest readiness HTTP status unexpected")
			}
			status, _ = strconv.Atoi(fields[1])
		}
	}
	if status == 204 && commandErr == nil {
		return status, nil
	}
	var exit *exec.ExitError
	if status == 503 && errors.As(commandErr, &exit) && exit.ExitCode() == 1 {
		return status, nil
	}
	return 0, errors.New("Guest readiness HTTP status and command result disagree")
}

func slice6ProbeGuestReady(parent context.Context, guestID string) (int, error) {
	probe, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	output, err, overflow := slice6DockerBounded(probe, 4096, nil, "exec", guestID,
		"/bin/busybox", "wget", "-S", "-O", "-", "-T", "2", "http://127.0.0.1:8086/readyz")
	defer clear(output)
	return slice6ParseGuestReadyProbe(output, err, overflow)
}

func TestSlice6GuestReadyProbeRequiresExplicitHTTPStatus(t *testing.T) {
	exitOne := exec.Command("/bin/sh", "-c", "exit 1").Run()
	if exitOne == nil {
		t.Fatal("test exit status unavailable")
	}
	for _, test := range []struct {
		name   string
		output string
		err    error
		want   int
	}{
		{"ready", "  HTTP/1.1 204 No Content\n", nil, 204},
		{"unready", "  HTTP/1.1 503 Service Unavailable\n", exitOne, 503},
		{"command failure", "docker exec failed", exitOne, 0},
		{"mismatched success", "HTTP/1.1 503 Service Unavailable\n", nil, 0},
		{"mismatched error", "HTTP/1.1 204 No Content\n", exitOne, 0},
		{"ambiguous", "HTTP/1.1 204 No Content\nHTTP/1.1 503 Service Unavailable\n", exitOne, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := slice6ParseGuestReadyProbe([]byte(test.output), test.err, false)
			if got != test.want || (err == nil) != (test.want != 0) {
				t.Fatalf("status=%d err=%v; want %d", got, err, test.want)
			}
		})
	}
	for _, sample := range []struct {
		output   []byte
		overflow bool
	}{
		{[]byte("HTTP/1.1 204 No Content\n"), true},
		{[]byte(strings.Repeat("a", 4097) + "HTTP/1.1 204 No Content\n"), false},
		{nil, false},
	} {
		if status, err := slice6ParseGuestReadyProbe(sample.output, nil, sample.overflow); status != 0 || err == nil {
			t.Fatalf("oversized/unavailable probe accepted: status=%d err=%v", status, err)
		}
	}
}

func slice6GuestStoppedAfterRevoke(ctx context.Context, run slice6DockerRun, id string,
	initial slice6ProductRuntimeInspect) (bool, error) {
	raw, err := run.docker(ctx, "inspect", id)
	var found []struct {
		ID, Name string
		Config   struct{ Labels map[string]string }
		State    struct {
			Running, OOMKilled bool
			ExitCode           int
			StartedAt          string
		}
		RestartCount int
	}
	if err != nil || json.Unmarshal(raw, &found) != nil || len(found) != 1 ||
		found[0].ID != id || found[0].Name != initial.Name ||
		found[0].Config.Labels[slice6RunLabel] != run.id ||
		found[0].State.StartedAt != initial.State.StartedAt || found[0].RestartCount != 0 ||
		found[0].State.OOMKilled {
		return false, errors.New("Guest post-revoke process state unavailable or drifted")
	}
	if found[0].State.Running {
		return false, nil
	}
	if found[0].State.ExitCode != 1 {
		return false, errors.New("Guest terminated with unexpected exit code after revoke")
	}
	return true, nil
}

// The finite task shares only the running Product network namespace. It is
// not a production revoke entrypoint or audit, and it cannot be run before
// the actual Guest PID1 has reached connected readiness.
func slice6RunGuestLiveRevoke(parent context.Context, run slice6DockerRun, profile phase6security.Profile,
	productID, guestContainerID, postgresID string, artifact slice6GuestBindingFixtureArtifact,
	initial slice6GuestBindingFixtureReceipt, sockets, anchors map[string]string,
	observer slice6ProductRuntimeObserver) (receipt slice6GuestRevokeFixtureReceipt, resultErr error) {
	ctx, cancel := context.WithTimeout(parent, 150*time.Second)
	defer cancel()
	if slice6VerifyApprovedGuestBindingFixture(artifact) != nil ||
		phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(productID) != 64 || !lowerHexSlice6(productID) ||
		len(guestContainerID) != 64 || !lowerHexSlice6(guestContainerID) ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) ||
		productID == guestContainerID || len(sockets) != 74 ||
		initial.Protocol != slice6GuestBindingFixtureProtocol || initial.RunID != run.id ||
		initial.ProfileDigest != profile.ProfileDigest || initial.BindingGeneration != 1 ||
		initial.GuestID == "" || !initial.IdempotentReplay {
		return receipt, errors.New("live Guest revoke exact source, Product or binding authority unavailable")
	}
	product, err := slice6InspectProductRuntimeMember(ctx, run, productID)
	guest, guestErr := slice6InspectProductRuntimeMember(ctx, run, guestContainerID)
	postgres, postgresErr := slice6InspectProductRuntimeMember(ctx, run, postgresID)
	if err != nil || guestErr != nil || postgresErr != nil ||
		product.Name != "/sr-p6-product-runtime-"+run.id ||
		guest.Name != "/sr-p6-guest-runtime-"+run.id ||
		postgres.Name != "/sr-p6-postgres-"+run.id {
		return receipt, errors.New("live revoke requires unchanged Product, Guest and PostgreSQL PID1")
	}
	productFingerprint := slice6RuntimeMemberFingerprint(product, true)
	guestFingerprint := slice6RuntimeMemberFingerprint(guest, true)
	postgresFingerprint := slice6RuntimeMemberFingerprint(postgres, true)
	guestAgents := make(map[string]string, 2)
	for _, name := range []string{"sr-p6-guest-tls-live-" + run.id, "sr-p6-guest-live-" + run.id} {
		member, err := slice6InspectProductRuntimeMember(ctx, run, name)
		if err != nil || member.Name != "/"+name {
			return receipt, errors.New("Guest private TLS or material agent unavailable before live revoke")
		}
		guestAgents[name] = slice6RuntimeMemberFingerprint(member, true)
	}
	plan, err := slice6BuildProductRuntimeLaunchPlan(profile)
	if err != nil || plan.Principal.Name != "product-runtime" {
		return receipt, errors.New("live revoke Product launch authority unavailable")
	}
	if err := slice6VerifyProductRuntimeSQLSession(ctx, postgresID, plan.SourceAddress); err != nil {
		return receipt, err
	}
	if slice6VerifyApprovedProductRuntimeObserver(observer) != nil {
		return receipt, errors.New("live revoke Product service observer unavailable")
	}
	if err := slice6VerifyGuestRevokeRoleReserve(ctx, postgresID, plan.SourceAddress); err != nil {
		return receipt, err
	}
	material, materialErr := profile.Slice6MaterialSocketForOwner("product-runtime")
	signer, _, _, _, _, signerErr := profile.PostgresClientSignerForOwner("product-runtime")
	private, privateOK := phase6security.Slice6PrivateConfigMount("product-runtime")
	if materialErr != nil || signerErr != nil || !privateOK ||
		material.SocketStorageID == signer.SocketStorageID ||
		private.Target != phase6security.Slice6PrivateConfigDirectory {
		return receipt, errors.New("live revoke Product SQL/material boundary unavailable")
	}
	configVolume := "sr-p6-config-product-runtime-" + run.id
	for _, volume := range []string{configVolume, sockets[material.SocketStorageID], sockets[signer.SocketStorageID]} {
		if err := slice6VerifyGuestFixtureVolume(ctx, run, volume); err != nil {
			return receipt, err
		}
	}
	root, err := filepath.Abs("..")
	if err != nil {
		return receipt, errors.New("live revoke seccomp source unavailable")
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "originals", "moby-default-seccomp-836ae4d3.json")
	seccompData, err := os.ReadFile(seccomp)
	seccompDigest := sha256.Sum256(seccompData)
	clear(seccompData)
	if err != nil || plan.Principal.SeccompDigest != "sha256:"+hex.EncodeToString(seccompDigest[:]) {
		return receipt, errors.New("live revoke Product seccomp drift")
	}
	anchorArgs, err := slice6AnchorMountArguments(profile, "product-runtime", anchors)
	if err != nil {
		return receipt, err
	}
	if err := slice6PreflightGuestStorageCapacity(ctx, run); err != nil {
		return receipt, errors.New("live revoke aggregate disk capacity unavailable")
	}
	if err := slice6AdmitGuestRevokeMemory(ctx, run, plan.Principal.Resources.MemoryBytes+(64<<20)); err != nil {
		return receipt, err
	}
	input := slice6GuestRevokeFixtureInput{
		Protocol:  slice6GuestRevokeFixtureProtocol,
		Operation: "revoke-exact-connected-binding", RunID: run.id,
		ProfileDigest: profile.ProfileDigest, ExecutableDigest: artifact.ExpectedDigest,
		ProductContainerID: productID, InitialBinding: initial,
	}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 4096 {
		return receipt, errors.New("live revoke canonical bounded input unavailable")
	}
	defer clear(encoded)
	name := "sr-p6-guest-revoke-fixture-" + run.id
	args := []string{"create", "-i", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network=container:" + productID, "--restart=no",
		"--user", fmt.Sprintf("%d:%d", plan.Principal.UID, plan.Principal.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(plan.Principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(plan.Principal.Resources.CPUMillis)/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(plan.Principal.Resources.PIDs, 10),
		"--mount", "type=bind,src=" + artifact.Path + ",dst=/phase6-guest-binding-fixture,readonly",
		"--mount", "type=volume,src=" + configVolume + ",dst=" + private.Target + ",readonly",
		"--mount", "type=volume,src=" + sockets[material.SocketStorageID] + ",dst=" + material.SocketDirectory + ",readonly",
		"--mount", "type=volume,src=" + sockets[signer.SocketStorageID] + ",dst=" + signer.SocketDirectory + ",readonly"}
	args = append(args, anchorArgs...)
	args = append(args, "--entrypoint=/phase6-guest-binding-fixture", slice6PinnedAlpineImage,
		"--config", private.Target+"/"+phase6security.Slice6StartupConfigFile,
		"phase6-guest-revoke-fixture")
	created, err := run.docker(ctx, args...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		return receipt, errors.New("create finite live revoke task unconfirmed")
	}
	removed := false
	defer func() {
		if removed {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := run.docker(cleanup, "rm", "-f", "-v", id); err != nil {
			resultErr = errors.Join(resultErr, errors.New("live revoke finite task cleanup unconfirmed"))
		}
	}()
	if err := slice6VerifyGuestRevokeContainer(ctx, run, id, productID, plan.Principal,
		artifact, configVolume, sockets[material.SocketStorageID], material.SocketDirectory,
		sockets[signer.SocketStorageID], signer.SocketDirectory, private.Target, anchors, profile, seccomp); err != nil {
		return receipt, err
	}
	mutationWindowStart := time.Now()
	output, runErr := slice6RunGuestRevokeInteraction(ctx, id, encoded,
		func(admission slice6GuestRevokeAdmission) error {
			if admission.RunID != run.id || admission.ProfileDigest != profile.ProfileDigest ||
				admission.ExecutableDigest != artifact.ExpectedDigest || admission.ProductContainerID != productID ||
				admission.GuestID != initial.GuestID {
				return errors.New("live revoke helper occupied an unapproved Product SQL connection")
			}
			if err := slice6VerifyGuestRevokeProductBackendPresent(ctx, postgresID, plan.SourceAddress,
				admission.PostgresBackendPID); err != nil {
				return err
			}
			endpoints := make([]slice6ProductRuntimeEndpoint, 0, len(plan.Networks))
			for _, network := range plan.Networks {
				edge, ok := product.NetworkSettings.Networks[network.Name]
				if !ok || edge.NetworkID == "" || edge.IPAddress == "" {
					return errors.New("Product service topology changed during helper admission")
				}
				endpoints = append(endpoints, slice6ProductRuntimeEndpoint{Network: network,
					ID: edge.NetworkID, IP: edge.IPAddress})
			}
			if _, err := slice6ObserveProductReady(ctx, run, profile, plan, endpoints,
				anchors, observer, http.StatusOK, 5); err != nil {
				return errors.New("Product did not serve independently after helper acquired its sole SQL slot")
			}
			return slice6VerifyGuestRevokeProductBackendPresent(ctx, postgresID, plan.SourceAddress,
				admission.PostgresBackendPID)
		})
	defer clear(output)
	if runErr != nil || len(output) < 2 || len(output) > 2049 ||
		output[len(output)-1] != '\n' || json.Unmarshal(output[:len(output)-1], &receipt) != nil {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("live revoke task result unavailable")
	}
	canonical, marshalErr := json.Marshal(receipt)
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, receipt.BindingExpiresAt)
	if marshalErr != nil || !bytes.Equal(canonical, output[:len(output)-1]) ||
		receipt.Protocol != slice6GuestRevokeFixtureProtocol || receipt.RunID != run.id ||
		receipt.ProfileDigest != profile.ProfileDigest || receipt.ExecutableDigest != artifact.ExpectedDigest ||
		receipt.ProductContainerID != productID || receipt.GuestID != initial.GuestID ||
		receipt.BindingGeneration != initial.BindingGeneration || receipt.MutationOutcome != "confirmed" ||
		!receipt.BeforeConnected || !receipt.AfterRevoked || !receipt.NonceCleared || receipt.PostgresBackendPID < 1 ||
		len(receipt.PostgresBackendPIDs) != 1 || receipt.PostgresBackendPIDs[0] != receipt.PostgresBackendPID ||
		expiryErr != nil || !expiresAt.After(time.Now().Add(5*time.Second)) {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("live revoke task did not confirm exact connected binding mutation")
	}
	state, err := run.docker(ctx, "inspect", "--format", "{{.State.ExitCode}} {{.State.Running}}", id)
	if err != nil || string(bytes.TrimSpace(state)) != "0 false" {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("live revoke task did not exit cleanly")
	}
	if _, err := run.docker(ctx, "rm", "-v", id); err != nil {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("live revoke task exact removal failed")
	}
	removed = true
	for _, backendPID := range receipt.PostgresBackendPIDs {
		if err := slice6VerifyGuestRevokeBackendAbsent(ctx, postgresID, backendPID); err != nil {
			return slice6GuestRevokeFixtureReceipt{}, err
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	closed := false
	for time.Now().Before(deadline) && ctx.Err() == nil {
		status, probeErr := slice6ProbeGuestReady(ctx, guestContainerID)
		if probeErr == nil {
			if status == 503 {
				closed = true
				break
			}
		} else {
			stopped, stateErr := slice6GuestStoppedAfterRevoke(ctx, run, guestContainerID, guest)
			if stateErr != nil || !stopped {
				return slice6GuestRevokeFixtureReceipt{}, errors.New("Guest readiness probe failed without exact post-mutation exit1 observation")
			}
			closed = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !closed {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("Guest remained ready after Product binding revocation")
	}
	if time.Since(mutationWindowStart) > 30*time.Second || !time.Now().Before(expiresAt) {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("Guest revoke-to-disconnect bound or unexpired-binding witness unavailable")
	}
	time.Sleep(3 * time.Second)
	status, probeErr := slice6ProbeGuestReady(ctx, guestContainerID)
	if probeErr == nil {
		if status != 503 {
			return slice6GuestRevokeFixtureReceipt{}, errors.New("revoked Guest became ready again on old identity")
		}
	} else {
		stopped, stateErr := slice6GuestStoppedAfterRevoke(ctx, run, guestContainerID, guest)
		if stateErr != nil || !stopped {
			return slice6GuestRevokeFixtureReceipt{}, errors.New("Guest post-mutation probe failed without exact exit1 observation")
		}
	}
	if !time.Now().Before(expiresAt) {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("old reconnect denial was observed only after natural binding expiry")
	}
	if err := slice6VerifyGuestRevokePersisted(ctx, postgresID, run.id, initial.GuestID); err != nil {
		return slice6GuestRevokeFixtureReceipt{}, err
	}
	for _, observed := range []struct{ id, fingerprint string }{
		{productID, productFingerprint}, {postgresID, postgresFingerprint},
	} {
		member, err := slice6InspectProductRuntimeMember(ctx, run, observed.id)
		if err != nil || slice6RuntimeMemberFingerprint(member, true) != observed.fingerprint {
			return slice6GuestRevokeFixtureReceipt{}, errors.New("Product or PostgreSQL PID1 changed during live revoke")
		}
	}
	if member, err := slice6InspectProductRuntimeMember(ctx, run, guestContainerID); err == nil {
		if slice6RuntimeMemberFingerprint(member, true) != guestFingerprint {
			return slice6GuestRevokeFixtureReceipt{}, errors.New("Guest PID1 restarted or changed after revoke")
		}
	} else if stopped, stateErr := slice6GuestStoppedAfterRevoke(ctx, run, guestContainerID, guest); stateErr != nil || !stopped {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("Guest final process state unavailable")
	}
	for name, before := range guestAgents {
		member, err := slice6InspectProductRuntimeMember(ctx, run, name)
		if err != nil || slice6RuntimeMemberFingerprint(member, true) != before {
			return slice6GuestRevokeFixtureReceipt{}, errors.New("Guest TLS or material agent changed during live revoke")
		}
	}
	if err := slice6VerifyProductRuntimeSQLSession(ctx, postgresID, plan.SourceAddress); err != nil {
		return slice6GuestRevokeFixtureReceipt{}, errors.New("Product SQL dependency was unavailable after live revoke")
	}
	return receipt, nil
}

func slice6VerifyGuestRevokePersisted(ctx context.Context, postgresID, runID, guestID string) error {
	if len(postgresID) != 64 || !lowerHexSlice6(postgresID) ||
		len(runID) != 32 || !lowerHexSlice6(runID) || guestID == "" || len(guestID) > 128 ||
		strings.ContainsAny(guestID, "\x00\n\r") {
		return errors.New("persisted revoke observation target invalid")
	}
	script := []byte("BEGIN READ ONLY;\nSET LOCAL statement_timeout='3000ms';\n" +
		"SELECT state||'|'||COALESCE(connection_nonce,'')||'|'||" +
		"(expires_at>clock_timestamp())::text FROM sandbox_runtime_product.guest_bindings " +
		"WHERE tenant_id='tenant-phase6-" + runID + "' AND guest_id=:'guest_id';\nCOMMIT;\n")
	defer clear(script)
	out, err, overflow := slice6DockerBounded(ctx, 128, script, "exec", "-i", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1",
		"-v", "guest_id="+guestID, "-U", "postgres", "-d", "product", "-f", "-")
	defer clear(out)
	if err != nil || overflow || strings.TrimSpace(string(out)) != "revoked||t" {
		return errors.New("old Guest identity was not persistently revoked with no nonce before expiry")
	}
	return nil
}

// Limits, not sampled RSS, are counted so simultaneous run-owned processes
// cannot silently oversubscribe the Docker VM when this extra task is added.
func slice6AdmitGuestRevokeMemory(ctx context.Context, run slice6DockerRun, helperBytes int64) error {
	if helperBytes < 1 || helperBytes > math.MaxInt64-(512<<20) {
		return errors.New("live revoke helper memory budget invalid")
	}
	rawTotal, err := run.docker(ctx, "info", "--format", "{{.MemTotal}}")
	total, parseErr := strconv.ParseInt(strings.TrimSpace(string(rawTotal)), 10, 64)
	if err != nil || parseErr != nil || total < 1<<30 {
		return errors.New("Docker VM memory capacity unavailable")
	}
	ids, err := run.labeledIDs(ctx, "container")
	if err != nil {
		return errors.New("run-owned container inventory unavailable for aggregate memory admission")
	}
	needed := helperBytes + (512 << 20)
	for _, id := range ids {
		raw, inspectErr := run.docker(ctx, "inspect", id)
		var item []struct {
			Config     struct{ Labels map[string]string }
			State      struct{ Running bool }
			HostConfig struct{ Memory int64 }
		}
		if inspectErr != nil || json.Unmarshal(raw, &item) != nil || len(item) != 1 ||
			item[0].Config.Labels[slice6RunLabel] != run.id {
			return errors.New("run-owned process memory inventory changed")
		}
		if !item[0].State.Running {
			continue
		}
		limit := item[0].HostConfig.Memory
		if limit < 1 || needed > math.MaxInt64-limit {
			return errors.New("running process has unbounded or overflowing memory limit")
		}
		needed += limit
	}
	if needed >= total {
		return errors.New("concurrent run-owned memory caps plus revoke helper exceed Docker VM capacity")
	}
	return nil
}

func slice6VerifyGuestRevokeBackendAbsent(ctx context.Context, postgresID string, pid int32) error {
	if pid < 1 || len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		return errors.New("revoke backend absence target invalid")
	}
	script := []byte("BEGIN READ ONLY;\nSET LOCAL statement_timeout='3000ms';\n" +
		"SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE pid=" + strconv.FormatInt(int64(pid), 10) + " AND pid<>pg_backend_pid();\nCOMMIT;\n")
	defer clear(script)
	out, err, overflow := slice6DockerBounded(ctx, 64, script, "exec", "-i", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "product", "-f", "-")
	defer clear(out)
	if err != nil || overflow || strings.TrimSpace(string(out)) != "0" {
		return errors.New("finite revoke task PostgreSQL backend connection remains")
	}
	return nil
}

// pg_stat_activity includes idle connections; this is admission only, not a
// reservation against a concurrent Product pool expansion. The fixture itself
// verifies the still-live role session again after acquiring its sole slot.
func slice6VerifyGuestRevokeRoleReserve(ctx context.Context, postgresID, sourceAddress string) error {
	address, addressErr := netip.ParseAddr(sourceAddress)
	if len(postgresID) != 64 || !lowerHexSlice6(postgresID) || addressErr != nil ||
		!address.Is4() || address.String() != sourceAddress {
		return errors.New("Guest revoke SQL role reserve target invalid")
	}
	query, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	script := []byte("BEGIN READ ONLY;\nSET LOCAL statement_timeout='3000ms';\n" +
		"SELECT r.rolconnlimit::text||'|'||count(a.pid)::text||'|'||" +
		"count(a.pid) FILTER (WHERE a.client_addr='" + sourceAddress + "'::inet)::text " +
		"FROM pg_catalog.pg_roles r LEFT JOIN pg_catalog.pg_stat_activity a " +
		"ON a.usename=r.rolname AND a.datname='product' " +
		"WHERE r.rolname='product_runtime' GROUP BY r.rolconnlimit;\nCOMMIT;\n")
	defer clear(script)
	out, err, overflow := slice6DockerBounded(query, 128, script, "exec", "-i", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "product", "-f", "-")
	defer clear(out)
	if err != nil || overflow {
		return errors.New("Guest revoke SQL role reserve unavailable")
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) != 3 {
		return errors.New("Guest revoke SQL role reserve ambiguous")
	}
	limit, limitErr := strconv.Atoi(parts[0])
	total, totalErr := strconv.Atoi(parts[1])
	bound, boundErr := strconv.Atoi(parts[2])
	if limitErr != nil || totalErr != nil || boundErr != nil || limit != 4 ||
		total < 1 || total > 2 || bound != total {
		return errors.New("Guest revoke cannot reserve one SQL role slot with Product retained")
	}
	return nil
}

func slice6VerifyGuestRevokeProductBackendPresent(ctx context.Context, postgresID, sourceAddress string,
	helperPID int32) error {
	address, addressErr := netip.ParseAddr(sourceAddress)
	if len(postgresID) != 64 || !lowerHexSlice6(postgresID) || addressErr != nil ||
		!address.Is4() || address.String() != sourceAddress || helperPID < 1 {
		return errors.New("post-admission Product SQL observation target invalid")
	}
	query, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	script := []byte("BEGIN READ ONLY;\nSET LOCAL statement_timeout='3000ms';\n" +
		"SELECT r.rolconnlimit::text||'|'||count(a.pid)::text||'|'||" +
		"count(a.pid) FILTER (WHERE a.pid=" + strconv.FormatInt(int64(helperPID), 10) + ")::text||'|'||" +
		"count(a.pid) FILTER (WHERE a.pid<>" + strconv.FormatInt(int64(helperPID), 10) +
		" AND a.client_addr='" + sourceAddress + "'::inet)::text " +
		"FROM pg_catalog.pg_roles r LEFT JOIN pg_catalog.pg_stat_activity a " +
		"ON a.usename=r.rolname AND a.datname='product' " +
		"WHERE r.rolname='product_runtime' GROUP BY r.rolconnlimit;\nCOMMIT;\n")
	defer clear(script)
	out, err, overflow := slice6DockerBounded(query, 128, script, "exec", "-i", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "product", "-f", "-")
	defer clear(out)
	if err != nil || overflow {
		return errors.New("Product SQL connection was not observable after helper admission")
	}
	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) != 4 {
		return errors.New("post-admission Product SQL counts ambiguous")
	}
	var counts [4]int
	for index, part := range parts {
		count, parseErr := strconv.Atoi(part)
		if parseErr != nil {
			return errors.New("post-admission Product SQL counts invalid")
		}
		counts[index] = count
	}
	if counts[0] != 4 || counts[1] < 2 || counts[1] > 4 || counts[2] != 1 ||
		counts[3] < 1 || counts[3] != counts[1]-1 {
		return errors.New("Product SQL role connection lost while helper occupied its sole slot")
	}
	return nil
}

func slice6VerifyGuestRevokeContainer(ctx context.Context, run slice6DockerRun, id, productID string,
	principal phase6security.Principal, artifact slice6GuestBindingFixtureArtifact,
	configVolume, materialVolume, materialDirectory, signerVolume, signerDirectory, configDirectory string,
	anchors map[string]string, profile phase6security.Profile, seccomp string) error {
	raw, err := run.docker(ctx, "inspect", id)
	var observed []struct {
		Image  string
		Config struct {
			Image, User     string
			Entrypoint, Cmd []string
			Labels          map[string]string
		}
		HostConfig struct {
			NetworkMode, PidMode, IpcMode string
			ReadonlyRootfs, Privileged    bool
			CapDrop, SecurityOpt          []string
			Memory, NanoCpus, PidsLimit   int64
			PortBindings                  map[string]any
			RestartPolicy                 struct{ Name string }
			LogConfig                     struct{ Type string }
		}
		Mounts []struct {
			Type, Name, Source, Destination string
			RW                              bool
		}
		NetworkSettings struct{ Networks map[string]any }
		State           struct{ Running bool }
	}
	seccompData, seccompErr := os.ReadFile(seccomp)
	var canonical bytes.Buffer
	if seccompErr == nil {
		seccompErr = json.Compact(&canonical, seccompData)
	}
	clear(seccompData)
	if err != nil || seccompErr != nil || json.Unmarshal(raw, &observed) != nil || len(observed) != 1 ||
		observed[0].Config.Image != slice6PinnedAlpineImage ||
		observed[0].Config.User != fmt.Sprintf("%d:%d", principal.UID, principal.GID) ||
		observed[0].Config.Labels[slice6RunLabel] != run.id ||
		!slices.Equal(observed[0].Config.Entrypoint, []string{"/phase6-guest-binding-fixture"}) ||
		!slices.Equal(observed[0].Config.Cmd, []string{"--config", configDirectory + "/" + phase6security.Slice6StartupConfigFile, "phase6-guest-revoke-fixture"}) ||
		observed[0].State.Running || !observed[0].HostConfig.ReadonlyRootfs ||
		observed[0].HostConfig.Privileged ||
		!slices.Equal(observed[0].HostConfig.CapDrop, []string{"ALL"}) ||
		!slices.Contains(observed[0].HostConfig.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(observed[0].HostConfig.SecurityOpt, "seccomp="+canonical.String()) ||
		observed[0].HostConfig.NetworkMode != "container:"+productID ||
		observed[0].HostConfig.PidMode != "" || observed[0].HostConfig.IpcMode != "private" ||
		observed[0].HostConfig.Memory != principal.Resources.MemoryBytes ||
		observed[0].HostConfig.NanoCpus != principal.Resources.CPUMillis*1_000_000 ||
		observed[0].HostConfig.PidsLimit != principal.Resources.PIDs ||
		observed[0].HostConfig.RestartPolicy.Name != "no" || observed[0].HostConfig.LogConfig.Type != "none" ||
		len(observed[0].HostConfig.PortBindings) != 0 || len(observed[0].NetworkSettings.Networks) != 0 {
		return errors.New("live revoke task gained an unreviewed principal, namespace or endpoint")
	}
	want := map[string]struct{ kind, source string }{
		"/phase6-guest-binding-fixture": {"bind", artifact.Path},
		configDirectory:                 {"volume", configVolume},
		materialDirectory:               {"volume", materialVolume},
		signerDirectory:                 {"volume", signerVolume},
	}
	for _, mount := range principal.Mounts {
		if mount.Kind == "trust_anchor" {
			want[mount.Target] = struct{ kind, source string }{"bind", anchors[mount.StorageID]}
		}
	}
	if len(want) < 5 || len(observed[0].Mounts) != len(want) {
		return errors.New("live revoke exact mount count drift")
	}
	for _, mount := range observed[0].Mounts {
		expected, ok := want[mount.Destination]
		if !ok || mount.RW || expected.source == "" || expected.kind != mount.Type ||
			(mount.Type == "volume" && mount.Name != expected.source) ||
			(mount.Type == "bind" && mount.Source != expected.source) {
			return errors.New("live revoke task received an unreviewed or writable mount")
		}
		delete(want, mount.Destination)
	}
	if len(want) != 0 || len(profile.TrustAnchors) != len(anchors) {
		return errors.New("live revoke task mount inventory incomplete")
	}
	return slice6VerifyApprovedGuestBindingFixture(artifact)
}

func TestSlice6GuestLiveRevokeRejectsUnsafeObservationTargets(t *testing.T) {
	ctx := t.Context()
	run := slice6DockerRun{id: strings.Repeat("a", 32)}
	if slice6AdmitGuestRevokeMemory(ctx, run, 0) == nil {
		t.Fatal("unbounded revoke helper memory accepted")
	}
	for _, guestID := range []string{"", "bad\nname", strings.Repeat("x", 129)} {
		if slice6VerifyGuestRevokePersisted(ctx, strings.Repeat("b", 64), run.id, guestID) == nil {
			t.Fatal("invalid persisted revoke observation target accepted")
		}
	}
}
