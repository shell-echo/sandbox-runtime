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
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

const slice6GuestTLSStackEnv = "SANDBOX_RUNTIME_PHASE6_GUEST_TLS_STACK"
const slice6GuestTLSCPUContrastEnv = "SANDBOX_RUNTIME_PHASE6_GUEST_TLS_CPU_CONTRAST"

// Component evidence only: the managed certificate controller remains alive
// while the independently isolated Guest TLS agent obtains a leaf and opens
// its subject-only signer socket. The material agent is not implied here.
func slice6RunGuestTLSAgentStartup(t *testing.T, ctx context.Context, run slice6DockerRun,
	composed slice6VaultComposedInputs, socketVolumes, anchorFiles map[string]string, onSignerReady func()) {
	t.Helper()
	profile := composed.Profile
	binding, principal, subject, err := profile.TLSAgentForSubject("guest-agent")
	if err != nil || principal.Name != "guest-agent-tls-agent" || subject.Name != "guest-agent" ||
		principal.ImageLocation != "local" || principal.ImageReference != principal.ImageDigest ||
		principal.UID == 0 || principal.GID == 0 || !principal.ReadOnlyRootFilesystem ||
		!principal.NoNewPrivileges || !slices.Equal(principal.DroppedCapabilities, []string{"ALL"}) ||
		len(principal.Networks) != 1 || principal.Networks[0] != "network-guest-agent-tls-agent" {
		t.Fatal("Guest TLS-agent immutable Profile identity drift")
	}
	cpuContrast := os.Getenv(slice6GuestTLSCPUContrastEnv) == "1"
	if cpuContrast && (principal.Resources.CPUMillis != 50 || os.Getenv(slice6GuestTLSStackEnv) == "1") {
		t.Fatal("non-release Guest TLS-agent CPU contrast requires the frozen 50m Profile and no QUIT diagnostic")
	}
	var controller phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == "certificate-controller" {
			controller = candidate
		}
	}
	_, ledgerPath, ledgerErr := phase6security.Slice6ControllerLedgerMount(controller.Name)
	if ledgerErr != nil || controller.UID != binding.ControllerUID || controller.GID != binding.ControllerGID {
		t.Fatal("Guest TLS-agent certificate controller witness unavailable")
	}
	var network phase6security.Network
	for _, candidate := range profile.Networks {
		if candidate.Name == principal.Networks[0] {
			network = candidate
		}
	}
	if network.Name == "" || !network.Internal || network.GatewayModeIPv4 != "isolated" ||
		!slices.Equal(network.Principals, []string{principal.Name}) || len(network.ExternalServices) != 0 {
		t.Fatal("Guest TLS-agent dedicated network drift")
	}
	prefix, err := netip.ParsePrefix(network.IPv4Subnet)
	if err != nil || prefix.Bits() != 24 || !prefix.Addr().Is4() {
		t.Fatal("Guest TLS-agent network address drift")
	}
	address := prefix.Addr().As4()
	address[3] = 2
	createdNetwork, err := createSlice6ProfileNetwork(ctx, run, network)
	if err != nil {
		t.Fatal("create Guest TLS-agent dedicated network")
	}
	config, err := slice6BuildGuestTLSAgentConfig(composed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	key, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[binding.AgentRequestKeyID])
	if err != nil {
		t.Fatal("Guest TLS-agent source-bound request key unavailable")
	}
	defer clear(key)
	privateMount, needed := phase6security.Slice6PrivateConfigMount(principal.Name)
	if !needed || privateMount.Target != "/run/phase6/config" ||
		socketVolumes[binding.SocketStorageID] == "" ||
		socketVolumes[binding.ControllerSocketStorageID] == "" {
		t.Fatal("Guest TLS-agent private mounts unavailable")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	seccomp := filepath.Join(root, "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	seccompBytes, err := os.ReadFile(seccomp)
	digest := sha256.Sum256(seccompBytes)
	if err != nil || principal.SeccompDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("Guest TLS-agent seccomp source drift")
	}
	nonce, err := phase6security.NewSlice6RunID()
	if err != nil {
		t.Fatal(err)
	}
	name := "sr-p6-guest-tls-live-" + run.id
	arguments := []string{"create", "-i", "--pull=never", "--name", name, "--label", run.label(),
		"--log-driver=none", "--network", createdNetwork.NetworkID, "--ip", netip.AddrFrom4(address).String(),
		"--restart=no", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + seccomp,
		"--read-only", "--memory", strconv.FormatInt(principal.Resources.MemoryBytes, 10),
		"--cpus", strconv.FormatFloat(float64(slice6GuestTLSCPUMillis(principal.Resources.CPUMillis, cpuContrast))/1000, 'f', 3, 64),
		"--pids-limit", strconv.FormatInt(principal.Resources.PIDs, 10),
		"--mount", "type=volume,src=sr-p6-config-" + principal.Name + "-" + run.id + ",dst=" + privateMount.Target + ",readonly"}
	anchorCount := 0
	for _, mount := range principal.Mounts {
		if mount.Kind == "trust_anchor" {
			anchorCount++
		}
	}
	if anchorCount != 0 {
		anchorArguments, anchorErr := slice6AnchorMountArguments(profile, principal.Name, anchorFiles)
		if anchorErr != nil || len(anchorArguments) != 2*anchorCount {
			t.Fatal("Guest TLS-agent trust-anchor mounts unavailable")
		}
		arguments = append(arguments, anchorArguments...)
	}
	count := 0
	for _, mount := range principal.Mounts {
		if mount.Kind != "private_socket" {
			continue
		}
		volume := socketVolumes[mount.StorageID]
		if volume == "" || (mount.StorageID == binding.ControllerSocketStorageID) != mount.ReadOnly ||
			mount.StorageID != binding.ControllerSocketStorageID && mount.StorageID != binding.SocketStorageID {
			t.Fatal("Guest TLS-agent socket mount drift")
		}
		value := "type=volume,src=" + volume + ",dst=" + mount.Target
		if mount.ReadOnly {
			value += ",readonly"
		}
		arguments = append(arguments, "--mount", value)
		count++
	}
	if count != 2 {
		t.Fatal("Guest TLS-agent socket count drift")
	}
	if cpuContrast {
		arguments = append(arguments, "--label", "io.github.shell-echo.sandbox-runtime.cpu-contrast=non-release")
	}
	const imageTarget = "workload-tls-agent"
	arguments = append(arguments, "-e", "SR_PHASE6_FD_RUN_ID="+run.id,
		"-e", "SR_PHASE6_FD_TARGET="+imageTarget, "-e", "SR_PHASE6_FD_NONCE="+nonce,
		principal.ImageReference)
	created, err := run.docker(ctx, arguments...)
	id := strings.TrimSpace(string(created))
	if err != nil || len(id) != 64 || !lowerHexSlice6(id) {
		t.Fatal("create real Guest TLS-agent process")
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
		containers[0].Image != principal.ImageDigest || containers[0].Config.Image != principal.ImageReference ||
		containers[0].Config.User != fmt.Sprintf("%d:%d", principal.UID, principal.GID) ||
		!slices.Equal(containers[0].Config.Entrypoint, []string{"/bin/sh", "-ec", phase6fdloader.FixedEntrypointCommand}) ||
		!containers[0].HostConfig.ReadonlyRootfs || containers[0].HostConfig.Privileged ||
		containers[0].HostConfig.NetworkMode != createdNetwork.NetworkID ||
		containers[0].HostConfig.NanoCpus != slice6GuestTLSCPUMillis(principal.Resources.CPUMillis, cpuContrast)*1_000_000 ||
		containers[0].HostConfig.Memory != principal.Resources.MemoryBytes ||
		containers[0].HostConfig.PidsLimit != principal.Resources.PIDs {
		t.Fatal("Guest TLS-agent created-container identity or isolation drift")
	}
	if cpuContrast {
		t.Logf("NON-RELEASE Guest TLS-agent CPU-only contrast: Profile=%dm Docker request=250m; all other Profile inputs unchanged",
			principal.Resources.CPUMillis)
	}
	envelope := phase6fdloader.Envelope{Protocol: phase6fdloader.ProtocolID, RunID: run.id,
		Target: imageTarget, ContainerID: id, Nonce: nonce, Config: bytes.Clone(config),
		Files: []phase6fdloader.PrivateFile{{FD: 3, Data: bytes.Clone(key)}}}
	defer envelope.Destroy()
	input, err := json.Marshal(envelope)
	if err != nil || envelope.Validate(phase6fdloader.Expected{RunID: run.id, Target: imageTarget,
		Nonce: nonce, ContainerHostname: id[:12]}) != nil {
		t.Fatal("Guest TLS-agent private FD envelope invalid")
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
	ready := false
	startupStarted := time.Now()
	deadline := startupStarted.Add(45 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if _, probeErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
			id, "/bin/sh", "-ec", "test -S "+binding.SocketPath); probeErr == nil {
			ready = true
			break
		}
		select {
		case done := <-completed:
			stage := slice6ControllerFailureStage(done.output)
			clear(done.output)
			t.Fatalf("Guest TLS-agent exited before signer listener: stage=%s exit=%v", stage, done.err)
		case <-time.After(250 * time.Millisecond):
		}
	}
	if !ready {
		state, stateErr := run.docker(ctx, "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", id)
		process, processErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
			id, "/bin/sh", "-ec", "readlink /proc/1/exe; stat -c '%u:%g:%a' "+binding.SocketDirectory+
				"; if test -S "+binding.ControllerSocketPath+"; then echo controller_socket_present; fi; cat /sys/fs/cgroup/cpu.max; cat /sys/fs/cgroup/cpu.stat")
		ledgerDocument, ledgerErr := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", controller.UID, controller.GID),
			"sr-p6-certificate-live-"+run.id, "/bin/sh", "-ec", "cat "+ledgerPath)
		var ledger workloadpki.Ledger
		issued := false
		if ledgerErr == nil && len(ledgerDocument) <= 8<<20 && json.Unmarshal(ledgerDocument, &ledger) == nil {
			for _, record := range ledger.Certificates {
				issued = issued || record.PolicyID == binding.IssuerPolicyID && record.State == "active"
			}
		}
		if os.Getenv(slice6GuestTLSStackEnv) == "1" && strings.TrimSpace(string(state)) == "running:0" {
			if _, signalErr := run.docker(ctx, "kill", "--signal=QUIT", id); signalErr != nil {
				t.Fatalf("diagnostic Guest TLS-agent QUIT could not be delivered: %v", signalErr)
			}
			select {
			case done := <-completed:
				frames := slice6MainGoStackFunctions(done.output)
				allSymbols := slice6GoStackSymbols(done.output)
				outputBytes := len(done.output)
				containsGoStack := bytes.Contains(done.output, []byte("goroutine 1 "))
				clear(done.output)
				t.Fatalf("diagnostic Guest TLS-agent intentionally stopped by QUIT: managed_leaf=%t output_bytes=%d go_stack_marker=%t main_stack_functions=%q stack_symbols=%q exit=%v",
					issued, outputBytes, containsGoStack, frames, allSymbols, done.err)
			case <-time.After(15 * time.Second):
				t.Fatal("diagnostic Guest TLS-agent QUIT output unavailable; intentionally failed closed")
			}
		}
		select {
		case done := <-completed:
			stage := slice6ControllerFailureStage(done.output)
			clear(done.output)
			t.Fatalf("Guest TLS-agent signer not ready: state=%q inspect=%v process=%q process_probe=%v managed_leaf=%t process_stage=%s exit=%v",
				strings.TrimSpace(string(state)), stateErr, strings.TrimSpace(string(process)), processErr, issued, stage, done.err)
		default:
			t.Fatalf("Guest TLS-agent signer not ready: state=%q inspect=%v process=%q process_probe=%v managed_leaf=%t attached start still pending",
				strings.TrimSpace(string(state)), stateErr, strings.TrimSpace(string(process)), processErr, issued)
		}
	}
	if _, err := observeSlice6ProfileNetwork(ctx, run, createdNetwork.NetworkID, network,
		map[string]string{principal.Name: id}); err != nil {
		t.Fatal("Guest TLS-agent exact network membership drift")
	}
	ledgerDocument, err := run.docker(ctx, "exec", "--user", fmt.Sprintf("%d:%d", controller.UID, controller.GID),
		"sr-p6-certificate-live-"+run.id, "/bin/sh", "-ec", "cat "+ledgerPath)
	var ledger workloadpki.Ledger
	if err != nil || len(ledgerDocument) > 8<<20 || json.Unmarshal(ledgerDocument, &ledger) != nil {
		t.Fatal("Guest TLS-agent managed certificate ledger witness unavailable")
	}
	issued := false
	for _, record := range ledger.Certificates {
		if record.PolicyID == binding.IssuerPolicyID && record.State == "active" {
			issued = true
		}
	}
	if !issued {
		t.Fatal("Guest TLS-agent did not obtain its managed certificate")
	}
	if cpuContrast {
		observedCPU, cpuErr := run.docker(ctx, "exec", id, "/bin/sh", "-ec", "cat /sys/fs/cgroup/cpu.max")
		if cpuErr != nil || strings.TrimSpace(string(observedCPU)) != "25000 100000" {
			t.Fatalf("NON-RELEASE Guest TLS-agent CPU contrast cgroup mismatch: %q: %v", observedCPU, cpuErr)
		}
	}
	t.Logf("real Guest TLS-agent managed leaf and signer socket ready after %s under Profile CPU=%dm, memory=%d, PIDs=%d",
		time.Since(startupStarted), principal.Resources.CPUMillis, principal.Resources.MemoryBytes, principal.Resources.PIDs)
	if onSignerReady != nil {
		onSignerReady()
	}
	if _, err := run.docker(ctx, "stop", "--time", "10", id); err != nil {
		t.Fatal("stop Guest TLS-agent")
	}
	select {
	case done := <-completed:
		stage := slice6ControllerFailureStage(done.output)
		clear(done.output)
		if done.err != nil {
			t.Fatalf("Guest TLS-agent did not drain cleanly: stage=%s exit=%v", stage, done.err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Guest TLS-agent did not drain")
	}
	if _, err := run.docker(ctx, "rm", id); err != nil {
		t.Fatal("remove stopped Guest TLS-agent")
	}
	if output, err := run.docker(ctx, "run", "--rm", "--pull=never", "--name", "sr-p6-guest-tls-clean-"+run.id,
		"--label", run.label(), "--network=none", "--user", fmt.Sprintf("%d:%d", principal.UID, principal.GID),
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--read-only",
		"--mount", "type=volume,src="+socketVolumes[binding.SocketStorageID]+",dst="+binding.SocketDirectory+",readonly",
		"--entrypoint=/bin/sh", principal.ImageReference, "-ec", "test ! -e "+binding.SocketPath); err != nil {
		t.Fatalf("Guest TLS-agent signer socket cleanup unproved: %v: %.128s", err, output)
	}
	t.Log("real Guest TLS-agent PID1 issued its managed certificate, opened the isolated signer listener and cleaned the exact socket; material-agent Vault mTLS and material read remain unproved")
}

func slice6GuestTLSCPUMillis(profile int64, contrast bool) int64 {
	if contrast {
		return 250
	}
	return profile
}

// Extract only repository/runtime function symbols from goroutine 1. Raw Go
// dumps can contain arguments and must not appear in logs or evidence.
func slice6MainGoStackFunctions(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	inMain := false
	functions := make([]string, 0, 24)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "goroutine 1 ") {
			inMain = true
			continue
		}
		if inMain && strings.HasPrefix(line, "goroutine ") {
			break
		}
		if !inMain || len(functions) == 24 {
			continue
		}
		if name, ok := slice6SafeStackSymbol(line); ok {
			functions = append(functions, name)
		}
	}
	return functions
}

func slice6GoStackSymbols(output []byte) []string {
	functions := make([]string, 0, 24)
	for _, line := range strings.Split(string(output), "\n") {
		if len(functions) == 24 {
			break
		}
		if name, ok := slice6SafeStackSymbol(strings.TrimSpace(line)); ok && !slices.Contains(functions, name) {
			functions = append(functions, name)
		}
	}
	return functions
}

func slice6SafeStackSymbol(line string) (string, bool) {
	if !strings.HasPrefix(line, "github.com/shell-echo/sandbox-runtime/") &&
		!strings.HasPrefix(line, "main.") && !strings.HasPrefix(line, "runtime.") &&
		!strings.HasPrefix(line, "syscall.") && !strings.HasPrefix(line, "internal/") {
		return "", false
	}
	argumentStart := strings.LastIndexByte(line, '(')
	if argumentStart < 1 || argumentStart >= 256 {
		return "", false
	}
	name := line[:argumentStart]
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '_' || character == '.' ||
			character == '/' || character == '*' || character == '-' ||
			character == '(' || character == ')' {
			continue
		}
		return "", false
	}
	return name, true
}

func TestSlice6MainGoStackFunctionsRedactsArguments(t *testing.T) {
	dump := []byte("SIGQUIT: quit\ngoroutine 99 gp=0x0 [runnable]:\n" +
		"prefix goroutine 1 gp=0x0 [runnable]:\n" +
		"github.com/shell-echo/sandbox-runtime/internal/phase6security.(*Profile).Validate({secret-token})\n" +
		"\t/private/source.go:99 +0x123\n" +
		"main.run({private-key})\n" +
		"goroutine 2 [sleep]:\nmain.other({secret})\n")
	want := []string{"github.com/shell-echo/sandbox-runtime/internal/phase6security.(*Profile).Validate", "main.run"}
	if actual := slice6MainGoStackFunctions(dump); !slices.Equal(actual, want) {
		t.Fatalf("stack symbol redaction drift: %q", actual)
	}
	if actual := slice6GoStackSymbols(dump); !slices.Equal(actual, []string{want[0], want[1], "main.other"}) {
		t.Fatalf("all-stack symbol redaction drift: %q", actual)
	}
}
