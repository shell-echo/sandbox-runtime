//go:build integration

package image

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const desktopImageIntegrationEnv = "SANDBOX_RUNTIME_DESKTOP_IMAGE_INTEGRATION"

func TestDesktopImageNativeIntegration(t *testing.T) {
	if os.Getenv(desktopImageIntegrationEnv) != "1" {
		t.Skip("set " + desktopImageIntegrationEnv + "=1 to build and test the Desktop image")
	}
	manifest, err := Load(LocalCandidateManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	platform := nativePlatform(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	suffix := fmt.Sprintf("%s-%d", runtime.GOARCH, time.Now().UnixNano())
	imageOne := "sandbox-runtime-desktop:integration-a-" + suffix
	imageTwo := "sandbox-runtime-desktop:integration-b-" + suffix
	containerName := "sandbox-runtime-desktop-integration-" + suffix
	highUIDContainer := containerName + "-highuid"
	bridgePublic, bridgePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mountRoot, err := os.MkdirTemp(".", ".desktop-image-integration-")
	if err != nil {
		t.Fatal(err)
	}
	mountRoot, err = filepath.Abs(mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	accountsPath := filepath.Join(mountRoot, "workload-accounts.json")
	if err := os.WriteFile(accountsPath, []byte(`{"schema":"sandbox.runtime/desktop-phase6-workload-accounts/v1","accounts":[{"uid":20000,"gid":30000},{"uid":20001,"gid":30001}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", containerName).Run()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", highUIDContainer).Run()
		_ = exec.CommandContext(cleanupContext, "docker", "image", "rm", imageOne, imageTwo).Run()
		_ = os.RemoveAll(mountRoot)
	})
	for _, image := range []string{imageOne, imageTwo} {
		run(t, ctx, "./build-phase6-locked.sh", platform, image, "integration-test", accountsPath)
	}

	idOne := strings.TrimSpace(run(t, ctx, "docker", "image", "inspect", "--format", "{{.Id}}", imageOne))
	idTwo := strings.TrimSpace(run(t, ctx, "docker", "image", "inspect", "--format", "{{.Id}}", imageTwo))
	if idOne == "" || idOne != idTwo {
		t.Fatalf("identical locked inputs produced different image IDs: %q != %q", idOne, idTwo)
	}
	inspectImagePolicy(t, ctx, imageOne, manifest)

	inputs := filepath.Join(mountRoot, "inputs")
	workspace := filepath.Join(mountRoot, "workspace")
	outputs := filepath.Join(mountRoot, "outputs")
	for _, path := range []string{inputs, workspace, outputs} {
		if err := os.Mkdir(path, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(inputs, 0o555); err != nil {
		t.Fatal(err)
	}

	run(t, ctx, "docker", "run", "-d", "--name", containerName,
		"-e", "SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY="+base64.RawStdEncoding.EncodeToString(bridgePublic),
		"-e", "SANDBOX_RUNTIME_DESKTOP_BRIDGE_KEY_ID=provider-desktop-v2",
		"-e", desktopbroker.SessionProtocolEnv+"="+desktopbroker.SessionProtocolV2ID,
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.namespace=desktop-image-integration",
		"--platform", platform,
		"--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--network", "none", "--ipc", "private", "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
		"--mount", "type=bind,src="+inputs+",dst=/inputs,readonly",
		"--mount", "type=bind,src="+workspace+",dst=/workspace",
		"--mount", "type=bind,src="+outputs+",dst=/outputs",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
		imageOne)
	localBroker := filepath.Join(mountRoot, "desktop-broker")
	run(t, ctx, "docker", "cp", containerName+":"+BrokerPath, localBroker)
	buildMetadata := run(t, ctx, "go", "version", "-m", localBroker)
	if !strings.Contains(buildMetadata, manifest.Provenance.GoVersion) ||
		!strings.Contains(buildMetadata, "CGO_ENABLED=0") ||
		!strings.Contains(buildMetadata, "GOARCH="+runtime.GOARCH) {
		t.Fatalf("candidate broker build metadata mismatch: %s", buildMetadata)
	}

	waitForBroker(t, ctx, containerName)
	describeText := run(t, ctx, "docker", "exec", containerName, BrokerPath, "describe", "--socket", BrokerSocket)
	var response desktopbroker.Response
	if err := json.Unmarshal([]byte(describeText), &response); err != nil || response.Validate() != nil || response.Descriptor == nil {
		t.Fatalf("invalid broker describe response: %v: %s", err, describeText)
	}
	if response.Descriptor.DisplayReference != DisplayReference || response.Descriptor.Width != 1280 || response.Descriptor.Height != 720 {
		t.Fatalf("unexpected display descriptor: %+v", response.Descriptor)
	}

	displayProbe := run(t, ctx, "docker", "exec", containerName, "/bin/sh", "-c",
		"set -eu; xdpyinfo -display :99 >/tmp/xdpyinfo; xwd -display :99 -root -silent -out /tmp/root.xwd; test -s /tmp/root.xwd; wc -c </tmp/root.xwd; for path in /dev/dri /dev/input /dev/snd; do test ! -e \"$path\"; done")
	if size := strings.TrimSpace(displayProbe); size == "" || size == "0" {
		t.Fatalf("empty native display capture: %q", displayProbe)
	}
	processes := run(t, ctx, "docker", "top", containerName, "-eo", "pid,ppid,user,args")
	if strings.Contains(processes, "root ") || !strings.Contains(processes, "Xvfb :99 -screen 0 1280x720x24 -nolisten tcp") || !strings.Contains(processes, "/usr/bin/openbox --sm-disable") {
		t.Fatalf("unsafe Desktop process tree:\n%s", processes)
	}
	runV2Session(t, ctx, containerName, bridgePrivate)
	inspectContainerPolicy(t, ctx, containerName)

	run(t, ctx, "docker", "run", "-d", "--name", highUIDContainer,
		"--user", "20000:30000",
		"-e", "SANDBOX_RUNTIME_DESKTOP_BRIDGE_PUBLIC_KEY="+base64.RawStdEncoding.EncodeToString(bridgePublic),
		"-e", "SANDBOX_RUNTIME_DESKTOP_BRIDGE_KEY_ID=provider-desktop-v2",
		"-e", desktopbroker.SessionProtocolEnv+"="+desktopbroker.SessionProtocolV2ID,
		"--platform", platform, "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--network", "none", "--ipc", "private", "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
		"--tmpfs", "/tmp:rw,nosuid,nodev,size=256m,mode=1777,uid=20000,gid=30000",
		"--tmpfs", "/workspace:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=20000,gid=30000",
		"--tmpfs", "/outputs:rw,noexec,nosuid,nodev,size=128m,mode=0700,uid=20000,gid=30000",
		imageOne)
	waitForBroker(t, ctx, highUIDContainer)
	identity := run(t, ctx, "docker", "exec", highUIDContainer, "/bin/sh", "-c",
		"set -eu; test \"$(id -u)\" = 20000; test \"$(id -g)\" = 30000; grep -q '^desktop-slot-20000:x:20000:30000:' /etc/passwd; grep -q '^desktop-slot-30000:x:30000:' /etc/group; stat -c '%u:%g:%a' "+BrokerSocket)
	if strings.TrimSpace(identity) != "20000:30000:600" {
		t.Fatalf("high-UID broker socket identity = %q", identity)
	}
	runV2Session(t, ctx, highUIDContainer, bridgePrivate)
}

func runV2Session(t *testing.T, ctx context.Context, containerName string, privateKey ed25519.PrivateKey) {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", "exec", "-i", containerName, BrokerPath, "session", "--socket", BrokerSocket)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = command.Process.Kill(); _, _ = io.ReadAll(stderr) }()
	now := time.Now().UTC()
	policy := desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}
	open := desktopbroker.SessionOpen{BindingVersion: desktopbroker.SessionBindingV2, BindingIssuer: desktopbroker.SessionBindingIssuerV2, Protocol: desktopbroker.SessionProtocolV2ID, RequestID: "image-open-1", Method: desktopbroker.SessionMethod, TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("a", 64), ProviderRevisionID: "provider-revision-1", SandboxID: "sandbox-1", DesktopSessionID: "desktop-session-1", CapabilityProfileID: "desktop-v1", MediaProfileID: "desktop-media-v1", ControlProfileID: "desktop-control-v1", HandoffReferenceDigest: executorprotocol.ReferenceDigest("ref:desktop-session:image"), AllocationReference: "ref:desktop/11111111111111111111111111111111", ConnectionGeneration: 1, ConnectionEpoch: "epoch-1", Fence: strings.Repeat("b", handoff.MinFenceBytes), AuthorityExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), HandoffExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano), AuthorityDigest: "sha256:" + strings.Repeat("c", 64), RequestDigest: "sha256:" + strings.Repeat("d", 64), HandoffReference: "ref:desktop-session:image", MediaPolicy: policy}
	statement := desktopbridge.Statement{Protocol: desktopbridge.ProtocolID, Version: desktopbridge.Version, KeyID: "provider-desktop-v2", ExecutorRole: "desktop", ExecutorIdentity: "executor-desktop-1", ProviderRevisionID: open.ProviderRevisionID, TenantBindingDigest: open.TenantBindingDigest, SandboxID: open.SandboxID, RuntimeSessionID: open.DesktopSessionID, HandoffReferenceDigest: open.HandoffReferenceDigest, AllocationReference: open.AllocationReference, MediaPolicy: policy, ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: open.ConnectionEpoch, Fence: open.Fence, AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt, NotBefore: now.Add(-time.Second).Format(time.RFC3339Nano), ExecutorAuthorityDigest: open.AuthorityDigest, ExecutorRequestDigest: open.RequestDigest, Nonce: "nonce-image-abcdefghijklmnopqrstuvwxyz123456"}
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, err := desktopbridge.Sign(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	open.Bridge = &bridge
	document, err := desktopbroker.EncodeSession(open)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(document); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReaderSize(stdout, desktopbroker.SessionMaxDocument)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var accepted desktopbroker.SessionMessage
	if desktopbroker.DecodeSession(line, &accepted) != nil || accepted.ValidateFor(desktopbroker.SessionProtocolV2ID) != nil || accepted.Type != desktopbroker.SessionAcceptedType {
		t.Fatalf("invalid v2 broker acceptance: %s", line)
	}
	deadline := time.Now().Add(30 * time.Second)
	var keyframe []byte
	var frameTimestamp uint32
	collecting := false
	for {
		if time.Now().After(deadline) {
			t.Fatal("real Desktop broker did not produce a complete VP8 keyframe")
		}
		line, err = reader.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read real Desktop RTP: %v", err)
		}
		var frame desktopbroker.SessionMessage
		if desktopbroker.DecodeSession(line, &frame) == nil && frame.ValidateFor(desktopbroker.SessionProtocolV2ID) == nil && frame.Type == desktopbroker.SessionFrameType {
			payload, decodeErr := base64.StdEncoding.DecodeString(frame.Payload)
			if decodeErr != nil {
				continue
			}
			var packet rtp.Packet
			if packet.Unmarshal(payload) != nil {
				continue
			}
			var vp8 codecs.VP8Packet
			part, partErr := vp8.Unmarshal(packet.Payload)
			if partErr != nil || len(part) == 0 {
				continue
			}
			if vp8.S == 1 && vp8.PID == 0 {
				collecting, frameTimestamp, keyframe = true, packet.Timestamp, keyframe[:0]
			}
			if !collecting || packet.Timestamp != frameTimestamp || len(keyframe)+len(part) > 8<<20 {
				collecting = false
				continue
			}
			keyframe = append(keyframe, part...)
			if packet.Marker {
				if len(keyframe) > 0 && keyframe[0]&1 == 0 {
					break
				}
				collecting = false
			}
		}
	}
	decodeNativeVP8Keyframe(t, ctx, containerName, keyframe)
	input := desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 10, Y: 10, ControlLeaseID: "lease-image-1", ControlFence: 1}
	inputCommand, err := desktopbroker.EncodeSession(desktopbroker.SessionCommand{Protocol: desktopbroker.SessionProtocolV2ID, Type: "input", RequestID: "input-1", Sequence: 1, Input: &input})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write(inputCommand); err != nil {
		t.Fatal(err)
	}
	resultDeadline := time.Now().Add(10 * time.Second)
	for {
		if time.Now().After(resultDeadline) {
			t.Fatal("real Desktop broker did not acknowledge input")
		}
		line, err = reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var result desktopbroker.SessionMessage
		if desktopbroker.DecodeSession(line, &result) != nil || result.ValidateFor(desktopbroker.SessionProtocolV2ID) != nil {
			t.Fatalf("invalid real Desktop input response: %s", line)
		}
		if result.Type == desktopbroker.SessionResultType {
			if !result.OK || result.RequestID != "input-1" || result.Sequence != 1 {
				t.Fatalf("real Desktop input was rejected: %s", line)
			}
			break
		}
		if result.Type != desktopbroker.SessionFrameType {
			t.Fatalf("unexpected real Desktop input ordering: %s", line)
		}
	}
	closeCommand, _ := desktopbroker.EncodeSession(desktopbroker.SessionCommand{Protocol: desktopbroker.SessionProtocolV2ID, Type: "close", RequestID: "close-1", Sequence: 2})
	if _, err := stdin.Write(closeCommand); err != nil {
		t.Fatal(err)
	}
	closeDeadline := time.Now().Add(10 * time.Second)
	for {
		if time.Now().After(closeDeadline) {
			t.Fatal("real Desktop broker did not close v2 session")
		}
		line, err = reader.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var closed desktopbroker.SessionMessage
		if desktopbroker.DecodeSession(line, &closed) != nil || closed.ValidateFor(desktopbroker.SessionProtocolV2ID) != nil {
			t.Fatalf("invalid real Desktop close message: %s", line)
		}
		if closed.Type == desktopbroker.SessionClosedType {
			break
		}
		if closed.Type != desktopbroker.SessionFrameType {
			t.Fatalf("unexpected real Desktop close ordering: %s", line)
		}
	}
	_ = stdin.Close()
	if err := command.Wait(); err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("desktop session helper exit: %v", err)
		}
	}
}

func decodeNativeVP8Keyframe(t *testing.T, ctx context.Context, containerName string, frame []byte) {
	t.Helper()
	if len(frame) == 0 || len(frame) > 8<<20 {
		t.Fatal("invalid complete VP8 keyframe")
	}
	ivf := make([]byte, 32+12+len(frame))
	copy(ivf[:4], "DKIF")
	binary.LittleEndian.PutUint16(ivf[4:6], 0)
	binary.LittleEndian.PutUint16(ivf[6:8], 32)
	copy(ivf[8:12], "VP80")
	binary.LittleEndian.PutUint16(ivf[12:14], 1280)
	binary.LittleEndian.PutUint16(ivf[14:16], 720)
	binary.LittleEndian.PutUint32(ivf[16:20], 30)
	binary.LittleEndian.PutUint32(ivf[20:24], 1)
	binary.LittleEndian.PutUint32(ivf[24:28], 1)
	binary.LittleEndian.PutUint32(ivf[32:36], uint32(len(frame)))
	copy(ivf[44:], frame)
	command := exec.CommandContext(ctx, "docker", "exec", "-i", containerName, "/usr/bin/ffmpeg",
		"-hide_banner", "-loglevel", "error", "-xerror", "-i", "pipe:0",
		"-frames:v", "1", "-an", "-pix_fmt", "rgb24", "-f", "rawvideo", "-")
	command.Stdin = bytes.NewReader(ivf)
	decoded, err := command.Output()
	if err != nil || len(decoded) != 1280*720*3 {
		t.Fatalf("Desktop broker keyframe was not fully client-decodable: bytes=%d err=%v", len(decoded), err)
	}
}

func nativePlatform(t *testing.T) string {
	t.Helper()
	requested := os.Getenv("SANDBOX_RUNTIME_DESKTOP_PLATFORM")
	if requested != "" {
		want := map[string]string{"amd64": "linux/amd64", "arm64": "linux/arm64/v8"}[runtime.GOARCH]
		if requested != want {
			t.Fatalf("native smoke rejects emulated platform %q on %q", requested, runtime.GOARCH)
		}
		return requested
	}
	switch runtime.GOARCH {
	case "amd64":
		return "linux/amd64"
	case "arm64":
		return "linux/arm64/v8"
	default:
		t.Fatalf("unsupported native architecture %q", runtime.GOARCH)
		return ""
	}
}

func waitForBroker(t *testing.T, ctx context.Context, containerName string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		command := exec.CommandContext(ctx, "docker", "exec", containerName, BrokerPath, "probe", "--socket", BrokerSocket)
		if command.Run() == nil {
			return
		}
		state := strings.TrimSpace(run(t, ctx, "docker", "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", containerName))
		if strings.HasPrefix(state, "exited:") {
			t.Fatalf("Desktop runtime exited before broker readiness: %s\n%s", state, run(t, ctx, "docker", "logs", containerName))
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("Desktop broker did not become ready: %s", run(t, ctx, "docker", "logs", containerName))
}

func inspectImagePolicy(t *testing.T, ctx context.Context, imageReference string, manifest Manifest) {
	t.Helper()
	output := run(t, ctx, "docker", "image", "inspect", imageReference)
	var inspected []struct {
		Config struct {
			User         string              `json:"User"`
			WorkingDir   string              `json:"WorkingDir"`
			Entrypoint   []string            `json:"Entrypoint"`
			Labels       map[string]string   `json:"Labels"`
			ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		} `json:"Config"`
	}
	if err := json.Unmarshal([]byte(output), &inspected); err != nil || len(inspected) != 1 {
		t.Fatalf("decode image inspection: %v", err)
	}
	config := inspected[0].Config
	platform := manifest.Source.Manifests[nativePlatform(t)]
	lockPath, err := APKLockPath(nativePlatform(t))
	if err != nil {
		t.Fatal(err)
	}
	lockBytes, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	lockDigest := sha256.Sum256(lockBytes)
	if config.User != "1000:1000" || config.WorkingDir != "/workspace" || strings.Join(config.Entrypoint, "\x00") != Entrypoint || len(config.ExposedPorts) != 0 {
		t.Fatalf("unsafe image identity: user=%q workdir=%q entrypoint=%v ports=%v", config.User, config.WorkingDir, config.Entrypoint, config.ExposedPorts)
	}
	if config.Labels["io.github.shell-echo.sandbox-runtime.profile"] != ProfileID ||
		config.Labels["io.github.shell-echo.sandbox-runtime.candidate-classification"] != "local-candidate-non-release" ||
		config.Labels["io.github.shell-echo.sandbox-runtime.candidate-apk-lock-digest"] != fmt.Sprintf("sha256:%x", lockDigest) ||
		config.Labels["io.github.shell-echo.sandbox-runtime.provenance.source-digest"] != platform.Digest ||
		config.Labels["io.github.shell-echo.sandbox-runtime.package-archive-set-digest"] != platform.PackageArchiveSetDigest ||
		config.Labels["io.github.shell-echo.sandbox-runtime.installed-set-digest"] != platform.InstalledSetDigest {
		t.Fatalf("image provenance labels do not match manifest: %v", config.Labels)
	}
}

func inspectContainerPolicy(t *testing.T, ctx context.Context, containerName string) {
	t.Helper()
	output := run(t, ctx, "docker", "inspect", containerName)
	var inspected []struct {
		HostConfig struct {
			ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
			Privileged     bool     `json:"Privileged"`
			CapDrop        []string `json:"CapDrop"`
			SecurityOpt    []string `json:"SecurityOpt"`
			NetworkMode    string   `json:"NetworkMode"`
			IpcMode        string   `json:"IpcMode"`
			Devices        []any    `json:"Devices"`
			DeviceRequests []any    `json:"DeviceRequests"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal([]byte(output), &inspected); err != nil || len(inspected) != 1 {
		t.Fatalf("decode container inspection: %v", err)
	}
	host := inspected[0].HostConfig
	if !host.ReadonlyRootfs || host.Privileged || !contains(host.CapDrop, "ALL") || !contains(host.SecurityOpt, "no-new-privileges:true") || host.NetworkMode != "none" || host.IpcMode != "private" || len(host.Devices) != 0 || len(host.DeviceRequests) != 0 {
		t.Fatalf("unsafe container policy: %+v", host)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func run(t *testing.T, ctx context.Context, name string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, name, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(arguments, " "), err, output)
	}
	return string(output)
}
