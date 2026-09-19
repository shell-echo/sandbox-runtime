//go:build integration

package image

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
)

const desktopImageIntegrationEnv = "SANDBOX_RUNTIME_DESKTOP_IMAGE_INTEGRATION"

func TestDesktopImageNativeIntegration(t *testing.T) {
	if os.Getenv(desktopImageIntegrationEnv) != "1" {
		t.Skip("set " + desktopImageIntegrationEnv + "=1 to build and test the Desktop image")
	}
	manifest, err := Load(ManifestPath)
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
	mountRoot, err := os.MkdirTemp(".", ".desktop-image-integration-")
	if err != nil {
		t.Fatal(err)
	}
	mountRoot, err = filepath.Abs(mountRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range []string{imageOne, imageTwo} {
		run(t, ctx, "./build.sh", platform, image, "integration-test")
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", containerName).Run()
		_ = exec.CommandContext(cleanupContext, "docker", "image", "rm", imageOne, imageTwo).Run()
		_ = os.RemoveAll(mountRoot)
	})

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
	inspectContainerPolicy(t, ctx, containerName)
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
	if config.User != "1000:1000" || config.WorkingDir != "/workspace" || strings.Join(config.Entrypoint, "\x00") != Entrypoint || len(config.ExposedPorts) != 0 {
		t.Fatalf("unsafe image identity: user=%q workdir=%q entrypoint=%v ports=%v", config.User, config.WorkingDir, config.Entrypoint, config.ExposedPorts)
	}
	if config.Labels["io.github.shell-echo.sandbox-runtime.profile"] != ProfileID ||
		config.Labels["io.github.shell-echo.sandbox-runtime.provenance.source-digest"] != platform.Digest ||
		config.Labels["io.github.shell-echo.sandbox-runtime.package-archive-set-digest"] != platform.PackageArchiveSetDigest {
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
