//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const dnsInspectorIntegrationEnv = "SANDBOX_RUNTIME_PHASE6_DNS_INSPECTOR_INTEGRATION"
const dnsInspectorImage = "docker.io/coredns/coredns@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"

func TestStockCoreDNSFixedProcessInspector(t *testing.T) {
	if os.Getenv(dnsInspectorIntegrationEnv) != "1" {
		t.Skip("set " + dnsInspectorIntegrationEnv + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	directory, err := os.MkdirTemp(".", ".sr-dns-inspector-")
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(directory, "inspector")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", binaryPath, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOARM64=v8.0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixed static inspector: %v: %s", err, output)
	}
	if err := os.Chmod(binaryPath, 0o555); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(binaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || info.Mode().Perm() != 0o555 {
		t.Fatal("inspector executable mode drift")
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil || len(binary) < 1 || len(binary) > 16<<20 {
		t.Fatal("bounded inspector binary unavailable")
	}
	binaryHash := sha256.Sum256(binary)
	source, err := os.ReadFile("main.go")
	if err != nil || len(source) < 1 || len(source) > 16<<10 {
		t.Fatal("inspector source unavailable")
	}
	sourceHash := sha256.Sum256(source)
	if output, err := exec.CommandContext(ctx, "docker", "image", "inspect", dnsInspectorImage).CombinedOutput(); err != nil {
		t.Fatalf("locked stock CoreDNS image unavailable: %v: %s", err, output)
	}
	container := fmt.Sprintf("sr-dns-inspector-%d", time.Now().UnixNano())
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			cleanupCtx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			if output, err := exec.CommandContext(cleanupCtx, "docker", "rm", "-f", container).CombinedOutput(); err != nil {
				t.Errorf("remove exact CoreDNS diagnostic container: %v: %.512s", err, output)
			}
			if output, err := exec.CommandContext(cleanupCtx, "docker", "ps", "-aq", "--filter", "name=^/"+container+"$").Output(); err != nil || len(bytes.TrimSpace(output)) != 0 {
				t.Error("CoreDNS diagnostic container remained after cleanup")
			}
		}
	})
	mount := "type=bind,source=" + binaryPath + ",target=/phase6-dns-status-inspector,readonly"
	cmd := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container,
		"--network", "none", "--user", "65532:65532", "--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE",
		"--security-opt", "no-new-privileges:true", "--read-only", "--mount", mount,
		dnsInspectorImage)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("launch stock CoreDNS with fixed read-only inspector: %v: %s", err, output)
	}
	var before dnsInspectorState
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		before = inspectDNSInspectorContainer(t, ctx, container)
		if before.State.Running && before.State.Pid > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("CoreDNS inspector boundary: ID=%s running=%v pid=%d restarts=%d image=%s user=%s host=%+v mounts=%+v",
		before.ID, before.State.Running, before.State.Pid, before.RestartCount,
		before.Config.Image, before.Config.User, before.HostConfig, before.Mounts)
	if !before.State.Running || before.State.Pid < 1 || before.Config.Image != dnsInspectorImage ||
		len(before.Config.Entrypoint) != 1 || before.Config.Entrypoint[0] != "/coredns" ||
		before.Config.User != "65532:65532" || before.RestartCount != 0 ||
		len(before.HostConfig.CapDrop) != 1 || before.HostConfig.CapDrop[0] != "ALL" ||
		len(before.HostConfig.CapAdd) != 1 || before.HostConfig.CapAdd[0] != "CAP_NET_BIND_SERVICE" ||
		!before.HostConfig.ReadonlyRootfs || len(before.Mounts) != 1 ||
		before.Mounts[0].Destination != "/phase6-dns-status-inspector" || before.Mounts[0].RW ||
		len(before.HostConfig.PortBindings) != 0 {
		t.Fatal("CoreDNS gate-only inspector Docker boundary drifted")
	}
	execCtx, execCancel := context.WithTimeout(ctx, 3*time.Second)
	defer execCancel()
	status, err := exec.CommandContext(execCtx, "docker", "exec", "--user", "65532:65532",
		container, "/phase6-dns-status-inspector").Output()
	if err != nil || len(status) < 1 || len(status) > maxStatusBytes {
		t.Fatalf("bounded fixed CoreDNS process inspection failed: %v", err)
	}
	after := inspectDNSInspectorContainer(t, ctx, container)
	if !after.State.Running || after.ID != before.ID || after.State.Pid != before.State.Pid ||
		after.State.StartedAt != before.State.StartedAt || after.RestartCount != before.RestartCount ||
		after.Image != before.Image || after.Config.Image != before.Config.Image ||
		len(after.Config.Entrypoint) != 1 || after.Config.Entrypoint[0] != "/coredns" {
		t.Fatal("CoreDNS process restarted or changed during inspector exec")
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(status), "\n") {
		name, value, found := strings.Cut(line, ":")
		if found {
			fields[name] = strings.Join(strings.Fields(value), " ")
		}
	}
	if fields["Name"] != "coredns" || fields["Pid"] != "1" ||
		fields["Uid"] != "65532 65532 65532 65532" ||
		fields["Gid"] != "65532 65532 65532 65532" ||
		fields["NoNewPrivs"] != "1" || fields["Seccomp"] != "2" {
		t.Fatalf("effective CoreDNS PID 1 identity/security drift: %q", status)
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value := fields[name]
		if len(value) != 16 {
			t.Fatalf("missing effective CoreDNS %s", name)
		}
		bits, err := strconv.ParseUint(value, 16, 64)
		if err != nil || bits&^uint64(0x400) != 0 || name == "CapBnd" && bits != 0x400 {
			t.Fatalf("extra or missing CoreDNS capability %s=%s", name, value)
		}
	}
	t.Logf("fixed inspector source=sha256:%s binary=sha256:%s CoreDNS caps Inh=%s Prm=%s Eff=%s Bnd=%s Amb=%s",
		hex.EncodeToString(sourceHash[:]), hex.EncodeToString(binaryHash[:]),
		fields["CapInh"], fields["CapPrm"], fields["CapEff"], fields["CapBnd"], fields["CapAmb"])
	if output, err := exec.CommandContext(ctx, "docker", "rm", "-f", container).CombinedOutput(); err != nil {
		t.Fatalf("remove exact CoreDNS diagnostic container: %v: %s", err, output)
	}
	cleaned = true
	if output, _ := exec.CommandContext(ctx, "docker", "ps", "-aq", "--filter", "name=^/"+container+"$").Output(); len(bytes.TrimSpace(output)) != 0 {
		t.Fatal("CoreDNS diagnostic container remained")
	}
}

type dnsInspectorState struct {
	ID           string `json:"Id"`
	Image        string `json:"Image"`
	RestartCount int    `json:"RestartCount"`
	Config       struct {
		Image      string   `json:"Image"`
		User       string   `json:"User"`
		Entrypoint []string `json:"Entrypoint"`
	} `json:"Config"`
	State struct {
		Running   bool   `json:"Running"`
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	HostConfig struct {
		CapDrop        []string       `json:"CapDrop"`
		CapAdd         []string       `json:"CapAdd"`
		ReadonlyRootfs bool           `json:"ReadonlyRootfs"`
		PortBindings   map[string]any `json:"PortBindings"`
	} `json:"HostConfig"`
	Mounts []struct {
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
}

func inspectDNSInspectorContainer(t *testing.T, ctx context.Context, container string) dnsInspectorState {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", "inspect", container).Output()
	if err != nil || len(output) < 1 || len(output) > 2<<20 {
		t.Fatalf("read exact CoreDNS container inspect: %v", err)
	}
	var values []dnsInspectorState
	if json.Unmarshal(output, &values) != nil || len(values) != 1 {
		t.Fatal("invalid CoreDNS container inspect")
	}
	return values[0]
}
