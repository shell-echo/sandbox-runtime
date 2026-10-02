//go:build integration

package workloadagent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const materialV2DockerImage = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

func TestMaterialV2CrossUIDDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_MATERIAL_V2_DOCKER_INTEGRATION") != "1" || os.Getenv("SR_MATERIAL_V2_HELPER") != "" {
		t.Skip("explicit Docker integration only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	buildDir, err := os.MkdirTemp(workspace, ".material-v2-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(buildDir); err != nil {
			t.Errorf("remove exact helper build directory: %v", err)
		}
	})
	binary := filepath.Join(buildDir, "helper.test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-tags=integration", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux helper: %v: %s", err, output)
	}
	volume := fmt.Sprintf("sr-material-v2-%d", time.Now().UnixNano())
	serverName := volume + "-server"
	holdName := volume + "-hold"
	materialDocker(t, ctx, "volume", "create", volume)
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		for _, name := range []string{serverName, holdName} {
			if _, err := exec.CommandContext(cleanup, "docker", "container", "inspect", name).CombinedOutput(); err == nil {
				if output, removeErr := exec.CommandContext(cleanup, "docker", "rm", "-f", "-v", name).CombinedOutput(); removeErr != nil {
					t.Errorf("remove exact helper %s: %v: %.512s", name, removeErr, output)
				}
			}
			if output, err := exec.CommandContext(cleanup, "docker", "container", "inspect", name).CombinedOutput(); err == nil || !strings.Contains(strings.ToLower(string(output)), "no such") {
				t.Errorf("helper %s cleanup unverified: %v: %.512s", name, err, output)
			}
		}
		if output, err := exec.CommandContext(cleanup, "docker", "volume", "rm", volume).CombinedOutput(); err != nil {
			t.Errorf("remove exact volume: %v: %.512s", err, output)
		}
		if output, err := exec.CommandContext(cleanup, "docker", "volume", "inspect", volume).CombinedOutput(); err == nil || !strings.Contains(strings.ToLower(string(output)), "no such") {
			t.Errorf("volume cleanup unverified: %v: %.512s", err, output)
		}
	})
	materialDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", materialV2DockerImage,
		"sh", "-ec", "mkdir /shared/socket; chown 20000:30001 /shared/socket; chmod 0710 /shared/socket")
	container := func(user, mode string) []string {
		return []string{"--network", "none", "--user", user, "--read-only", "--cap-drop=ALL",
			"--security-opt", "no-new-privileges:true", "--memory", "128m", "--memory-swap", "128m",
			"--cpus", "0.2", "--pids-limit", "32", "-v", volume + ":/shared",
			"-v", binary + ":/helper:ro", "-e", "SR_MATERIAL_V2_HELPER=" + mode,
			materialV2DockerImage, "/helper", "-test.run=^TestMaterialV2ContainerHelper$", "-test.v"}
	}
	materialDocker(t, ctx, append([]string{"run", "-d", "--name", serverName}, container("20000:30000", "server")...)...)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(materialDocker(t, ctx, "logs", serverName), "READY") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(materialDocker(t, ctx, "logs", serverName), "READY") {
		t.Fatal("material agent did not become ready")
	}
	for _, scenario := range []struct{ user, mode string }{
		{"20001:30001", "normal"},
		{"20002:30001", "wrong-peer"},
		{"20001:30002", "wrong-gid"},
		{"20001:30001", "no-frame"},
	} {
		materialDocker(t, ctx, append([]string{"run", "--rm"}, container(scenario.user, scenario.mode)...)...)
	}
	materialDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", materialV2DockerImage,
		"sh", "-ec", "touch /shared/block")
	materialDocker(t, ctx, append([]string{"run", "--rm"}, container("20001:30001", "cancel")...)...)
	materialDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", materialV2DockerImage,
		"sh", "-ec", "rm /shared/block")
	materialDocker(t, ctx, append([]string{"run", "-d", "--name", holdName}, container("20001:30001", "hold")...)...)
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(materialDocker(t, ctx, "logs", holdName), "HOLD") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(materialDocker(t, ctx, "logs", holdName), "HOLD") {
		t.Fatal("stalled material client did not connect")
	}
	materialDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", materialV2DockerImage,
		"sh", "-ec", "touch /shared/stop")
	if code := strings.TrimSpace(materialDocker(t, ctx, "wait", serverName)); code != "0" {
		t.Fatalf("server exit = %s; logs: %s", code, materialDocker(t, ctx, "logs", serverName))
	}
	if code := strings.TrimSpace(materialDocker(t, ctx, "wait", holdName)); code != "0" {
		t.Fatalf("stalled client exit = %s; logs: %s", code, materialDocker(t, ctx, "logs", holdName))
	}
	materialDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", materialV2DockerImage,
		"sh", "-ec", "test ! -e /shared/socket/agent.sock; rm /shared/stop")
	materialDocker(t, ctx, "rm", serverName, holdName)
}

func materialDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("Docker %q: %v: %s", args[:min(len(args), 2)], err, output)
	}
	return string(output)
}

type materialV2Provider struct{ base *agentMaterialProvider }

func (p *materialV2Provider) ResolveSecret(ctx context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	if _, err := os.Stat("/shared/block"); err == nil {
		<-ctx.Done()
		return secretref.SecretMaterial{}, ctx.Err()
	}
	return p.base.ResolveSecret(ctx, binding)
}

func TestMaterialV2ContainerHelper(t *testing.T) {
	mode := os.Getenv("SR_MATERIAL_V2_HELPER")
	if mode == "" {
		t.Skip("container helper only")
	}
	path := "/shared/socket/agent.sock"
	binding := agentTestBinding(secretref.RoleProduct)
	switch mode {
	case "server":
		now := time.Now().UTC()
		value := []byte("cross-uid material")
		provider := &agentMaterialProvider{binding: binding, material: secretref.SecretMaterial{
			Binding: binding, Bytes: value, Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(value)), Revision: "revision-1",
			Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive},
		}}
		server, err := ListenV2(ServerConfig{DeploymentName: "product-runtime-agent", SocketPath: path,
			SocketUID: 20000, SocketGID: 30001, ExpectedClientUID: 20001, ExpectedClientGID: 30001,
			Role: secretref.RoleProduct, AllowedPurposes: []secretref.Purpose{binding.Purpose},
			Bindings: []secretref.Binding{binding}, MaxConnections: 4, MaxOperationSeconds: 3, Now: time.Now}, &materialV2Provider{base: provider})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for {
				if _, err := os.Stat("/shared/stop"); err == nil {
					cancel()
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}()
		fmt.Println("READY")
		if err := server.Serve(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve = %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket inode not removed: %v", err)
		}
	case "normal":
		client, err := NewProductionV2(Config{SocketPath: path, ExpectedUID: 20000, ExpectedGID: 30000,
			Role: secretref.RoleProduct, OperationTimeout: 3 * time.Second, Now: time.Now}, 30001)
		if err != nil {
			t.Fatal(err)
		}
		material, err := client.ResolveSecret(context.Background(), binding)
		if err != nil || string(material.Bytes) != "cross-uid material" {
			t.Fatalf("ResolveSecret = %#v, %v", material, err)
		}
		material.Destroy()
	case "wrong-peer":
		connection, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := ReadFrame(connection, maxResponseBytes); err == nil {
			t.Fatal("third-party UID received material")
		}
	case "wrong-gid":
		if connection, err := net.DialTimeout("unix", path, time.Second); err == nil {
			_ = connection.Close()
			t.Fatal("third-party GID traversed restricted directory")
		}
	case "no-frame":
		connection, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(4 * time.Second))
		var probe [1]byte
		if _, err := connection.Read(probe[:]); err == nil {
			t.Fatal("stalled peer was not closed")
		}
	case "cancel":
		client, err := NewProductionV2(Config{SocketPath: path, ExpectedUID: 20000, ExpectedGID: 30000,
			Role: secretref.RoleProduct, OperationTimeout: 3 * time.Second, Now: time.Now}, 30001)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(200 * time.Millisecond); cancel() }()
		started := time.Now()
		if _, err := client.ResolveSecret(ctx, binding); !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
			t.Fatalf("cancellation did not promptly close material request: %v", err)
		}
	case "hold":
		connection, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		fmt.Println("HOLD")
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		var probe [1]byte
		if _, err := connection.Read(probe[:]); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("draining server left stalled connection open: %v", err)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
