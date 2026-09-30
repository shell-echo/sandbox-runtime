//go:build integration

package workloadcredentialv2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/credentialbackend"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

const credentialV2DockerImage = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

func TestCredentialV2CrossUIDDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_CREDENTIAL_V2_DOCKER_INTEGRATION") != "1" || os.Getenv("SR_CREDENTIAL_V2_HELPER") != "" {
		t.Skip("explicit Docker integration only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(workspace, "..", "..", "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	policy, err := os.ReadFile(policyPath)
	if err != nil || fmt.Sprintf("sha256:%x", sha256.Sum256(policy)) !=
		"sha256:a7f79239f02d9326e74deb212d2022f4bb2db9e2316367e0d89c9e35f7893eaa" {
		t.Fatalf("source-bound controller/agent seccomp candidate unavailable: %v", err)
	}
	temporary, err := os.MkdirTemp(workspace, ".credential-v2-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(temporary); err != nil {
			t.Errorf("remove exact credential helper build directory: %v", err)
		}
		if _, err := os.Lstat(temporary); !os.IsNotExist(err) {
			t.Errorf("credential helper build directory remains or cleanup is unverified: %v", err)
		}
	})
	binary := filepath.Join(temporary, "helper.test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-tags=integration", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=arm64", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux helper: %v: %s", err, output)
	}
	volume := fmt.Sprintf("sr-credential-v2-%d", time.Now().UnixNano())
	serverName := volume + "-server"
	attackName := volume + "-attack"
	dockerV2(t, ctx, "volume", "create", volume)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, name := range []string{serverName, attackName} {
			if _, err := exec.CommandContext(cleanup, "docker", "container", "inspect", name).CombinedOutput(); err == nil {
				if output, removeErr := exec.CommandContext(cleanup, "docker", "rm", "-f", "-v", name).CombinedOutput(); removeErr != nil {
					t.Errorf("remove exact credential helper %s: %v: %.512s", name, removeErr, output)
				}
			}
			if output, err := exec.CommandContext(cleanup, "docker", "container", "inspect", name).CombinedOutput(); err == nil || !strings.Contains(strings.ToLower(string(output)), "no such") {
				t.Errorf("credential helper %s remains or cleanup is unverified: %v: %.512s", name, err, output)
			}
		}
		if output, err := exec.CommandContext(cleanup, "docker", "volume", "rm", volume).CombinedOutput(); err != nil {
			t.Errorf("remove exact credential helper volume %s: %v: %.512s", volume, err, output)
		}
		if output, err := exec.CommandContext(cleanup, "docker", "volume", "inspect", volume).CombinedOutput(); err == nil || !strings.Contains(strings.ToLower(string(output)), "no such") {
			t.Errorf("credential helper volume %s remains or cleanup is unverified: %v: %.512s", volume, err, output)
		}
	})
	operator := func(script string) string {
		return dockerV2(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared",
			credentialV2DockerImage, "sh", "-ec", script)
	}
	operator("mkdir -p /shared/socket /shared/ledger; chown 20000:30001 /shared/socket; chmod 0710 /shared/socket; chown 20000:30000 /shared/ledger; chmod 0700 /shared/ledger")
	containerArgs := func(user, mode string) []string {
		memory, cpu := "96m", "0.1" // runtime_material_agent candidate tier
		if mode == "server" {
			memory, cpu = "128m", "0.2" // credential_controller candidate tier
		}
		return []string{"--network", "none", "--user", user, "--read-only", "--cap-drop=ALL",
			"--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + policyPath,
			"--memory", memory, "--memory-swap", memory, "--cpus", cpu, "--pids-limit", "32",
			"-v", volume + ":/shared",
			"-v", binary + ":/helper:ro", "-e", "SR_CREDENTIAL_V2_HELPER=" + mode,
			credentialV2DockerImage, "/helper", "-test.run=^TestCredentialV2ContainerHelper$", "-test.v"}
	}
	serverArgs := append([]string{"run", "-d", "--name", serverName}, containerArgs("20000:30000", "server")...)
	dockerV2(t, ctx, serverArgs...)
	var options []string
	if json.Unmarshal([]byte(dockerV2(t, ctx, "inspect", "--format", "{{json .HostConfig.SecurityOpt}}", serverName)), &options) != nil ||
		len(options) != 2 || options[0] != "no-new-privileges:true" || !strings.HasPrefix(options[1], "seccomp=") {
		t.Fatal("credential controller helper did not select explicit candidate seccomp")
	}
	var wanted, applied bytes.Buffer
	if json.Compact(&wanted, policy) != nil ||
		json.Compact(&applied, []byte(strings.TrimPrefix(options[1], "seccomp="))) != nil ||
		!bytes.Equal(wanted.Bytes(), applied.Bytes()) {
		t.Fatal("Docker did not retain exact normalized controller/agent candidate policy")
	}
	status := dockerV2(t, ctx, "exec", serverName, "cat", "/proc/1/status")
	if !strings.Contains(status, "Uid:\t20000\t20000\t20000\t20000") ||
		!strings.Contains(status, "Gid:\t30000\t30000\t30000\t30000") ||
		!strings.Contains(status, "CapEff:\t0000000000000000") ||
		!strings.Contains(status, "NoNewPrivs:\t1") || !strings.Contains(status, "Seccomp:\t2") {
		t.Fatal("credential controller helper active security context drifted")
	}
	cgroup := dockerV2(t, ctx, "exec", serverName, "sh", "-c",
		"cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max")
	if strings.TrimSpace(cgroup) != "134217728\n32\n20000 100000" {
		t.Fatalf("credential controller candidate cgroup limits drifted: %q", cgroup)
	}
	waitLogV2(t, ctx, serverName, "READY")
	for _, scenario := range []struct{ user, mode string }{
		{"20001:30001", "normal"},
		{"20002:30001", "wrong-peer"},
		{"20001:30002", "wrong-gid"},
		{"20001:30001", "no-frame"},
		{"20001:30001", "half-frame"},
		{"20001:30001", "cancel"},
	} {
		args := append([]string{"run", "--rm"}, containerArgs(scenario.user, scenario.mode)...)
		dockerV2(t, ctx, args...)
	}
	operator("chmod 0750 /shared/socket")
	badLayoutArgs := append([]string{"run", "--rm"}, containerArgs("20001:30001", "bad-layout")...)
	dockerV2(t, ctx, badLayoutArgs...)
	operator("chmod 0710 /shared/socket")
	attackArgs := append([]string{"run", "-d", "--name", attackName}, containerArgs("20001:30001", "hold")...)
	dockerV2(t, ctx, attackArgs...)
	waitLogV2(t, ctx, attackName, "HOLD")
	operator("mv /shared/socket/issuer.sock /shared/socket/original.sock; : > /shared/socket/issuer.sock")
	badSocketArgs := append([]string{"run", "--rm"}, containerArgs("20001:30001", "bad-layout")...)
	dockerV2(t, ctx, badSocketArgs...)
	metrics := dockerV2(t, ctx, "exec", serverName, "sh", "-c",
		"cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/pids.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/cpu.stat")
	lines := strings.Split(strings.TrimSpace(metrics), "\n")
	if len(lines) < 9 || !strings.Contains("\n"+metrics, "\noom 0\n") ||
		!strings.Contains("\n"+metrics, "\noom_kill 0\n") {
		t.Fatalf("credential controller helper cgroup observation incomplete: %q", metrics)
	}
	memoryPeak, memoryErr := strconv.ParseInt(lines[0], 10, 64)
	pidsPeak, pidsErr := strconv.ParseInt(lines[1], 10, 64)
	if memoryErr != nil || pidsErr != nil || memoryPeak < 1 || memoryPeak > 128<<20 ||
		pidsPeak < 1 || pidsPeak > 32 {
		t.Fatalf("credential controller helper exceeded finite cgroup limits: %q", metrics)
	}
	t.Logf("credential controller cross-UID helper candidate cgroup sample (includes exec probes): %s", strings.TrimSpace(metrics))
	operator("touch /shared/ledger/stop")
	if code := strings.TrimSpace(dockerV2(t, ctx, "wait", serverName)); code != "0" {
		t.Fatalf("server exit = %s", code)
	}
	if code := strings.TrimSpace(dockerV2(t, ctx, "wait", attackName)); code != "0" {
		t.Fatalf("stalled peer exit = %s", code)
	}
	operator("test -f /shared/socket/issuer.sock; test -S /shared/socket/original.sock")
	dockerV2(t, ctx, "rm", serverName, attackName)
	operator("rm /shared/socket/issuer.sock /shared/socket/original.sock /shared/ledger/stop; test ! -e /shared/socket/issuer.sock")
}

func dockerV2(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("Docker %q: %v: %s", args[:min(len(args), 2)], err, output)
	}
	return string(output)
}

func waitLogV2(t *testing.T, ctx context.Context, container, marker string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if strings.Contains(dockerV2(t, ctx, "logs", container), marker) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("container %s did not reach %s", container, marker)
}

func TestCredentialV2ContainerHelper(t *testing.T) {
	mode := os.Getenv("SR_CREDENTIAL_V2_HELPER")
	if mode == "" {
		t.Skip("container helper only")
	}
	policy, key := containerV2Policy(t)
	socket := "/shared/socket/issuer.sock"
	switch mode {
	case "server":
		now := time.Now().UTC()
		backend := &cancelV2Backend{fakeBackend: &fakeBackend{now: &now}}
		controller, err := NewProductionController(ControllerConfig{LedgerPath: "/shared/ledger/ledger.json", Policies: []Policy{policy},
			Issuer: backend, Overlap: time.Second, Now: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: 20000, SocketGID: 30001,
			ExpectedClientUID: 20001, ExpectedClientGID: 30001, MaxConnections: 4, ReapInterval: time.Second}, controller)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			for {
				if _, err := os.Stat("/shared/ledger/stop"); err == nil {
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
		if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
			// In the substitution case the replacement must remain untouched.
			if info, statErr := os.Lstat(socket); statErr != nil || !info.Mode().IsRegular() {
				t.Fatalf("unexpected socket cleanup = %v", err)
			}
		}
	case "normal":
		client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: 20000, ExpectedGID: 30000,
			DirectoryGID: 30001, Policy: policy, PrivateKey: key, OperationTimeout: 3 * time.Second, Now: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		lease, err := client.Issue(context.Background(), 5*time.Minute)
		if err != nil || lease.Revision != 1 || len(lease.Credential) == 0 {
			t.Fatalf("issue = %#v, %v", lease, err)
		}
		renewed, err := client.Renew(context.Background(), lease, 5*time.Minute)
		if err != nil || renewed.Revision != 2 || renewed.ID != lease.ID {
			t.Fatalf("renew = %#v, %v", renewed, err)
		}
		if client.Status(context.Background(), renewed) != nil || client.Revoke(context.Background(), renewed) != nil {
			t.Fatal("status/revoke failed")
		}
	case "wrong-peer":
		request, err := NewSignedRequest(policy, IssueType, "", 0, time.Minute, time.Now().Add(3*time.Second),
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)), key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		document, err := EncodeRequest(request, policy, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		connection, err := net.DialTimeout("unix", socket, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		if writeFrame(connection, document, MaxRequestBytes) == nil {
			if response, readErr := readFrame(connection, MaxResponseBytes); readErr == nil {
				t.Fatalf("wrong peer accepted: %q", response)
			}
		}
	case "wrong-gid":
		if connection, err := net.DialTimeout("unix", socket, time.Second); err == nil {
			_ = connection.Close()
			t.Fatal("wrong group traversed private directory")
		}
	case "bad-layout":
		if client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: 20000, ExpectedGID: 30000,
			DirectoryGID: 30001, Policy: policy, PrivateKey: key, OperationTimeout: 3 * time.Second, Now: time.Now}); err == nil || client != nil {
			t.Fatal("invalid directory or replaced socket accepted")
		}
	case "cancel":
		client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: 20000, ExpectedGID: 30000,
			DirectoryGID: 30001, Policy: policy, PrivateKey: key, OperationTimeout: 3 * time.Second, Now: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(200 * time.Millisecond); cancel() }()
		started := time.Now()
		if _, err := client.Issue(ctx, time.Minute); !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
			t.Fatalf("cancellation did not promptly close client: %v", err)
		}
	case "no-frame", "half-frame", "hold":
		connection, err := net.DialTimeout("unix", socket, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if mode == "half-frame" {
			_, _ = connection.Write([]byte{0, 0})
		}
		if mode == "hold" {
			fmt.Println("HOLD")
		}
		_ = connection.SetReadDeadline(time.Now().Add(4 * time.Second))
		var one [1]byte
		if count, err := connection.Read(one[:]); count != 0 || err == nil {
			t.Fatalf("stalled connection not closed: %d, %v", count, err)
		}
	default:
		t.Fatalf("unknown helper mode %s", mode)
	}
}

type cancelV2Backend struct{ *fakeBackend }

func (b *cancelV2Backend) IssueScoped(ctx context.Context, spec credentialbackend.IssueSpec) (credentialbackend.IssuedCredential, error) {
	if spec.TTL == time.Minute {
		<-ctx.Done()
		return credentialbackend.IssuedCredential{}, ctx.Err()
	}
	return b.fakeBackend.IssueScoped(ctx, spec)
}

func containerV2Policy(t *testing.T) (Policy, ed25519.PrivateKey) {
	t.Helper()
	digest := func(value byte) string { return "sha256:" + strings.Repeat(string(value), 64) }
	registry, err := securityprincipal.NewRegistry(digest('a'), digest('b'), nil)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.New(securityprincipal.KindController, "certificate_controller", "", digest('c'))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	policy := Policy{ID: "certificate-controller-token", Registry: registry, Principal: principal,
		Purpose: secretref.PurposeWorkloadCredential, BackendID: "vault-primary", BackendPolicy: "certificate-controller-pki",
		MaxTTL: 10 * time.Minute, Renewable: true, PublicKey: key.Public().(ed25519.PublicKey), ExpectedUID: 20001, ExpectedGID: 30001}
	if policy.Validate() != nil {
		t.Fatal("test policy invalid")
	}
	return policy, key
}
