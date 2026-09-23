//go:build integration

package workloadtlsagent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const dockerTLSImage = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

func TestDockerDistinctUIDTLSAgentSocket(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_TLS_SOCKET_DOCKER") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PHASE6_TLS_SOCKET_DOCKER=1")
	}
	const agentUID, agentGID, roleUID, roleGID = 61001, 61011, 61002, 61012
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	arch, err := dockerTLS(ctx, nil, "version", "--format", "{{.Server.Arch}}")
	arch = strings.TrimSpace(arch)
	if err != nil || (arch != "arm64" && arch != "amd64") {
		t.Fatalf("Docker architecture %q unavailable: %v", arch, err)
	}
	if _, err := dockerTLS(ctx, nil, "image", "inspect", dockerTLSImage); err != nil {
		t.Fatalf("pinned image unavailable: %v", err)
	}
	fixture := filepath.Join(t.TempDir(), "tls-agent-test")
	build := exec.CommandContext(ctx, "go", "test", "-c", "-tags=integration", "-o", fixture, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux TLS agent test fixture: %v: %.2048s", err, output)
	}
	binary, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	socketVolume, binaryVolume, agentContainer := "p6-tls-socket-"+suffix, "p6-tls-binary-"+suffix, "p6-tls-agent-"+suffix
	volumes := []string{}
	agentCreated := false
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if agentCreated {
			_, _ = dockerTLS(cleanupCtx, nil, "rm", "-f", agentContainer)
			if _, err := dockerTLS(cleanupCtx, nil, "inspect", agentContainer); err == nil {
				t.Error("TLS agent container remained")
			}
		}
		for _, volume := range volumes {
			if _, err := dockerTLS(cleanupCtx, nil, "volume", "rm", volume); err != nil {
				t.Errorf("remove exact TLS volume %s: %v", volume, err)
			}
			if _, err := dockerTLS(cleanupCtx, nil, "volume", "inspect", volume); err == nil {
				t.Errorf("TLS volume %s remained", volume)
			}
		}
	})
	for _, volume := range []string{socketVolume, binaryVolume} {
		if _, err := dockerTLS(ctx, nil, "volume", "create", volume); err != nil {
			t.Fatal(err)
		}
		volumes = append(volumes, volume)
	}
	if _, err := dockerTLS(ctx, nil, "run", "--rm", "--network", "none", "-v", socketVolume+":/work", dockerTLSImage,
		"sh", "-c", "chown 61001:61012 /work && chmod 0710 /work"); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerTLS(ctx, binary, "run", "--rm", "-i", "--network", "none", "-v", binaryVolume+":/work", dockerTLSImage,
		"sh", "-c", "cat > /work/fixture && chmod 0755 /work/fixture"); err != nil {
		t.Fatal(err)
	}
	socketMount := "type=volume,src=" + socketVolume + ",dst=/run/agent"
	binaryMount := "type=volume,src=" + binaryVolume + ",dst=/probe,readonly"
	startAgent := func() {
		t.Helper()
		if _, err := dockerTLS(ctx, nil, "run", "-d", "--name", agentContainer, "--network", "none", "--user", "61001:61011",
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", socketMount, "--mount", binaryMount,
			"-e", "SANDBOX_RUNTIME_TLS_SOCKET_CHILD=agent", dockerTLSImage, "/probe/fixture", "-test.run", "^TestDockerChildTLSAgent$"); err != nil {
			t.Fatal(err)
		}
		agentCreated = true
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			logs, err := dockerTLS(ctx, nil, "logs", agentContainer)
			if err == nil && strings.Contains(logs, "TLS_AGENT_READY") {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		logs, err := dockerTLS(ctx, nil, "logs", agentContainer)
		t.Fatalf("distinct-UID agent did not become ready: %v: %.2048s", err, logs)
	}
	startAgent()
	client := func(user, expectation string) error {
		output, err := dockerTLS(ctx, nil, "run", "--rm", "--network", "none", "--user", user,
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", socketMount+",readonly",
			"--mount", binaryMount, "-e", "SANDBOX_RUNTIME_TLS_SOCKET_CHILD=client", "-e", "SANDBOX_RUNTIME_TLS_EXPECT="+expectation,
			dockerTLSImage, "/probe/fixture", "-test.run", "^TestDockerChildTLSClient$")
		if err != nil {
			return fmt.Errorf("TLS client %s: %w: %.2048s", user, err, output)
		}
		return nil
	}
	for _, item := range []struct{ user, expectation string }{
		{"61002:61012", "allow"},
		{"61003:61012", "deny"},
		{"61002:61013", "deny"},
		{"61004:61014", "deny"},
	} {
		if err := client(item.user, item.expectation); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dockerTLS(ctx, nil, "kill", "--signal=KILL", agentContainer); err != nil {
		t.Fatal(err)
	}
	exit, err := dockerTLS(ctx, nil, "wait", agentContainer)
	if err != nil || strings.TrimSpace(exit) != "137" {
		t.Fatalf("killed agent exit = %q, %v", exit, err)
	}
	if err := client("61002:61012", "deny"); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerTLS(ctx, nil, "rm", agentContainer); err != nil {
		t.Fatal(err)
	}
	agentCreated = false
	startAgent()
	if err := client("61002:61012", "allow"); err != nil {
		t.Fatal(err)
	}
	if _, err := dockerTLS(ctx, nil, "kill", "--signal=TERM", agentContainer); err != nil {
		t.Fatal(err)
	}
	exit, err = dockerTLS(ctx, nil, "wait", agentContainer)
	if err != nil || strings.TrimSpace(exit) != "0" {
		t.Fatalf("agent exit = %q, %v", exit, err)
	}
	if err := client("61002:61012", "deny"); err != nil {
		t.Fatal(err)
	}
	t.Log("distinct agent/role UIDs and GIDs, role-only path traversal, wrong UID/GID/extra role denial, signed remote operation, SIGKILL stale-socket recovery, graceful agent-loss denial, exact cleanup")
}

func TestDockerChildTLSAgent(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_TLS_SOCKET_CHILD") != "agent" {
		t.Skip("Docker child only")
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager, _ := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	server, err := Listen(ServerConfig{SocketPath: "/run/agent/agent.sock", SocketUID: uint32(os.Getuid()),
		SocketGID: 61012, AgentGID: uint32(os.Getgid()), ExpectedClientUID: 61002, ExpectedClientGID: 61012,
		MaxConnections: 4, ReplayCapacity: 128, Now: time.Now}, manager)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	fmt.Fprintln(os.Stdout, "TLS_AGENT_READY")
	err = server.Serve(ctx)
	_ = server.Close()
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDockerChildTLSClient(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_TLS_SOCKET_CHILD") != "client" {
		t.Skip("Docker child only")
	}
	client, err := NewProductionClient(ClientConfig{SocketPath: "/run/agent/agent.sock", ExpectedUID: 61001, ExpectedGID: 61011,
		RoleGID: uint32(os.Getgid()), OperationTimeout: time.Second, Now: time.Now})
	if err == nil {
		var snapshot Snapshot
		snapshot, err = client.Snapshot(context.Background())
		if err == nil {
			digest := sha256.Sum256([]byte("distinct UID remote signature"))
			var signature []byte
			signature, err = client.Sign(context.Background(), snapshot.Generation, digest[:], crypto.SHA256)
			if err == nil {
				var publicKey any
				publicKey, err = x509.ParsePKIXPublicKey(snapshot.PublicKeyDER)
				if err == nil {
					key, ok := publicKey.(*ecdsa.PublicKey)
					if !ok || !ecdsa.VerifyASN1(key, digest[:], signature) {
						err = ErrUnavailable
					}
				}
			}
			snapshot.Destroy()
		}
	}
	switch os.Getenv("SANDBOX_RUNTIME_TLS_EXPECT") {
	case "allow":
		if err != nil {
			t.Fatalf("authorized role denied: %v", err)
		}
	case "deny":
		if err == nil {
			t.Fatal("unauthorized or disconnected role received certificate/signature")
		}
	default:
		t.Fatal("missing child expectation")
	}
}

func dockerTLS(ctx context.Context, input []byte, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	}
	output, err := command.CombinedOutput()
	return string(output), err
}
