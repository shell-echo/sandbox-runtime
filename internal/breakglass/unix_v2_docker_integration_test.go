//go:build integration

package breakglass

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

const breakGlassV2DockerImage = "alpine@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0"

func TestBreakGlassV2CrossUIDDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BREAK_GLASS_V2_DOCKER_INTEGRATION") != "1" || os.Getenv("SR_BREAK_GLASS_V2_HELPER") != "" {
		t.Skip("explicit Docker integration only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	buildDir, err := os.MkdirTemp(workspace, ".break-glass-v2-docker-")
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
	volume := fmt.Sprintf("sr-break-glass-v2-%d", time.Now().UnixNano())
	serverName, holdName := volume+"-server", volume+"-hold"
	breakGlassDocker(t, ctx, "volume", "create", volume)
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
	breakGlassDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", breakGlassV2DockerImage,
		"sh", "-ec", "mkdir /shared/control /shared/consume /shared/state; chown 20030:30091 /shared/control; chown 20030:30031 /shared/consume; chown 20030:30030 /shared/state; chmod 0710 /shared/control /shared/consume; chmod 0700 /shared/state")
	container := func(user, mode string) []string {
		return []string{"--network", "none", "--user", user, "--read-only", "--cap-drop=ALL",
			"--security-opt", "no-new-privileges:true", "--memory", "128m", "--memory-swap", "128m",
			"--cpus", "0.2", "--pids-limit", "32", "-v", volume + ":/shared",
			"-v", binary + ":/helper:ro", "-e", "SR_BREAK_GLASS_V2_HELPER=" + mode,
			breakGlassV2DockerImage, "/helper", "-test.run=^TestBreakGlassV2ContainerHelper$", "-test.v"}
	}
	breakGlassDocker(t, ctx, append([]string{"run", "-d", "--name", serverName}, container("20030:30030", "server")...)...)
	breakGlassWaitLog(t, ctx, serverName, "READY")
	for _, scenario := range []struct{ user, mode string }{
		{"20091:30091", "control-submit"},
		{"20031:30031", "consume-denied"},
		{"20092:30091", "wrong-peer"},
		{"20091:30092", "wrong-gid"},
	} {
		breakGlassDocker(t, ctx, append([]string{"run", "--rm"}, container(scenario.user, scenario.mode)...)...)
	}
	breakGlassDocker(t, ctx, append([]string{"run", "-d", "--name", holdName}, container("20091:30091", "hold")...)...)
	breakGlassWaitLog(t, ctx, holdName, "HOLD")
	breakGlassDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", breakGlassV2DockerImage,
		"sh", "-ec", "touch /shared/stop")
	for _, name := range []string{serverName, holdName} {
		if code := strings.TrimSpace(breakGlassDocker(t, ctx, "wait", name)); code != "0" {
			t.Fatalf("%s exit = %s; logs: %s", name, code, breakGlassDocker(t, ctx, "logs", name))
		}
	}
	breakGlassDocker(t, ctx, "run", "--rm", "--network", "none", "-v", volume+":/shared", breakGlassV2DockerImage,
		"sh", "-ec", "test ! -e /shared/control/controller.sock; test ! -e /shared/consume/controller.sock; test -s /shared/state/ledger.json; test -s /shared/state/audit.ndjson; rm /shared/stop")
	breakGlassDocker(t, ctx, "rm", serverName, holdName)
}

func breakGlassDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("Docker %q: %v: %s", args[:min(len(args), 2)], err, output)
	}
	return string(output)
}

func breakGlassWaitLog(t *testing.T, ctx context.Context, name, marker string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(breakGlassDocker(t, ctx, "logs", name), marker) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("helper %s did not reach %s", name, marker)
}

func breakGlassV2Key(index byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{index}, ed25519.SeedSize))
}

func TestBreakGlassV2ContainerHelper(t *testing.T) {
	mode := os.Getenv("SR_BREAK_GLASS_V2_HELPER")
	if mode == "" {
		t.Skip("container helper only")
	}
	control := "/shared/control/controller.sock"
	consume := "/shared/consume/controller.sock"
	switch mode {
	case "server":
		actors := []Actor{
			{ID: "requester-a", Kind: ActorRequester, PublicKey: breakGlassV2Key(1).Public().(ed25519.PublicKey)},
			{ID: "approver-a", Kind: ActorApprover, PublicKey: breakGlassV2Key(2).Public().(ed25519.PublicKey)},
			{ID: "approver-b", Kind: ActorApprover, PublicKey: breakGlassV2Key(3).Public().(ed25519.PublicKey)},
			{ID: "operator-a", Kind: ActorOperator, PublicKey: breakGlassV2Key(4).Public().(ed25519.PublicKey)},
			{ID: "guest-agent", Kind: ActorTarget, PublicKey: breakGlassV2Key(5).Public().(ed25519.PublicKey)},
		}
		controller, err := NewProduction(Config{LedgerPath: "/shared/state/ledger.json", AuditPath: "/shared/state/audit.ndjson",
			Actors: actors, ControllerPrivateKey: breakGlassV2Key(6), MaxTTL: 15 * time.Minute, Now: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		defer controller.Close()
		operatorServer, err := ListenV2Controller(V2ControllerServerConfig{ServerConfig: ServerConfig{
			SocketPath: control, SocketUID: 20030, SocketGID: 30091, ExpectedClientUID: 20091,
			ExpectedClientGID: 30091, MaxConnections: 4}, Kind: "control"}, controller)
		if err != nil {
			t.Fatal(err)
		}
		defer operatorServer.Close()
		agentServer, err := ListenV2Controller(V2ControllerServerConfig{ServerConfig: ServerConfig{
			SocketPath: consume, SocketUID: 20030, SocketGID: 30031, ExpectedClientUID: 20031,
			ExpectedClientGID: 30031, MaxConnections: 4}, Kind: "consume", TargetAgentID: "guest-agent"}, controller)
		if err != nil {
			t.Fatal(err)
		}
		defer agentServer.Close()
		ctx, cancel := context.WithCancel(context.Background())
		results := make(chan error, 2)
		go func() { results <- operatorServer.Serve(ctx) }()
		go func() { results <- agentServer.Serve(ctx) }()
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
		for range 2 {
			if err := <-results; !errors.Is(err, context.Canceled) {
				t.Fatalf("Serve = %v", err)
			}
		}
		for _, path := range []string{control, consume} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("controller socket retained: %v", err)
			}
		}
	case "control-submit":
		deadline := time.Now().Add(20 * time.Second)
		request, err := NewSignedAccessRequest(AccessRequest{RequestID: "bgreq_" + strings.Repeat("a", 32),
			RequesterID: "requester-a", TargetAgentID: "guest-agent", Role: secretref.RoleGuest,
			Purpose: secretref.PurposeGuestSigningKey, BindingDigest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("binding"))),
			TenantID: secretref.SystemTenant, Operation: "material.resolve",
			ReasonDigest:        fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("reason"))),
			TicketDigest:        fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("ticket"))),
			RequestedTTLSeconds: 60, Deadline: deadline.UTC().Format(time.RFC3339Nano),
			JTI: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}, breakGlassV2Key(1))
		if err != nil {
			t.Fatal(err)
		}
		response, err := CallV2(context.Background(), V2ControllerClientConfig{SocketPath: control,
			ExpectedUID: 20030, ExpectedGID: 30030, DirectoryGID: 30091, Kind: "control"},
			WireRequest{Protocol: ProtocolID, Type: SubmitType, Request: &request})
		if err != nil || response.Revision != 1 {
			t.Fatalf("signed cross-UID submit = %#v, %v", response, err)
		}
		if _, err := CallV2(context.Background(), V2ControllerClientConfig{SocketPath: control,
			ExpectedUID: 20030, ExpectedGID: 30030, DirectoryGID: 30091, Kind: "control"},
			WireRequest{Protocol: ProtocolID, Type: ConsumeType, Consume: &Consume{}}); err == nil {
			t.Fatal("operator control socket accepted consume")
		}
	case "consume-denied":
		consumeRequest := Consume{TargetAgentID: "guest-agent", Capability: Capability{TargetAgentID: "guest-agent"}}
		if _, err := CallV2(context.Background(), V2ControllerClientConfig{SocketPath: consume,
			ExpectedUID: 20030, ExpectedGID: 30030, DirectoryGID: 30031, Kind: "consume", TargetAgentID: "guest-agent"},
			WireRequest{Protocol: ProtocolID, Type: ConsumeType, Consume: &consumeRequest}); !errors.Is(err, ErrDenied) {
			t.Fatalf("unsigned consume was not denied by business verifier: %v", err)
		}
		if _, err := CallV2(context.Background(), V2ControllerClientConfig{SocketPath: consume,
			ExpectedUID: 20030, ExpectedGID: 30030, DirectoryGID: 30031, Kind: "consume", TargetAgentID: "guest-agent"},
			WireRequest{Protocol: ProtocolID, Type: SubmitType, Request: &AccessRequest{}}); err == nil {
			t.Fatal("agent consume socket accepted control operation")
		}
	case "wrong-peer":
		connection, err := net.DialTimeout("unix", control, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := readFrame(connection, maxResponseBytes); err == nil {
			t.Fatal("third-party UID received controller response")
		}
	case "wrong-gid":
		if connection, err := net.DialTimeout("unix", control, time.Second); err == nil {
			_ = connection.Close()
			t.Fatal("third-party GID traversed controller directory")
		}
	case "hold":
		connection, err := net.DialTimeout("unix", control, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		fmt.Println("HOLD")
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		var probe [1]byte
		if _, err := connection.Read(probe[:]); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("controller drain left stalled peer open: %v", err)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
