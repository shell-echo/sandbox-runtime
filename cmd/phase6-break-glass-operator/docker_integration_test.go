//go:build integration

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/breakglass"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const operatorCarrier = "docker.io/library/alpine@" + phase6security.Slice6BreakGlassCarrierIndexDigest

func TestFiniteBreakGlassOperatorDocker(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_BREAK_GLASS_OPERATOR_DOCKER_INTEGRATION") != "1" || os.Getenv("SR_PHASE6_BREAK_GLASS_SERVER") != "" {
		t.Skip("explicit Linux Docker component gate only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	workspace, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(workspace, ".break-glass-operator-docker-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove exact operator build directory: %v", err)
		}
	})
	operatorBinary, helperBinary := filepath.Join(root, "phase6-break-glass-operator"), filepath.Join(root, "server.test")
	for _, spec := range []struct {
		output string
		args   []string
	}{
		{operatorBinary, []string{"build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", operatorBinary, "."}},
		{helperBinary, []string{"test", "-c", "-tags=integration", "-o", helperBinary, "."}},
	} {
		build := exec.CommandContext(ctx, "go", spec.args...)
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build Linux component executable: %v: %.512s", err, output)
		}
	}
	if err := os.Chmod(operatorBinary, 0o555); err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(operatorBinary)
	if err != nil || len(source) < 1 || len(source) > 32<<20 {
		t.Fatal("bounded operator executable unavailable")
	}
	sourceSum := sha256.Sum256(source)
	clear(source)
	id := fmt.Sprintf("sr-p6-break-glass-operator-%d", time.Now().UnixNano())
	controlVolume, stateVolume := id+"-control", id+"-state"
	serverName, operatorName := id+"-server", id+"-task"
	for _, volume := range []string{controlVolume, stateVolume} {
		operatorDocker(t, ctx, "volume", "create", volume)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		for _, name := range []string{operatorName, serverName} {
			_, _ = exec.CommandContext(cleanup, "docker", "rm", "-f", "-v", name).CombinedOutput()
			if output, err := exec.CommandContext(cleanup, "docker", "container", "inspect", name).CombinedOutput(); err == nil || !strings.Contains(strings.ToLower(string(output)), "no such") {
				t.Errorf("container %s not cleaned: %v", name, err)
			}
		}
		for _, volume := range []string{controlVolume, stateVolume} {
			if output, err := exec.CommandContext(cleanup, "docker", "volume", "rm", volume).CombinedOutput(); err != nil {
				t.Errorf("remove %s: %v: %.256s", volume, err, output)
			}
			if output, err := exec.CommandContext(cleanup, "docker", "volume", "inspect", volume).CombinedOutput(); err == nil || !strings.Contains(strings.ToLower(string(output)), "no such") {
				t.Errorf("volume %s not cleaned: %v", volume, err)
			}
		}
	})
	operatorDocker(t, ctx, "pull", "--platform", "linux/arm64", operatorCarrier)
	verifyOperatorCarrier(t, ctx)
	operatorDocker(t, ctx, "run", "--rm", "--network=none", "-v", controlVolume+":/socket", "-v", stateVolume+":/state",
		operatorCarrier, "sh", "-ec", "chown 20030:30091 /socket; chmod 0710 /socket; chown 20030:30030 /state; chmod 0700 /state")
	socketPath := "/run/phase6/break-glass/controller/operator/break-glass.sock"
	operatorDocker(t, ctx, "run", "-d", "--name", serverName, "--network=none", "--user", "20030:30030",
		"--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--memory=128m", "--cpus=0.2", "--pids-limit=32",
		"--mount", "type=volume,src="+controlVolume+",dst="+filepath.Dir(socketPath),
		"--mount", "type=volume,src="+stateVolume+",dst=/state",
		"--mount", "type=bind,src="+helperBinary+",dst=/server.test,readonly",
		"--env", "SR_PHASE6_BREAK_GLASS_SERVER=1", "--entrypoint=/server.test", operatorCarrier,
		"-test.run=^TestFiniteOperatorServerHelper$", "-test.v")
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(operatorDocker(t, ctx, "logs", serverName), "READY") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(operatorDocker(t, ctx, "logs", serverName), "READY") {
		t.Fatal("real controller helper did not start")
	}
	seccompPath := filepath.Join("..", "..", "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json")
	absoluteSeccomp, err := filepath.Abs(seccompPath)
	if err != nil {
		t.Fatal(err)
	}
	operatorDocker(t, ctx, "create", "-i", "--name", operatorName, "--pull=never", "--log-driver=none", "--network=none",
		"--restart=no", "--user=20091:30091", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--security-opt", "seccomp="+absoluteSeccomp, "--read-only", "--memory=64m", "--cpus=0.1", "--pids-limit=16",
		"--mount", "type=bind,src="+operatorBinary+",dst=/phase6-break-glass-operator,readonly",
		"--mount", "type=volume,src="+controlVolume+",dst="+filepath.Dir(socketPath)+",readonly",
		"--entrypoint=/phase6-break-glass-operator", operatorCarrier)
	verifyCreatedOperator(t, ctx, operatorName, operatorBinary, controlVolume, sourceSum)
	request, err := breakglass.NewSignedAccessRequest(breakglass.AccessRequest{
		RequestID: "bgreq_" + strings.Repeat("a", 32), RequesterID: "requester-a", TargetAgentID: "guest-agent",
		Role: secretref.RoleGuest, Purpose: secretref.PurposeGuestSigningKey, TenantID: secretref.SystemTenant,
		Operation: "material.resolve", BindingDigest: operatorTestDigest("binding"),
		ReasonDigest: operatorTestDigest("reason"), TicketDigest: operatorTestDigest("ticket"),
		RequestedTTLSeconds: 60, Deadline: time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano),
		JTI: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
	}, operatorTestKey(1))
	if err != nil {
		t.Fatal(err)
	}
	input := inputDocument{Protocol: inputProtocol, Operation: breakglass.SubmitType, SocketPath: socketPath,
		ExpectedUID: 20030, ExpectedGID: 30030, DirectoryGID: 30091,
		Request: &breakglass.WireRequest{Protocol: breakglass.ProtocolID, Type: breakglass.SubmitType, Request: &request}}
	document, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	start := exec.CommandContext(ctx, "docker", "start", "-a", "-i", operatorName)
	start.Stdin = bytes.NewReader(document)
	response, err := start.CombinedOutput()
	var result outputDocument
	if err != nil || len(response) > 128<<10 || json.Unmarshal(bytes.TrimSpace(response), &result) != nil ||
		result.Status != "ok" || result.Revision != 1 || result.Capability != nil {
		t.Fatalf("one-shot signed request did not complete: %v: %.256s", err, response)
	}
	operatorDocker(t, ctx, "run", "--rm", "--network=none", "-v", stateVolume+":/state", operatorCarrier, "sh", "-ec", "touch /state/stop")
	if code := strings.TrimSpace(operatorDocker(t, ctx, "wait", serverName)); code != "0" {
		t.Fatalf("server exit=%s", code)
	}
	operatorDocker(t, ctx, "run", "--rm", "--network=none", "-v", controlVolume+":/socket", "-v", stateVolume+":/state",
		operatorCarrier, "sh", "-ec", "test ! -e /socket/break-glass.sock; test -s /state/ledger.json; test -s /state/audit.ndjson")
	operatorDocker(t, ctx, "rm", operatorName, serverName)
}

func verifyCreatedOperator(t *testing.T, ctx context.Context, container, binaryPath, volume string, expected [32]byte) {
	t.Helper()
	document := operatorDocker(t, ctx, "inspect", container)
	var observed []struct {
		Image  string `json:"Image"`
		Config struct {
			Image      string   `json:"Image"`
			User       string   `json:"User"`
			Entrypoint []string `json:"Entrypoint"`
			Cmd        []string `json:"Cmd"`
			Tty        bool     `json:"Tty"`
		} `json:"Config"`
		HostConfig struct {
			NetworkMode    string   `json:"NetworkMode"`
			ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
			Privileged     bool     `json:"Privileged"`
			CapDrop        []string `json:"CapDrop"`
			CapAdd         []string `json:"CapAdd"`
			SecurityOpt    []string `json:"SecurityOpt"`
			Memory         int64    `json:"Memory"`
			NanoCPUs       int64    `json:"NanoCpus"`
			PidsLimit      int64    `json:"PidsLimit"`
			LogConfig      struct {
				Type string `json:"Type"`
			} `json:"LogConfig"`
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
			PortBindings map[string]any `json:"PortBindings"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Name        string `json:"Name"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if json.Unmarshal([]byte(document), &observed) != nil || len(observed) != 1 {
		t.Fatal("operator inspect unavailable")
	}
	c := observed[0]
	seccomp, err := os.ReadFile(filepath.Join("..", "..", "profiles", "phase6", "security", "go-controller-agent-seccomp-arm64.json"))
	var compactSeccomp bytes.Buffer
	if err != nil || json.Compact(&compactSeccomp, seccomp) != nil {
		t.Fatal("operator seccomp source unavailable")
	}
	if c.Image != phase6security.Slice6BreakGlassCarrierIndexDigest ||
		c.Config.Image != operatorCarrier || c.Config.User != "20091:30091" || c.Config.Tty ||
		!slices.Equal(c.Config.Entrypoint, []string{"/phase6-break-glass-operator"}) || len(c.Config.Cmd) != 0 ||
		c.HostConfig.NetworkMode != "none" || !c.HostConfig.ReadonlyRootfs || c.HostConfig.Privileged ||
		!slices.Equal(c.HostConfig.CapDrop, []string{"ALL"}) || len(c.HostConfig.CapAdd) != 0 ||
		c.HostConfig.Memory != 64<<20 || c.HostConfig.NanoCPUs != 100000000 || c.HostConfig.PidsLimit != 16 ||
		c.HostConfig.LogConfig.Type != "none" || c.HostConfig.RestartPolicy.Name != "no" ||
		len(c.HostConfig.PortBindings) != 0 ||
		!slices.Contains(c.HostConfig.SecurityOpt, "no-new-privileges:true") ||
		!slices.Contains(c.HostConfig.SecurityOpt, "seccomp="+compactSeccomp.String()) || len(c.Mounts) != 2 {
		t.Fatal("operator effective restrictions drift")
	}
	seenBinary, seenSocket := false, false
	for _, mount := range c.Mounts {
		if mount.Type == "bind" && mount.Source == binaryPath && mount.Destination == "/phase6-break-glass-operator" && !mount.RW {
			seenBinary = true
		}
		if mount.Type == "volume" && mount.Name == volume && mount.Destination == "/run/phase6/break-glass/controller/operator" && !mount.RW {
			seenSocket = true
		}
	}
	if !seenBinary || !seenSocket {
		t.Fatal("operator mount set widened or source changed")
	}
	archive := operatorDocker(t, ctx, "cp", container+":/phase6-break-glass-operator", "-")
	reader := tar.NewReader(bytes.NewReader([]byte(archive)))
	header, err := reader.Next()
	if err != nil || header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > 32<<20 || header.Mode&0o777 != 0o555 {
		t.Fatal("mounted executable type/mode/size drift")
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, reader, header.Size); err != nil {
		t.Fatal("mounted executable truncated")
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) || !bytes.Equal(hash.Sum(nil), expected[:]) {
		t.Fatal("mounted executable bytes differ from built artifact")
	}
}

func verifyOperatorCarrier(t *testing.T, ctx context.Context) {
	t.Helper()
	image := operatorDocker(t, ctx, "image", "inspect", operatorCarrier)
	var inspected []struct {
		ID           string   `json:"Id"`
		OS           string   `json:"Os"`
		Architecture string   `json:"Architecture"`
		RepoDigests  []string `json:"RepoDigests"`
		Descriptor   struct {
			Digest    string `json:"digest"`
			MediaType string `json:"mediaType"`
		} `json:"Descriptor"`
	}
	if json.Unmarshal([]byte(image), &inspected) != nil || len(inspected) != 1 ||
		inspected[0].ID != phase6security.Slice6BreakGlassCarrierIndexDigest ||
		inspected[0].OS != "linux" || inspected[0].Architecture != "arm64" ||
		inspected[0].Descriptor.Digest != phase6security.Slice6BreakGlassCarrierIndexDigest ||
		inspected[0].Descriptor.MediaType != "application/vnd.oci.image.index.v1+json" ||
		!slices.Contains(inspected[0].RepoDigests, "alpine@"+phase6security.Slice6BreakGlassCarrierIndexDigest) {
		t.Fatal("carrier local index/platform identity drift")
	}
	index := exec.CommandContext(ctx, "docker", "buildx", "imagetools", "inspect", "--raw", operatorCarrier)
	indexBytes, err := index.Output()
	var indexDoc struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err != nil || json.Unmarshal(indexBytes, &indexDoc) != nil {
		t.Fatal("carrier index descriptor unavailable")
	}
	selected := 0
	for _, entry := range indexDoc.Manifests {
		if entry.Digest == phase6security.Slice6BreakGlassCarrierManifestDigest &&
			entry.Platform.OS == "linux" && entry.Platform.Architecture == "arm64" &&
			(entry.Platform.Variant == "" || entry.Platform.Variant == "v8") {
			selected++
		}
	}
	if selected != 1 {
		t.Fatal("carrier selected arm64 manifest absent from pinned index")
	}
	manifest := exec.CommandContext(ctx, "docker", "buildx", "imagetools", "inspect", "--raw",
		"docker.io/library/alpine@"+phase6security.Slice6BreakGlassCarrierManifestDigest)
	manifestBytes, err := manifest.Output()
	var manifestDoc struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err != nil || json.Unmarshal(manifestBytes, &manifestDoc) != nil ||
		manifestDoc.Config.Digest != phase6security.Slice6BreakGlassCarrierConfigDigest {
		t.Fatal("carrier config digest does not match selected manifest")
	}
}

func operatorDocker(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("Docker %q failed: %v: %.256s", args[:min(2, len(args))], err, output)
	}
	return string(output)
}

func operatorTestKey(index byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{index}, 32))
}
func operatorTestDigest(value string) string {
	hash := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func TestFiniteOperatorServerHelper(t *testing.T) {
	if os.Getenv("SR_PHASE6_BREAK_GLASS_SERVER") != "1" {
		t.Skip("container helper only")
	}
	actors := []breakglass.Actor{
		{ID: "requester-a", Kind: breakglass.ActorRequester, PublicKey: operatorTestKey(1).Public().(ed25519.PublicKey)},
		{ID: "approver-a", Kind: breakglass.ActorApprover, PublicKey: operatorTestKey(2).Public().(ed25519.PublicKey)},
		{ID: "approver-b", Kind: breakglass.ActorApprover, PublicKey: operatorTestKey(3).Public().(ed25519.PublicKey)},
		{ID: "operator-a", Kind: breakglass.ActorOperator, PublicKey: operatorTestKey(4).Public().(ed25519.PublicKey)},
		{ID: "guest-agent", Kind: breakglass.ActorTarget, PublicKey: operatorTestKey(5).Public().(ed25519.PublicKey)},
	}
	controller, err := breakglass.NewProduction(breakglass.Config{LedgerPath: "/state/ledger.json", AuditPath: "/state/audit.ndjson",
		Actors: actors, ControllerPrivateKey: operatorTestKey(6), MaxTTL: 15 * time.Minute, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	server, err := breakglass.ListenV2Controller(breakglass.V2ControllerServerConfig{ServerConfig: breakglass.ServerConfig{
		SocketPath: "/run/phase6/break-glass/controller/operator/break-glass.sock", SocketUID: 20030, SocketGID: 30091,
		ExpectedClientUID: 20091, ExpectedClientGID: 30091, MaxConnections: 4}, Kind: "control"}, controller)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			if _, err := os.Lstat("/state/stop"); err == nil {
				cancel()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	fmt.Println("READY")
	if err := server.Serve(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("server exit: %v", err)
	}
}
