//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func slice6ObserveProductIdentityMaterial(t *testing.T, ctx context.Context, run slice6DockerRun,
	profile phase6security.Profile, agent, owner phase6security.Principal,
	material phase6security.Slice6MaterialSocketBinding, config []byte,
	expectedDigest, expectedDSNDigest, volume, root string) {
	t.Helper()
	if agent.Name != "product-runtime-agent" || owner.Name != "product-runtime" ||
		volume == "" || len(expectedDigest) != len("sha256:")+64 {
		t.Fatal("Product identity observer authority unavailable")
	}
	access, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil {
		t.Fatal(err)
	}
	var binding, runtimeBinding secretref.Binding
	for _, item := range access {
		if item.Agent == agent.Name && len(item.Bindings) == 2 {
			binding = item.Bindings[0]
			runtimeBinding = item.Bindings[1]
		}
	}
	var active slice6MaterialAgentConfig
	if binding.Validate() != nil || binding.Purpose != secretref.PurposeIdentityKeyRing ||
		json.Unmarshal(config, &active) != nil || active.Role != secretref.RoleProduct ||
		active.ExpectedClientUID != owner.UID || active.ExpectedClientGID != owner.GID ||
		len(active.Bindings) != 2 || active.Bindings[0] != binding ||
		active.Bindings[1] != runtimeBinding ||
		runtimeBinding.Purpose != secretref.PurposePostgresRuntimeDSN {
		t.Fatal("Product observer and live material-agent authorization inputs disagree")
	}
	directory := run.privateSibling(t, root, ".sr-product-identity-observer-")
	binary, err := filepath.Abs(filepath.Join(directory, "observer"))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
		"-ldflags=-buildid=", "-o", binary, "./productphase6gate/testdata/productmaterialobserver")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64", "GOTOOLCHAIN=local", "GOFLAGS=")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixed Product identity observer: %v: %.256s", err, output)
	}
	request, err := json.Marshal(struct {
		SocketPath     string            `json:"socket_path"`
		AgentUID       uint32            `json:"agent_uid"`
		AgentGID       uint32            `json:"agent_gid"`
		OwnerUID       uint32            `json:"owner_uid"`
		OwnerGID       uint32            `json:"owner_gid"`
		Binding        secretref.Binding `json:"binding"`
		ExpectedDigest string            `json:"expected_digest"`
	}{SocketPath: material.SocketPath, AgentUID: agent.UID, AgentGID: agent.GID,
		OwnerUID: owner.UID, OwnerGID: owner.GID, Binding: binding, ExpectedDigest: expectedDigest})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(request)
	command := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--pull=never",
		"--name", "sr-p6-product-identity-observe-"+run.id, "--label", run.label(), "--network=none",
		"--user", fmt.Sprintf("%d:%d", owner.UID, owner.GID), "--read-only", "--cap-drop=ALL",
		"--security-opt", "no-new-privileges:true", "--memory=64m", "--cpus=0.2", "--pids-limit=16",
		"--mount", "type=volume,src="+volume+",dst="+material.SocketDirectory+",readonly",
		"--mount", "type=bind,src="+binary+",dst=/observer,readonly",
		"--entrypoint=/observer", agent.ImageReference)
	command.Stdin = bytes.NewReader(request)
	output, observeErr := command.CombinedOutput()
	if observeErr != nil || string(output) != "product-identity-material-resolved=exact-vault-key-ring\n" {
		stage, resolveMS := slice6ProductIdentityObservationFailure(output)
		clear(output)
		t.Fatalf("Product owner-side Vault-backed key-ring resolution failed: stage=%s resolve_ms=%d exit=%v", stage, resolveMS, observeErr)
	}
	if expectedDSNDigest != "" {
		if len(expectedDSNDigest) != len("sha256:")+64 {
			t.Fatal("Product runtime DSN digest unavailable")
		}
		target := phase6egress.BoundPostgresTarget{Host: "postgres.sandbox-runtime.test",
			Port: 5432, Database: "product", User: "product_runtime"}
		dsnRequest, err := json.Marshal(struct {
			SocketPath     string                            `json:"socket_path"`
			AgentUID       uint32                            `json:"agent_uid"`
			AgentGID       uint32                            `json:"agent_gid"`
			OwnerUID       uint32                            `json:"owner_uid"`
			OwnerGID       uint32                            `json:"owner_gid"`
			Binding        secretref.Binding                 `json:"binding"`
			ExpectedDigest string                            `json:"expected_digest"`
			Target         *phase6egress.BoundPostgresTarget `json:"target,omitempty"`
		}{SocketPath: material.SocketPath, AgentUID: agent.UID, AgentGID: agent.GID,
			OwnerUID: owner.UID, OwnerGID: owner.GID, Binding: runtimeBinding,
			ExpectedDigest: expectedDSNDigest, Target: &target})
		if err != nil {
			t.Fatal("encode Product runtime DSN observer authority")
		}
		defer clear(dsnRequest)
		dsnCommand := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--pull=never",
			"--name", "sr-p6-product-dsn-observe-"+run.id, "--label", run.label(), "--network=none",
			"--user", fmt.Sprintf("%d:%d", owner.UID, owner.GID), "--read-only", "--cap-drop=ALL",
			"--security-opt", "no-new-privileges:true", "--memory=64m", "--cpus=0.2", "--pids-limit=16",
			"--mount", "type=volume,src="+volume+",dst="+material.SocketDirectory+",readonly",
			"--mount", "type=bind,src="+binary+",dst=/observer,readonly",
			"--entrypoint=/observer", agent.ImageReference)
		dsnCommand.Stdin = bytes.NewReader(dsnRequest)
		dsnOutput, dsnErr := dsnCommand.CombinedOutput()
		if dsnErr != nil || string(dsnOutput) != "product-dsn-material-resolved=exact-vault-dsn\n" {
			stage, resolveMS := slice6ProductIdentityObservationFailure(dsnOutput)
			clear(dsnOutput)
			t.Fatalf("Product owner-side runtime DSN resolve failed: stage=%s resolve_ms=%d exit=%v",
				stage, resolveMS, dsnErr)
		}
		t.Log("real Product material-agent served exact KVv2 runtime DSN to cross-UID/GID Product owner; strict Profile target/digest parsing passed; SQL login remains unproved")
	} else {
		t.Log("real Product material-agent served exact KVv2 identity key-ring to cross-UID/GID Product owner; PostgreSQL DSN and runtime remain unproved")
	}
}

var slice6ProductIdentityObservationPattern = regexp.MustCompile(`^product-identity-observation stage=(input|identity-or-binding|parent-layout|socket-layout|client-init|resolve-canceled|resolve-deadline|resolve-revoked|resolve-expired|resolve-unavailable|material-binding|material-window|material-digest|key-ring|dsn) resolve_ms=(-1|[0-9]{1,6})\n$`)

func slice6ProductIdentityObservationFailure(output []byte) (string, int64) {
	match := slice6ProductIdentityObservationPattern.FindSubmatch(output)
	if match == nil {
		return "unclassified", -1
	}
	millis, err := strconv.ParseInt(string(match[2]), 10, 64)
	if err != nil || millis > 30000 {
		return "unclassified", -1
	}
	return strings.Clone(string(match[1])), millis
}

func TestSlice6ProductIdentityObservationFailure(t *testing.T) {
	for _, tc := range []struct {
		output, stage string
		millis        int64
	}{
		{"product-identity-observation stage=socket-layout resolve_ms=-1\n", "socket-layout", -1},
		{"product-identity-observation stage=resolve-unavailable resolve_ms=15001\n", "resolve-unavailable", 15001},
		{"product-identity-observation stage=other resolve_ms=1\n", "unclassified", -1},
		{"secret\nproduct-identity-observation stage=key-ring resolve_ms=1\n", "unclassified", -1},
	} {
		stage, millis := slice6ProductIdentityObservationFailure([]byte(tc.output))
		if stage != tc.stage || millis != tc.millis {
			t.Fatalf("Product observer diagnostic classified as %s/%d; want %s/%d", stage, millis, tc.stage, tc.millis)
		}
	}
}
