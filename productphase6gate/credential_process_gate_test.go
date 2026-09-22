//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
)

const credentialProcessGateEnv = "SANDBOX_RUNTIME_PHASE6_CREDENTIAL_PROCESS_GATE"

func TestPhase6CredentialAndBreakGlassProcessGate(t *testing.T) {
	if os.Getenv(credentialProcessGateEnv) != "1" {
		t.Skip("set " + credentialProcessGateEnv + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	environment := &gateEnvironment{runID: "credential-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", ""), root: root,
		paths: gatePaths{directory: directory, materialAgentBin: filepath.Join(directory, "workload-material-agent"),
			credentialControllerBin: filepath.Join(directory, "workload-credential-controller"), breakGlassControllerBin: filepath.Join(directory, "break-glass-controller"),
			materialSockets: make(map[string]string), breakGlassSockets: make(map[string]string)},
		materials: make(map[string][]secretref.SecretMaterial), materialAgents: make(map[string]*gateProcess)}
	for _, build := range []struct{ output, target string }{
		{environment.paths.materialAgentBin, "./cmd/workload-material-agent"},
		{environment.paths.credentialControllerBin, "./cmd/workload-credential-controller"},
		{environment.paths.breakGlassControllerBin, "./cmd/break-glass-controller"},
	} {
		command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", build.output, build.target)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", build.target, err, output)
		}
	}
	roles := map[string]secretref.Role{
		"product-migration": secretref.RoleProduct, "provider-migration": secretref.RoleProvider,
		"product-runtime": secretref.RoleProduct, "provider-runtime": secretref.RoleProvider,
		"gateway": secretref.RoleGateway, "guest": secretref.RoleGuest, "browser": secretref.RoleBrowser, "desktop": secretref.RoleDesktop,
	}
	now := time.Now().UTC()
	for name, role := range roles {
		purpose := secretref.PurposeTLSCertificate
		if strings.HasSuffix(name, "-migration") {
			purpose = secretref.PurposePostgresMigrationDSN
		}
		binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://phase6/kv/process_" + strings.ReplaceAll(name, "-", "_")), Version: "v1",
			Purpose: purpose, TenantID: secretref.SystemTenant, Role: role}
		material := []byte("phase6-process-material-" + name)
		digest := sha256.Sum256(material)
		environment.materials[name] = []secretref.SecretMaterial{{Binding: binding, Bytes: material,
			Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1",
			Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), State: secretref.KeyActive}}}
		socketDirectory, err := os.MkdirTemp("/tmp", "sr-p6-cpg-")
		if err != nil {
			t.Fatal(err)
		}
		if os.Chmod(socketDirectory, 0o700) != nil || os.Chown(socketDirectory, os.Getuid(), os.Getgid()) != nil {
			t.Fatal("prepare credential process socket")
		}
		t.Cleanup(func() { _ = os.RemoveAll(socketDirectory) })
		environment.paths.materialSockets[name] = filepath.Join(socketDirectory, "agent.sock")
	}
	prepareGateVault(t, ctx, environment)
	prepareGateBreakGlass(t, environment)
	startGateCredentialController(t, ctx, environment)
	startGateBreakGlassController(t, ctx, environment)

	for _, name := range []string{"product-migration", "provider-migration"} {
		agent := startGateMaterialAgent(t, ctx, environment, name, 1)
		resolveGateMaterial(t, ctx, environment, name)
		select {
		case err := <-agent.done:
			if err != nil {
				t.Fatalf("%s agent exit: %v; log=%s", name, err, gateLog(agent))
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s migration agent did not exit", name)
		}
	}
	startRuntimeMaterialAgents(t, ctx, environment)
	for _, name := range []string{"product-runtime", "provider-runtime", "gateway", "guest", "browser", "desktop"} {
		resolveGateMaterial(t, ctx, environment, name)
	}
	runBreakGlassScenarios(t, ctx, environment)
	waitFor(t, 30*time.Second, "process-gate credential renewals", func() bool {
		ledger, err := readGateCredentialLedger(environment.paths.credentialLedger)
		if err != nil {
			return false
		}
		renewed := 0
		migrations := 0
		for _, lease := range ledger.Leases {
			if lease.Migration && lease.State == "revoked" && !lease.Renewable {
				migrations++
			}
			if !lease.Migration && lease.State == "active" && lease.Revision >= 2 {
				renewed++
			}
		}
		return renewed == 6 && migrations == 2
	})
	for index := len(environment.dependencies) - 1; index >= 0; index-- {
		stopGateProcess(t, environment.dependencies[index], 10*time.Second)
	}
	if output, err := exec.CommandContext(ctx, "docker", "rm", "-f", environment.vaultContainer).CombinedOutput(); err != nil {
		t.Fatalf("remove process-gate Vault: %v: %s", err, output)
	}
	if count := gateAuthoritySocketCount(environment); count != 0 {
		t.Fatalf("credential process gate retained sockets=%d", count)
	}
}

func resolveGateMaterial(t *testing.T, ctx context.Context, environment *gateEnvironment, name string) {
	t.Helper()
	material := environment.materials[name][0]
	client, err := workloadagent.NewProduction(workloadagent.Config{SocketPath: environment.paths.materialSockets[name],
		ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: material.Binding.Role,
		OperationTimeout: 3 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := client.ResolveSecret(ctx, material.Binding)
	if err != nil || resolved.Binding != material.Binding || string(resolved.Bytes) != string(material.Bytes) {
		resolved.Destroy()
		t.Fatalf("%s material resolution error=%v", name, err)
	}
	resolved.Destroy()
}
