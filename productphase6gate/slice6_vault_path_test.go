//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const (
	slice6VaultPathEnv   = "SANDBOX_RUNTIME_PHASE6_SLICE6_VAULT_PATH_DIAGNOSTIC"
	slice6VaultTestImage = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
)

// This boots a real pinned Vault process on the reviewed isolated controller
// bridge, then uses a separate OS container at the controller's planned IP to
// verify TLS and Vault health. The probe is NOT certificate-controller and
// dev-TLS is NOT the final external identity or controlled PKI bootstrap.
func TestPhase6Slice6VaultBridgeTLSPathDiagnostic(t *testing.T) {
	if os.Getenv(slice6VaultPathEnv) != "1" {
		t.Skip("set " + slice6VaultPathEnv + "=1 for real Vault bridge diagnostic")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	run, err := newSlice6DockerRun()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		if err := run.cleanup(cleanupCtx); err != nil {
			t.Errorf("exact Vault diagnostic cleanup: %v", err)
		}
	})
	var expected phase6security.Network
	for _, network := range phase6security.Slice6DesiredFinalNetworks() {
		if network.Name == "network-certificate-controller" {
			expected = network
			break
		}
	}
	if expected.Name == "" || !expected.Internal || expected.GatewayModeIPv4 != "isolated" ||
		len(expected.Principals) != 1 || expected.Principals[0] != "certificate-controller" ||
		len(expected.ExternalServices) != 1 || expected.ExternalServices[0] != "vault" {
		t.Fatal("reviewed certificate-controller/Vault bridge is unavailable")
	}
	created, err := createSlice6ProfileNetwork(ctx, run, expected)
	if err != nil {
		t.Fatal(err)
	}
	vaultAddress, err := phase6security.Slice6DesiredServiceEndpointAddress(expected.Name, "vault")
	if err != nil {
		t.Fatal(err)
	}
	controllerAddress, err := phase6security.Slice6DesiredServiceEndpointAddress(expected.Name, "certificate-controller")
	if err != nil {
		t.Fatal(err)
	}
	serverName := "sr-p6-vault-" + run.id
	started, err := run.docker(ctx, "run", "-d", "--pull=never", "--name", serverName,
		"--label", run.label(), "--log-driver=none", "--network", created.NetworkID, "--ip", vaultAddress,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		slice6VaultTestImage, "server", "-dev", "-dev-root-token-id=route-diagnostic-only",
		"-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls")
	vaultID := strings.TrimSpace(string(started))
	if err != nil || len(vaultID) != 64 || !lowerHexSlice6(vaultID) {
		t.Fatalf("pinned Vault diagnostic process failed to start: %v", err)
	}
	var ca []byte
	for ctx.Err() == nil {
		ca, err = run.docker(ctx, "exec", vaultID, "cat", "/tmp/vault-tls/vault-ca.pem")
		roots := x509.NewCertPool()
		if err == nil && len(ca) < 64<<10 && roots.AppendCertsFromPEM(ca) {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	if ctx.Err() != nil {
		t.Fatal("Vault did not publish a valid diagnostic CA")
	}
	caPath := filepath.Join(t.TempDir(), "vault-ca.pem")
	if err := os.WriteFile(caPath, ca, 0o644); err != nil {
		t.Fatal(err)
	}
	// The probe is an ephemeral Vault CLI in a second container. Its source
	// address is the reviewed controller slot, but it is never recorded as the
	// actual certificate-controller deployment or a release scenario.
	probeCreated, err := run.docker(ctx, "create", "--pull=never", "--name", "sr-p6-vault-probe-"+run.id,
		"--label", run.label(), "--network", created.NetworkID, "--ip", controllerAddress,
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--user", "100:1000",
		slice6VaultTestImage, "status", "-address=https://"+vaultAddress+":8200",
		"-ca-cert=/tmp/ca.pem", "-tls-server-name=127.0.0.1")
	probeID := strings.TrimSpace(string(probeCreated))
	if err != nil || len(probeID) != 64 || !lowerHexSlice6(probeID) {
		t.Fatal("create run-owned Vault path probe")
	}
	// Docker cp streams the public CA over the Docker API. A macOS test
	// temporary path is not necessarily mountable in Docker Desktop's VM.
	if _, err := run.docker(ctx, "cp", caPath, probeID+":/tmp/ca.pem"); err != nil {
		t.Fatal("copy diagnostic CA into run-owned probe")
	}
	probeOutput, err := run.docker(ctx, "start", "-a", probeID)
	if err != nil || !strings.Contains(string(probeOutput), "Sealed          false") {
		t.Fatalf("separate-container authenticated Vault path failed: %v: %.512s", err, probeOutput)
	}
	if _, err := run.docker(ctx, "rm", probeID); err != nil {
		t.Fatal("remove stopped Vault path probe")
	}
	partial := expected
	partial.Principals = nil
	inspect, err := run.docker(ctx, "network", "inspect", created.NetworkID)
	if err != nil {
		t.Fatal("inspect run-owned Vault bridge")
	}
	observed, err := phase6security.ObserveDockerNetworkWithExternal(inspect, partial, nil, map[string]string{"vault": vaultID})
	if err != nil || len(observed.Endpoints) != 1 || observed.Endpoints[0].IPv4Address != vaultAddress {
		t.Fatal("Vault is not the only remaining member at the reviewed address")
	}
	if err := run.cleanup(ctx); err != nil {
		t.Fatalf("exact run-owned Vault bridge cleanup: %v", err)
	}
	for _, class := range []string{"container", "network", "volume"} {
		ids, err := run.labeledIDs(ctx, class)
		if err != nil || len(ids) != 0 {
			t.Fatal(errors.New("Vault bridge diagnostic retained run-owned Docker resources"))
		}
	}
	t.Log("real isolated bridge, separate-container TLS health, exact cleanup passed; final controller/Vault profile remains unproven")
}
