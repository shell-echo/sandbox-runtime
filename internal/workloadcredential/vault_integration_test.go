//go:build integration

package workloadcredential

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	vaultCredentialIntegrationEnvironment = "SANDBOX_RUNTIME_WORKLOAD_CREDENTIAL_INTEGRATION"
	vaultCredentialIntegrationImage       = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
)

func TestVaultWorkloadCredentialControllerIntegration(t *testing.T) {
	if os.Getenv(vaultCredentialIntegrationEnvironment) != "1" {
		t.Skip("set " + vaultCredentialIntegrationEnvironment + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	container := "sr-workload-credential-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	rootToken := "credential-integration-root"
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = exec.Command("docker", "rm", "-f", container).Run()
		}
	})
	runCredentialCommand(t, ctx, "docker", "pull", vaultCredentialIntegrationImage)
	runCredentialCommand(t, ctx, "docker", "run", "-d", "--name", container, "-p", "127.0.0.1::8200",
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken, vaultCredentialIntegrationImage,
		"server", "-dev", "-dev-root-token-id="+rootToken, "-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls")
	portOutput := strings.TrimSpace(runCredentialCommand(t, ctx, "docker", "port", container, "8200/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("Vault port unavailable")
	}
	endpoint := "https://127.0.0.1:" + portOutput[separator+1:]
	caDocument := waitCredentialVaultCA(t, ctx, container)
	defer clear(caDocument)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caDocument) {
		t.Fatal("Vault CA invalid")
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	waitCredentialVault(t, ctx, httpClient, endpoint, rootToken)
	vaultCredentialWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/product-runtime-vault", rootToken,
		map[string]any{"policy": `path "secret/data/runtime" { capabilities = ["read"] }`})

	directory, err := os.MkdirTemp("/tmp", "sr-wci-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if os.Chmod(directory, 0o700) != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare controller directory")
	}
	issuer, err := NewVaultIssuer(VaultIssuerConfig{Endpoint: endpoint, BackendID: "vault-primary",
		Policies: map[string]string{"product-runtime": "product-runtime-vault"}, ManagementToken: []byte(rootToken),
		OperationTimeout: 3 * time.Second, Now: time.Now}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{ID: "product-runtime", AgentID: "product-runtime-agent", Role: secretref.RoleProduct,
		Purpose: secretref.PurposeWorkloadCredential, BindingDigest: "sha256:" + strings.Repeat("a", 64), BackendID: "vault-primary",
		MaxTTL: 10 * time.Second, Renewable: true}
	controller, err := NewProductionController(ControllerConfig{LedgerPath: filepath.Join(directory, "ledger.json"),
		Identities: map[string]ed25519.PublicKey{policy.AgentID: publicKey}, Policies: []Policy{policy}, Issuer: issuer,
		Overlap: 2 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "controller.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), MaxConnections: 4, ReapInterval: time.Second}, controller)
	if err != nil {
		t.Fatal(err)
	}
	serverContext, stopServer := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverContext) }()
	client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		AgentID: policy.AgentID, Role: policy.Role, Purpose: policy.Purpose, PolicyID: policy.ID, BindingDigest: policy.BindingDigest,
		BackendID: policy.BackendID, PrivateKey: privateKey, OperationTimeout: 3 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	first, err := client.Issue(ctx, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()
	second, err := client.Renew(ctx, first, 10*time.Second)
	if err != nil || bytes.Equal(first.Credential, second.Credential) || second.Revision != first.Revision+1 {
		t.Fatalf("renew first=%#v second=%#v error=%v", first, second, err)
	}
	defer second.Destroy()
	previousAccessor := controller.ledger.Leases[0].PreviousBackendLeaseID
	currentAccessor := controller.ledger.Leases[0].BackendLeaseID
	assertVaultAccessorStatus(t, ctx, httpClient, endpoint, rootToken, previousAccessor, http.StatusOK)
	time.Sleep(3 * time.Second)
	if err := controller.Reap(ctx); err != nil {
		t.Fatal(err)
	}
	assertVaultAccessorStatus(t, ctx, httpClient, endpoint, rootToken, previousAccessor, http.StatusBadRequest)
	if err := client.Revoke(ctx, second); err != nil {
		t.Fatal(err)
	}
	assertVaultAccessorStatus(t, ctx, httpClient, endpoint, rootToken, currentAccessor, http.StatusBadRequest)

	runCredentialCommand(t, ctx, "docker", "stop", "--time", "5", container)
	if _, err := client.Issue(ctx, 5*time.Second); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Vault-loss issue error=%v", err)
	}
	stopServer()
	if err := <-serverDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("controller server exit=%v", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("controller socket cleanup=%v", err)
	}
	runCredentialCommand(t, context.Background(), "docker", "rm", "-f", container)
	cleaned = true
	if output := strings.TrimSpace(runCredentialCommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+container+"$")); output != "" {
		t.Fatal("Vault workload credential container retained")
	}
}

func runCredentialCommand(t *testing.T, ctx context.Context, command string, arguments ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, command, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", command, err, output)
	}
	return string(output)
}

func waitCredentialVaultCA(t *testing.T, ctx context.Context, container string) []byte {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		document, err := exec.CommandContext(ctx, "docker", "exec", container, "cat", "/tmp/vault-tls/vault-ca.pem").Output()
		if err == nil && bytes.Contains(document, []byte("BEGIN CERTIFICATE")) {
			return document
		}
		clear(document)
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("Vault CA unavailable")
	return nil
}

func waitCredentialVault(t *testing.T, ctx context.Context, client *http.Client, endpoint, token string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/sys/health", nil)
		request.Header.Set("X-Vault-Token", token)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("Vault unavailable")
}

func vaultCredentialWrite(t *testing.T, ctx context.Context, client *http.Client, target, token string, body any) {
	t.Helper()
	document, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(document)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusOK {
		t.Fatalf("Vault setup status=%d", response.StatusCode)
	}
}

func assertVaultAccessorStatus(t *testing.T, ctx context.Context, client *http.Client, endpoint, rootToken, accessor string, want int) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"accessor": accessor})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/auth/token/lookup-accessor", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", rootToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != want {
		t.Fatalf("Vault token status=%d want=%d", response.StatusCode, want)
	}
}
