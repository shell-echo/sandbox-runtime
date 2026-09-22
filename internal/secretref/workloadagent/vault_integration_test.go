//go:build integration

package workloadagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	productprocess "github.com/shell-echo/sandbox-runtime/productapi/process"
)

const (
	vaultAgentIntegrationEnvironment = "SANDBOX_RUNTIME_VAULT_AGENT_INTEGRATION"
	vaultAgentIntegrationImage       = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
)

type integrationMaterialDocument struct {
	Schema        string `json:"schema"`
	BindingDigest string `json:"binding_digest"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	Digest        string `json:"digest"`
	State         string `json:"state"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	Material      []byte `json:"material"`
}

func TestVaultKVWorkloadAgentProductTLSIntegration(t *testing.T) {
	if os.Getenv(vaultAgentIntegrationEnvironment) != "1" {
		t.Skip("set " + vaultAgentIntegrationEnvironment + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	containerName := "sandbox-runtime-vault-agent-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	rootToken := "phase6-vault-agent-root"
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", containerName).Run()
		}
	})
	runAgentIntegrationCommand(t, ctx, "", "docker", "pull", vaultAgentIntegrationImage)
	runAgentIntegrationCommand(t, ctx, "", "docker", "run", "-d", "--name", containerName,
		"-p", "127.0.0.1::8200", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken,
		vaultAgentIntegrationImage, "server", "-dev", "-dev-root-token-id="+rootToken,
		"-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls")

	portOutput := strings.TrimSpace(runAgentIntegrationCommand(t, ctx, "", "docker", "port", containerName, "8200/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("Vault published port is unavailable")
	}
	port := portOutput[separator+1:]
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal("Vault published port is invalid")
	}
	caPath := filepath.Join(t.TempDir(), "vault-ca.pem")
	waitForAgentVaultCA(t, ctx, containerName, caPath)
	caDocument, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caDocument) {
		t.Fatal("Vault integration CA is invalid")
	}
	endpoint := "https://127.0.0.1:" + port
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	waitForAgentVaultHealth(t, ctx, httpClient, endpoint, rootToken)
	vaultAgentWrite(t, ctx, httpClient, endpoint+"/v1/sys/mounts/kv", rootToken, map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, nil)

	now := time.Now().UTC()
	v1Certificate, v1Key := integrationServerIdentity(t, now, 1)
	v1CertificateBinding, v1KeyBinding := integrationTLSBindings("v1")
	writeVaultMaterial(t, ctx, httpClient, endpoint, rootToken, "product-tls-certificate", v1CertificateBinding, "bundle-revision-1", secretref.KeyActive, now, v1Certificate)
	writeVaultMaterial(t, ctx, httpClient, endpoint, rootToken, "product-tls-private-key", v1KeyBinding, "bundle-revision-1", secretref.KeyActive, now, v1Key)

	policy := `path "kv/data/product-tls-certificate" { capabilities = ["read"] }
path "kv/data/product-tls-private-key" { capabilities = ["read"] }`
	vaultAgentWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/product-material-agent", rootToken, map[string]any{"policy": policy}, nil)
	var tokenResponse struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	vaultAgentWrite(t, ctx, httpClient, endpoint+"/v1/auth/token/create", rootToken, map[string]any{
		"policies": []string{"product-material-agent"}, "ttl": "5m", "renewable": false, "no_default_policy": true,
	}, &tokenResponse)
	if tokenResponse.Auth.ClientToken == "" || tokenResponse.Auth.ClientToken == rootToken {
		t.Fatal("Vault did not issue a distinct scoped token")
	}

	sourceRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), "workload-material-agent-fixture")
	runAgentIntegrationCommand(t, ctx, sourceRoot, "go", "build", "-o", binaryPath, "./cmd/workload-material-agent-fixture")

	v1SocketDirectory := shortIntegrationSocketDirectory(t)
	v1Socket := filepath.Join(v1SocketDirectory, "agent.sock")
	v1Agent := startFixtureProcess(t, ctx, binaryPath, v1Socket, endpoint, caPath, tokenResponse.Auth.ClientToken, v1CertificateBinding, v1KeyBinding)
	v1Client := integrationAgentClient(t, v1Socket)
	v1Registry := integrationTLSRegistry(t, v1Client, v1CertificateBinding, v1KeyBinding)
	if _, err := productprocess.LoadTLSConfigFromRegistry(ctx, v1Registry, "product-tls-certificate", "product-tls-private-key", "product.example.test", time.Now); err != nil {
		t.Fatalf("v1 Product TLS load: %v", err)
	}

	v2Certificate, v2Key := integrationServerIdentity(t, now, 2)
	v2CertificateBinding, v2KeyBinding := integrationTLSBindings("v2")
	writeVaultMaterial(t, ctx, httpClient, endpoint, rootToken, "product-tls-certificate", v2CertificateBinding, "bundle-revision-2", secretref.KeyActive, now, v2Certificate)
	writeVaultMaterial(t, ctx, httpClient, endpoint, rootToken, "product-tls-private-key", v2KeyBinding, "bundle-revision-2", secretref.KeyActive, now, v2Key)
	v2SocketDirectory := shortIntegrationSocketDirectory(t)
	v2Socket := filepath.Join(v2SocketDirectory, "agent.sock")
	v2Agent := startFixtureProcess(t, ctx, binaryPath, v2Socket, endpoint, caPath, tokenResponse.Auth.ClientToken, v2CertificateBinding, v2KeyBinding)
	v2Client := integrationAgentClient(t, v2Socket)
	v2Registry := integrationTLSRegistry(t, v2Client, v2CertificateBinding, v2KeyBinding)
	if _, err := productprocess.LoadTLSConfigFromRegistry(ctx, v2Registry, "product-tls-certificate", "product-tls-private-key", "product.example.test", time.Now); err != nil {
		t.Fatalf("v2 Product TLS load: %v", err)
	}
	if _, err := productprocess.LoadTLSConfigFromRegistry(ctx, v1Registry, "product-tls-certificate", "product-tls-private-key", "product.example.test", time.Now); err != nil {
		t.Fatalf("v1 overlap Product TLS load: %v", err)
	}

	v2Agent.stop(t)
	v2Agent = startFixtureProcess(t, ctx, binaryPath, v2Socket, endpoint, caPath, tokenResponse.Auth.ClientToken, v2CertificateBinding, v2KeyBinding)
	v2Client = integrationAgentClient(t, v2Socket)
	v2Registry = integrationTLSRegistry(t, v2Client, v2CertificateBinding, v2KeyBinding)
	if _, err := productprocess.LoadTLSConfigFromRegistry(ctx, v2Registry, "product-tls-certificate", "product-tls-private-key", "product.example.test", time.Now); err != nil {
		t.Fatalf("restarted v2 Product TLS load: %v", err)
	}

	runAgentIntegrationCommand(t, ctx, "", "docker", "stop", "--time", "5", containerName)
	if _, err := v2Registry.Resolve(ctx, "product-tls-certificate", secretref.PurposeTLSCertificate, secretref.SystemTenant); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("Vault-loss resolution error = %v", err)
	}
	v1Agent.stop(t)
	v2Agent.stop(t)
	if _, err := os.Lstat(v1Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v1 socket cleanup = %v", err)
	}
	if _, err := os.Lstat(v2Socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v2 socket cleanup = %v", err)
	}
	runAgentIntegrationCommand(t, context.Background(), "", "docker", "rm", "-f", containerName)
	cleaned = true
	remaining := strings.TrimSpace(runAgentIntegrationCommand(t, context.Background(), "", "docker", "ps", "-aq", "--filter", "name=^/"+containerName+"$"))
	if remaining != "" {
		t.Fatal("Vault workload-agent container cleanup is incomplete")
	}
}

func integrationTLSBindings(version string) (secretref.Binding, secretref.Binding) {
	certificate := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-tls-certificate", Version: version, Purpose: secretref.PurposeTLSCertificate, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct}
	privateKey := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-tls-private-key", Version: version, Purpose: secretref.PurposeTLSPrivateKey, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct}
	return certificate, privateKey
}

func integrationServerIdentity(t *testing.T, now time.Time, serial int64) ([]byte, []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "product.example.test"}, DNSNames: []string{"product.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey})
}

func writeVaultMaterial(t *testing.T, ctx context.Context, client *http.Client, endpoint, token, path string, binding secretref.Binding, revision string, state secretref.KeyState, now time.Time, material []byte) {
	t.Helper()
	digest := sha256.Sum256(material)
	document := integrationMaterialDocument{Schema: "sandbox-runtime.vault-kv-material.v1", BindingDigest: binding.Digest(), Version: binding.Version, Revision: revision, Digest: "sha256:" + hex.EncodeToString(digest[:]), State: string(state), NotBefore: now.Add(-time.Minute).Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano), Material: material}
	vaultAgentWrite(t, ctx, client, endpoint+"/v1/kv/data/"+path, token, map[string]any{"data": document}, nil)
}

func integrationAgentClient(t *testing.T, socket string) *Client {
	t.Helper()
	client, err := NewProduction(Config{SocketPath: socket, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: secretref.RoleProduct, OperationTimeout: 3 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func integrationTLSRegistry(t *testing.T, client *Client, certificateBinding, keyBinding secretref.Binding) *secretref.Registry {
	t.Helper()
	registry, err := secretref.NewRegistry(secretref.RoleProduct,
		[]secretref.Purpose{secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey},
		[]secretref.ProviderRegistration{{Name: "role-material-agent", Provider: client}},
		[]secretref.BindingRegistration{{ID: "product-tls-certificate", Provider: "role-material-agent", Binding: certificateBinding}, {ID: "product-tls-private-key", Provider: "role-material-agent", Binding: keyBinding}}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

type fixtureProcess struct {
	command *exec.Cmd
	done    chan error
	stderr  *bytes.Buffer
	socket  string
	stopped bool
}

func startFixtureProcess(t *testing.T, ctx context.Context, binary, socket, endpoint, caPath, token string, certificateBinding, keyBinding secretref.Binding) *fixtureProcess {
	t.Helper()
	command := exec.CommandContext(ctx, binary,
		"-socket", socket, "-vault-endpoint", endpoint, "-vault-ca", caPath,
		"-certificate-reference", certificateBinding.Reference.String(), "-certificate-version", certificateBinding.Version,
		"-private-key-reference", keyBinding.Reference.String(), "-private-key-version", keyBinding.Version,
		"-expected-client-uid", strconv.Itoa(os.Getuid()), "-expected-client-gid", strconv.Itoa(os.Getgid()))
	command.Env = append(os.Environ(), "SANDBOX_RUNTIME_FIXTURE_VAULT_TOKEN="+token)
	stderr := new(bytes.Buffer)
	command.Stdout = io.Discard
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		t.Fatal("workload material fixture did not start")
	}
	process := &fixtureProcess{command: command, done: make(chan error, 1), stderr: stderr, socket: socket}
	go func() { process.done <- command.Wait() }()
	t.Cleanup(func() {
		if !process.stopped {
			process.stop(t)
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
			return process
		}
		select {
		case <-process.done:
			clear(stderr.Bytes())
			t.Fatal("workload material fixture exited before readiness")
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("workload material fixture did not become ready")
	return nil
}

func (p *fixtureProcess) stop(t *testing.T) {
	t.Helper()
	if p == nil || p.stopped {
		return
	}
	p.stopped = true
	_ = p.command.Process.Signal(syscall.SIGTERM)
	select {
	case err := <-p.done:
		if err != nil {
			clear(p.stderr.Bytes())
			t.Fatal("workload material fixture did not stop cleanly")
		}
	case <-time.After(10 * time.Second):
		_ = p.command.Process.Kill()
		<-p.done
		clear(p.stderr.Bytes())
		t.Fatal("workload material fixture drain timed out")
	}
	clear(p.stderr.Bytes())
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(p.socket); errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("workload material fixture retained its socket")
}

func shortIntegrationSocketDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-wai-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	return directory
}

func waitForAgentVaultCA(t *testing.T, ctx context.Context, containerName, destination string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		certificate, err := exec.CommandContext(ctx, "docker", "exec", containerName, "cat", "/tmp/vault-tls/vault-ca.pem").Output()
		if err == nil && bytes.Contains(certificate, []byte("-----BEGIN CERTIFICATE-----")) {
			if err := os.WriteFile(destination, certificate, 0o600); err != nil {
				clear(certificate)
				t.Fatal("Vault integration CA could not be persisted")
			}
			clear(certificate)
			return
		}
		clear(certificate)
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("Vault TLS authority did not become available")
}

func waitForAgentVaultHealth(t *testing.T, ctx context.Context, client *http.Client, endpoint, token string) {
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
	t.Fatal("Vault did not become healthy")
}

func vaultAgentWrite(t *testing.T, ctx context.Context, client *http.Client, target, token string, requestBody any, responseTarget any) {
	t.Helper()
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("Vault setup request failed")
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 256<<10))
	if err != nil || (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent) {
		clear(responseBody)
		t.Fatal("Vault setup request was rejected")
	}
	defer clear(responseBody)
	if responseTarget != nil && json.Unmarshal(responseBody, responseTarget) != nil {
		t.Fatal("Vault setup response is invalid")
	}
}

func runAgentIntegrationCommand(t *testing.T, ctx context.Context, directory, name string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, name, arguments...)
	if directory != "" {
		command.Dir = directory
	}
	output, err := command.CombinedOutput()
	if err != nil {
		clear(output)
		t.Fatalf("integration command %q failed", name)
	}
	result := string(output)
	clear(output)
	return result
}
