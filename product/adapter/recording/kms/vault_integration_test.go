//go:build integration

package kms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	"github.com/shell-echo/sandbox-runtime/internal/secretref/vaulttransit"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	vaultIntegrationEnv   = "SANDBOX_RUNTIME_VAULT_TRANSIT_INTEGRATION"
	vaultIntegrationImage = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
)

type integrationTokenSource struct{ value []byte }

func (s integrationTokenSource) Resolve(context.Context, secretref.Reference) ([]byte, error) {
	return append([]byte(nil), s.value...), nil
}

func TestVaultTransitRecordingStoreIntegration(t *testing.T) {
	if os.Getenv(vaultIntegrationEnv) != "1" {
		t.Skip("set " + vaultIntegrationEnv + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	containerName := "sandbox-runtime-vault-transit-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	rootToken := "phase6-vault-root-integration"
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			_ = exec.CommandContext(cleanupContext, "docker", "rm", "-f", containerName).Run()
		}
	})

	runIntegrationCommand(t, ctx, "docker", "pull", vaultIntegrationImage)
	runIntegrationCommand(t, ctx, "docker", "run", "-d", "--name", containerName,
		"-p", "127.0.0.1::8200", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken,
		vaultIntegrationImage, "server", "-dev", "-dev-root-token-id="+rootToken,
		"-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls")

	portOutput := strings.TrimSpace(runIntegrationCommand(t, ctx, "docker", "port", containerName, "8200/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("Vault published port is unavailable")
	}
	port := portOutput[separator+1:]
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatal("Vault published port is invalid")
	}
	caPath := filepath.Join(t.TempDir(), "vault-ca.pem")
	waitForVaultCA(t, ctx, containerName, caPath)
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
	waitForVaultHealth(t, ctx, httpClient, endpoint, rootToken)

	vaultWrite(t, ctx, httpClient, endpoint+"/v1/sys/mounts/transit", rootToken, map[string]any{"type": "transit"}, nil)
	vaultWrite(t, ctx, httpClient, endpoint+"/v1/transit/keys/recording-primary", rootToken, map[string]any{
		"type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false,
	}, nil)
	policy := `path "transit/encrypt/recording-primary" { capabilities = ["update"] }
path "transit/decrypt/recording-primary" { capabilities = ["update"] }`
	vaultWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/recording-runtime", rootToken, map[string]any{"policy": policy}, nil)
	var tokenResponse struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	vaultWrite(t, ctx, httpClient, endpoint+"/v1/auth/token/create", rootToken, map[string]any{
		"policies": []string{"recording-runtime"}, "ttl": "5m", "renewable": false, "no_default_policy": true,
	}, &tokenResponse)
	if tokenResponse.Auth.ClientToken == "" || tokenResponse.Auth.ClientToken == rootToken {
		t.Fatal("Vault did not issue a distinct scoped token")
	}

	now := time.Now().UTC()
	tokenBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/product/transit-token", Version: "v1",
		Purpose: secretref.PurposeWorkloadCredential, TenantID: secretref.SystemTenant,
		Role: secretref.RoleProduct,
	}
	tokenBytes := []byte(tokenResponse.Auth.ClientToken)
	tokenDigest := sha256.Sum256(tokenBytes)
	tokenSourceBytes := append([]byte(nil), tokenBytes...)
	t.Cleanup(func() { clear(tokenSourceBytes) })
	tokenProvider, err := secretref.NewBoundSecretProvider(
		integrationTokenSource{value: tokenSourceBytes}, tokenBinding,
		secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(4 * time.Minute), State: secretref.KeyActive},
		"vault-token-revision-1", "sha256:"+hex.EncodeToString(tokenDigest[:]), func() time.Time { return time.Now().UTC() },
	)
	clear(tokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	transitClient, err := vaulttransit.New(vaulttransit.Config{
		Endpoint: endpoint, Mount: "transit", ReferenceAuthority: "vault",
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return time.Now().UTC() },
	}, httpClient, tokenProvider, tokenBinding)
	if err != nil {
		t.Fatal(err)
	}

	v1 := secretref.EnvelopeKeyVersion{
		Reference: "kms://vault/transit/recording-primary", Version: "v1", KeyID: "recording-primary",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), State: secretref.KeyActive},
	}
	v1Bindings, err := secretref.NewEnvelopeBindingSet(secretref.PurposeRecordingEnvelopeKey, secretref.RoleProduct, v1.KeyID, v1.Version, []secretref.EnvelopeKeyVersion{v1}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	storeRoot := t.TempDir()
	store, err := New(storeRoot, transitClient, v1Bindings)
	if err != nil {
		t.Fatal(err)
	}
	v1Handle, err := store.CreateKeyReference(ctx, "tenant-a", "recording-v1")
	if err != nil {
		t.Fatal(err)
	}
	v1Reference, err := store.PutSegment(ctx, "tenant-a", "recording-v1", v1Handle, 1, []byte("real Vault Transit v1 payload"))
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := store.ReadSegment(ctx, "tenant-a", "recording-v1", v1Handle, 1, v1Reference); err != nil || string(payload) != "real Vault Transit v1 payload" {
		t.Fatalf("Vault v1 round trip = %q, %v", payload, err)
	}

	vaultWrite(t, ctx, httpClient, endpoint+"/v1/transit/keys/recording-primary/rotate", rootToken, map[string]any{}, nil)
	v1.Window.State = secretref.KeyGrace
	v2 := secretref.EnvelopeKeyVersion{
		Reference: v1.Reference, Version: "v2", KeyID: v1.KeyID,
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute), State: secretref.KeyActive},
	}
	rotatedBindings, err := secretref.NewEnvelopeBindingSet(secretref.PurposeRecordingEnvelopeKey, secretref.RoleProduct, v2.KeyID, v2.Version, []secretref.EnvelopeKeyVersion{v1, v2}, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	restartedStore, err := New(storeRoot, transitClient, rotatedBindings)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := restartedStore.ReadSegment(ctx, "tenant-a", "recording-v1", v1Handle, 1, v1Reference); err != nil || string(payload) != "real Vault Transit v1 payload" {
		t.Fatalf("Vault grace read = %q, %v", payload, err)
	}
	v2Handle, err := restartedStore.CreateKeyReference(ctx, "tenant-a", "recording-v2")
	if err != nil {
		t.Fatal(err)
	}
	decodedV2, err := decodeKeyHandle(v2Handle)
	if err != nil || decodedV2.KMSKeyVersion != "v2" {
		t.Fatalf("Vault rotated handle = %#v, %v", decodedV2, err)
	}
	v2Reference, err := restartedStore.PutSegment(ctx, "tenant-a", "recording-v2", v2Handle, 1, []byte("real Vault Transit v2 payload"))
	if err != nil {
		t.Fatal(err)
	}

	runIntegrationCommand(t, ctx, "docker", "stop", "--time", "5", containerName)
	lossContext, lossCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer lossCancel()
	if _, err := restartedStore.ReadSegment(lossContext, "tenant-a", "recording-v2", v2Handle, 1, v2Reference); !errors.Is(err, product.ErrStoreUnavailable) {
		t.Fatalf("Vault loss error = %v", err)
	}
	if err := restartedStore.DeleteRecording(context.Background(), "tenant-a", "recording-v2", v2Handle); err != nil {
		t.Fatalf("Vault-loss cleanup = %v", err)
	}

	runIntegrationCommand(t, context.Background(), "docker", "rm", "-f", containerName)
	cleaned = true
	remaining := strings.TrimSpace(runIntegrationCommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+containerName+"$"))
	if remaining != "" {
		t.Fatal("Vault integration container cleanup is incomplete")
	}
}

func waitForVaultCA(t *testing.T, ctx context.Context, containerName, destination string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		command := exec.CommandContext(ctx, "docker", "exec", containerName, "cat", "/tmp/vault-tls/vault-ca.pem")
		certificate, err := command.Output()
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

func waitForVaultHealth(t *testing.T, ctx context.Context, client *http.Client, endpoint, token string) {
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

func vaultWrite(t *testing.T, ctx context.Context, client *http.Client, target, token string, requestBody any, responseTarget any) {
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

func runIntegrationCommand(t *testing.T, ctx context.Context, name string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(ctx, name, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		clear(output)
		t.Fatalf("integration command %q failed", name)
	}
	result := string(output)
	clear(output)
	return result
}
