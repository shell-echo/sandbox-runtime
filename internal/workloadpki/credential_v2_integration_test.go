//go:build integration

package workloadpki

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredentialv2"
)

// This is a Vault-policy component gate. The credential.v2 Unix transport is
// separately exercised with distinct Linux UIDs/GIDs in workloadcredentialv2.
func TestV2PrincipalScopedVaultCredentialController(t *testing.T) {
	if os.Getenv(vaultPKIIntegrationEnvironment) != "1" {
		t.Skip("set " + vaultPKIIntegrationEnvironment + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	container := "sr-workload-pki-v2-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	rootToken := "workload-pki-v2-integration-root"
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = exec.Command("docker", "rm", "-f", container).Run()
		}
	})
	runPKICommand(t, ctx, "docker", "run", "-d", "--name", container, "-p", "127.0.0.1::8200",
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
		"--tmpfs", "/tmp/vault-tls:rw,nosuid,nodev,noexec,size=64m,mode=0700,uid=100,gid=1000",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+rootToken, vaultPKIIntegrationImage,
		"server", "-dev", "-dev-root-token-id="+rootToken, "-dev-listen-address=0.0.0.0:8200", "-dev-tls", "-dev-tls-cert-dir=/tmp/vault-tls")
	portOutput := strings.TrimSpace(runPKICommand(t, ctx, "docker", "port", container, "8200/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("Vault port unavailable")
	}
	endpoint := "https://127.0.0.1:" + portOutput[separator+1:]
	caDocument := waitPKIVaultCA(t, ctx, container)
	defer clear(caDocument)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caDocument) {
		t.Fatal("Vault CA invalid")
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	waitPKIVault(t, ctx, httpClient, endpoint, rootToken)
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/sys/mounts/pki", rootToken,
		map[string]any{"type": "pki", "config": map[string]string{"default_lease_ttl": "1h", "max_lease_ttl": "1h"}}, nil)
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/pki/root/generate/internal", rootToken,
		map[string]any{"common_name": "sandbox-runtime.test", "ttl": "1h", "key_type": "ec", "key_bits": 256}, nil)
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/pki/roles/product-runtime", rootToken, map[string]any{
		"allowed_domains": []string{"product.example.test"}, "allow_bare_domains": true, "allow_subdomains": false,
		"allowed_uri_sans": []string{"spiffe://sandbox-runtime.test/product-runtime"}, "require_cn": false,
		"use_csr_common_name": true, "use_csr_sans": true, "max_ttl": "15m", "key_type": "ec", "key_bits": 256,
		"client_flag": true, "server_flag": true, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{"ClientAuth", "ServerAuth"},
	}, nil)
	policyACL := `path "pki/sign/product-runtime" { capabilities = ["update"] }
path "pki/crl" { capabilities = ["read"] }
path "pki/revoke" { capabilities = ["update"] }`
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/certificate-controller-pki", rootToken, map[string]any{"policy": policyACL}, nil)

	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	registry, err := securityprincipal.NewRegistry(digest("a"), digest("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.New(securityprincipal.KindController, "certificate_controller", "", digest("c"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	credentialPolicy := workloadcredentialv2.Policy{ID: "certificate-controller-token", Registry: registry, Principal: principal,
		Purpose: secretref.PurposeWorkloadCredential, BackendID: "vault-primary", BackendPolicy: "certificate-controller-pki",
		MaxTTL: 10 * time.Minute, Renewable: true, PublicKey: publicKey, ExpectedUID: uid, ExpectedGID: gid}
	issuer, err := workloadcredential.NewVaultIssuer(workloadcredential.VaultIssuerConfig{Endpoint: endpoint, BackendID: "vault-primary",
		Policies: map[string]string{credentialPolicy.ID: credentialPolicy.BackendPolicy}, ManagementToken: []byte(rootToken),
		OperationTimeout: 5 * time.Second, Now: time.Now}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	directory, err := os.MkdirTemp("/tmp", "sr-pki-v2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if os.Chmod(directory, 0o700) != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare v2 controller directory")
	}
	credentialController, err := workloadcredentialv2.NewProductionController(workloadcredentialv2.ControllerConfig{
		LedgerPath: filepath.Join(directory, "credential-ledger.json"), Policies: []workloadcredentialv2.Policy{credentialPolicy},
		Issuer: issuer, Overlap: 2 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	adapter := directV2CredentialClient{controller: credentialController, policy: credentialPolicy, key: privateKey}
	tokenSource, err := NewCredentialTokenSource(CredentialTokenSourceConfig{Client: adapter, TTL: 10 * time.Minute, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}

	fixture := newProtocolFixture(t)
	pkiClient, err := NewVaultClient(VaultConfig{Endpoint: endpoint, Mount: "pki", AllowedPolicies: map[string]string{fixture.policy.ID: fixture.policy.VaultRole},
		OperationTimeout: 5 * time.Second, Now: time.Now}, httpClient, tokenSource)
	if err != nil {
		t.Fatal(err)
	}
	initialToken, err := tokenSource.Token(ctx)
	if err != nil {
		t.Fatalf("v2 token source: %v", err)
	}
	if len(initialToken.Value) == 0 || bytes.Equal(initialToken.Value, []byte(rootToken)) {
		t.Fatal("v2 token source returned an empty or operator-root token")
	}
	initialToken.Destroy()
	issued, err := pkiClient.Issue(ctx, fixture.policy, fixture.csr, 10*time.Minute)
	if err != nil || issued.Serial == "" {
		t.Fatalf("v2-scoped PKI issue = %#v, %v", issued, err)
	}
	defer issued.Destroy()
	token, err := tokenSource.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/v1/pki/root/generate/internal", "/v1/pki/sign/other-role", "/v1/secret/data/business"} {
		assertVaultDenied(t, ctx, httpClient, endpoint+target, token.Value)
	}
	token.Destroy()
	if err := pkiClient.Revoke(ctx, issued.Serial); err != nil {
		t.Fatal(err)
	}
	snapshot, err := pkiClient.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Destroy()
	if err := tokenSource.Close(ctx); err != nil {
		t.Fatal(err)
	}
	runPKICommand(t, context.Background(), "docker", "rm", "-f", container)
	cleaned = true
}

type directV2CredentialClient struct {
	controller *workloadcredentialv2.Controller
	policy     workloadcredentialv2.Policy
	key        ed25519.PrivateKey
}

func (c directV2CredentialClient) Issue(ctx context.Context, ttl time.Duration) (CredentialLease, error) {
	return c.execute(ctx, workloadcredentialv2.IssueType, CredentialLease{}, ttl)
}

func (c directV2CredentialClient) Renew(ctx context.Context, lease CredentialLease, ttl time.Duration) (CredentialLease, error) {
	return c.execute(ctx, workloadcredentialv2.RenewType, lease, ttl)
}

func (c directV2CredentialClient) Revoke(ctx context.Context, lease CredentialLease) error {
	_, err := c.execute(ctx, workloadcredentialv2.RevokeType, lease, 0)
	return err
}

func (c directV2CredentialClient) execute(ctx context.Context, operation string, lease CredentialLease, ttl time.Duration) (CredentialLease, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return CredentialLease{}, err
	}
	now := time.Now().UTC()
	request, err := workloadcredentialv2.NewSignedRequest(c.policy, operation, lease.ID, lease.Revision, ttl,
		now.Add(5*time.Second), base64.RawURLEncoding.EncodeToString(nonce), c.key, now)
	clear(nonce)
	if err != nil {
		return CredentialLease{}, err
	}
	response, err := c.controller.Handle(ctx, request, c.policy.ExpectedUID, c.policy.ExpectedGID)
	if err != nil || response.Status != workloadcredentialv2.StatusOK {
		return CredentialLease{}, ErrUnavailable
	}
	if operation == workloadcredentialv2.RevokeType {
		return CredentialLease{}, nil
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, response.IssuedAt)
	if err != nil {
		return CredentialLease{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, response.ExpiresAt)
	if err != nil {
		return CredentialLease{}, err
	}
	return CredentialLease{ID: response.LeaseID, Revision: response.Revision, IssuedAt: issuedAt, ExpiresAt: expiresAt,
		Renewable: response.Renewable, Credential: append([]byte(nil), response.Credential...)}, nil
}

func assertVaultDenied(t *testing.T, ctx context.Context, client *http.Client, target string, token []byte) {
	t.Helper()
	document, _ := json.Marshal(map[string]any{"common_name": "denied.example.test"})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", string(token))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("Vault target %s status=%d, want 403", target, response.StatusCode)
	}
}
