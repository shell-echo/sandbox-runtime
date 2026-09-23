//go:build integration

package workloadpki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	vaultPKIIntegrationEnvironment = "SANDBOX_RUNTIME_WORKLOAD_PKI_INTEGRATION"
	vaultPKIIntegrationImage       = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
)

func TestVaultPKIIntegration(t *testing.T) {
	if os.Getenv(vaultPKIIntegrationEnvironment) != "1" {
		t.Skip("set " + vaultPKIIntegrationEnvironment + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	container := "sr-workload-pki-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	rootToken := "workload-pki-integration-root"
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = exec.Command("docker", "rm", "-f", container).Run()
		}
	})
	runPKICommand(t, ctx, "docker", "pull", vaultPKIIntegrationImage)
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
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	waitPKIVault(t, ctx, httpClient, endpoint, rootToken)
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/sys/mounts/pki", rootToken,
		map[string]any{"type": "pki", "config": map[string]string{"default_lease_ttl": "1h", "max_lease_ttl": "1h"}}, nil)
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/pki/root/generate/internal", rootToken,
		map[string]any{"common_name": "sandbox-runtime.test", "ttl": "1h", "key_type": "ec", "key_bits": 256}, nil)
	issuerRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/pki/config/issuers", nil)
	if err != nil {
		t.Fatal(err)
	}
	issuerRequest.Header.Set("X-Vault-Token", rootToken)
	issuerResponse, err := httpClient.Do(issuerRequest)
	if err != nil {
		t.Fatal(err)
	}
	var issuerConfig struct {
		Data struct {
			Default string `json:"default"`
		} `json:"data"`
	}
	issuerDecodeErr := json.NewDecoder(io.LimitReader(issuerResponse.Body, 64<<10)).Decode(&issuerConfig)
	_ = issuerResponse.Body.Close()
	if issuerResponse.StatusCode != http.StatusOK || issuerDecodeErr != nil || !vaultIssuerIDPattern.MatchString(issuerConfig.Data.Default) {
		t.Fatalf("fixed-version Vault issuer ID unavailable: status=%d decode=%v", issuerResponse.StatusCode, issuerDecodeErr)
	}
	issuerID := issuerConfig.Data.Default
	crlConfigRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/pki/config/crl", nil)
	if err != nil {
		t.Fatal(err)
	}
	crlConfigRequest.Header.Set("X-Vault-Token", rootToken)
	crlConfigResponse, err := httpClient.Do(crlConfigRequest)
	if err != nil {
		t.Fatal(err)
	}
	var crlConfig struct {
		Data struct {
			Disable     *bool `json:"disable"`
			AutoRebuild *bool `json:"auto_rebuild"`
			EnableDelta *bool `json:"enable_delta"`
		} `json:"data"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(crlConfigResponse.Body, 64<<10)).Decode(&crlConfig)
	_ = crlConfigResponse.Body.Close()
	if crlConfigResponse.StatusCode != http.StatusOK || decodeErr != nil || crlConfig.Data.Disable == nil ||
		crlConfig.Data.AutoRebuild == nil || crlConfig.Data.EnableDelta == nil || *crlConfig.Data.Disable ||
		*crlConfig.Data.AutoRebuild || *crlConfig.Data.EnableDelta {
		t.Fatalf("fixed-version Vault does not provide immediate complete CRL publication: status=%d decode=%v", crlConfigResponse.StatusCode, decodeErr)
	}
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/pki/roles/product-runtime", rootToken, map[string]any{
		"allowed_domains": []string{"product.example.test"}, "allow_bare_domains": true, "allow_subdomains": false,
		"allowed_uri_sans": []string{"spiffe://sandbox-runtime.test/product-runtime"}, "require_cn": false,
		"use_csr_common_name": true, "use_csr_sans": true, "enforce_hostnames": true, "max_ttl": "15m",
		"client_flag": true, "server_flag": true, "code_signing_flag": false, "email_protection_flag": false,
		"key_type": "ec", "key_bits": 256,
		"key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{"ClientAuth", "ServerAuth"},
	}, nil)
	policyDocument := `path "pki/sign/product-runtime" { capabilities = ["update"] }
path "pki/cert/crl" { capabilities = ["read"] }
path "pki/crl" { capabilities = ["read"] }
path "pki/config/crl" { capabilities = ["read"] }
path "pki/issuer/` + issuerID + `/der" { capabilities = ["read"] }
path "pki/issuer/` + issuerID + `/crl/der" { capabilities = ["read"] }
path "pki/revoke" { capabilities = ["update"] }`
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/certificate-controller", rootToken, map[string]any{"policy": policyDocument}, nil)
	var tokenResponse struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/auth/token/create", rootToken, map[string]any{
		"policies": []string{"certificate-controller"}, "ttl": "15m", "renewable": false, "no_default_policy": true,
	}, &tokenResponse)
	if !validVaultToken([]byte(tokenResponse.Auth.ClientToken)) || tokenResponse.Auth.LeaseDuration < 1 {
		t.Fatal("Vault did not return a scoped certificate-controller token")
	}

	fixture := newProtocolFixture(t)
	client, err := NewVaultClient(VaultConfig{Endpoint: endpoint, Mount: "pki", AllowedPolicies: map[string]string{fixture.policy.ID: fixture.policy.VaultRole},
		OperationTimeout: 5 * time.Second, Now: time.Now, RequireImmediateCompleteCRL: true}, httpClient, staticVaultTokenSource{token: VaultToken{Value: []byte(tokenResponse.Auth.ClientToken),
		ExpiresAt: time.Now().Add(time.Duration(tokenResponse.Auth.LeaseDuration) * time.Second), Revision: "vault-token-1"}})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := client.Issue(ctx, fixture.policy, fixture.csr, 10*time.Minute)
	if err != nil || issued.Serial == "" || issued.IssuerRevision == "" {
		t.Fatalf("real Vault issue = %#v, %v", issued, err)
	}
	defer issued.Destroy()
	before, err := client.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeList, err := x509.ParseRevocationList(before.DER)
	if err != nil || beforeList.Number == nil {
		t.Fatalf("initial Vault CRL number unavailable: %v", err)
	}
	before.Destroy()
	if err := client.Revoke(ctx, issued.Serial); err != nil {
		t.Fatal(err)
	}
	after, err := client.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Destroy()
	list, err := x509.ParseRevocationList(after.DER)
	if err != nil {
		t.Fatal(err)
	}
	if list.Number == nil || list.Number.Cmp(beforeList.Number) <= 0 {
		t.Fatal("real Vault did not synchronously advance the complete CRL after revoke")
	}
	issuerBlock, remainder := pem.Decode(issued.IssuingCAPEM)
	if issuerBlock == nil || issuerBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(remainder)) != 0 {
		t.Fatal("real Vault issuer PEM is invalid")
	}
	verified, err := VerifyCRLForIssuer(after, issuerBlock.Bytes, time.Now())
	if err != nil || verified.IssuerDigest() == "" {
		t.Fatalf("real Vault complete CRL did not verify under issued CA: %v", err)
	}
	found := false
	for _, entry := range list.RevokedCertificateEntries {
		if serialString(entry.SerialNumber.Bytes()) == issued.Serial {
			found = true
		}
	}
	if !found {
		t.Fatal("revoked certificate serial missing from real Vault CRL")
	}
	issuerHash := sha256.Sum256(issuerBlock.Bytes)
	peerClient, err := NewVaultClient(VaultConfig{Endpoint: endpoint, Mount: "pki", AllowedPolicies: map[string]string{fixture.policy.ID: fixture.policy.VaultRole},
		OperationTimeout: 5 * time.Second, Now: time.Now, RequireImmediateCompleteCRL: true,
		PeerIssuerSources: []VaultPeerIssuerSource{{SourceID: "product-peer-source", Mount: "pki", IssuerID: issuerID,
			IssuerDigest: "sha256:" + hex.EncodeToString(issuerHash[:])}}}, httpClient,
		staticVaultTokenSource{token: VaultToken{Value: []byte(tokenResponse.Auth.ClientToken),
			ExpiresAt: time.Now().Add(time.Duration(tokenResponse.Auth.LeaseDuration) * time.Second), Revision: "vault-token-1"}})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := peerClient.PeerRevocations(ctx, "product-peer-source", issuerBlock.Bytes)
	if err != nil {
		t.Fatalf("real fixed issuer CRL read failed: %v", err)
	}
	defer selected.Destroy()
	selectedVerified, err := VerifyCRLForIssuer(selected, issuerBlock.Bytes, time.Now())
	if err != nil || selectedVerified.CheckPeer(mustPEMCertificateDER(t, issued.CertificatePEM), issuerBlock.Bytes, time.Now()) != ErrPeerRevoked {
		t.Fatalf("real fixed issuer CRL missed revoked leaf: %v", err)
	}

	runPKICommand(t, context.Background(), "docker", "rm", "-f", container)
	cleaned = true
	if retained := strings.TrimSpace(runPKICommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+container+"$")); retained != "" {
		t.Fatal("Vault PKI integration container retained")
	}
}

func mustPEMCertificateDER(t *testing.T, document []byte) []byte {
	t.Helper()
	block, trailing := pem.Decode(document)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(trailing)) != 0 {
		t.Fatal("issued leaf PEM invalid")
	}
	return block.Bytes
}

func runPKICommand(t *testing.T, ctx context.Context, command string, arguments ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, command, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", command, err, output)
	}
	return string(output)
}

func waitPKIVaultCA(t *testing.T, ctx context.Context, container string) []byte {
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

func waitPKIVault(t *testing.T, ctx context.Context, client *http.Client, endpoint, token string) {
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

func vaultPKIWrite(t *testing.T, ctx context.Context, client *http.Client, target, token string, body, result any) {
	t.Helper()
	document, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(document)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(document))
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
	responseDocument, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if err != nil || (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent) {
		t.Fatalf("Vault setup status=%d body=%s error=%v", response.StatusCode, responseDocument, err)
	}
	if result != nil && json.Unmarshal(responseDocument, result) != nil {
		t.Fatal("decode Vault setup response")
	}
}
