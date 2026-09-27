//go:build integration

package workloadpki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestVaultPostgresClientPurposeIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_POSTGRES_CLIENT_VAULT_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_POSTGRES_CLIENT_VAULT_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	container := fmt.Sprintf("sr-pg-client-vault-%d-%d", os.Getpid(), time.Now().UnixNano())
	rootToken := "postgres-client-integration-root"
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
		t.Fatal("Vault TLS CA invalid")
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1"}}}
	waitPKIVault(t, ctx, httpClient, endpoint, rootToken)
	const mount = "postgres-client-pki"
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/sys/mounts/"+mount, rootToken,
		map[string]any{"type": "pki", "config": map[string]string{"default_lease_ttl": "1h", "max_lease_ttl": "1h"}}, nil)
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/"+mount+"/root/generate/internal", rootToken,
		map[string]any{"common_name": "PostgreSQL client purpose CA", "ttl": "1h", "key_type": "ec", "key_bits": 256}, nil)
	policy, _ := postgresPolicyFixture(t)
	identity := policy.Postgres
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/"+mount+"/roles/"+policy.VaultRole, rootToken, map[string]any{
		"allowed_domains": []string{identity.CommonName}, "allow_bare_domains": true, "allow_subdomains": false,
		"allowed_uri_sans": []string{identity.URI}, "require_cn": true, "use_csr_common_name": true,
		"use_csr_sans": true, "enforce_hostnames": false, "max_ttl": "15m",
		"client_flag": true, "server_flag": false, "code_signing_flag": false, "email_protection_flag": false,
		"key_type": "ec", "key_bits": 256, "key_usage": []string{"DigitalSignature"},
		"ext_key_usage": []string{"ClientAuth"},
	}, nil)
	acl := `path "` + mount + `/sign/` + policy.VaultRole + `" { capabilities = ["update"] }
path "` + mount + `/cert/crl" { capabilities = ["read"] }
path "` + mount + `/crl" { capabilities = ["read"] }
path "` + mount + `/config/crl" { capabilities = ["read"] }
path "` + mount + `/revoke" { capabilities = ["update"] }`
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/postgres-client-controller", rootToken,
		map[string]any{"policy": acl}, nil)
	var tokenResponse struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	vaultPKIWrite(t, ctx, httpClient, endpoint+"/v1/auth/token/create", rootToken,
		map[string]any{"policies": []string{"postgres-client-controller"}, "ttl": "15m",
			"renewable": false, "no_default_policy": true}, &tokenResponse)
	if !validVaultToken([]byte(tokenResponse.Auth.ClientToken)) || tokenResponse.Auth.LeaseDuration < 1 {
		t.Fatal("scoped PostgreSQL certificate-controller token unavailable")
	}
	client, err := NewVaultClient(VaultConfig{Endpoint: endpoint, Mount: mount,
		AllowedPolicies: map[string]string{policy.ID: policy.VaultRole}, OperationTimeout: 5 * time.Second,
		Now: time.Now, RequireImmediateCompleteCRL: true}, httpClient,
		staticVaultTokenSource{token: VaultToken{Value: []byte(tokenResponse.Auth.ClientToken),
			ExpiresAt: time.Now().Add(time.Duration(tokenResponse.Auth.LeaseDuration) * time.Second), Revision: "pg-vault-token-1"}})
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := testPostgresCSR(t, pkix.Name{CommonName: identity.CommonName}, identity.URI, nil)
	issued, err := client.Issue(ctx, policy, csr, 10*time.Minute)
	if err != nil {
		t.Fatalf("dedicated real Vault issue: %v; %s", err,
			diagnoseVaultPostgresIssue(ctx, httpClient, endpoint+"/v1/"+mount+"/sign/"+policy.VaultRole,
				rootToken, csr, identity))
	}
	defer issued.Destroy()
	leafDER := mustPEMCertificateDER(t, issued.CertificatePEM)
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || ValidatePostgresClientLeaf(leaf, identity, time.Now()) != nil {
		t.Fatalf("real PostgreSQL client leaf: %v", err)
	}
	for name, candidate := range map[string]struct{ cn, uri string }{
		"wrong CN":  {"desktop_provider_runtime", identity.URI},
		"wrong URI": {identity.CommonName, "spiffe://sandbox-runtime.test/provider-desktop-runtime"},
	} {
		t.Run(name, func(t *testing.T) {
			wrongCSR, _ := testPostgresCSR(t, pkix.Name{CommonName: candidate.cn}, candidate.uri, nil)
			body, marshalErr := json.Marshal(map[string]string{"csr": string(wrongCSR), "ttl": "10m", "format": "pem",
				"exclude_cn_from_sans": "true"})
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost,
				endpoint+"/v1/"+mount+"/sign/"+policy.VaultRole, bytes.NewReader(body))
			if requestErr != nil {
				t.Fatal(requestErr)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Vault-Token", tokenResponse.Auth.ClientToken)
			response, doErr := httpClient.Do(request)
			if doErr != nil {
				t.Fatal(doErr)
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				t.Fatal("Vault role signed a cross-purpose PostgreSQL CSR")
			}
		})
	}
	if err := client.Revoke(ctx, issued.Serial); err != nil {
		t.Fatal(err)
	}
	revocations, err := client.Revocations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revocations.Destroy()
	issuerDER := mustPEMCertificateDER(t, issued.IssuingCAPEM)
	verified, err := VerifyCRLForIssuer(revocations, issuerDER, time.Now())
	if err != nil || verified.CheckPeer(leafDER, issuerDER, time.Now()) != ErrPeerRevoked {
		t.Fatalf("dedicated real Vault CRL missed revoked PostgreSQL leaf: %v", err)
	}
	runPKICommand(t, context.Background(), "docker", "rm", "-f", container)
	cleaned = true
	if retained := strings.TrimSpace(runPKICommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+container+"$")); retained != "" {
		t.Fatal("PostgreSQL client Vault integration container retained")
	}
}

func diagnoseVaultPostgresIssue(ctx context.Context, client *http.Client, target, token string, csr []byte,
	identity PostgresClientIdentity) string {
	body, _ := json.Marshal(map[string]any{"csr": string(csr), "ttl": "600s", "format": "pem",
		"remove_roots_from_chain": false, "exclude_cn_from_sans": true})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Sprintf("diagnostic request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", token)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Sprintf("diagnostic response: %v", err)
	}
	defer response.Body.Close()
	document, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if err != nil {
		return fmt.Sprintf("diagnostic body: %v", err)
	}
	var result struct {
		Errors []string `json:"errors"`
		Data   struct {
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	if json.Unmarshal(document, &result) != nil {
		return fmt.Sprintf("diagnostic status=%d malformed response", response.StatusCode)
	}
	if result.Data.Certificate == "" {
		return fmt.Sprintf("diagnostic status=%d errors=%v", response.StatusCode, result.Errors)
	}
	block := mustPEMCertificateDERForDiagnostic(result.Data.Certificate)
	leaf, err := x509.ParseCertificate(block)
	if err != nil {
		return fmt.Sprintf("diagnostic status=%d parse=%v", response.StatusCode, err)
	}
	expectedSubject, _ := postgresSubject(identity.CommonName)
	expectedSAN, _ := postgresSAN(identity.URI)
	var actualSAN []byte
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(postgresClientSAN) {
			actualSAN = extension.Value
		}
	}
	return fmt.Sprintf("diagnostic status=%d subject=%q subjectDER=%s expectedSubject=%s DNS=%v URI=%v EKU=%v keyUsage=%d isCA=%t basicConstraints=%t unknownEKU=%v TTL=%s SAN=%s expectedSAN=%s leafCheck=%v",
		response.StatusCode, leaf.Subject.String(), hex.EncodeToString(leaf.RawSubject), hex.EncodeToString(expectedSubject),
		leaf.DNSNames, leaf.URIs, leaf.ExtKeyUsage, leaf.KeyUsage, leaf.IsCA, leaf.BasicConstraintsValid, leaf.UnknownExtKeyUsage, leaf.NotAfter.Sub(leaf.NotBefore),
		hex.EncodeToString(actualSAN), hex.EncodeToString(expectedSAN), ValidatePostgresClientLeaf(leaf, identity, time.Now()))
}

func mustPEMCertificateDERForDiagnostic(document string) []byte {
	block, _ := pem.Decode([]byte(document))
	if block == nil {
		return nil
	}
	return block.Bytes
}
