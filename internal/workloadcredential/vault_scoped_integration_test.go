//go:build integration

package workloadcredential

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/credentialbackend"
	"github.com/shell-echo/sandbox-runtime/internal/phase6vaultbootstrap"
)

const scopedVaultIntegrationEnv = "SANDBOX_RUNTIME_WORKLOAD_CREDENTIAL_SCOPED_INTEGRATION"

// This is a real, non-dev Vault component gate for the fixed token-role
// boundary. The loopback publication and test CA do not represent the final
// isolated service bridge or complete Phase 6 process topology.
func TestVaultScopedCredentialRoleAfterRootRevocation(t *testing.T) { //nolint:gocyclo
	if os.Getenv(scopedVaultIntegrationEnv) != "1" {
		t.Skip("set " + scopedVaultIntegrationEnv + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	directory, err := os.MkdirTemp(".", ".sr-vault-scoped-")
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	serverCA, serverCAKey := scopedVaultCA(t, now, "server CA")
	clientCA, clientCAKey := scopedVaultCA(t, now, "client CA")
	serverCertificate, serverKey := scopedVaultLeaf(t, now, serverCA, serverCAKey, false)
	clientCertificate, clientKey := scopedVaultLeaf(t, now, clientCA, clientCAKey, true)
	clientCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw})
	serverKeyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	clientKeyDER, _ := x509.MarshalPKCS8PrivateKey(clientKey)
	for name, value := range map[string][]byte{
		"server.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertificate.Raw}),
		"server-key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
		"client-ca.pem":  clientCAPEM,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), value, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	configuration := `ui = false
disable_mlock = true
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/vault/config/server.pem"
  tls_key_file = "/vault/config/server-key.pem"
  tls_client_ca_file = "/vault/config/client-ca.pem"
  tls_min_version = "tls13"
  tls_require_and_verify_client_cert = true
}
storage "inmem" {}
`
	if err := os.WriteFile(filepath.Join(directory, "vault.hcl"), []byte(configuration), 0o444); err != nil {
		t.Fatal(err)
	}
	container := "sr-vault-scoped-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = exec.Command("docker", "rm", "-f", container).Run()
		}
	})
	if _, err := exec.CommandContext(ctx, "docker", "image", "inspect", vaultCredentialIntegrationImage).Output(); err != nil {
		runCredentialCommand(t, ctx, "docker", "pull", vaultCredentialIntegrationImage)
	}
	runCredentialCommand(t, ctx, "docker", "run", "-d", "--name", container, "-p", "127.0.0.1::8200",
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "-v", directory+":/vault/config:ro",
		vaultCredentialIntegrationImage, "server")
	portOutput := strings.TrimSpace(runCredentialCommand(t, ctx, "docker", "port", container, "8200/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("Vault port unavailable")
	}
	endpoint := "https://127.0.0.1:" + portOutput[separator+1:]
	clientPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertificate.Raw}), clientCAPEM...)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})
	pair, err := tls.X509KeyPair(clientPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(serverCA)
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{pair}}},
		Timeout: 5 * time.Second}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		status, _ := scopedVaultRequest(ctx, httpClient, http.MethodGet, endpoint+"/v1/sys/init", "", nil)
		if status == http.StatusOK {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	var initialized struct {
		KeysBase64 []string `json:"keys_base64"`
		RootToken  string   `json:"root_token"`
	}
	scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/sys/init", "",
		map[string]any{"secret_shares": 1, "secret_threshold": 1}, &initialized)
	if len(initialized.KeysBase64) != 1 || initialized.RootToken == "" {
		t.Fatal("Vault init did not return one unseal share and root token")
	}
	scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/sys/unseal", "",
		map[string]string{"key": initialized.KeysBase64[0]}, nil)
	initialized.KeysBase64 = nil
	// This real, non-dev mTLS bootstrap freezes Vault's actual issuer UUID,
	// full DER and complete-CRL source before the root token is revoked. It is
	// source input only; no final security profile or workload is admitted here.
	scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/sys/mounts/pki", initialized.RootToken,
		map[string]any{"type": "pki", "config": map[string]string{"default_lease_ttl": "1h", "max_lease_ttl": "1h"}}, nil)
	scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/pki/root/generate/internal", initialized.RootToken,
		map[string]any{"common_name": "sandbox-runtime.test", "ttl": "1h", "key_type": "ec", "key_bits": 256}, nil)
	observedIssuer, err := phase6vaultbootstrap.ObserveIssuer(ctx, httpClient, endpoint, "127.0.0.1",
		[]byte(initialized.RootToken), time.Now().UTC())
	if err != nil || observedIssuer.ID == "" || len(observedIssuer.DER) == 0 ||
		observedIssuer.Digest != scopedVaultDigestDER(observedIssuer.DER) || observedIssuer.CRLNextUpdate.IsZero() {
		t.Fatalf("real Vault fixed issuer bootstrap: %v", err)
	}
	policy := "certificate-controller-pki"
	otherPolicy := "product-runtime-vault"
	unrelatedPolicy := "unrelated-business-vault"
	role := Phase6TokenRole(policy)
	otherRole := Phase6TokenRole(otherPolicy)
	scopedVaultMust(t, ctx, httpClient, http.MethodPut, endpoint+"/v1/sys/policies/acl/"+policy, initialized.RootToken,
		map[string]string{"policy": `path "secret/data/certificate" { capabilities = ["read"] }`}, nil)
	scopedVaultMust(t, ctx, httpClient, http.MethodPut, endpoint+"/v1/sys/policies/acl/"+otherPolicy, initialized.RootToken,
		map[string]string{"policy": `path "secret/data/product" { capabilities = ["read"] }`}, nil)
	scopedVaultMust(t, ctx, httpClient, http.MethodPut, endpoint+"/v1/sys/policies/acl/"+unrelatedPolicy, initialized.RootToken,
		map[string]string{"policy": `path "secret/data/unrelated" { capabilities = ["read"] }`}, nil)
	managementACL := `path "auth/token/create/` + role + `" { capabilities = ["update"] }
path "auth/token/create/` + otherRole + `" { capabilities = ["update"] }
path "auth/token/roles/` + role + `" { capabilities = ["read"] }
path "auth/token/roles/` + otherRole + `" { capabilities = ["read"] }
path "auth/token/lookup-accessor" { capabilities = ["update"] }
path "auth/token/revoke-accessor" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }`
	scopedVaultMust(t, ctx, httpClient, http.MethodPut, endpoint+"/v1/sys/policies/acl/phase6-credential-management", initialized.RootToken,
		map[string]string{"policy": managementACL}, nil)
	for roleName, allowed := range map[string]string{role: policy, otherRole: otherPolicy} {
		scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/roles/"+roleName, initialized.RootToken,
			map[string]any{"allowed_policies": []string{allowed}, "disallowed_policies": []string{"default", "root"},
				"token_no_default_policy": true, "token_type": "service", "token_explicit_max_ttl": "15m",
				"renewable": false, "orphan": false}, nil)
	}
	var unrelated struct {
		Auth struct {
			Accessor string `json:"accessor"`
			Orphan   bool   `json:"orphan"`
		} `json:"auth"`
	}
	scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/create-orphan", initialized.RootToken,
		map[string]any{"policies": []string{unrelatedPolicy}, "ttl": "5m", "renewable": false,
			"no_default_policy": true}, &unrelated)
	if unrelated.Auth.Accessor == "" || !unrelated.Auth.Orphan {
		t.Fatal("disposable unrelated-domain accessor missing")
	}
	var management struct {
		Auth struct {
			ClientToken string   `json:"client_token"`
			Policies    []string `json:"policies"`
			Orphan      bool     `json:"orphan"`
		} `json:"auth"`
	}
	scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/create-orphan", initialized.RootToken,
		map[string]any{"policies": []string{"phase6-credential-management"}, "ttl": "15m", "renewable": false,
			"no_default_policy": true}, &management)
	if management.Auth.ClientToken == "" || !management.Auth.Orphan || len(management.Auth.Policies) != 1 ||
		management.Auth.Policies[0] != "phase6-credential-management" {
		t.Fatal("limited orphan management token has the wrong authority")
	}
	scopedVaultMust(t, ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/revoke-self", initialized.RootToken, nil, nil)
	if status, _ := scopedVaultRequest(ctx, httpClient, http.MethodGet, endpoint+"/v1/auth/token/lookup-self", initialized.RootToken, nil); status != http.StatusForbidden {
		t.Fatalf("revoked initial root token status = %d", status)
	}
	initialized.RootToken = ""
	if status, _ := scopedVaultRequest(ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/create", management.Auth.ClientToken,
		map[string]any{"policies": []string{policy}, "ttl": "20s", "no_default_policy": true}); status != http.StatusForbidden {
		t.Fatalf("generic token creation status = %d", status)
	}
	if status, _ := scopedVaultRequest(ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/create/"+role, management.Auth.ClientToken,
		map[string]any{"policies": []string{otherPolicy}, "ttl": "20s", "no_default_policy": true}); status < http.StatusBadRequest {
		t.Fatalf("cross-role policy creation status = %d", status)
	}
	if status, _ := scopedVaultRequest(ctx, httpClient, http.MethodGet, endpoint+"/v1/secret/data/product", management.Auth.ClientToken, nil); status != http.StatusForbidden {
		t.Fatalf("management token direct business read status = %d", status)
	}
	if status, document := scopedVaultRequest(ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/lookup-accessor",
		management.Auth.ClientToken, map[string]string{"accessor": unrelated.Auth.Accessor}); status != http.StatusOK {
		clear(document)
		t.Fatalf("Vault accessor ACL unexpectedly isolated unrelated token: %d", status)
	} else {
		clear(document)
	}
	if status, document := scopedVaultRequest(ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/revoke-accessor",
		management.Auth.ClientToken, map[string]string{"accessor": unrelated.Auth.Accessor}); status != http.StatusNoContent {
		clear(document)
		t.Fatalf("Vault accessor ACL unexpectedly isolated unrelated revocation: %d", status)
	} else {
		clear(document)
	}
	if status, document := scopedVaultRequest(ctx, httpClient, http.MethodPost, endpoint+"/v1/auth/token/lookup-accessor",
		management.Auth.ClientToken, map[string]string{"accessor": unrelated.Auth.Accessor}); status < http.StatusBadRequest {
		clear(document)
		t.Fatalf("unrelated token remained active after accessor revoke: %d", status)
	} else {
		clear(document)
	}
	spec := credentialbackend.IssueSpec{SubjectID: "certificate_controller", SubjectDigest: scopedVaultDigest("subject"),
		Purpose: "workload_credential", PolicyID: "certificate-credential", PolicyDigest: scopedVaultDigest("policy"),
		BindingDigest: scopedVaultDigest("binding"), BackendID: "vault-primary", BackendPolicy: policy,
		LeaseID: "lease2_" + strings.Repeat("a", 32), TTL: 90 * time.Second}
	issuer, err := NewVaultIssuer(VaultIssuerConfig{Endpoint: endpoint, BackendID: spec.BackendID,
		Policies: map[string]string{spec.PolicyID: policy}, ManagementToken: []byte(management.Auth.ClientToken),
		OperationTimeout: 5 * time.Second, Now: time.Now, RequireScopedTokenRoles: true}, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	if err := issuer.ValidateScopedRoles(ctx); err != nil {
		t.Fatalf("real Vault fixed-role preflight: %v", err)
	}
	issued, err := issuer.IssueScoped(ctx, spec)
	if err != nil {
		t.Fatalf("real Vault fixed-role issuance: %v", err)
	}
	defer issued.Destroy()
	if err := issuer.Verify(ctx, issued); err != nil {
		t.Fatalf("real Vault fixed-role verification: %v", err)
	}
	if err := issuer.Revoke(ctx, issued.BackendLeaseID); err != nil {
		t.Fatalf("real Vault exact accessor revocation: %v", err)
	}
	if err := issuer.Verify(ctx, issued); err == nil {
		t.Fatal("revoked child token remained verifiable")
	}
	runCredentialCommand(t, context.Background(), "docker", "rm", "-f", container)
	cleaned = true
	if retained := strings.TrimSpace(runCredentialCommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+container+"$")); retained != "" {
		t.Fatal("real Vault scoped role container retained")
	}
}

func scopedVaultRequest(ctx context.Context, client *http.Client, method, target, token string, value any) (int, []byte) {
	var body io.Reader
	if value != nil {
		document, err := json.Marshal(value)
		if err != nil {
			return 0, nil
		}
		defer clear(document)
		body = bytes.NewReader(document)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return 0, nil
	}
	request.Header.Set("Accept", "application/json")
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	if value != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil
	}
	defer response.Body.Close()
	document, err := io.ReadAll(io.LimitReader(response.Body, 256<<10+1))
	if err != nil || len(document) > 256<<10 {
		clear(document)
		return 0, nil
	}
	return response.StatusCode, document
}

func scopedVaultMust(t *testing.T, ctx context.Context, client *http.Client, method, target, token string, value, result any) {
	t.Helper()
	status, document := scopedVaultRequest(ctx, client, method, target, token, value)
	defer clear(document)
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Fatalf("fixed Vault bootstrap operation failed with status %d", status)
	}
	if result != nil && json.Unmarshal(document, result) != nil {
		t.Fatal("fixed Vault bootstrap response was invalid")
	}
}

func scopedVaultDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func scopedVaultDigestDER(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func scopedVaultCA(t *testing.T, now time.Time, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func scopedVaultLeaf(t *testing.T, now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(30 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		identity, _ := url.Parse("spiffe://sandbox-runtime.test/workload-credential-controller")
		template.URIs = []*url.URL{identity}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}
