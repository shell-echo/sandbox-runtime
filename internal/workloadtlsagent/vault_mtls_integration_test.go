//go:build integration

package workloadtlsagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

const (
	vaultMTLSIntegrationEnvironment = "SANDBOX_RUNTIME_WORKLOAD_TLS_INTEGRATION"
	vaultMTLSIntegrationImage       = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
)

type integrationTokenSource struct{ token workloadpki.VaultToken }

func (s integrationTokenSource) Token(context.Context) (workloadpki.VaultToken, error) {
	return workloadpki.VaultToken{Value: append([]byte(nil), s.token.Value...), ExpiresAt: s.token.ExpiresAt, Revision: s.token.Revision}, nil
}

type policyVaultClient struct {
	client *workloadpki.VaultClient
	policy workloadpki.Policy
}

func (c policyVaultClient) Issue(ctx context.Context, csr []byte, ttl time.Duration) (workloadpki.IssuedCertificate, error) {
	return c.client.Issue(ctx, c.policy, csr, ttl)
}

func (c policyVaultClient) Revocations(ctx context.Context) (workloadpki.RevocationSnapshot, error) {
	return c.client.Revocations(ctx)
}

func (c policyVaultClient) Revoke(ctx context.Context, serial string) error {
	return c.client.Revoke(ctx, serial)
}

func TestVaultMTLSBootstrapSwitchesToManagedCertificateAndRevokesIt(t *testing.T) { //nolint:gocyclo
	if os.Getenv(vaultMTLSIntegrationEnvironment) != "1" {
		t.Skip("set " + vaultMTLSIntegrationEnvironment + "=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	directory, err := os.MkdirTemp(".", ".sr-vault-mtls-")
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
	serverCA, serverCAKey := integrationCA(t, now, "Vault server CA")
	clientCA, clientCAKey := integrationCA(t, now, "Vault workload CA")
	serverCertificate, serverKey := integrationCertificate(t, now, serverCA, serverCAKey, false, "", nil, []net.IP{net.ParseIP("127.0.0.1")})
	bootstrapCertificate, bootstrapKey := integrationCertificate(t, now, clientCA, clientCAKey, true,
		"spiffe://sandbox-runtime.test/certificate-controller", []string{"certificate-controller.internal.test"}, nil)
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCA.Raw})
	clientCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCA.Raw})
	serverPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertificate.Raw})
	serverKeyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})
	bootstrapPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bootstrapCertificate.Raw}), clientCAPEM...)
	bootstrapKeyDER, _ := x509.MarshalPKCS8PrivateKey(bootstrapKey)
	bootstrapKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bootstrapKeyDER})
	clientCAKeyDER, _ := x509.MarshalPKCS8PrivateKey(clientCAKey)
	clientCAKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientCAKeyDER})
	for name, value := range map[string][]byte{"server-ca.pem": serverCAPEM, "client-ca.pem": clientCAPEM,
		"server.pem": serverPEM, "server-key.pem": serverKeyPEM} {
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
	container := "sr-vault-mtls-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = exec.Command("docker", "rm", "-f", container).Run()
		}
	})
	if _, err := exec.CommandContext(ctx, "docker", "image", "inspect", vaultMTLSIntegrationImage).Output(); err != nil {
		runVaultMTLSCommand(t, ctx, "docker", "pull", vaultMTLSIntegrationImage)
	}
	runVaultMTLSCommand(t, ctx, "docker", "run", "-d", "--name", container, "-p", "127.0.0.1::8200",
		"--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "-v", directory+":/vault/config:ro",
		vaultMTLSIntegrationImage, "server")
	portOutput := strings.TrimSpace(runVaultMTLSCommand(t, ctx, "docker", "port", container, "8200/tcp"))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("Vault port unavailable")
	}
	endpoint := "https://127.0.0.1:" + portOutput[separator+1:]
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverCA)
	digest := func(value string) string { return "sha256:" + strings.Repeat(value, 64) }
	registry, err := securityprincipal.NewRegistry(digest("a"), digest("b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := registry.New(securityprincipal.KindController, "certificate_controller", "", digest("c"))
	if err != nil {
		t.Fatal(err)
	}
	requestPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := workloadpki.Policy{ID: "certificate-controller-vault-tls", Registry: registry, Requester: principal, Subject: principal,
		TrustDomain: "sandbox-runtime.test", URI: "spiffe://sandbox-runtime.test/certificate-controller",
		DNSNames: []string{"certificate-controller.internal.test"}, Usages: []string{"client_auth"}, VaultRole: "certificate-controller-vault",
		MaxTTLSeconds: 600, PublicKey: requestPublic}
	bootstrapPair, err := ValidateBootstrapCertificate(bootstrapPEM, bootstrapKeyPEM, integrationRoots(clientCA), policy, now)
	if err != nil {
		t.Fatal(err)
	}
	var managed atomic.Pointer[Manager]
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: serverRoots, ServerName: "127.0.0.1"}
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if manager := managed.Load(); manager != nil {
			certificate, certificateErr := manager.Certificate()
			return &certificate, certificateErr
		}
		return &bootstrapPair, nil
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	tracked := NewBootstrapTrackingTransport(transport)
	httpClient := &http.Client{Transport: tracked}
	waitForVaultMTLS(t, ctx, httpClient, endpoint, container)
	withoutClientCertificate := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: serverRoots, ServerName: "127.0.0.1"}}, Timeout: 3 * time.Second}
	if request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/sys/health", nil); requestErr != nil {
		t.Fatal(requestErr)
	} else if response, requestErr := withoutClientCertificate.Do(request); requestErr == nil {
		_ = response.Body.Close()
		t.Fatal("Vault accepted a client without a certificate")
	}
	var initialize struct {
		KeysBase64 []string `json:"keys_base64"`
		RootToken  string   `json:"root_token"`
	}
	vaultMTLSWrite(t, ctx, httpClient, endpoint+"/v1/sys/init", "", map[string]any{"secret_shares": 1, "secret_threshold": 1}, &initialize)
	if len(initialize.KeysBase64) != 1 || initialize.RootToken == "" {
		t.Fatal("Vault initialization response incomplete")
	}
	vaultMTLSWrite(t, ctx, httpClient, endpoint+"/v1/sys/unseal", "", map[string]any{"key": initialize.KeysBase64[0]}, nil)
	vaultMTLSWrite(t, ctx, httpClient, endpoint+"/v1/sys/mounts/pki", initialize.RootToken,
		map[string]any{"type": "pki", "config": map[string]string{"default_lease_ttl": "1h", "max_lease_ttl": "1h"}}, nil)
	bundle := append(append([]byte(nil), clientCAKeyPEM...), clientCAPEM...)
	vaultMTLSWrite(t, ctx, httpClient, endpoint+"/v1/pki/config/ca", initialize.RootToken, map[string]any{"pem_bundle": string(bundle)}, nil)
	clear(bundle)
	vaultMTLSWrite(t, ctx, httpClient, endpoint+"/v1/pki/roles/certificate-controller-vault", initialize.RootToken, map[string]any{
		"allowed_domains": policy.DNSNames, "allow_bare_domains": true, "allow_subdomains": false,
		"allowed_uri_sans": []string{policy.URI}, "require_cn": false, "use_csr_common_name": true, "use_csr_sans": true,
		"max_ttl": "10m", "key_type": "ec", "key_bits": 256, "client_flag": true, "server_flag": false,
		"key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{"ClientAuth"},
	}, nil)
	acl := `path "pki/sign/certificate-controller-vault" { capabilities = ["update"] }
path "pki/cert/crl" { capabilities = ["read"] }
path "pki/crl" { capabilities = ["read"] }
path "pki/revoke" { capabilities = ["update"] }`
	vaultMTLSWrite(t, ctx, httpClient, endpoint+"/v1/sys/policies/acl/certificate-controller-pki", initialize.RootToken,
		map[string]any{"policy": acl}, nil)
	var tokenResponse struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	vaultMTLSWrite(t, ctx, httpClient, endpoint+"/v1/auth/token/create", initialize.RootToken,
		map[string]any{"policies": []string{"certificate-controller-pki"}, "ttl": "10m", "renewable": false, "no_default_policy": true}, &tokenResponse)
	token := workloadpki.VaultToken{Value: []byte(tokenResponse.Auth.ClientToken), ExpiresAt: time.Now().Add(time.Duration(tokenResponse.Auth.LeaseDuration) * time.Second), Revision: "mtls-vault-token-1"}
	vaultClient, err := workloadpki.NewVaultClient(workloadpki.VaultConfig{Endpoint: endpoint, Mount: "pki",
		AllowedPolicies: map[string]string{policy.ID: policy.VaultRole}, OperationTimeout: 5 * time.Second, Now: time.Now},
		httpClient, integrationTokenSource{token: token})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewProduction(Config{Policy: policy, Client: policyVaultClient{client: vaultClient, policy: policy}, TTL: 5 * time.Minute,
		RotateAfter: 2 * time.Minute, Overlap: 30 * time.Second, CheckInterval: time.Second, RevocationPollInterval: time.Second,
		RevocationMaxStaleness: 30 * time.Second, OperationTimeout: 5 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	managedSerial := snapshot.Serial
	snapshot.Destroy()
	managed.Store(manager)
	tracked.Switch()
	transport.CloseIdleConnections()
	if err := tracked.WaitBootstrapDrain(ctx); err != nil {
		t.Fatalf("bootstrap mTLS requests did not drain: %v", err)
	}
	DestroyTLSCertificate(&bootstrapPair)
	revocations, err := vaultClient.Revocations(ctx)
	if err != nil {
		t.Fatalf("post-switch managed mTLS request = %v", err)
	}
	revocations.Destroy()
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	managed.Store(nil)
	transport.CloseIdleConnections()
	if request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/sys/health", nil); err != nil {
		t.Fatal(err)
	} else if _, err := httpClient.Do(request); err == nil {
		t.Fatal("Vault request succeeded after both bootstrap and managed certificates were destroyed")
	}
	verificationPair, err := tls.X509KeyPair(bootstrapPEM, bootstrapKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	verificationClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: serverRoots, ServerName: "127.0.0.1", Certificates: []tls.Certificate{verificationPair}}}}
	crlDocument := vaultMTLSRead(t, ctx, verificationClient, endpoint+"/v1/pki/crl", token.Value)
	list, err := x509.ParseRevocationList(crlDocument)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range list.RevokedCertificateEntries {
		actual := strings.TrimLeft(strings.ReplaceAll(managedSerial, ":", ""), "0")
		if actual == "" {
			actual = "0"
		}
		if strings.EqualFold(actual, entry.SerialNumber.Text(16)) {
			found = true
		}
	}
	if !found {
		t.Fatal("managed certificate was not present in the authoritative Vault CRL")
	}
	runVaultMTLSCommand(t, context.Background(), "docker", "rm", "-f", container)
	cleaned = true
	if retained := strings.TrimSpace(runVaultMTLSCommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+container+"$")); retained != "" {
		t.Fatal("Vault mTLS integration container retained")
	}
}

func integrationCA(t *testing.T, now time.Time, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
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

func integrationCertificate(t *testing.T, now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool,
	identity string, dns []string, ips []net.IP) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns, IPAddresses: ips}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		parsed, parseErr := url.Parse(identity)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		template.URIs = []*url.URL{parsed}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
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

func integrationRoots(certificate *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return pool
}

func runVaultMTLSCommand(t *testing.T, ctx context.Context, command string, arguments ...string) string {
	t.Helper()
	output, err := exec.CommandContext(ctx, command, arguments...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v: %s", command, err, output)
	}
	return string(output)
}

func waitForVaultMTLS(t *testing.T, ctx context.Context, client *http.Client, endpoint, container string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/sys/health", nil)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	logs, _ := exec.CommandContext(ctx, "docker", "logs", container).CombinedOutput()
	t.Fatalf("mTLS Vault unavailable: %s", logs)
}

func vaultMTLSWrite(t *testing.T, ctx context.Context, client *http.Client, target, token string, body, result any) {
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
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseDocument, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if err != nil || response.StatusCode < 200 || response.StatusCode > 299 {
		t.Fatalf("Vault setup target=%s status=%d body=%s error=%v", target, response.StatusCode, responseDocument, err)
	}
	if result != nil && json.Unmarshal(responseDocument, result) != nil {
		t.Fatalf("decode Vault response for %s", target)
	}
}

func vaultMTLSRead(t *testing.T, ctx context.Context, client *http.Client, target string, token []byte) []byte {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Vault-Token", string(token))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	document, err := io.ReadAll(io.LimitReader(response.Body, 512<<10))
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("Vault read status=%d error=%v", response.StatusCode, err)
	}
	return document
}
