//go:build integration

package workloadcredential

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6vaultbootstrap"
)

const vaultDNSComponentImage = "docker.io/coredns/coredns@sha256:7efd3c635b03efd68c4e8398fc45f0d993d0e9ab016f72c1cefb0fd6d01aa286"

type vaultDNSLeaf struct {
	certificate []byte
	privateKey  *ecdsa.PrivateKey
	issuer      []byte
}

// This is a real two-issuer Vault and stock CoreDNS component probe. The
// loopback Docker publication is controlled test ingress, not the final
// isolated 82-principal network graph or a Slice 6 evidence receipt.
func runVaultDNSIssuerSeparationComponent(t *testing.T, ctx context.Context, client *http.Client,
	endpoint, rootToken string, general, broker phase6vaultbootstrap.Issuer, parent string) {
	t.Helper()
	type roleSpec struct {
		name, commonName, uri, issuerID string
		server                          bool
	}
	roles := []roleSpec{
		{name: "component-broker", commonName: "egress-broker-product.sandbox-runtime.test",
			uri: "spiffe://sandbox-runtime.test/egress-broker-product", issuerID: broker.ID},
		{name: "component-general", commonName: "product-runtime.sandbox-runtime.test",
			uri: "spiffe://sandbox-runtime.test/product-runtime", issuerID: general.ID},
		{name: "component-dns", commonName: "dns.sandbox-runtime.test",
			uri: "spiffe://sandbox-runtime.test/external/dns", issuerID: general.ID, server: true},
	}
	for _, role := range roles {
		scopedVaultMust(t, ctx, client, http.MethodPost, endpoint+"/v1/pki/roles/"+role.name, rootToken,
			map[string]any{"issuer_ref": role.issuerID, "allowed_domains": []string{role.commonName},
				"allow_bare_domains": true, "allow_subdomains": false, "allow_ip_sans": false,
				"allowed_uri_sans": []string{role.uri}, "require_cn": true,
				"use_csr_common_name": true, "use_csr_sans": true, "enforce_hostnames": true,
				"max_ttl": "15m", "client_flag": !role.server, "server_flag": role.server,
				"code_signing_flag": false, "email_protection_flag": false,
				"key_type": "ec", "key_bits": 256,
				"key_usage":     []string{"DigitalSignature"},
				"ext_key_usage": []string{map[bool]string{true: "ServerAuth", false: "ClientAuth"}[role.server]}}, nil)
		var configured struct {
			Data struct {
				IssuerRef string `json:"issuer_ref"`
			} `json:"data"`
		}
		scopedVaultMust(t, ctx, client, http.MethodGet, endpoint+"/v1/pki/roles/"+role.name,
			rootToken, nil, &configured)
		if configured.Data.IssuerRef != role.issuerID {
			t.Fatalf("Vault role %s did not pin immutable issuer UUID", role.name)
		}
	}
	acl := `path "pki/sign/component-broker" { capabilities = ["update"] }
path "pki/sign/component-general" { capabilities = ["update"] }
path "pki/sign/component-dns" { capabilities = ["update"] }`
	scopedVaultMust(t, ctx, client, http.MethodPut, endpoint+"/v1/sys/policies/acl/phase6-dns-component-signer",
		rootToken, map[string]string{"policy": acl}, nil)
	var credential struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	scopedVaultMust(t, ctx, client, http.MethodPost, endpoint+"/v1/auth/token/create-orphan", rootToken,
		map[string]any{"policies": []string{"phase6-dns-component-signer"}, "ttl": "5m",
			"renewable": false, "no_default_policy": true}, &credential)
	if credential.Auth.ClientToken == "" {
		t.Fatal("restricted DNS component signer token missing")
	}
	tokenRevoked := false
	t.Cleanup(func() {
		if !tokenRevoked {
			_, _ = scopedVaultRequest(context.Background(), client, http.MethodPost,
				endpoint+"/v1/auth/token/revoke", rootToken,
				map[string]string{"token": credential.Auth.ClientToken})
		}
	})
	leaves := make(map[string]vaultDNSLeaf, len(roles))
	for _, role := range roles {
		csr, key := vaultDNSCSR(t, role.commonName, role.uri)
		var issued struct {
			Data struct {
				Certificate string `json:"certificate"`
				IssuingCA   string `json:"issuing_ca"`
			} `json:"data"`
		}
		scopedVaultMust(t, ctx, client, http.MethodPost, endpoint+"/v1/pki/sign/"+role.name,
			credential.Auth.ClientToken, map[string]any{"csr": string(csr), "ttl": "5m"}, &issued)
		issuer := general.DER
		if role.name == "component-broker" {
			issuer = broker.DER
		}
		leafBlock, rest := pem.Decode([]byte(issued.Data.Certificate))
		caBlock, caRest := pem.Decode([]byte(issued.Data.IssuingCA))
		if leafBlock == nil || caBlock == nil || len(bytes.TrimSpace(rest)) != 0 ||
			len(bytes.TrimSpace(caRest)) != 0 || !bytes.Equal(caBlock.Bytes, issuer) {
			t.Fatalf("Vault role %s issued under wrong CA", role.name)
		}
		certificate, err := x509.ParseCertificate(leafBlock.Bytes)
		if err != nil || certificate.CheckSignatureFrom(mustVaultDNSIssuer(t, issuer)) != nil ||
			len(certificate.URIs) != 1 || certificate.URIs[0].String() != role.uri ||
			certificate.Subject.CommonName != role.commonName {
			t.Fatalf("Vault role %s issued wrong subject: %v", role.name, err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(mustVaultDNSIssuer(t, issuer))
		usage := x509.ExtKeyUsageClientAuth
		if role.server {
			usage = x509.ExtKeyUsageServerAuth
		}
		if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots,
			DNSName: role.commonName, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			t.Fatalf("Vault role %s leaf chain or EKU invalid: %v", role.name, err)
		}
		leaves[role.name] = vaultDNSLeaf{certificate: []byte(issued.Data.Certificate), privateKey: key, issuer: issuer}
	}
	wrongCSR, _ := vaultDNSCSR(t, roles[0].commonName, roles[1].uri)
	status, _ := scopedVaultRequest(ctx, client, http.MethodPost, endpoint+"/v1/pki/sign/component-broker",
		credential.Auth.ClientToken, map[string]any{"csr": string(wrongCSR), "ttl": "5m"})
	if status < 400 || status >= 500 {
		t.Fatalf("broker role accepted wrong subject or did not return a policy denial: status=%d", status)
	}
	status, _ = scopedVaultRequest(ctx, client, http.MethodPost,
		endpoint+"/v1/pki/issuer/"+general.ID+"/sign/component-broker", credential.Auth.ClientToken,
		map[string]any{"csr": string(wrongCSR), "ttl": "5m"})
	if status != http.StatusForbidden {
		t.Fatalf("restricted signer reached per-issuer override: status=%d", status)
	}
	probeStockCoreDNSClientCA(t, ctx, parent, general.DER, broker.DER,
		leaves["component-dns"], leaves["component-broker"], leaves["component-general"])
	scopedVaultMust(t, ctx, client, http.MethodPost, endpoint+"/v1/auth/token/revoke", rootToken,
		map[string]string{"token": credential.Auth.ClientToken}, nil)
	tokenRevoked = true
}

func vaultDNSCSR(t *testing.T, commonName, uri string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identity, uriErr := url.Parse(uri)
	if err != nil || uriErr != nil {
		t.Fatal("component CSR key or URI")
	}
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}, URIs: []*url.URL{identity},
		DNSNames: []string{commonName}}
	der, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key
}

func mustVaultDNSIssuer(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func probeStockCoreDNSClientCA(t *testing.T, ctx context.Context, parent string,
	generalDER, brokerDER []byte, server, broker, ordinary vaultDNSLeaf) {
	t.Helper()
	directory := filepath.Join(parent, "dns-component")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(server.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	corefile := "tls://.:853 {\n  tls /config/server.pem /config/server-key.pem /config/broker-ca.pem {\n    client_auth require_and_verify\n  }\n  whoami\n}\n"
	for name, data := range map[string][]byte{
		"Corefile": []byte(corefile), "server.pem": server.certificate,
		"server-key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"broker-ca.pem":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: brokerDER}),
	} {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exec.CommandContext(ctx, "docker", "image", "inspect", vaultDNSComponentImage).Output(); err != nil {
		runCredentialCommand(t, ctx, "docker", "pull", vaultDNSComponentImage)
	}
	container := fmt.Sprintf("sr-dns-issuer-%d", time.Now().UnixNano())
	cleaned := false
	t.Cleanup(func() {
		if !cleaned {
			_ = exec.Command("docker", "rm", "-f", container).Run()
		}
	})
	runCredentialCommand(t, ctx, "docker", "run", "-d", "--name", container,
		// The locked stock image requires this file-capability in the bounding
		// set even on port 853. This is a diagnostic component fixture only;
		// the reviewed final Profile awaits Sandbox privilege adjudication.
		"--user", "20000:30000", "--cap-drop=ALL", "--cap-add=NET_BIND_SERVICE",
		"--security-opt", "no-new-privileges:true",
		"-p", "127.0.0.1::853/tcp", "-v", directory+":/config:ro",
		vaultDNSComponentImage, "-conf", "/config/Corefile")
	portBytes, portErr := exec.CommandContext(ctx, "docker", "port", container, "853/tcp").CombinedOutput()
	if portErr != nil {
		logs, _ := exec.CommandContext(ctx, "docker", "logs", container).CombinedOutput()
		t.Fatalf("CoreDNS port unavailable: %v: %s; logs: %s", portErr,
			strings.TrimSpace(string(portBytes)), strings.TrimSpace(string(logs)))
	}
	portOutput := strings.TrimSpace(string(portBytes))
	separator := strings.LastIndex(portOutput, ":")
	if separator < 0 {
		t.Fatal("CoreDNS TLS port unavailable")
	}
	address := "127.0.0.1:" + portOutput[separator+1:]
	roots := x509.NewCertPool()
	roots.AddCert(mustVaultDNSIssuer(t, generalDER))
	brokerPair := vaultDNSPair(t, broker)
	ordinaryPair := vaultDNSPair(t, ordinary)
	var ready bool
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		if vaultDNSExchange(address, roots, brokerPair) == nil {
			ready = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !ready {
		logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
		t.Fatalf("broker certificate did not complete real CoreDNS query: %s", strings.TrimSpace(string(logs)))
	}
	ordinaryError := vaultDNSExchange(address, roots, ordinaryPair)
	if ordinaryError == nil || !strings.Contains(ordinaryError.Error(), "unknown certificate authority") {
		t.Fatalf("ordinary valid client was not rejected at certificate authority validation: %v", ordinaryError)
	}
	logs, _ := exec.CommandContext(ctx, "docker", "logs", container).CombinedOutput()
	t.Logf("ordinary CoreDNS client rejection: %v; listener logs: %s", ordinaryError, strings.TrimSpace(string(logs)))
	if err := vaultDNSExchange(address, roots, brokerPair); err != nil {
		t.Fatalf("CoreDNS became unreachable after ordinary-client denial: %v", err)
	}
	runCredentialCommand(t, context.Background(), "docker", "rm", "-f", container)
	cleaned = true
	if retained := strings.TrimSpace(runCredentialCommand(t, context.Background(), "docker", "ps", "-aq", "--filter", "name=^/"+container+"$")); retained != "" {
		t.Fatal("real CoreDNS component container retained")
	}
}

func vaultDNSPair(t *testing.T, leaf vaultDNSLeaf) tls.Certificate {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(leaf.certificate,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func vaultDNSExchange(address string, roots *x509.CertPool, pair tls.Certificate) error {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "dns.sandbox-runtime.test",
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// Force the valid general leaf onto the wire even though the
			// server's acceptable-CA list advertises only the broker CA.
			return &pair, nil
		}})
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"whoami", "example", "org"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	message := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(message[:2], uint16(len(query)))
	copy(message[2:], query)
	if _, err := connection.Write(message); err != nil {
		return err
	}
	var prefix [2]byte
	if _, err := io.ReadFull(connection, prefix[:]); err != nil {
		return err
	}
	responseSize := binary.BigEndian.Uint16(prefix[:])
	if responseSize < 12 || responseSize > 4096 {
		return errors.New("invalid DNS-over-TLS response length")
	}
	response := make([]byte, responseSize)
	if _, err := io.ReadFull(connection, response); err != nil {
		return err
	}
	if !bytes.Equal(response[:2], query[:2]) || response[2]&0x80 == 0 || response[3]&0x0f != 0 {
		return errors.New("DNS-over-TLS query did not receive a successful answer")
	}
	return nil
}
