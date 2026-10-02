//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

const (
	slice6PostgresServerLeafEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_POSTGRES_SERVER_LEAF"
	slice6PostgresServerRole    = "final-external-postgres-server"
	slice6PostgresServerURI     = "spiffe://sandbox-runtime.test/external/postgres"
	slice6PostgresServerDNS     = "postgres.sandbox-runtime.test"
	slice6PostgresServerLeafTTL = 30 * time.Minute
)

// The private key stays outside the Vault bind and is later mounted only into
// the external PostgreSQL server. This bootstrap witness does not prove that
// PostgreSQL has started or that any SQL client can connect.
type slice6PostgresServerLeaf struct {
	CertificatePath string
	KeyPath         string
	IssuerPath      string
	Serial          string
	IssuerID        string
	LeafDigest      string
	Record          phase6terminalcleanup.ExternalPostgresRecord
}

func slice6VaultPreparePostgresServerLeaf(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, root, vaultConfig string, profile phase6security.Profile, general slice6VaultRoot,
	managementToken []byte) slice6PostgresServerLeaf {
	t.Helper()
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		!phase6security.ValidSlice6IssuerID(general.ID) ||
		len(profile.External) != 5 {
		t.Fatal("unverified external PostgreSQL certificate input")
	}
	var serviceFound bool
	for _, service := range profile.External {
		if service.Name == "postgres" {
			serviceFound = service.URI == slice6PostgresServerURI &&
				reflect.DeepEqual(service.DNSNames, []string{slice6PostgresServerDNS})
		}
	}
	if !serviceFound {
		t.Fatal("external PostgreSQL service identity drifted")
	}
	role := slice6VaultPKIRole{Name: slice6PostgresServerRole, Subject: "external/postgres",
		Issuer: general.ID, URI: slice6PostgresServerURI,
		DNSNames: []string{slice6PostgresServerDNS}, Server: true,
		MaxTTLSeconds: int64(time.Hour / time.Second)}
	slice6VaultInstallPKIRoles(t, ctx, run, serverID, []slice6VaultPKIRole{role})
	if len(managementToken) == 0 {
		t.Fatal("scoped management token unavailable for PostgreSQL signer denial")
	}
	managementFile := "external-postgres-management-scope-token"
	writeSlice6VaultPrivateFile(t, vaultConfig, managementFile, managementToken)
	slice6VaultRequireCapability(t, ctx, run, serverID, managementFile,
		"pki/sign/"+slice6PostgresServerRole, "deny")
	if err := os.Remove(filepath.Join(vaultConfig, managementFile)); err != nil {
		t.Fatal("remove exact management token capability probe")
	}
	certificatePolicy := "certificate-controller-pki"
	certificateRole := workloadcredential.Phase6TokenRole(certificatePolicy)
	if certificateRole == "" {
		t.Fatal("certificate-controller PKI token role unavailable")
	}
	certificateToken, certificateAccessor := slice6VaultMintScopedTokenWithAccessor(t, ctx, run,
		serverID, certificateRole, certificatePolicy)
	certificateTokenFile := "external-postgres-certificate-scope-token"
	certificateAccessorFile := "external-postgres-certificate-scope-accessor"
	writeSlice6VaultPrivateFile(t, vaultConfig, certificateTokenFile, []byte(certificateToken))
	writeSlice6VaultPrivateFile(t, vaultConfig, certificateAccessorFile, []byte(certificateAccessor))
	slice6VaultRequireCapability(t, ctx, run, serverID, certificateTokenFile,
		"pki/sign/"+slice6PostgresServerRole, "deny")
	if err := slice6VaultRevokeScopedToken(ctx, run, serverID, certificateAccessorFile,
		certificateAccessor, certificatePolicy); err != nil {
		t.Fatal("revoke exact certificate-controller capability probe token")
	}
	for _, name := range []string{certificateTokenFile, certificateAccessorFile} {
		if err := os.Remove(filepath.Join(vaultConfig, name)); err != nil {
			t.Fatal("remove exact certificate-controller capability probe material")
		}
	}
	directory := filepath.Join(root, "postgres-server")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal("create run-private PostgreSQL server key directory")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate run-owned PostgreSQL server key")
	}
	identity, err := url.Parse(slice6PostgresServerURI)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{URIs: []*url.URL{identity}, DNSNames: []string{slice6PostgresServerDNS}}, key)
	if err != nil {
		t.Fatal("generate exact PostgreSQL server CSR")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("marshal run-owned PostgreSQL server key")
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer clear(privatePEM)
	defer clear(keyDER)
	keyPath := filepath.Join(directory, "server-key.pem")
	if err := os.WriteFile(keyPath, privatePEM, 0o600); err != nil {
		t.Fatal("write run-private PostgreSQL server key")
	}
	csrFile := "external-postgres-server.csr"
	writeSlice6VaultPrivateFile(t, vaultConfig, csrFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	defer func() {
		if err := os.Remove(filepath.Join(vaultConfig, csrFile)); err != nil {
			t.Errorf("remove public PostgreSQL server CSR: %v", err)
		}
	}()
	// Both negative probes are signed using this role, not a different role.
	// The existing Vault CSR requests another URI and DNS SAN.
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "pki/sign/"+slice6PostgresServerRole,
		"csr=@/vault/config/final-server.csr", "ttl=2m")...); err == nil {
		t.Fatal("PostgreSQL role issued Vault server identity")
	}
	wrongDNSDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{URIs: []*url.URL{identity}, DNSNames: []string{"wrong.sandbox-runtime.test"}}, key)
	if err != nil {
		t.Fatal("generate wrong-DNS PostgreSQL CSR")
	}
	wrongFile := "external-postgres-wrong-dns.csr"
	writeSlice6VaultPrivateFile(t, vaultConfig, wrongFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: wrongDNSDER}))
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "pki/sign/"+slice6PostgresServerRole,
		"csr=@/vault/config/"+wrongFile, "ttl=2m")...); err == nil {
		t.Fatal("PostgreSQL role issued foreign DNS name")
	}
	if err := os.Remove(filepath.Join(vaultConfig, wrongFile)); err != nil {
		t.Fatal("remove wrong-DNS public CSR")
	}
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json",
		"pki/sign/"+slice6PostgresServerRole,
		"csr=@/vault/config/"+csrFile, "ttl=30m")...)
	var signed struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
			Serial      string `json:"serial_number"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &signed) != nil || signed.Data.Serial == "" {
		t.Fatal("Vault did not issue exact PostgreSQL server certificate")
	}
	leaf := slice6VaultParsePEMCertificate(t, []byte(signed.Data.Certificate))
	issuer := slice6VaultParsePEMCertificate(t, []byte(signed.Data.IssuingCA))
	now := time.Now().UTC()
	if !bytes.Equal(issuer.Raw, general.Certificate.Raw) || leaf.CheckSignatureFrom(issuer) != nil ||
		leaf.IsCA || !leaf.BasicConstraintsValid || leaf.Subject.String() != "" ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != slice6PostgresServerURI ||
		!reflect.DeepEqual(leaf.DNSNames, []string{slice6PostgresServerDNS}) ||
		len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
		len(leaf.UnknownExtKeyUsage) != 0 || len(leaf.UnhandledCriticalExtensions) != 0 ||
		!key.PublicKey.Equal(leaf.PublicKey) ||
		leaf.PublicKeyAlgorithm != x509.ECDSA || key.Curve != elliptic.P256() ||
		!leaf.NotBefore.Before(leaf.NotAfter) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > time.Hour ||
		leaf.NotAfter.Sub(now) > slice6PostgresServerLeafTTL+time.Minute {
		t.Fatal("Vault PostgreSQL server leaf issuer, identity, usages, key or lifetime drifted")
	}
	pool := x509.NewCertPool()
	pool.AddCert(general.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: slice6PostgresServerDNS,
		CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatal("PostgreSQL server leaf failed exact DNS/issuer chain verification")
	}
	certificatePath := filepath.Join(directory, "server.pem")
	issuerPath := filepath.Join(directory, "server-ca.pem")
	for path, content := range map[string][]byte{
		certificatePath: []byte(signed.Data.Certificate), issuerPath: general.PEM,
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal("write run-private PostgreSQL certificate material")
		}
	}
	leafDigest := sha256.Sum256(leaf.Raw)
	issuerDigest := sha256.Sum256(issuer.Raw)
	serialBytes := leaf.SerialNumber.Bytes()
	serialParts := make([]string, len(serialBytes))
	for index, value := range serialBytes {
		serialParts[index] = fmt.Sprintf("%02x", value)
	}
	serial := strings.Join(serialParts, ":")
	if len(serialBytes) < 8 || len(serialBytes) > 32 || signed.Data.Serial != serial {
		t.Fatal("Vault PostgreSQL signing response serial disagreed with leaf DER")
	}
	record := phase6terminalcleanup.ExternalPostgresRecord{
		Protocol: phase6terminalcleanup.ExternalPostgresRecordProtocol,
		RunID:    run.id, ProfileDigest: profile.ProfileDigest,
		IssuerID: general.ID, IssuerDigest: "sha256:" + hex.EncodeToString(issuerDigest[:]),
		URI: slice6PostgresServerURI, DNSName: slice6PostgresServerDNS,
		Serial: serial, LeafDigest: "sha256:" + hex.EncodeToString(leafDigest[:]),
		CertificatePEM: []byte(signed.Data.Certificate), IssuerPEM: []byte(signed.Data.IssuingCA),
		SignedAt: now,
	}
	t.Logf("same-run external PostgreSQL server leaf passed exact Vault role/issuer/identity/key/EKU/chain and wrong-identity refusal; leaf_sha256=%s; no PostgreSQL process started",
		hex.EncodeToString(leafDigest[:]))
	return slice6PostgresServerLeaf{CertificatePath: certificatePath, KeyPath: keyPath,
		IssuerPath: issuerPath, Serial: serial, IssuerID: general.ID,
		LeafDigest: hex.EncodeToString(leafDigest[:]), Record: record}
}
