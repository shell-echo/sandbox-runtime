//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

const slice6TerminalOperatorPolicy = "phase6-terminal-cleanup"
const slice6TerminalOperatorRole = "phase6-terminal-cleanup-client"
const slice6TerminalOperatorURI = "spiffe://sandbox-runtime.test/phase6-terminal-cleanup"

type slice6TerminalOperatorCredential struct {
	Token     []byte
	Accessor  string
	LeafPEM   []byte
	KeyPEM    []byte
	ExpiresAt time.Time
}

func (c *slice6TerminalOperatorCredential) clear() {
	clear(c.Token)
	clear(c.LeafPEM)
	clear(c.KeyPEM)
	c.Token, c.LeafPEM, c.KeyPEM = nil, nil, nil
}

// This finite-task capability is installed before bootstrap-root revocation.
// The only persistent Vault objects are its exact ACL, URI-pinned signing
// role and short-lived orphan token; the CSR file contains no secret.
func slice6VaultPrepareTerminalOperator(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string, profile phase6security.Profile, general slice6VaultRoot) slice6TerminalOperatorCredential {
	t.Helper()
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		!phase6security.ValidSlice6IssuerID(general.ID) || general.Certificate == nil ||
		profile.ProfileDigest == "" {
		t.Fatal("unverified terminal operator bootstrap source")
	}
	acl := fmt.Sprintf(`path "pki/revoke" { capabilities = ["update"] }
path "pki/config/crl" { capabilities = ["read"] }
path "pki/issuer/%s/der" { capabilities = ["read"] }
path "pki/issuer/%s/crl/der" { capabilities = ["read"] }
path "auth/token/lookup-accessor" { capabilities = ["update"] }
path "auth/token/revoke-accessor" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
`, general.ID, general.ID)
	slice6VaultWriteAndReadACL(t, ctx, run, serverID, configDir, slice6TerminalOperatorPolicy, acl)
	slice6VaultInstallPKIRoles(t, ctx, run, serverID, []slice6VaultPKIRole{{
		Name: slice6TerminalOperatorRole, Subject: slice6TerminalOperatorPolicy,
		Issuer: general.ID, URI: slice6TerminalOperatorURI, Client: true, MaxTTLSeconds: 900,
	}})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate independent terminal operator key")
	}
	identity, err := url.Parse(slice6TerminalOperatorURI)
	if err != nil || identity.String() != slice6TerminalOperatorURI {
		t.Fatal("terminal operator URI drift")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{URIs: []*url.URL{identity}}, key)
	if err != nil {
		t.Fatal("create terminal operator CSR")
	}
	csrName := "terminal-operator.csr"
	writeSlice6VaultPrivateFile(t, configDir, csrName,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	defer func() {
		if removeErr := os.Remove(filepath.Join(configDir, csrName)); removeErr != nil {
			t.Error("remove exact terminal operator public CSR")
		}
	}()
	// The role backdates NotBefore by 30 seconds; 868+30 seconds remains
	// strictly inside the 900-second reviewed lifetime.
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json",
		"pki/sign/"+slice6TerminalOperatorRole,
		"csr=@/vault/config/"+csrName, "ttl=868s")...)
	var signed struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &signed) != nil {
		t.Fatal("terminal operator CSR signing failed")
	}
	leafPEM := []byte(signed.Data.Certificate)
	leaf := slice6VaultParsePEMCertificate(t, leafPEM)
	issuer := slice6VaultParsePEMCertificate(t, []byte(signed.Data.IssuingCA))
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !issuer.Equal(general.Certificate) || leaf.CheckSignatureFrom(issuer) != nil || !ok ||
		!public.Equal(&key.PublicKey) || len(leaf.Subject.Names) != 0 || len(leaf.URIs) != 1 ||
		leaf.URIs[0].String() != slice6TerminalOperatorURI || len(leaf.DNSNames) != 0 ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > 900*time.Second {
		t.Fatal("terminal operator leaf identity, issuer, key, EKU or lifetime drift")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode terminal operator key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	clear(keyDER)
	parsed, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil || len(parsed.Certificate) != 1 {
		clear(keyPEM)
		t.Fatal("terminal operator leaf/key handoff invalid")
	}
	issuedAt := time.Now().UTC()
	tokenResponse, err := run.docker(ctx, slice6VaultExec(serverID, true, "token", "create", "-format=json",
		"-orphan", "-policy="+slice6TerminalOperatorPolicy, "-ttl=15m", "-renewable=false",
		"-no-default-policy", "-metadata=run_id="+run.id,
		"-metadata=profile_digest="+profile.ProfileDigest,
		"-metadata=issuer_id="+general.ID)...)
	defer clear(tokenResponse)
	var token struct {
		Auth struct {
			ClientToken   string            `json:"client_token"`
			Accessor      string            `json:"accessor"`
			Policies      []string          `json:"policies"`
			Orphan        bool              `json:"orphan"`
			Renewable     bool              `json:"renewable"`
			LeaseDuration int64             `json:"lease_duration"`
			Metadata      map[string]string `json:"metadata"`
		} `json:"auth"`
	}
	if err != nil || json.Unmarshal(tokenResponse, &token) != nil ||
		token.Auth.ClientToken == "" || token.Auth.Accessor == "" ||
		!slices.Equal(token.Auth.Policies, []string{slice6TerminalOperatorPolicy}) ||
		!token.Auth.Orphan || token.Auth.Renewable ||
		token.Auth.LeaseDuration < 1 || token.Auth.LeaseDuration > 900 ||
		len(token.Auth.Metadata) != 3 || token.Auth.Metadata["run_id"] != run.id ||
		token.Auth.Metadata["profile_digest"] != profile.ProfileDigest ||
		token.Auth.Metadata["issuer_id"] != general.ID {
		clear(keyPEM)
		t.Fatal("terminal operator token authority drift")
	}
	lookup, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json",
		"auth/token/lookup-accessor", "accessor="+token.Auth.Accessor)...)
	var observed struct {
		Data struct {
			Accessor  string            `json:"accessor"`
			Policies  []string          `json:"policies"`
			Meta      map[string]string `json:"meta"`
			Type      string            `json:"type"`
			Orphan    bool              `json:"orphan"`
			Renewable bool              `json:"renewable"`
			TTL       int64             `json:"ttl"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(lookup, &observed) != nil ||
		observed.Data.Accessor != token.Auth.Accessor ||
		!slices.Equal(observed.Data.Policies, []string{slice6TerminalOperatorPolicy}) ||
		observed.Data.Type != "service" || !observed.Data.Orphan || observed.Data.Renewable ||
		observed.Data.TTL < 1 || observed.Data.TTL > 900 ||
		len(observed.Data.Meta) != 3 || observed.Data.Meta["run_id"] != run.id ||
		observed.Data.Meta["profile_digest"] != profile.ProfileDigest ||
		observed.Data.Meta["issuer_id"] != general.ID {
		clear(keyPEM)
		t.Fatal("terminal operator token lookup drift")
	}
	// Use the issue timestamp before the Vault command, never the later
	// lookup time, so the in-memory client cannot outlive the real token.
	return slice6TerminalOperatorCredential{Token: []byte(token.Auth.ClientToken), Accessor: token.Auth.Accessor,
		LeafPEM: bytes.Clone(leafPEM), KeyPEM: keyPEM,
		ExpiresAt: issuedAt.Add(time.Duration(token.Auth.LeaseDuration) * time.Second)}
}
