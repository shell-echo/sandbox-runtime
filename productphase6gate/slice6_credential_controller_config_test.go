//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

// Keep the field order identical to the production command's closed canonical
// JSON document. The command remains the final authority when it consumes the
// bytes; this builder does not claim a controller was launched.
type slice6CredentialControllerConfig struct {
	Protocol                  string                           `json:"protocol"`
	SecurityProfilePath       string                           `json:"security_profile_path"`
	SecurityProfileDigest     string                           `json:"security_profile_digest"`
	LedgerPath                string                           `json:"ledger_path"`
	ReapIntervalSeconds       int                              `json:"reap_interval_seconds"`
	OverlapSeconds            int                              `json:"overlap_seconds"`
	EnvironmentDigest         string                           `json:"environment_digest"`
	ProfileDigest             string                           `json:"profile_digest"`
	VaultEndpoint             string                           `json:"vault_endpoint"`
	VaultServerName           string                           `json:"vault_server_name"`
	VaultClientCertificatePEM []byte                           `json:"vault_client_certificate_pem"`
	VaultBackendID            string                           `json:"vault_backend_id"`
	ControllerKeyID           string                           `json:"controller_key_id"`
	ControllerPublicKey       string                           `json:"controller_public_key"`
	ManagedVaultTLS           slice6CredentialManagedTLS       `json:"managed_vault_tls"`
	OperationTimeoutSeconds   int                              `json:"operation_timeout_seconds"`
	Listeners                 []slice6CredentialListener       `json:"listeners"`
	Policies                  []slice6CredentialIssuancePolicy `json:"policies"`
}

type slice6CredentialManagedTLS struct {
	PolicyID                      string `json:"policy_id"`
	ControllerSocket              string `json:"controller_socket"`
	ControllerReadyTimeoutSeconds int    `json:"controller_ready_timeout_seconds"`
	CertificateTTLSeconds         int    `json:"certificate_ttl_seconds"`
	RotateAfterSeconds            int    `json:"rotate_after_seconds"`
	OverlapSeconds                int    `json:"overlap_seconds"`
	CheckIntervalMilliseconds     int    `json:"check_interval_milliseconds"`
	RevocationPollIntervalSeconds int    `json:"revocation_poll_interval_seconds"`
	RevocationMaxStalenessSeconds int    `json:"revocation_max_staleness_seconds"`
}

type slice6CredentialListener struct {
	SocketPath        string `json:"socket_path"`
	SocketUID         uint32 `json:"socket_uid"`
	SocketGID         uint32 `json:"socket_gid"`
	ExpectedClientUID uint32 `json:"expected_client_uid"`
	ExpectedClientGID uint32 `json:"expected_client_gid"`
	MaxConnections    int    `json:"max_connections"`
}

type slice6CredentialIssuancePolicy struct {
	ID            string                      `json:"id"`
	Principal     securityprincipal.Principal `json:"principal"`
	Purpose       secretref.Purpose           `json:"purpose"`
	BackendPolicy string                      `json:"backend_policy"`
	MaxTTLSeconds int                         `json:"max_ttl_seconds"`
	Renewable     bool                        `json:"renewable"`
	PublicKey     string                      `json:"public_key"`
	ExpectedUID   uint32                      `json:"expected_uid"`
	ExpectedGID   uint32                      `json:"expected_gid"`
}

func slice6BuildCredentialControllerConfig(composed slice6VaultComposedInputs, vaultClientCertificate []byte) ([]byte, error) {
	profile := composed.Profile
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(vaultClientCertificate) == 0 || len(composed.CredentialKeys) != 12 ||
		composed.ProfilePath == "" {
		return nil, errors.New("incomplete same-run credential controller input")
	}
	_, ledgerPath, err := phase6security.Slice6ControllerLedgerMount("workload-credential-controller")
	if err != nil || phase6security.VerifySlice6ControllerLedgerMounts(profile) != nil {
		return nil, errors.New("credential ledger binding drift")
	}
	var controller, certificate phase6security.Principal
	for _, principal := range profile.Principals {
		switch principal.Name {
		case "workload-credential-controller":
			controller = principal
		case "certificate-controller":
			certificate = principal
		}
	}
	if controller.TLS == nil || controller.AuthorizationPrincipal == nil || certificate.AuthorizationPrincipal == nil ||
		len(profile.CredentialIssuerSockets) != 12 || controller.UID == 0 || controller.GID == 0 {
		return nil, errors.New("credential controller principal drift")
	}
	responseKey, err := slice6ReadPrivateSigningKey(composed.CertificateKeys[profile.CertificateController.ResponseKeyID])
	if err != nil || phase6security.CertificateControllerPublicKeyDigest(responseKey.Public().(ed25519.PublicKey)) !=
		profile.CertificateController.ResponsePublicKeyDigest {
		clear(responseKey)
		return nil, errors.New("certificate response key drift")
	}
	defer clear(responseKey)
	plan, err := phase6security.BuildSlice6DesiredMaterialAccess(profile)
	if err != nil || len(plan) != 11 {
		return nil, errors.New("credential material policy drift")
	}
	byClient := make(map[string]phase6security.Slice6MaterialAccess, len(plan))
	for _, entry := range plan {
		byClient[entry.Agent] = entry
	}
	config := slice6CredentialControllerConfig{
		Protocol:            "sandbox-runtime.workload-credential-controller-config.v2",
		SecurityProfilePath: "/run/phase6/config/profile.json", SecurityProfileDigest: profile.ProfileDigest,
		LedgerPath: ledgerPath, ReapIntervalSeconds: 1, OverlapSeconds: 30,
		EnvironmentDigest: profile.EnvironmentDigest, ProfileDigest: profile.PrincipalProfileDigest,
		VaultEndpoint: "https://vault.sandbox-runtime.test:8200", VaultServerName: "vault.sandbox-runtime.test",
		VaultClientCertificatePEM: bytes.Clone(vaultClientCertificate), VaultBackendID: "vault-primary",
		ControllerKeyID:     profile.CertificateController.ResponseKeyID,
		ControllerPublicKey: base64.RawURLEncoding.EncodeToString(responseKey.Public().(ed25519.PublicKey)),
		ManagedVaultTLS: slice6CredentialManagedTLS{
			PolicyID:                      profile.CertificateController.CredentialController.PolicyID,
			ControllerSocket:              profile.CertificateController.CredentialController.SocketPath,
			ControllerReadyTimeoutSeconds: 180, CertificateTTLSeconds: int(controller.TLS.TTLSeconds),
			RotateAfterSeconds: int(controller.TLS.RotateAfterSeconds), OverlapSeconds: int(controller.TLS.OverlapSeconds),
			CheckIntervalMilliseconds: 1000, RevocationPollIntervalSeconds: 1,
			RevocationMaxStalenessSeconds: int(controller.TLS.RevocationMaxStalenessSeconds),
		}, OperationTimeoutSeconds: 15,
		Listeners: make([]slice6CredentialListener, 0, 12),
		Policies:  make([]slice6CredentialIssuancePolicy, 0, 12),
	}
	seen := make(map[string]bool, 12)
	seenKeyPaths := make(map[string]bool, 12)
	seenPublicKeys := map[string]bool{config.ControllerPublicKey: true}
	for _, binding := range profile.CredentialIssuerSockets {
		_, server, client, resolveErr := profile.CredentialIssuerSocketForClient(binding.ClientDeployment)
		if resolveErr != nil || server.Name != controller.Name || client.AuthorizationPrincipal == nil ||
			seen[client.Name] || binding.SocketPath == "" {
			return nil, errors.New("credential issuer socket drift")
		}
		seen[client.Name] = true
		keyPath := composed.CredentialKeys["credential-"+client.Name]
		if seenKeyPaths[keyPath] || keyPath == composed.CertificateKeys[profile.CertificateController.ResponseKeyID] {
			return nil, errors.New("credential signing key aliased")
		}
		seenKeyPaths[keyPath] = true
		private, keyErr := slice6ReadPrivateSigningKey(keyPath)
		if keyErr != nil {
			return nil, fmt.Errorf("credential key for %s: %w", client.Name, keyErr)
		}
		publicKey := base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
		if seenPublicKeys[publicKey] {
			clear(private)
			return nil, errors.New("credential public key aliased")
		}
		seenPublicKeys[publicKey] = true
		policy := slice6CredentialIssuancePolicy{Principal: *client.AuthorizationPrincipal,
			Purpose: secretref.PurposeWorkloadCredential, MaxTTLSeconds: 900,
			PublicKey:   publicKey,
			ExpectedUID: client.UID, ExpectedGID: client.GID}
		clear(private)
		if client.Name == certificate.Name {
			policy.ID, policy.BackendPolicy, policy.Renewable = "credential-certificate-controller", "certificate-controller-pki", true
		} else {
			entry, found := byClient[client.Name]
			if !found || entry.AgentUID != client.UID || entry.AgentGID != client.GID ||
				entry.CredentialSocket != binding.SocketPath {
				return nil, errors.New("material credential policy drift")
			}
			policy.ID, policy.BackendPolicy, policy.Renewable = entry.CredentialPolicyID, entry.BackendPolicy, !entry.Migration
		}
		config.Listeners = append(config.Listeners, slice6CredentialListener{SocketPath: binding.SocketPath,
			SocketUID: controller.UID, SocketGID: client.GID,
			ExpectedClientUID: client.UID, ExpectedClientGID: client.GID, MaxConnections: 16})
		config.Policies = append(config.Policies, policy)
	}
	if len(seen) != 12 || len(config.Policies) != 12 || len(config.Listeners) != 12 {
		return nil, errors.New("incomplete credential listener inventory")
	}
	return json.Marshal(config)
}

func slice6ReadPrivateSigningKey(path string) (ed25519.PrivateKey, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("non-absolute private signing key")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != ed25519.PrivateKeySize {
		return nil, errors.New("unsafe private signing key")
	}
	private, err := os.ReadFile(path)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		clear(private)
		return nil, errors.New("unreadable private signing key")
	}
	canonical := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	if !bytes.Equal(private, canonical) {
		clear(canonical)
		clear(private)
		return nil, errors.New("noncanonical private signing key")
	}
	clear(canonical)
	return private, nil
}

// The bootstrap certificate is signed by the exact already-installed Vault
// role. Its P-256 private key stays in operator memory until FD handoff; it is
// never copied into the Profile, JSON configuration, argv, environment or log.
func slice6VaultSignControllerBootstrap(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, configDir string, profile phase6security.Profile, general slice6VaultRoot,
	deployment, role, policyID, requestKeyPath string) ([]byte, []byte) {
	t.Helper()
	csrName := deployment + "-bootstrap.csr"
	if deployment != "certificate-controller" && deployment != "workload-credential-controller" {
		t.Fatal("unreviewed controller bootstrap deployment")
	}
	if deployment == "certificate-controller" &&
		(role != profile.CertificateController.ManagedVaultRole || policyID != profile.CertificateController.ManagedPolicyID) ||
		deployment == "workload-credential-controller" &&
			(role != profile.CertificateController.CredentialController.VaultRole ||
				policyID != profile.CertificateController.CredentialController.PolicyID) {
		t.Fatal("controller bootstrap role or policy drift")
	}
	var principal phase6security.Principal
	for _, candidate := range profile.Principals {
		if candidate.Name == deployment {
			principal = candidate
			break
		}
	}
	if principal.TLS == nil || principal.TLS.URI == "" || principal.TLS.TTLSeconds < 120 || role == "" {
		t.Fatal("controller bootstrap TLS policy unavailable")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate credential bootstrap P-256 key")
	}
	identity, err := url.Parse(principal.TLS.URI)
	if err != nil || identity.String() != principal.TLS.URI {
		t.Fatal("credential bootstrap URI invalid")
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{URIs: []*url.URL{identity}, DNSNames: principal.TLS.DNSNames}, key)
	if err != nil {
		t.Fatal("generate credential bootstrap CSR")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode credential bootstrap key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	clear(keyDER)
	writeSlice6VaultPrivateFile(t, configDir, csrName,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	t.Cleanup(func() {
		if err := os.Remove(filepath.Join(configDir, csrName)); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove exact controller CSR input: %v", err)
		}
	})
	// Vault backdates NotBefore by the role's audited 30 seconds. The
	// credential command checks the complete X.509 interval against its
	// Profile TTL, so leave one additional second for timestamp rounding.
	bootstrapTTL := principal.TLS.TTLSeconds - 31
	if bootstrapTTL < 60 {
		clear(keyPEM)
		t.Fatal("credential bootstrap TTL cannot fit audited Vault backdate")
	}
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json", "pki/sign/"+role,
		"csr=@/vault/config/"+csrName, "ttl="+strconv.FormatInt(bootstrapTTL, 10)+"s")...)
	var signed struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &signed) != nil {
		clear(keyPEM)
		t.Fatal("real Vault credential bootstrap signing failed")
	}
	leafPEM := []byte(signed.Data.Certificate)
	leaf := slice6VaultParsePEMCertificate(t, leafPEM)
	issuer := slice6VaultParsePEMCertificate(t, []byte(signed.Data.IssuingCA))
	issuedPublic, publicOK := leaf.PublicKey.(*ecdsa.PublicKey)
	issuerMatches := issuer.Equal(general.Certificate)
	signatureValid := leaf.CheckSignatureFrom(issuer) == nil
	keyMatches := publicOK && issuedPublic.Equal(&key.PublicKey)
	if !issuerMatches || !signatureValid ||
		!keyMatches ||
		len(leaf.Subject.Names) != 0 || len(leaf.URIs) != 1 || leaf.URIs[0].String() != principal.TLS.URI ||
		!reflect.DeepEqual(leaf.DNSNames, principal.TLS.DNSNames) ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) ||
		leaf.NotAfter.Sub(leaf.NotBefore) > time.Duration(principal.TLS.TTLSeconds)*time.Second {
		clear(keyPEM)
		t.Fatalf("real Vault credential bootstrap leaf drifted: issuer=%t signature=%t key=%t subject_names=%d uris=%d uri_match=%t dns_match=%t client_auth_only=%t validity_seconds=%d max_seconds=%d",
			issuerMatches, signatureValid, keyMatches, len(leaf.Subject.Names), len(leaf.URIs),
			len(leaf.URIs) == 1 && leaf.URIs[0].String() == principal.TLS.URI,
			reflect.DeepEqual(leaf.DNSNames, principal.TLS.DNSNames),
			reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}),
			int64(leaf.NotAfter.Sub(leaf.NotBefore)/time.Second), principal.TLS.TTLSeconds)
	}
	chain := append(bytes.Clone(bytes.TrimSpace(leafPEM)), '\n')
	chain = append(chain, bytes.TrimSpace(general.PEM)...)
	chain = append(chain, '\n')
	parsedPair, pairErr := tls.X509KeyPair(chain, keyPEM)
	if pairErr != nil || len(parsedPair.Certificate) != 2 {
		clear(keyPEM)
		t.Fatalf("real Vault credential PEM chain/key handoff invalid: chain_count=%d err=%v",
			len(parsedPair.Certificate), pairErr)
	}
	workloadtlsagent.DestroyTLSCertificate(&parsedPair)
	registry, registryErr := profile.PrincipalRegistry()
	requestPrivate, requestErr := slice6ReadPrivateSigningKey(requestKeyPath)
	if registryErr != nil || requestErr != nil || principal.AuthorizationPrincipal == nil {
		clear(requestPrivate)
		clear(keyPEM)
		t.Fatal("credential bootstrap policy material unavailable")
	}
	policy := workloadpki.Policy{ID: policyID,
		Registry: registry, Requester: *principal.AuthorizationPrincipal, Subject: *principal.AuthorizationPrincipal,
		TrustDomain: principal.TLS.TrustDomain, URI: principal.TLS.URI, DNSNames: principal.TLS.DNSNames,
		Usages: principal.TLS.Usages, VaultRole: role, MaxTTLSeconds: principal.TLS.TTLSeconds,
		ExpectedUID: principal.UID, ExpectedGID: principal.GID,
		PublicKey: requestPrivate.Public().(ed25519.PublicKey)}
	clear(requestPrivate)
	if policy.Validate() != nil {
		clear(keyPEM)
		t.Fatal("credential bootstrap policy invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(general.Certificate)
	validated, validateErr := workloadtlsagent.ValidateBootstrapCertificate(chain, keyPEM, roots, policy, time.Now().UTC())
	if validateErr != nil {
		pair, pairErr := tls.X509KeyPair(chain, keyPEM)
		intermediates := x509.NewCertPool()
		intermediates.AddCert(issuer)
		verified, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
			CurrentTime: time.Now().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		curveOK := publicOK && issuedPublic.Curve == elliptic.P256()
		pathLength := 0
		if len(verified) != 0 {
			pathLength = len(verified[0])
		}
		clear(keyPEM)
		t.Fatalf("real Vault credential bootstrap failed production certificate validator: pair=%t pair_chain=%d verify=%t verified_paths=%d first_path=%d issuer_ca=%t leaf_ca=%t key_usage=%d basic_constraints=%t curve=%t subject_empty=%t unknown_eku=%d email=%d ip=%d validity_seconds=%d chain_bytes=%d",
			pairErr == nil, len(pair.Certificate), verifyErr == nil, len(verified), pathLength, issuer.IsCA,
			leaf.IsCA, leaf.KeyUsage, leaf.BasicConstraintsValid, curveOK, leaf.Subject.String() == "",
			len(leaf.UnknownExtKeyUsage), len(leaf.EmailAddresses), len(leaf.IPAddresses),
			int64(leaf.NotAfter.Sub(leaf.NotBefore)/time.Second), len(chain))
	}
	workloadtlsagent.DestroyTLSCertificate(&validated)
	return chain, keyPEM
}

func TestSlice6CredentialSigningKeyHandoffRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "signing.key")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	observed, err := slice6ReadPrivateSigningKey(keyPath)
	if err != nil || !bytes.Equal(observed, private) {
		t.Fatal("exact private signing key rejected")
	}
	clear(observed)
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := slice6ReadPrivateSigningKey(keyPath); err == nil {
		t.Fatal("public-permission signing key admitted")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias.key")
	if err := os.Symlink(keyPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := slice6ReadPrivateSigningKey(alias); err == nil {
		t.Fatal("symlink signing key admitted")
	}
	corrupt := bytes.Clone(private)
	corrupt[ed25519.PrivateKeySize-1] ^= 1
	if err := os.WriteFile(keyPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(corrupt)
	if _, err := slice6ReadPrivateSigningKey(keyPath); err == nil {
		t.Fatal("inconsistent Ed25519 private encoding admitted")
	}
	clear(private)
}
