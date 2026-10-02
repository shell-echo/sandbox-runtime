//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type slice6VaultPKIRole struct {
	Name, Subject, Issuer, URI, CommonName string
	DNSNames                               []string
	Client, Server                         bool
	MaxTTLSeconds                          int64
}

func slice6VaultDesiredPKIRoles(t *testing.T, profile phase6security.Profile,
	generalIssuer, brokerIssuer string) []slice6VaultPKIRole {
	t.Helper()
	if phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		!phase6security.ValidSlice6IssuerID(generalIssuer) || !phase6security.ValidSlice6IssuerID(brokerIssuer) ||
		generalIssuer == brokerIssuer {
		t.Fatal("unverified desired PKI role input")
	}
	byName := make(map[string]phase6security.Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		byName[principal.Name] = principal
	}
	result := make([]slice6VaultPKIRole, 0, 38)
	add := func(name, subject, commonName string) {
		principal := byName[subject]
		if name == "" || principal.Name != subject || principal.TLS == nil ||
			principal.TLS.URI == "" || principal.TLS.TTLSeconds < 60 || principal.TLS.TTLSeconds > 3600 {
			t.Fatalf("unreviewed PKI role subject %s", subject)
		}
		issuer := generalIssuer
		if slice6VaultBrokerOnlySubject(subject) {
			issuer = brokerIssuer
		}
		client := slices.Contains(principal.TLS.Usages, "client_auth")
		server := slices.Contains(principal.TLS.Usages, "server_auth")
		dnsNames := slices.Clone(principal.TLS.DNSNames)
		if commonName != "" {
			// A PostgreSQL purpose certificate is client-only even when the
			// owning runtime also serves HTTPS under its ordinary identity.
			server = false
			dnsNames = nil
		}
		if !client && !server || commonName != "" && !client {
			t.Fatalf("invalid PKI EKU/CN for %s", subject)
		}
		result = append(result, slice6VaultPKIRole{Name: name, Subject: subject,
			Issuer: issuer, URI: principal.TLS.URI, CommonName: commonName,
			DNSNames: dnsNames, Client: client, Server: server,
			MaxTTLSeconds: principal.TLS.TTLSeconds})
	}
	add(profile.CertificateController.ManagedVaultRole, "certificate-controller", "")
	add(profile.CertificateController.CredentialController.VaultRole, "workload-credential-controller", "")
	for _, binding := range profile.TLSAgentBindings {
		add(binding.IssuerVaultRole, binding.SubjectDeployment, "")
	}
	for _, binding := range profile.PostgresClientAgents {
		add(binding.IssuerVaultRole, binding.SubjectDeployment, binding.CommonName)
	}
	slices.SortFunc(result, func(a, b slice6VaultPKIRole) int { return strings.Compare(a.Name, b.Name) })
	if len(result) != 38 {
		t.Fatal("reviewed PKI role count changed")
	}
	for index := range result {
		if index > 0 && result[index].Name == result[index-1].Name {
			t.Fatal("PKI role reused for two certificate purposes")
		}
	}
	return result
}

func slice6VaultBrokerOnlySubject(subject string) bool {
	switch subject {
	case "egress-broker-product", "egress-broker-gateway", "egress-broker-browser-action-ingress",
		"egress-broker-provider-browser", "egress-broker-provider-desktop":
		return true
	default:
		return false
	}
}

// Install real Vault PKI roles with immutable issuer UUIDs and exact subject
// restrictions before either controller is launched. This remains component
// configuration evidence until a managed controller actually signs a CSR.
func slice6VaultInstallPKIRoles(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID string, roles []slice6VaultPKIRole) {
	t.Helper()
	for _, role := range roles {
		bareDomain := role.CommonName != "" || len(role.DNSNames) != 0
		arguments := []string{"write", "pki/roles/" + role.Name,
			"issuer_ref=" + role.Issuer, "allowed_uri_sans=" + role.URI,
			"not_before_duration=" + strconv.FormatInt(phase6security.Slice6VaultRoleBackdateSeconds, 10) + "s",
			"basic_constraints_valid_for_non_ca=true",
			"allow_bare_domains=" + strconv.FormatBool(bareDomain), "allow_subdomains=false", "allow_ip_sans=false",
			"allow_any_name=false", "allow_localhost=false", "allow_glob_domains=false",
			"allow_wildcard_certificates=false", "allowed_uri_sans_template=false",
			"use_csr_sans=true", "max_ttl=" + strconv.FormatInt(role.MaxTTLSeconds, 10) + "s",
			"key_type=ec", "key_bits=256", "key_usage=DigitalSignature",
			"code_signing_flag=false", "email_protection_flag=false",
			"client_flag=" + strconv.FormatBool(role.Client), "server_flag=" + strconv.FormatBool(role.Server)}
		usages := make([]string, 0, 2)
		if role.Client {
			usages = append(usages, "ClientAuth")
		}
		if role.Server {
			usages = append(usages, "ServerAuth")
		}
		arguments = append(arguments, "ext_key_usage="+strings.Join(usages, ","))
		if role.CommonName != "" {
			arguments = append(arguments, "allowed_domains="+role.CommonName,
				"require_cn=true", "use_csr_common_name=true", "enforce_hostnames=false")
		} else {
			arguments = append(arguments, "require_cn=false", "use_csr_common_name=false", "enforce_hostnames=true")
			if len(role.DNSNames) != 0 {
				arguments = append(arguments, "allowed_domains="+strings.Join(role.DNSNames, ","))
			}
		}
		if _, err := run.docker(ctx, slice6VaultExec(serverID, true, arguments...)...); err != nil {
			t.Fatalf("install exact Vault PKI role %s failed", role.Name)
		}
		response, err := run.docker(ctx, slice6VaultExec(serverID, true, "read", "-format=json", "pki/roles/"+role.Name)...)
		var observed struct {
			Data struct {
				IssuerRef                     string   `json:"issuer_ref"`
				AllowedURISANs                []string `json:"allowed_uri_sans"`
				AllowedDomains                []string `json:"allowed_domains"`
				RequireCN                     bool     `json:"require_cn"`
				UseCSRCommonName              bool     `json:"use_csr_common_name"`
				UseCSRSANs                    bool     `json:"use_csr_sans"`
				AllowBareDomains              bool     `json:"allow_bare_domains"`
				AllowSubdomains               bool     `json:"allow_subdomains"`
				AllowIPSANs                   bool     `json:"allow_ip_sans"`
				AllowAnyName                  bool     `json:"allow_any_name"`
				AllowLocalhost                bool     `json:"allow_localhost"`
				AllowGlobDomains              bool     `json:"allow_glob_domains"`
				AllowWildcards                bool     `json:"allow_wildcard_certificates"`
				URITemplate                   bool     `json:"allowed_uri_sans_template"`
				AllowedOtherSANs              []string `json:"allowed_other_sans"`
				ClientFlag                    bool     `json:"client_flag"`
				ServerFlag                    bool     `json:"server_flag"`
				MaxTTL                        int64    `json:"max_ttl"`
				NotBeforeDuration             int64    `json:"not_before_duration"`
				BasicConstraintsValidForNonCA bool     `json:"basic_constraints_valid_for_non_ca"`
				EnforceHostnames              bool     `json:"enforce_hostnames"`
				KeyType                       string   `json:"key_type"`
				KeyBits                       int      `json:"key_bits"`
				KeyUsage                      []string `json:"key_usage"`
				ExtKeyUsage                   []string `json:"ext_key_usage"`
				CodeSigningFlag               bool     `json:"code_signing_flag"`
				EmailProtectionFlag           bool     `json:"email_protection_flag"`
			} `json:"data"`
		}
		wantDomains := role.DNSNames
		if role.CommonName != "" {
			wantDomains = []string{role.CommonName}
		}
		if err != nil || json.Unmarshal(response, &observed) != nil ||
			observed.Data.IssuerRef != role.Issuer ||
			!slices.Equal(observed.Data.AllowedURISANs, []string{role.URI}) ||
			!slices.Equal(observed.Data.AllowedDomains, wantDomains) ||
			observed.Data.RequireCN != (role.CommonName != "") ||
			observed.Data.UseCSRCommonName != (role.CommonName != "") ||
			!observed.Data.UseCSRSANs || observed.Data.AllowBareDomains != bareDomain ||
			observed.Data.AllowSubdomains || observed.Data.AllowIPSANs ||
			observed.Data.AllowAnyName || observed.Data.AllowLocalhost || observed.Data.AllowGlobDomains ||
			observed.Data.AllowWildcards || observed.Data.URITemplate || len(observed.Data.AllowedOtherSANs) != 0 ||
			observed.Data.ClientFlag != role.Client || observed.Data.ServerFlag != role.Server ||
			observed.Data.MaxTTL != role.MaxTTLSeconds ||
			observed.Data.NotBeforeDuration != phase6security.Slice6VaultRoleBackdateSeconds ||
			!observed.Data.BasicConstraintsValidForNonCA ||
			observed.Data.EnforceHostnames != (role.CommonName == "") ||
			observed.Data.KeyType != "ec" || observed.Data.KeyBits != 256 ||
			!slices.Equal(observed.Data.KeyUsage, []string{"DigitalSignature"}) ||
			!slices.Equal(observed.Data.ExtKeyUsage, usages) ||
			observed.Data.CodeSigningFlag || observed.Data.EmailProtectionFlag {
			t.Fatalf("installed Vault PKI role %s readback drifted", role.Name)
		}
	}
}

func slice6VaultAssertControllerManagedSign(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID string, roles []slice6VaultPKIRole, general slice6VaultRoot) {
	t.Helper()
	var role slice6VaultPKIRole
	for _, candidate := range roles {
		if candidate.Subject == "certificate-controller" {
			role = candidate
		}
	}
	if role.Name == "" || role.Issuer != general.ID {
		t.Fatal("managed certificate-controller PKI role missing")
	}
	// The CSR was independently generated with a run-owned P-256 key and
	// exact certificate-controller URI during the Vault trust switch.
	response, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "-format=json", "pki/sign/"+role.Name,
		"csr=@/vault/config/final-client.csr", "ttl=2m")...)
	var issued struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &issued) != nil {
		t.Fatal("run-owned managed controller role did not sign its exact CSR")
	}
	leaf := slice6VaultParsePEMCertificate(t, []byte(issued.Data.Certificate))
	issuer := slice6VaultParsePEMCertificate(t, []byte(issued.Data.IssuingCA))
	if !issuer.Equal(general.Certificate) || leaf.CheckSignatureFrom(issuer) != nil ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != role.URI ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatal("managed controller role signed wrong issuer, URI or EKU")
	}
	// The Vault server CSR belongs to a different exact URI and requests a
	// DNS SAN. It must not be issued through the controller's scoped role.
	if _, err := run.docker(ctx, slice6VaultExec(serverID, true, "write", "pki/sign/"+role.Name,
		"csr=@/vault/config/final-server.csr", "ttl=2m")...); err == nil {
		t.Fatal("managed controller role accepted a different principal's CSR")
	}
}

func slice6VaultAssertScopedPKISign(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, roleName string, general slice6VaultRoot, expectedURI string) {
	t.Helper()
	if roleName == "" || expectedURI == "" {
		t.Fatal("unreviewed scoped PKI signer input")
	}
	// The token is read inside the private Vault container. It is never passed
	// through the Docker command's arguments, environment or test logs.
	execScoped := func(arguments ...string) []string {
		result := []string{"exec", "-e", "VAULT_ADDR=https://127.0.0.1:8200",
			"-e", "VAULT_CACERT=/vault/config/server-ca.pem",
			"-e", "VAULT_CLIENT_CERT=/vault/config/client.pem",
			"-e", "VAULT_CLIENT_KEY=/vault/config/client-key.pem",
			"-e", "VAULT_TLS_SERVER_NAME=vault.sandbox-runtime.test"}
		return append(append(result, serverID, "sh", "-c",
			"VAULT_TOKEN=\"$(cat /vault/config/scope-token-certificate)\" exec vault \"$@\"", "--"), arguments...)
	}
	response, err := run.docker(ctx, execScoped("write", "-format=json", "pki/sign/"+roleName,
		"csr=@/vault/config/final-client.csr", "ttl=2m")...)
	var signed struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuingCA   string `json:"issuing_ca"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(response, &signed) != nil {
		t.Fatal("exact scoped PKI token could not sign its managed controller CSR")
	}
	leaf := slice6VaultParsePEMCertificate(t, []byte(signed.Data.Certificate))
	issuer := slice6VaultParsePEMCertificate(t, []byte(signed.Data.IssuingCA))
	if !issuer.Equal(general.Certificate) || leaf.CheckSignatureFrom(issuer) != nil ||
		len(leaf.URIs) != 1 || leaf.URIs[0].String() != expectedURI ||
		!reflect.DeepEqual(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatal("scoped PKI token signed wrong issuer, URI or EKU")
	}
	if _, err := run.docker(ctx, execScoped("write", "pki/sign/"+roleName,
		"csr=@/vault/config/final-server.csr", "ttl=2m")...); err == nil {
		t.Fatal("scoped PKI token signed another principal's CSR")
	}
}
