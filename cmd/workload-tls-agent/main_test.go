package main

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func TestAgentStartupMatchesExactProfileBinding(t *testing.T) {
	requester := securityprincipal.Principal{Name: "product_tls_agent", PrincipalDigest: "agent-digest"}
	subjectIdentity := securityprincipal.Principal{Name: "product", PrincipalDigest: "subject-digest"}
	requestPublic := bytes.Repeat([]byte{7}, 32)
	controllerPublic := bytes.Repeat([]byte{8}, 32)
	profile := phase6security.Profile{ProfileDigest: "security-digest", EnvironmentDigest: "environment-digest",
		PrincipalProfileDigest: "principal-profile-digest", CertificateController: phase6security.CertificateControllerAuthority{
			DeploymentName: "certificate-controller", ResponseKeyID: "controller-response",
			ResponsePublicKeyDigest: phase6security.CertificateControllerPublicKeyDigest(controllerPublic)}}
	binding := phase6security.TLSAgentBinding{AgentDeployment: "product-tls-agent", AgentPrincipalDigest: requester.Digest(),
		SubjectDeployment: "product-runtime", SubjectPrincipalDigest: subjectIdentity.Digest(),
		AgentUID: 20001, AgentGID: 30001, SubjectUID: 20002, SubjectGID: 30002,
		SocketPath: "/run/tls/product-tls-agent/signer.sock", IssuerPolicyID: "issuer-product", IssuerVaultRole: "vault-product",
		AgentRequestKeyID: "request-product", AgentRequestKeyDigest: phase6security.TLSAgentRequestPublicKeyDigest(requestPublic),
		ControllerDeployment: "certificate-controller", ControllerUID: 20003, ControllerGID: 30003,
		ControllerSocketPath: "/run/certificate-controller/product-tls-agent/request.sock"}
	agent := phase6security.Principal{Name: binding.AgentDeployment, PrincipalDigest: requester.Digest(), AuthorizationPrincipal: &requester}
	subject := phase6security.Principal{Name: binding.SubjectDeployment, PrincipalDigest: subjectIdentity.Digest(),
		AuthorizationPrincipal: &subjectIdentity, TLS: &phase6security.TLSIdentity{TrustDomain: "sandbox.test", URI: "spiffe://sandbox.test/product",
			DNSNames: []string{"product.sandbox.test"}, Usages: []string{"client_auth", "server_auth"}, TTLSeconds: 600,
			RotateAfterSeconds: 300, OverlapSeconds: 30, RevocationMaxStalenessSeconds: 10}}
	config := configDocument{Protocol: peerCRLConfigProtocol, SecurityProfileDigest: profile.ProfileDigest, EnvironmentDigest: profile.EnvironmentDigest,
		ProfileDigest: profile.PrincipalProfileDigest, AgentDeployment: binding.AgentDeployment, SubjectDeployment: binding.SubjectDeployment,
		Requester: requester, Subject: subjectIdentity, PolicyID: binding.IssuerPolicyID, VaultRole: binding.IssuerVaultRole,
		AgentRequestKeyID: binding.AgentRequestKeyID, AgentPublicKey: base64.RawURLEncoding.EncodeToString(requestPublic),
		CertificateControllerSocket: binding.ControllerSocketPath, CertificateControllerUID: binding.ControllerUID,
		CertificateControllerGID: binding.ControllerGID, CertificateControllerKeyID: profile.CertificateController.ResponseKeyID,
		CertificateControllerPublic: base64.RawURLEncoding.EncodeToString(controllerPublic),
		AgentUID:                    binding.AgentUID, AgentGID: binding.AgentGID, ExpectedRoleUID: binding.SubjectUID, ExpectedRoleGID: binding.SubjectGID,
		SignerSocket: binding.SocketPath, SignerSocketUID: binding.AgentUID, SignerSocketGID: binding.SubjectGID,
		TrustDomain: subject.TLS.TrustDomain, URI: subject.TLS.URI, DNSNames: append([]string(nil), subject.TLS.DNSNames...),
		Usages: append([]string(nil), subject.TLS.Usages...), MaxTTLSeconds: subject.TLS.TTLSeconds,
		CertificateTTLSeconds: 569, RotateAfterSeconds: int(subject.TLS.RotateAfterSeconds),
		OverlapSeconds: int(subject.TLS.OverlapSeconds), RevocationMaxStalenessSeconds: int(subject.TLS.RevocationMaxStalenessSeconds)}
	if !matchesProfileBinding(profile, binding, agent, subject, config) {
		t.Fatal("exact profile binding rejected")
	}
	legacy := config
	legacy.Protocol = configProtocol
	legacy.CertificateTTLSeconds = int(subject.TLS.TTLSeconds)
	if !matchesProfileBinding(profile, binding, agent, subject, legacy) {
		t.Fatal("historical v2 binding rejected")
	}
	legacy.CertificateTTLSeconds = config.CertificateTTLSeconds
	if matchesProfileBinding(profile, binding, agent, subject, legacy) {
		t.Fatal("historical v2 request lifetime silently changed")
	}
	for name, change := range map[string]func(*configDocument){
		"profile":       func(c *configDocument) { c.SecurityProfileDigest = "other" },
		"agent":         func(c *configDocument) { c.Requester.Name = "other" },
		"subject":       func(c *configDocument) { c.Subject.Name = "other" },
		"issuer policy": func(c *configDocument) { c.PolicyID = "other" },
		"request key": func(c *configDocument) {
			c.AgentPublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		},
		"controller key": func(c *configDocument) {
			c.CertificateControllerPublic = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		},
		"controller socket": func(c *configDocument) { c.CertificateControllerSocket += "-other" },
		"controller UID":    func(c *configDocument) { c.CertificateControllerUID++ },
		"vault role":        func(c *configDocument) { c.VaultRole = "other" },
		"socket":            func(c *configDocument) { c.SignerSocket += "-other" },
		"role uid":          func(c *configDocument) { c.ExpectedRoleUID++ },
		"role gid":          func(c *configDocument) { c.ExpectedRoleGID++ },
		"agent uid":         func(c *configDocument) { c.AgentUID++ },
		"agent gid":         func(c *configDocument) { c.AgentGID++ },
		"URI":               func(c *configDocument) { c.URI = "spiffe://sandbox.test/other" },
		"DNS SAN":           func(c *configDocument) { c.DNSNames = nil },
		"EKU":               func(c *configDocument) { c.Usages = []string{"client_auth"} },
		"TTL":               func(c *configDocument) { c.CertificateTTLSeconds++ },
		"old request TTL":   func(c *configDocument) { c.CertificateTTLSeconds = int(subject.TLS.TTLSeconds) },
		"rotation":          func(c *configDocument) { c.RotateAfterSeconds++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			change(&candidate)
			if matchesProfileBinding(profile, binding, agent, subject, candidate) {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestPostgresAgentConfigMatchesOnlyDedicatedPurpose(t *testing.T) {
	agentIdentity := securityprincipal.Principal{Name: "provider_tls_agent", PrincipalDigest: "agent-digest"}
	ownerIdentity := securityprincipal.Principal{Name: "provider", PrincipalDigest: "owner-digest"}
	requestPublic, controllerPublic := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
	profile := phase6security.Profile{ProfileDigest: "security-digest", EnvironmentDigest: "environment-digest",
		PrincipalProfileDigest: "principal-profile-digest", CertificateController: phase6security.CertificateControllerAuthority{
			DeploymentName: "certificate-controller", ResponseKeyID: "controller-response",
			ResponsePublicKeyDigest: phase6security.CertificateControllerPublicKeyDigest(controllerPublic)}}
	base := phase6security.TLSAgentBinding{AgentDeployment: "provider-browser-postgres-tls-agent", AgentPrincipalDigest: agentIdentity.Digest(),
		SubjectDeployment: "provider-browser-runtime", SubjectPrincipalDigest: ownerIdentity.Digest(),
		AgentUID: 20001, AgentGID: 30001, SubjectUID: 20002, SubjectGID: 30002,
		SocketPath: "/run/tls/provider-browser-postgres-tls-agent/signer.sock", IssuerPolicyID: "issuer-postgres",
		IssuerVaultRole: "vault-postgres", AgentRequestKeyID: "request-postgres",
		AgentRequestKeyDigest: phase6security.TLSAgentRequestPublicKeyDigest(requestPublic),
		ControllerDeployment:  "certificate-controller", ControllerUID: 20003, ControllerGID: 30003,
		ControllerSocketPath: "/run/certificate-controller/provider-browser-postgres-tls-agent/request.sock"}
	binding := phase6security.PostgresClientAgentBinding{TLSAgentBinding: base,
		CommonName: workloadpki.PostgresClientCommonName("browser_provider_runtime"), IssuerAnchorID: "postgres-client-ca"}
	target := phase6security.Slice6PostgresSignerTarget{SubjectDeployment: base.SubjectDeployment,
		DatabaseName: "provider_browser", SQLRole: "browser_provider_runtime"}
	agent := phase6security.Principal{Name: base.AgentDeployment, PrincipalDigest: agentIdentity.Digest(), AuthorizationPrincipal: &agentIdentity}
	owner := phase6security.Principal{Name: base.SubjectDeployment, PrincipalDigest: ownerIdentity.Digest(),
		AuthorizationPrincipal: &ownerIdentity, TLS: &phase6security.TLSIdentity{TrustDomain: "sandbox.test",
			URI: "spiffe://sandbox.test/provider-browser-runtime", DNSNames: []string{"provider-browser.sandbox.test"},
			Usages: []string{"client_auth", "server_auth"}, TTLSeconds: 600, RotateAfterSeconds: 300,
			OverlapSeconds: 30, RevocationMaxStalenessSeconds: 10}}
	config := configDocument{Protocol: postgresConfigProtocol, Purpose: workloadpki.PostgresClientPurpose,
		Postgres: &postgresClientConfig{OwnerDeployment: base.SubjectDeployment, DatabaseName: target.DatabaseName,
			RuntimeRole: target.SQLRole, CommonName: binding.CommonName, IssuerAnchorID: binding.IssuerAnchorID},
		SecurityProfileDigest: profile.ProfileDigest, EnvironmentDigest: profile.EnvironmentDigest,
		ProfileDigest: profile.PrincipalProfileDigest, AgentDeployment: base.AgentDeployment, SubjectDeployment: base.SubjectDeployment,
		Requester: agentIdentity, Subject: ownerIdentity, PolicyID: base.IssuerPolicyID, VaultRole: base.IssuerVaultRole,
		AgentRequestKeyID: base.AgentRequestKeyID, AgentPublicKey: base64.RawURLEncoding.EncodeToString(requestPublic),
		CertificateControllerSocket: base.ControllerSocketPath, CertificateControllerUID: base.ControllerUID,
		CertificateControllerGID: base.ControllerGID, CertificateControllerKeyID: profile.CertificateController.ResponseKeyID,
		CertificateControllerPublic: base64.RawURLEncoding.EncodeToString(controllerPublic),
		AgentUID:                    base.AgentUID, AgentGID: base.AgentGID, ExpectedRoleUID: base.SubjectUID, ExpectedRoleGID: base.SubjectGID,
		SignerSocket: base.SocketPath, SignerSocketUID: base.AgentUID, SignerSocketGID: base.SubjectGID,
		TrustDomain: owner.TLS.TrustDomain, URI: owner.TLS.URI, Usages: []string{"client_auth"},
		MaxTTLSeconds: owner.TLS.TTLSeconds, CertificateTTLSeconds: 569,
		RotateAfterSeconds: int(owner.TLS.RotateAfterSeconds), OverlapSeconds: int(owner.TLS.OverlapSeconds),
		RevocationMaxStalenessSeconds: int(owner.TLS.RevocationMaxStalenessSeconds)}
	if !matchesPostgresProfileBinding(profile, binding, target, agent, owner, config) {
		t.Fatal("exact PostgreSQL certificate agent config rejected")
	}
	oldRequest := config
	oldRequest.CertificateTTLSeconds = int(owner.TLS.TTLSeconds)
	if matchesPostgresProfileBinding(profile, binding, target, agent, owner, oldRequest) {
		t.Fatal("PostgreSQL v4 accepted pre-backdate request lifetime")
	}
	for name, change := range map[string]func(*configDocument){
		"database":         func(c *configDocument) { c.Postgres.DatabaseName = "provider_desktop" },
		"role":             func(c *configDocument) { c.Postgres.RuntimeRole = "desktop_provider_runtime" },
		"owner":            func(c *configDocument) { c.Postgres.OwnerDeployment = "provider-desktop-runtime" },
		"CN":               func(c *configDocument) { c.Postgres.CommonName = "other" },
		"issuer":           func(c *configDocument) { c.Postgres.IssuerAnchorID = "internal-client-ca" },
		"ordinary purpose": func(c *configDocument) { c.Purpose = "" },
		"DNS SAN":          func(c *configDocument) { c.DNSNames = []string{"unexpected.sandbox.test"} },
		"socket":           func(c *configDocument) { c.SignerSocket += "-other" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			postgres := *config.Postgres
			candidate.Postgres = &postgres
			change(&candidate)
			if matchesPostgresProfileBinding(profile, binding, target, agent, owner, candidate) {
				t.Fatal("PostgreSQL agent config drift accepted")
			}
		})
	}
}
