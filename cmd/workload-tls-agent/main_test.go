package main

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
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
	config := configDocument{SecurityProfileDigest: profile.ProfileDigest, EnvironmentDigest: profile.EnvironmentDigest,
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
		CertificateTTLSeconds: int(subject.TLS.TTLSeconds), RotateAfterSeconds: int(subject.TLS.RotateAfterSeconds),
		OverlapSeconds: int(subject.TLS.OverlapSeconds), RevocationMaxStalenessSeconds: int(subject.TLS.RevocationMaxStalenessSeconds)}
	if !matchesProfileBinding(profile, binding, agent, subject, config) {
		t.Fatal("exact profile binding rejected")
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
