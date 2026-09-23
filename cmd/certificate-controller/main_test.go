package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func TestReadBoundedAcceptsOnlyPrivateRegularDescriptorAtStart(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "certificate-controller-secret-")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	t.Cleanup(func() { _ = os.Remove(name) })
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	descriptor, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	value, err := readBounded(uintptr(descriptor), "test-secret", 32)
	if err != nil || string(value) != "secret" {
		t.Fatalf("readBounded() = %q, %v", value, err)
	}
	clear(value)
	if _, err := file.Seek(1, 0); err != nil {
		t.Fatal(err)
	}
	descriptor, err = syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(uintptr(descriptor), "offset-secret", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("offset descriptor error = %v", err)
	}
	if err := file.Chmod(0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	descriptor, err = syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(uintptr(descriptor), "public-secret", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("public descriptor error = %v", err)
	}
	_ = file.Close()
}

func TestVaultEndpointMustMatchDeclaredTrustEdge(t *testing.T) {
	profile := phase6security.Profile{
		External: []phase6security.ExternalService{{Name: "vault", URI: "spiffe://sandbox-runtime.test/external/vault",
			DNSNames: []string{"vault.sandbox-runtime.test"}}},
		TrustEdges: []phase6security.TrustEdge{{ID: "certificate-vault", From: "certificate-controller", To: "vault",
			Protocol: "https", Authentication: "mtls", Port: 8200, ToURI: "spiffe://sandbox-runtime.test/external/vault"}},
	}
	if !vaultTrustEdgeMatches(profile, "https://vault.sandbox-runtime.test:8200", "vault.sandbox-runtime.test") {
		t.Fatal("declared Vault endpoint rejected")
	}
	for _, endpoint := range []string{"https://other.test:8200", "https://vault.sandbox-runtime.test:8300",
		"http://vault.sandbox-runtime.test:8200", "https://vault.sandbox-runtime.test:8200/other"} {
		if vaultTrustEdgeMatches(profile, endpoint, "vault.sandbox-runtime.test") {
			t.Fatalf("Vault endpoint drift accepted: %s", endpoint)
		}
	}
}

func TestControllerRequiresCompleteProfileBoundBrokerAgentInventory(t *testing.T) {
	responsePublic := bytes.Repeat([]byte{3}, 32)
	managedPublic := bytes.Repeat([]byte{4}, 32)
	agentPublic := bytes.Repeat([]byte{5}, 32)
	controllerIdentity := securityprincipal.Principal{Name: "certificate_controller", PrincipalDigest: "controller-digest"}
	agentIdentity := securityprincipal.Principal{Name: "product_egress_broker_tls_agent", PrincipalDigest: "agent-digest"}
	brokerIdentity := securityprincipal.Principal{Name: "product_egress_broker", PrincipalDigest: "broker-digest"}
	controllerTLS := phase6security.TLSIdentity{TrustDomain: "sandbox.test", URI: "spiffe://sandbox.test/certificate-controller",
		Usages: []string{"client_auth"}, TTLSeconds: 600, RotateAfterSeconds: 300, OverlapSeconds: 30,
		RevocationMaxStalenessSeconds: 10}
	brokerTLS := phase6security.TLSIdentity{TrustDomain: "sandbox.test", URI: "spiffe://sandbox.test/egress-broker",
		Usages: []string{"client_auth", "server_auth"}, TTLSeconds: 600, RotateAfterSeconds: 300, OverlapSeconds: 30,
		RevocationMaxStalenessSeconds: 10}
	controller := phase6security.Principal{Name: "certificate-controller", UID: uint32(os.Getuid()), GID: uint32(os.Getgid()),
		AuthorizationPrincipal: &controllerIdentity, TLS: &controllerTLS}
	agent := phase6security.Principal{Name: "egress-broker-product-tls-agent", UID: 20001, GID: 30001,
		AuthorizationPrincipal: &agentIdentity}
	broker := phase6security.Principal{Name: "egress-broker-product", AuthorizationPrincipal: &brokerIdentity, TLS: &brokerTLS}
	authority := phase6security.CertificateControllerAuthority{DeploymentName: controller.Name, UID: controller.UID, GID: controller.GID,
		ResponseKeyID: "controller-response", ResponsePublicKeyDigest: phase6security.CertificateControllerPublicKeyDigest(responsePublic),
		ManagedPolicyID: "managed-policy", ManagedVaultRole: "managed-vault",
		ManagedRequestKeyID: "managed-request", ManagedRequestKeyDigest: phase6security.TLSAgentRequestPublicKeyDigest(managedPublic),
		SelfSocketPath: "/run/certificate-controller/self/managed.sock"}
	binding := phase6security.TLSAgentBinding{AgentDeployment: agent.Name, SubjectDeployment: broker.Name,
		AgentUID: agent.UID, AgentGID: agent.GID, ControllerSocketPath: "/run/certificate-controller/egress-broker-product-tls-agent/request.sock",
		IssuerPolicyID: "broker-policy", IssuerVaultRole: "broker-vault", AgentRequestKeyID: "broker-request",
		AgentRequestKeyDigest: phase6security.TLSAgentRequestPublicKeyDigest(agentPublic)}
	profile := phase6security.Profile{CertificateController: authority, TLSAgentBindings: []phase6security.TLSAgentBinding{binding},
		Principals: []phase6security.Principal{controller, agent, broker}}
	policy := func(id, keyID, vaultRole string, requester, subject securityprincipal.Principal, identity phase6security.TLSIdentity,
		uid, gid uint32, public []byte) certificatePolicy {
		return certificatePolicy{ID: id, AgentRequestKeyID: keyID, Requester: requester, Subject: subject,
			TrustDomain: identity.TrustDomain, URI: identity.URI, DNSNames: identity.DNSNames, Usages: identity.Usages,
			VaultRole: vaultRole, MaxTTLSeconds: identity.TTLSeconds, ExpectedUID: uid, ExpectedGID: gid,
			AgentPublicKey: base64.RawURLEncoding.EncodeToString(public)}
	}
	valid := func() configDocument {
		return configDocument{ControllerKeyID: authority.ResponseKeyID,
			Credential: credentialDocument{Principal: controllerIdentity},
			ManagedVaultTLS: managedTLSConfig{PolicyID: authority.ManagedPolicyID, ControllerSocket: authority.SelfSocketPath,
				CertificateTTLSeconds: 600, RotateAfterSeconds: 300, OverlapSeconds: 30, RevocationMaxStalenessSeconds: 10},
			Policies: []certificatePolicy{
				policy(authority.ManagedPolicyID, authority.ManagedRequestKeyID, authority.ManagedVaultRole,
					controllerIdentity, controllerIdentity, controllerTLS, controller.UID, controller.GID, managedPublic),
				policy(binding.IssuerPolicyID, binding.AgentRequestKeyID, binding.IssuerVaultRole,
					agentIdentity, brokerIdentity, brokerTLS, agent.UID, agent.GID, agentPublic),
			},
			Listeners: []listenerDocument{
				{SocketPath: authority.SelfSocketPath, SocketUID: authority.UID, SocketGID: authority.GID,
					ExpectedClientUID: authority.UID, ExpectedClientGID: authority.GID},
				{SocketPath: binding.ControllerSocketPath, SocketUID: authority.UID, SocketGID: agent.GID,
					ExpectedClientUID: agent.UID, ExpectedClientGID: agent.GID},
			}}
	}
	if !validateControllerProfileConfig(profile, valid(), responsePublic, managedPublic) {
		t.Fatal("exact controller/agent inventory rejected")
	}
	for name, change := range map[string]func(*configDocument){
		"missing broker policy": func(c *configDocument) { c.Policies = c.Policies[:1] },
		"extra broker policy":   func(c *configDocument) { c.Policies = append(c.Policies, c.Policies[1]) },
		"wrong requester":       func(c *configDocument) { c.Policies[1].Requester.Name = "other" },
		"wrong CSR key": func(c *configDocument) {
			c.Policies[1].AgentPublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		},
		"wrong issuer":         func(c *configDocument) { c.Policies[1].VaultRole = "other" },
		"missing listener":     func(c *configDocument) { c.Listeners = c.Listeners[:1] },
		"extra listener":       func(c *configDocument) { c.Listeners = append(c.Listeners, c.Listeners[1]) },
		"wrong peer":           func(c *configDocument) { c.Listeners[1].ExpectedClientUID++ },
		"swapped endpoint":     func(c *configDocument) { c.Listeners[1].SocketPath = "/run/certificate-controller/other/request.sock" },
		"wrong managed socket": func(c *configDocument) { c.ManagedVaultTLS.ControllerSocket += "-other" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			change(&candidate)
			if validateControllerProfileConfig(profile, candidate, responsePublic, managedPublic) {
				t.Fatal("controller binding drift accepted")
			}
		})
	}
}

func TestReadBoundedRejectsPipeDirectoryMissingAndOversizedDescriptors(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	if _, err := readBounded(reader.Fd(), "pipe", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("pipe descriptor error = %v", err)
	}
	directory, err := os.Open("/tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(directory.Fd(), "directory", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("directory descriptor error = %v", err)
	}
	file, err := os.CreateTemp("/tmp", "certificate-controller-oversized-")
	if err != nil {
		t.Fatal(err)
	}
	name := file.Name()
	t.Cleanup(func() { _ = os.Remove(name) })
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(make([]byte, 33)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(file.Fd(), "oversized", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("oversized descriptor error = %v", err)
	}
	if _, err := readBounded(^uintptr(0), "missing", 32); !errors.Is(err, workloadpki.ErrUnavailable) {
		t.Fatalf("missing descriptor error = %v", err)
	}
}
