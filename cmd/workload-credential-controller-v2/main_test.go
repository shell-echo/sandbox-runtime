package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

func TestCredentialControllerManagedBindingRejectsPolicyKeyAndPeerDrift(t *testing.T) {
	if os.Getuid() == 0 || os.Getgid() == 0 {
		t.Skip("distinct non-root peer identity required")
	}
	requestPublic := ed25519.PublicKey(bytes.Repeat([]byte{1}, ed25519.PublicKeySize))
	controllerPublic := ed25519.PublicKey(bytes.Repeat([]byte{2}, ed25519.PublicKeySize))
	credentialIdentity := securityprincipal.Principal{Name: "credential_controller", PrincipalDigest: "credential-digest"}
	certificateIdentity := securityprincipal.Principal{Name: "certificate_controller", PrincipalDigest: "certificate-digest"}
	credential := phase6security.Principal{Name: "workload-credential-controller", UID: uint32(os.Getuid()), GID: uint32(os.Getgid()),
		AuthorizationPrincipal: &credentialIdentity, TLS: &phase6security.TLSIdentity{TrustDomain: "sandbox.test",
			URI: "spiffe://sandbox.test/workload-credential-controller", Usages: []string{"client_auth"},
			TTLSeconds: 600, RotateAfterSeconds: 300, OverlapSeconds: 30, RevocationMaxStalenessSeconds: 10}}
	certificate := phase6security.Principal{Name: "certificate-controller", UID: credential.UID + 1, GID: credential.GID + 1,
		AuthorizationPrincipal: &certificateIdentity}
	profile := phase6security.Profile{Principals: []phase6security.Principal{credential, certificate},
		CredentialIssuerSockets: []phase6security.CredentialIssuerSocketBinding{{ClientDeployment: certificate.Name,
			SocketDirectory: "/run/workload-credential-controller/certificate-controller",
			SocketStorageID: "credential-issuer-certificate-controller-socket",
			SocketPath:      "/run/workload-credential-controller/certificate-controller/issuer.sock",
			UnixEdgeID:      "credential-issuer-certificate-controller"}},
		CertificateController: phase6security.CertificateControllerAuthority{DeploymentName: certificate.Name,
			UID: certificate.UID, GID: certificate.GID, ResponseKeyID: "controller-key",
			ResponsePublicKeyDigest: phase6security.CertificateControllerPublicKeyDigest(controllerPublic),
			CredentialController: phase6security.CredentialControllerManagedAuthority{PolicyID: "managed-policy",
				RequestKeyDigest: phase6security.TLSAgentRequestPublicKeyDigest(requestPublic),
				SocketPath:       "/run/certificate-controller/workload-credential-controller/request.sock"}}}
	valid := func() configDocument {
		return configDocument{ControllerKeyID: "controller-key", ManagedVaultTLS: managedTLSConfig{
			PolicyID: "managed-policy", ControllerSocket: profile.CertificateController.CredentialController.SocketPath,
			CertificateTTLSeconds: 600, RotateAfterSeconds: 300, OverlapSeconds: 30, RevocationMaxStalenessSeconds: 10},
			Policies: []policyDocument{{ID: "certificate-credential", Principal: certificateIdentity,
				Purpose: secretref.PurposeWorkloadCredential, BackendPolicy: "certificate-controller-pki",
				MaxTTLSeconds: 300, Renewable: true, ExpectedUID: certificate.UID, ExpectedGID: certificate.GID}},
			Listeners: []listenerDocument{{SocketPath: profile.CredentialIssuerSockets[0].SocketPath,
				SocketUID: credential.UID, SocketGID: certificate.GID, ExpectedClientUID: certificate.UID,
				ExpectedClientGID: certificate.GID, MaxConnections: 2}}}
	}
	if !validateProfileConfig(profile, valid(), requestPublic, controllerPublic) {
		t.Fatal("exact managed binding rejected")
	}
	for name, change := range map[string]func(*configDocument){
		"policy removed":                 func(c *configDocument) { c.Policies = nil },
		"policy widened":                 func(c *configDocument) { c.Policies[0].BackendPolicy = "root" },
		"peer changed":                   func(c *configDocument) { c.Policies[0].ExpectedUID++ },
		"socket changed":                 func(c *configDocument) { c.ManagedVaultTLS.ControllerSocket += "-other" },
		"TTL changed":                    func(c *configDocument) { c.ManagedVaultTLS.CertificateTTLSeconds++ },
		"issuer socket path changed":     func(c *configDocument) { c.Listeners[0].SocketPath += "-other" },
		"issuer directory group changed": func(c *configDocument) { c.Listeners[0].SocketGID++ },
		"issuer server UID changed":      func(c *configDocument) { c.Listeners[0].SocketUID++ },
		"issuer peer GID changed":        func(c *configDocument) { c.Listeners[0].ExpectedClientGID++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			change(&candidate)
			if validateProfileConfig(profile, candidate, requestPublic, controllerPublic) {
				t.Fatal("managed binding drift accepted")
			}
		})
	}
	if validateProfileConfig(profile, valid(), ed25519.PublicKey(bytes.Repeat([]byte{3}, 32)), controllerPublic) ||
		validateProfileConfig(profile, valid(), requestPublic, ed25519.PublicKey(bytes.Repeat([]byte{4}, 32))) {
		t.Fatal("request or controller signing key substitution accepted")
	}
}

func TestCredentialControllerBindsAllMaterialPoliciesToPlan(t *testing.T) {
	profile := phase6security.Profile{ProfileDigest: "sha256:" + strings.Repeat("a", 64)}
	plan := make([]phase6security.Slice6MaterialAccess, 0, 11)
	policies := []policyDocument{{ID: "credential-certificate-controller", BackendPolicy: "certificate-controller-pki"}}
	for index := range 11 {
		name := fmt.Sprintf("agent-%d", index)
		principal := securityprincipal.Principal{Name: name}
		profile.Principals = append(profile.Principals, phase6security.Principal{Name: name,
			UID: uint32(20000 + index), GID: uint32(30000 + index), AuthorizationPrincipal: &principal})
		migration := index == 10
		entry := phase6security.Slice6MaterialAccess{SecurityProfileDigest: profile.ProfileDigest,
			Agent: name, AgentUID: uint32(20000 + index), AgentGID: uint32(30000 + index),
			Migration: migration, CredentialPolicyID: "credential-" + name, BackendPolicy: name + "-kv"}
		plan = append(plan, entry)
		policies = append(policies, policyDocument{ID: entry.CredentialPolicyID, Principal: principal,
			Purpose: secretref.PurposeWorkloadCredential, BackendPolicy: entry.BackendPolicy,
			MaxTTLSeconds: 300, Renewable: !migration, ExpectedUID: entry.AgentUID, ExpectedGID: entry.AgentGID})
	}
	if !validateMaterialPolicyBindings(profile, policies, plan) {
		t.Fatal("exact closed material policy plan rejected")
	}
	for name, mutate := range map[string]func([]policyDocument){
		"cross owner backend":   func(values []policyDocument) { values[1].BackendPolicy = values[2].BackendPolicy },
		"policy alias":          func(values []policyDocument) { values[1].ID = values[2].ID },
		"wrong purpose":         func(values []policyDocument) { values[1].Purpose = secretref.PurposePostgresRuntimeDSN },
		"migration renewable":   func(values []policyDocument) { values[11].Renewable = true },
		"runtime nonrenewable":  func(values []policyDocument) { values[1].Renewable = false },
		"wrong UID":             func(values []policyDocument) { values[1].ExpectedUID++ },
		"excessive TTL":         func(values []policyDocument) { values[1].MaxTTLSeconds = 901 },
		"cross owner principal": func(values []policyDocument) { values[1].Principal = values[2].Principal },
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]policyDocument(nil), policies...)
			mutate(changed)
			if validateMaterialPolicyBindings(profile, changed, plan) {
				t.Fatal("material controller policy drift admitted")
			}
		})
	}
	if validateMaterialPolicyBindings(profile, policies[:len(policies)-1], plan) {
		t.Fatal("missing policy admitted")
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (fn responseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestBootstrapTransportWaitsForPreSwitchResponseBody(t *testing.T) {
	transport := workloadtlsagent.NewBootstrapTrackingTransport(responseTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
	}))
	request, err := http.NewRequest(http.MethodGet, "https://vault.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	transport.Switch()
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if transport.WaitBootstrapDrain(short) == nil {
		t.Fatal("pre-switch response body was ignored")
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	long, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := transport.WaitBootstrapDrain(long); err != nil {
		t.Fatalf("completed bootstrap response remained active: %v", err)
	}
}

func TestBootstrapTransportReleasesOnEOFAndRequestFailure(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://vault.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := workloadtlsagent.NewBootstrapTrackingTransport(responseTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
	}))
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	transport.Switch()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := transport.WaitBootstrapDrain(ctx); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	failed := workloadtlsagent.NewBootstrapTrackingTransport(responseTransport(func(*http.Request) (*http.Response, error) {
		return nil, workloadpki.ErrUnavailable
	}))
	if _, err := failed.RoundTrip(request); err == nil {
		t.Fatal("failed transport request unexpectedly succeeded")
	}
	failed.Switch()
	if err := failed.WaitBootstrapDrain(ctx); err != nil {
		t.Fatalf("failed request retained bootstrap transport: %v", err)
	}
}

func TestCredentialVaultEndpointRequiresExactReviewedEdge(t *testing.T) {
	profile := phase6security.Profile{External: []phase6security.ExternalService{{Name: "vault",
		URI: "spiffe://sandbox.test/external/vault", DNSNames: []string{"vault.sandbox.test"}}},
		TrustEdges: []phase6security.TrustEdge{{ID: "credential-controller-vault", From: "workload-credential-controller",
			To: "vault", Protocol: "https", Port: 8200, Authentication: "mtls",
			ToURI: "spiffe://sandbox.test/external/vault"}}}
	if !vaultTrustEdgeMatches(profile, "https://vault.sandbox.test:8200", "vault.sandbox.test") {
		t.Fatal("exact credential Vault edge rejected")
	}
	for _, endpoint := range []string{"http://vault.sandbox.test:8200", "https://vault.sandbox.test:8300",
		"https://other.sandbox.test:8200", "https://vault.sandbox.test:8200/other"} {
		if vaultTrustEdgeMatches(profile, endpoint, "vault.sandbox.test") {
			t.Fatalf("Vault edge drift admitted: %s", endpoint)
		}
	}
}

func TestReadPrivateFDRequiresBoundedPrivateRegularDescriptor(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "secret-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("limited-token")); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	duplicate, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	value, err := readPrivateFD(uintptr(duplicate), "limited-token", 64)
	if err != nil || string(value) != "limited-token" {
		t.Fatalf("private FD = %q, %v", value, err)
	}
	clear(value)
	if err := file.Chmod(0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	duplicate, err = syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateFD(uintptr(duplicate), "public-token", 64); err == nil {
		t.Fatal("public-permission descriptor admitted")
	}
}

func TestManagedClientWaitsOnlyUntilReadyOrCancelled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempts := 0
	client, err := waitForManagedClient(ctx, func() (*workloadpki.Client, error) {
		attempts++
		if attempts < 3 {
			return nil, workloadpki.ErrUnavailable
		}
		return &workloadpki.Client{}, nil
	})
	if err != nil || client == nil || attempts != 3 {
		t.Fatalf("bounded controller socket wait = %v, attempts %d", err, attempts)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	attempts = 0
	if _, err := waitForManagedClient(cancelled, func() (*workloadpki.Client, error) {
		attempts++
		return &workloadpki.Client{}, nil
	}); err == nil || attempts != 0 {
		t.Fatal("cancelled startup attempted a managed client")
	}
}
