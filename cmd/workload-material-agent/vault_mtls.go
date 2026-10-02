package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

func vaultMTLSUnavailable(category string) error {
	return fmt.Errorf("vault-mtls-%s: %w", category, secretref.ErrUnavailable)
}

func vaultMTLSBootstrapUnavailable(category string, elapsed time.Duration) error {
	return fmt.Errorf("vault-mtls-signer-bootstrap-%s: bootstrap_ms=%d: %w",
		category, elapsed.Milliseconds(), secretref.ErrUnavailable)
}

// remotetls intentionally returns no credential bytes or endpoints in these
// errors. Preserve only a fixed reason category at the process boundary.
func vaultMTLSBootstrapCategory(err error) string {
	if err == nil {
		return "unknown"
	}
	switch err.Error() {
	case "invalid live TLS client authority":
		return "authority"
	case "live TLS signer is unavailable":
		return "signer-unavailable"
	case "live TLS context ended":
		return "context-ended"
	case "live TLS chain or signer is missing", "live TLS chain is invalid", "live TLS chain differs from verified chain":
		return "chain"
	case "live TLS leaf is invalid":
		return "leaf"
	case "live TLS key is not a signer", "live TLS signer public key is invalid",
		"live TLS signer does not match certificate", "live TLS signer key type is invalid":
		return "signer-identity"
	case "live TLS signer challenge is unavailable", "live TLS signer challenge failed":
		return "signer-challenge"
	case "live TLS issuer is not pinned":
		return "issuer"
	default:
		if errors.Is(err, context.DeadlineExceeded) {
			return "deadline"
		}
		return "other"
	}
}

// A v2 material agent has no server-only Vault fallback. Its own client leaf
// is signed by its distinct TLS-agent process, while the Vault server remains
// a separately pinned external identity on one isolated service bridge.
func newV2VaultHTTPClient(config configDocument, v2 configDocumentV2) (*http.Client, error) {
	profile, err := phase6security.VerifyFile(v2.SecurityProfilePath)
	if err != nil || phase6security.VerifySlice6FinalExternalDependencyClosure(profile) != nil ||
		profile.ProfileDigest != v2.SecurityProfileDigest ||
		phase6security.VerifySlice6PrivateConfigPath(profile, config.CredentialAgentID,
			phase6security.Slice6ProfileConfigFile, v2.SecurityProfilePath) != nil ||
		config.Protocol != configProtocolV2 || len(config.VaultCABundle) != 0 {
		return nil, vaultMTLSUnavailable("profile")
	}
	var subject phase6security.Principal
	var vault phase6security.ExternalService
	for _, principal := range profile.Principals {
		if principal.Name == config.CredentialAgentID {
			subject = principal
		}
	}
	for _, service := range profile.External {
		if service.Name == "vault" {
			vault = service
		}
	}
	if !validV2MaterialProcessIdentity(observeV2MaterialProcessIdentity(), subject, config) ||
		!validV2MaterialSocketInProfile(profile, config) || subject.TLS == nil ||
		vault.Name != "vault" || len(vault.DNSNames) != 1 ||
		config.VaultServerName != vault.DNSNames[0] {
		return nil, vaultMTLSUnavailable("identity")
	}
	var dependency phase6security.Slice6DirectExternalDependency
	for _, candidate := range phase6security.Slice6RequiredDirectExternalDependencies() {
		if candidate.Dialer == subject.Name && candidate.Service == "vault" {
			dependency = candidate
			break
		}
	}
	if dependency.Network == "" || dependency.EdgeID == "" {
		return nil, vaultMTLSUnavailable("dependency")
	}
	address, err := phase6security.Slice6DesiredServiceEndpointAddress(dependency.Network, "vault")
	endpoint, parseErr := url.Parse(config.VaultEndpoint)
	if err != nil || parseErr != nil || endpoint.Scheme != "https" ||
		endpoint.Host != net.JoinHostPort(address, "8200") || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil ||
		endpoint.String() != config.VaultEndpoint {
		return nil, vaultMTLSUnavailable("endpoint")
	}
	bridgeOK := false
	var plannedBridge phase6security.Network
	for _, candidate := range phase6security.Slice6DesiredServiceBridges() {
		if candidate.Name == dependency.Network {
			plannedBridge = candidate
			break
		}
	}
	for _, network := range profile.Networks {
		if network.Name == dependency.Network && network.Internal && network.GatewayModeIPv4 == "isolated" &&
			plannedBridge.Name == network.Name && plannedBridge.IPv4Subnet == network.IPv4Subnet &&
			plannedBridge.Kind == network.Kind &&
			slices.Equal(network.Principals, []string{subject.Name}) &&
			slices.Equal(network.ExternalServices, []string{"vault"}) &&
			slices.Contains(subject.Networks, network.Name) && slices.Contains(vault.Networks, network.Name) {
			bridgeOK = true
		}
	}
	if !bridgeOK {
		return nil, vaultMTLSUnavailable("bridge")
	}
	edgeOK := false
	for _, edge := range profile.TrustEdges {
		if edge.ID == dependency.EdgeID && edge.From == subject.Name && edge.To == "vault" &&
			edge.Protocol == "https" && edge.Port == 8200 && edge.Authentication == "mtls" &&
			edge.CrossDomain && edge.FromPrincipalDigest == subject.PrincipalDigest &&
			edge.ExternalIdentityDigest == vault.IdentityDigest && edge.ToURI == vault.URI &&
			edge.ClientAnchorID == "" && edge.TargetAddress == "" {
			edgeOK = true
		}
	}
	if !edgeOK {
		return nil, vaultMTLSUnavailable("edge")
	}
	binding, signer, material, err := profile.TLSAgentForSubject(subject.Name)
	if err != nil || !validV2VaultSignerBinding(binding, signer, material, subject, v2) {
		return nil, vaultMTLSUnavailable("signer-binding")
	}
	serverAnchor, _, err := profile.EdgeTrustAnchors(dependency.EdgeID)
	if err != nil {
		return nil, vaultMTLSUnavailable("server-anchor")
	}
	clientAnchor, err := profile.ConsumerTrustAnchor("vault-client-ca", subject.Name, "client_verification")
	if err != nil {
		return nil, vaultMTLSUnavailable("client-anchor")
	}
	serverPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, vaultMTLSUnavailable("server-anchor-bytes")
	}
	defer clear(serverPEM)
	clientPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, vaultMTLSUnavailable("client-anchor-bytes")
	}
	defer clear(clientPEM)
	serverRoots, clientRoots := x509.NewCertPool(), x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(serverPEM) || !clientRoots.AppendCertsFromPEM(clientPEM) {
		return nil, vaultMTLSUnavailable("anchor-roots")
	}
	agent, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: v2.VaultTLSAgentSocket, ExpectedUID: v2.VaultTLSAgentUID,
		ExpectedGID: v2.VaultTLSAgentGID, RoleGID: subject.GID,
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now,
	})
	if err != nil {
		return nil, vaultMTLSUnavailable("signer-socket")
	}
	bootstrapStarted := time.Now()
	transportTLS, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientRoots, ServerRoots: serverRoots, ServerName: config.VaultServerName,
		Identity: remotetls.Identity{URI: subject.TLS.URI, DNSNames: subject.TLS.DNSNames,
			Usages: subject.TLS.Usages, MaxTTL: time.Duration(subject.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: vault.URI, DNSNames: vault.DNSNames,
			Usages: []string{"server_auth"}, MaxTTL: time.Hour},
		Source: agent.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, vaultMTLSBootstrapUnavailable(vaultMTLSBootstrapCategory(err), time.Since(bootstrapStarted))
	}
	transport := &http.Transport{TLSClientConfig: transportTLS, DisableKeepAlives: true,
		TLSHandshakeTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second,
		DialContext:         (&net.Dialer{Timeout: time.Duration(config.OperationTimeoutSeconds) * time.Second}).DialContext}
	return &http.Client{Transport: transport, Timeout: time.Duration(config.OperationTimeoutSeconds) * time.Second}, nil
}

func validV2VaultSignerBinding(binding phase6security.TLSAgentBinding, signer, material,
	subject phase6security.Principal, v2 configDocumentV2) bool {
	return signer.Name == subject.Name+"-tls-agent" && binding.AgentDeployment == signer.Name &&
		binding.SubjectDeployment == subject.Name && material.Name == subject.Name &&
		material.PrincipalDigest == subject.PrincipalDigest &&
		binding.AgentPrincipalDigest == signer.PrincipalDigest &&
		binding.SubjectPrincipalDigest == subject.PrincipalDigest &&
		binding.SubjectUID == subject.UID && binding.SubjectGID == subject.GID &&
		v2.VaultTLSAgentSocket == binding.SocketPath && v2.VaultTLSAgentUID == binding.AgentUID &&
		v2.VaultTLSAgentGID == binding.AgentGID && signer.UID == binding.AgentUID && signer.GID == binding.AgentGID
}
