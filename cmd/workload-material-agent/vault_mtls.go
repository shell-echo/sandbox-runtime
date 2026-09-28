package main

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

// A v2 material agent has no server-only Vault fallback. Its own client leaf
// is signed by its distinct TLS-agent process, while the Vault server remains
// a separately pinned external identity on one isolated service bridge.
func newV2VaultHTTPClient(config configDocument, v2 configDocumentV2) (*http.Client, error) {
	profile, err := phase6security.VerifyFile(v2.SecurityProfilePath)
	if err != nil || phase6security.VerifySlice6FinalExternalDependencyClosure(profile) != nil ||
		profile.ProfileDigest != v2.SecurityProfileDigest ||
		config.Protocol != configProtocolV2 || len(config.VaultCABundle) != 0 ||
		uint32(os.Getuid()) != config.SocketUID || uint32(os.Getgid()) != config.SocketGID {
		return nil, secretref.ErrUnavailable
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	for _, group := range groups {
		if uint32(group) != config.SocketGID {
			return nil, secretref.ErrUnavailable
		}
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
	if subject.Kind != "material_agent" || subject.TLS == nil || subject.UID != config.SocketUID ||
		subject.GID != config.SocketGID || vault.Name != "vault" || len(vault.DNSNames) != 1 ||
		config.VaultServerName != vault.DNSNames[0] {
		return nil, secretref.ErrUnavailable
	}
	var dependency phase6security.Slice6DirectExternalDependency
	for _, candidate := range phase6security.Slice6RequiredDirectExternalDependencies() {
		if candidate.Dialer == subject.Name && candidate.Service == "vault" {
			dependency = candidate
			break
		}
	}
	if dependency.Network == "" || dependency.EdgeID == "" {
		return nil, secretref.ErrUnavailable
	}
	address, err := phase6security.Slice6DesiredServiceEndpointAddress(dependency.Network, "vault")
	endpoint, parseErr := url.Parse(config.VaultEndpoint)
	if err != nil || parseErr != nil || endpoint.Scheme != "https" ||
		endpoint.Host != net.JoinHostPort(address, "8200") || endpoint.Path != "" ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil ||
		endpoint.String() != config.VaultEndpoint {
		return nil, secretref.ErrUnavailable
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
		return nil, secretref.ErrUnavailable
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
		return nil, secretref.ErrUnavailable
	}
	binding, signer, material, err := profile.TLSAgentForSubject(subject.Name)
	if err != nil || signer.Name != subject.Name+"-tls-agent" || material.PrincipalDigest != subject.PrincipalDigest ||
		v2.VaultTLSAgentSocket != binding.SocketPath || v2.VaultTLSAgentUID != binding.AgentUID ||
		v2.VaultTLSAgentGID != binding.AgentGID || signer.UID != binding.AgentUID || signer.GID != binding.AgentGID {
		return nil, secretref.ErrUnavailable
	}
	serverAnchor, _, err := profile.EdgeTrustAnchors(dependency.EdgeID)
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	clientAnchor, err := profile.ConsumerTrustAnchor("vault-client-ca", subject.Name, "client_verification")
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	serverPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	defer clear(serverPEM)
	clientPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	defer clear(clientPEM)
	serverRoots, clientRoots := x509.NewCertPool(), x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(serverPEM) || !clientRoots.AppendCertsFromPEM(clientPEM) {
		return nil, secretref.ErrUnavailable
	}
	agent, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: v2.VaultTLSAgentSocket, ExpectedUID: v2.VaultTLSAgentUID,
		ExpectedGID: v2.VaultTLSAgentGID, RoleGID: subject.GID,
		OperationTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second, Now: time.Now,
	})
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	transportTLS, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientRoots, ServerRoots: serverRoots, ServerName: config.VaultServerName,
		Identity: remotetls.Identity{URI: subject.TLS.URI, DNSNames: subject.TLS.DNSNames,
			Usages: subject.TLS.Usages, MaxTTL: time.Duration(subject.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: vault.URI, DNSNames: vault.DNSNames,
			Usages: []string{"server_auth"}, MaxTTL: time.Hour},
		Source: agent.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, secretref.ErrUnavailable
	}
	transport := &http.Transport{TLSClientConfig: transportTLS, DisableKeepAlives: true,
		TLSHandshakeTimeout: time.Duration(config.OperationTimeoutSeconds) * time.Second,
		DialContext:         (&net.Dialer{Timeout: time.Duration(config.OperationTimeoutSeconds) * time.Second}).DialContext}
	return &http.Client{Transport: transport, Timeout: time.Duration(config.OperationTimeoutSeconds) * time.Second}, nil
}
