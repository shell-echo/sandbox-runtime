package phase6tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type GatewayProviderClientAuthority struct {
	Origin           string
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// GatewayProviderClient builds only the profile-bound private handoff mTLS
// client. Its local client issuer and remote Provider server roots never share
// a pool or fall back to the operating-system trust store.
func GatewayProviderClient(profile phase6security.Profile, authority GatewayProviderClientAuthority) (*tls.Config, error) {
	_, gateway, provider, serverAnchor, clientAnchor, err := profile.GatewayProviderBoundary(authority.Origin)
	if err != nil || gateway.TLS == nil || provider.TLS == nil ||
		uint32(os.Getuid()) != gateway.UID || uint32(os.Getgid()) != gateway.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second {
		return nil, errors.New("Gateway Provider TLS authority does not match profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject("gateway-runtime")
	if err != nil || subject.PrincipalDigest != gateway.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, errors.New("Gateway Provider TLS signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, errors.New("Gateway TLS supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != gateway.GID {
			return nil, errors.New("Gateway TLS role has supplementary group authority")
		}
	}
	clientIssuerPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, errors.New("Gateway own-client issuer anchor unavailable")
	}
	defer clear(clientIssuerPEM)
	serverRootPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, errors.New("Gateway Provider server anchor unavailable")
	}
	defer clear(serverRootPEM)
	clientIssuerRoots := x509.NewCertPool()
	serverRoots := x509.NewCertPool()
	if !clientIssuerRoots.AppendCertsFromPEM(clientIssuerPEM) || !serverRoots.AppendCertsFromPEM(serverRootPEM) {
		return nil, errors.New("Gateway Provider TLS anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: gateway.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, errors.New("Gateway TLS agent unavailable")
	}
	return remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientIssuerRoots, ServerRoots: serverRoots, ServerName: provider.TLS.DNSNames[0],
		Identity: remotetls.Identity{URI: gateway.TLS.URI, DNSNames: gateway.TLS.DNSNames,
			Usages: gateway.TLS.Usages, MaxTTL: time.Duration(gateway.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: provider.TLS.URI, DNSNames: provider.TLS.DNSNames,
			Usages: provider.TLS.Usages, MaxTTL: time.Duration(provider.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
}
