package phase6tls

import (
	"context"
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

type ProviderServerAuthority struct {
	EdgeID           string
	ListenAddress    string
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// ProviderServer constructs one of the two separate Provider mTLS listeners.
// The Contract edge admits only Product; the private handoff edge admits only
// Gateway. Both verify the locally signed server leaf against the exact
// server-verification root and the peer against a separate client root.
func ProviderServer(profile phase6security.Profile, authority ProviderServerAuthority) (*tls.Config, func(context.Context) error, string, error) {
	var edge phase6security.TrustEdge
	var caller, provider phase6security.Principal
	var serverAnchor, clientAnchor phase6security.TrustAnchor
	var err error
	switch authority.EdgeID {
	case phase6security.ProductProviderContractEdgeID:
		edge, caller, provider, serverAnchor, clientAnchor, err = profile.ProductProviderBoundary()
	case phase6security.GatewayProviderPrivateEdgeID:
		edge, caller, provider, serverAnchor, clientAnchor, err = profile.GatewayProviderBoundary("wss://" + authority.ListenAddress + "/private/terminal")
	default:
		return nil, nil, "", errors.New("Provider TLS edge is not authorized")
	}
	if err != nil || edge.TargetAddress != authority.ListenAddress || provider.TLS == nil || caller.TLS == nil ||
		uint32(os.Getuid()) != provider.UID || uint32(os.Getgid()) != provider.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second {
		return nil, nil, "", errors.New("Provider TLS listener does not match profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject("provider-runtime")
	if err != nil || subject.PrincipalDigest != provider.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, "", errors.New("Provider TLS signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, "", errors.New("Provider TLS supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != provider.GID {
			return nil, nil, "", errors.New("Provider TLS role has supplementary group authority")
		}
	}
	serverIssuerPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, "", errors.New("Provider own-server issuer anchor unavailable")
	}
	defer clear(serverIssuerPEM)
	clientRootPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, "", errors.New("Provider client-verification anchor unavailable")
	}
	defer clear(clientRootPEM)
	serverIssuerRoots := x509.NewCertPool()
	clientRoots := x509.NewCertPool()
	if !serverIssuerRoots.AppendCertsFromPEM(serverIssuerPEM) || !clientRoots.AppendCertsFromPEM(clientRootPEM) {
		return nil, nil, "", errors.New("Provider TLS anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: provider.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, "", errors.New("Provider TLS agent unavailable")
	}
	config, probe, err := remotetls.NewServerWithProbe(remotetls.ServerOptions{
		IssuerRoots: serverIssuerRoots, ClientRoots: clientRoots,
		Identity: remotetls.Identity{URI: provider.TLS.URI, DNSNames: provider.TLS.DNSNames,
			Usages: provider.TLS.Usages, MaxTTL: time.Duration(provider.TLS.TTLSeconds) * time.Second},
		Client: &remotetls.Identity{URI: caller.TLS.URI, DNSNames: caller.TLS.DNSNames,
			Usages: caller.TLS.Usages, MaxTTL: time.Duration(caller.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, nil, "", err
	}
	return config, probe, caller.TLS.URI, nil
}
