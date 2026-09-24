package phase6tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type ProviderPrivateRoleClientAuthority struct {
	Role             string
	Origin           string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// ProviderPrivateRoleClient binds a Provider instance to its own Browser or
// Desktop attach listener. The role-to-backend executor edge is not accepted.
func ProviderPrivateRoleClient(profile phase6security.Profile, authority ProviderPrivateRoleClientAuthority) (
	*http.Transport, *PeerCRLGuard, error) {
	origin, err := url.Parse(authority.Origin)
	if err != nil || origin.Scheme != "wss" || origin.Host == "" || origin.Path != "/executor" ||
		origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || origin.String() != authority.Origin {
		return nil, nil, errors.New("Provider attach origin is invalid")
	}
	edge, provider, role, serverAnchor, clientAnchor, err := profile.PrivateRoleAttachBoundary(authority.Role, origin.Host)
	if err != nil || edge.TargetAddress != origin.Host || uint32(os.Getuid()) != provider.UID || uint32(os.Getgid()) != provider.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second ||
		edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 3600 {
		return nil, nil, errors.New("Provider attach authority does not match profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject(provider.Name)
	if err != nil || subject.PrincipalDigest != provider.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, errors.New("Provider attach signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, errors.New("Provider attach supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != provider.GID {
			return nil, nil, errors.New("Provider attach has supplementary group authority")
		}
	}
	issuerPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("Provider attach own-client issuer unavailable")
	}
	defer clear(issuerPEM)
	serverPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("Provider attach server root unavailable")
	}
	defer clear(serverPEM)
	issuerRoots, serverRoots := x509.NewCertPool(), x509.NewCertPool()
	if !issuerRoots.AppendCertsFromPEM(issuerPEM) || !serverRoots.AppendCertsFromPEM(serverPEM) {
		return nil, nil, errors.New("Provider attach trust anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: provider.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, errors.New("Provider attach TLS agent unavailable")
	}
	transportTLS, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: issuerRoots, ServerRoots: serverRoots, ServerName: role.TLS.DNSNames[0],
		Identity: remotetls.Identity{URI: provider.TLS.URI, DNSNames: provider.TLS.DNSNames,
			Usages: provider.TLS.Usages, MaxTTL: time.Duration(provider.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: role.TLS.URI, DNSNames: role.TLS.DNSNames,
			Usages: role.TLS.Usages, MaxTTL: time.Duration(role.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now})
	if err != nil {
		return nil, nil, err
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, provider.PrincipalDigest, "outbound",
		agentClient, authority.OperationTimeout, time.Now)
	if err != nil || transportTLS.VerifyConnection == nil {
		return nil, nil, errors.New("Provider attach peer revocation boundary unavailable")
	}
	identityCheck := transportTLS.VerifyConnection
	transportTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if err := identityCheck(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	transport := guardedClientTransport(transportTLS, identityCheck, guard, origin.Host)
	dial := transport.DialTLSContext
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return newBoundedClientConn(connection, time.Duration(edge.MaxConnectionSeconds)*time.Second), nil
	}
	return transport, guard, nil
}
