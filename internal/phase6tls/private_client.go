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
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type GatewayProviderClientAuthority struct {
	Origin           string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// GatewayProviderClient builds only the profile-bound private handoff mTLS
// client. Its local client issuer and remote Provider server roots never share
// a pool or fall back to the operating-system trust store.
func GatewayProviderClient(profile phase6security.Profile, authority GatewayProviderClientAuthority) (*http.Transport, *PeerCRLGuard, error) {
	edge, gateway, provider, serverAnchor, clientAnchor, err := profile.GatewayProviderBoundary(authority.Origin)
	if err != nil || gateway.TLS == nil || provider.TLS == nil ||
		uint32(os.Getuid()) != gateway.UID || uint32(os.Getgid()) != gateway.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second {
		return nil, nil, errors.New("Gateway Provider TLS authority does not match profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject("gateway-runtime")
	if err != nil || subject.PrincipalDigest != gateway.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, errors.New("Gateway Provider TLS signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, errors.New("Gateway TLS supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != gateway.GID {
			return nil, nil, errors.New("Gateway TLS role has supplementary group authority")
		}
	}
	clientIssuerPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("Gateway own-client issuer anchor unavailable")
	}
	defer clear(clientIssuerPEM)
	serverRootPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("Gateway Provider server anchor unavailable")
	}
	defer clear(serverRootPEM)
	clientIssuerRoots := x509.NewCertPool()
	serverRoots := x509.NewCertPool()
	if !clientIssuerRoots.AppendCertsFromPEM(clientIssuerPEM) || !serverRoots.AppendCertsFromPEM(serverRootPEM) {
		return nil, nil, errors.New("Gateway Provider TLS anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: gateway.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, errors.New("Gateway TLS agent unavailable")
	}
	config, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientIssuerRoots, ServerRoots: serverRoots, ServerName: provider.TLS.DNSNames[0],
		Identity: remotetls.Identity{URI: gateway.TLS.URI, DNSNames: gateway.TLS.DNSNames,
			Usages: gateway.TLS.Usages, MaxTTL: time.Duration(gateway.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: provider.TLS.URI, DNSNames: provider.TLS.DNSNames,
			Usages: provider.TLS.Usages, MaxTTL: time.Duration(provider.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, gateway.PrincipalDigest, "outbound", agentClient,
		authority.OperationTimeout, time.Now)
	if err != nil || config.VerifyConnection == nil {
		return nil, nil, errors.New("Gateway Provider peer revocation boundary is unavailable")
	}
	identityCheck := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := identityCheck(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	origin, err := url.Parse(authority.Origin)
	if err != nil || origin.Scheme != "wss" || origin.Host == "" {
		return nil, nil, errors.New("Gateway Provider origin is invalid")
	}
	return guardedClientTransport(config, identityCheck, guard, origin.Host), guard, nil
}

func guardedClientTransport(config *tls.Config, identityCheck func(tls.ConnectionState) error,
	guard *PeerCRLGuard, expectedAddress string) *http.Transport {
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx == nil || network != "tcp" || address != expectedAddress {
			return nil, ErrPeerCRLUnavailable
		}
		dialConfig := config.Clone()
		dialConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if err := identityCheck(state); err != nil {
				return err
			}
			return guard.CheckHandshake(ctx, state)
		}
		connection, err := (&tls.Dialer{Config: dialConfig}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tlsConnection, ok := connection.(*tls.Conn)
		if !ok || guard.Track(connection, tlsConnection.ConnectionState()) != nil {
			_ = connection.Close()
			return nil, ErrPeerCRLUnavailable
		}
		return &guardedClientConn{Conn: connection, guard: guard}, nil
	}
	return transport
}

type guardedClientConn struct {
	net.Conn
	guard *PeerCRLGuard
	once  sync.Once
}

func (c *guardedClientConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.guard.Forget(c.Conn) })
	return err
}
