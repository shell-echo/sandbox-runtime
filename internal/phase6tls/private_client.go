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
	return GatewayProviderInstanceClient(profile, "provider-runtime", authority)
}

// GatewayProviderInstanceClient selects the Terminal or Desktop Provider
// private route. Browser cannot use this path; it must traverse the distinct
// action-ingress principal and two separately fenced TLS edges.
func GatewayProviderInstanceClient(profile phase6security.Profile, providerName string, authority GatewayProviderClientAuthority) (*http.Transport, *PeerCRLGuard, error) {
	edge, caller, provider, serverAnchor, clientAnchor, err := profile.GatewayProviderInstanceBoundary(providerName, authority.Origin)
	if err != nil {
		return nil, nil, errors.New("Gateway Provider TLS authority does not match profile")
	}
	return privateRuntimeClient(profile, authority, edge, caller, provider, serverAnchor, clientAnchor)
}

func GatewayBrowserActionIngressClient(profile phase6security.Profile, authority GatewayProviderClientAuthority) (*http.Transport, *PeerCRLGuard, error) {
	edge, caller, ingress, serverAnchor, clientAnchor, err := profile.GatewayBrowserActionIngressBoundary(authority.Origin)
	if err != nil {
		return nil, nil, errors.New("Gateway Browser action ingress TLS authority does not match profile")
	}
	return privateRuntimeClient(profile, authority, edge, caller, ingress, serverAnchor, clientAnchor)
}

func BrowserActionIngressProviderClient(profile phase6security.Profile, authority GatewayProviderClientAuthority) (*http.Transport, *PeerCRLGuard, error) {
	edge, ingress, provider, serverAnchor, clientAnchor, err := profile.BrowserActionIngressProviderBoundary(authority.Origin)
	if err != nil {
		return nil, nil, errors.New("Browser action ingress Provider TLS authority does not match profile")
	}
	return privateRuntimeClient(profile, authority, edge, ingress, provider, serverAnchor, clientAnchor)
}

func privateRuntimeClient(profile phase6security.Profile, authority GatewayProviderClientAuthority, edge phase6security.TrustEdge,
	caller, provider phase6security.Principal, serverAnchor, clientAnchor phase6security.TrustAnchor) (*http.Transport, *PeerCRLGuard, error) {
	if caller.TLS == nil || provider.TLS == nil || len(provider.TLS.DNSNames) != 1 ||
		uint32(os.Getuid()) != caller.UID || uint32(os.Getgid()) != caller.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second ||
		edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 3600 {
		return nil, nil, errors.New("private runtime TLS authority does not match profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject(caller.Name)
	if err != nil || subject.PrincipalDigest != caller.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, errors.New("private runtime TLS signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, errors.New("private runtime TLS supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != caller.GID {
			return nil, nil, errors.New("private runtime TLS role has supplementary group authority")
		}
	}
	clientIssuerPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("private runtime own-client issuer anchor unavailable")
	}
	defer clear(clientIssuerPEM)
	serverRootPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("private runtime server anchor unavailable")
	}
	defer clear(serverRootPEM)
	clientIssuerRoots := x509.NewCertPool()
	serverRoots := x509.NewCertPool()
	if !clientIssuerRoots.AppendCertsFromPEM(clientIssuerPEM) || !serverRoots.AppendCertsFromPEM(serverRootPEM) {
		return nil, nil, errors.New("private runtime TLS anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: caller.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, errors.New("private runtime TLS agent unavailable")
	}
	config, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientIssuerRoots, ServerRoots: serverRoots, ServerName: provider.TLS.DNSNames[0],
		Identity: remotetls.Identity{URI: caller.TLS.URI, DNSNames: caller.TLS.DNSNames,
			Usages: caller.TLS.Usages, MaxTTL: time.Duration(caller.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: provider.TLS.URI, DNSNames: provider.TLS.DNSNames,
			Usages: provider.TLS.Usages, MaxTTL: time.Duration(provider.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, caller.PrincipalDigest, "outbound", agentClient,
		authority.OperationTimeout, time.Now)
	if err != nil || config.VerifyConnection == nil {
		return nil, nil, errors.New("private runtime peer revocation boundary is unavailable")
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
		return nil, nil, errors.New("private runtime origin is invalid")
	}
	transport := guardedClientTransport(config, identityCheck, guard, origin.Host)
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

func guardedClientTransport(config *tls.Config, identityCheck func(tls.ConnectionState) error,
	guard *PeerCRLGuard, expectedAddress string) *http.Transport {
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	// WebSocket clients can follow an HTTP redirect before the upgrade. A
	// plaintext redirect must never fall through to net/http's default dialer.
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, ErrPeerCRLUnavailable
	}
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
