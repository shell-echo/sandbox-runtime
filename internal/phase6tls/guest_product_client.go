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

type GuestProductClientAuthority struct {
	Origin           string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// GuestProductClient binds the outbound Guest agent to Product's private
// control listener, not Product's public API or any Provider endpoint.
func GuestProductClient(profile phase6security.Profile, authority GuestProductClientAuthority) (
	*http.Transport, *PeerCRLGuard, error) {
	edge, guest, product, serverAnchor, clientAnchor, err := profile.GuestProductBoundary(authority.Origin)
	if err != nil || uint32(os.Getuid()) != guest.UID || uint32(os.Getgid()) != guest.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second ||
		edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 3600 {
		return nil, nil, errors.New("Guest Product TLS authority does not match profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject(guest.Name)
	if err != nil || subject.PrincipalDigest != guest.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, errors.New("Guest signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, errors.New("Guest supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != guest.GID {
			return nil, nil, errors.New("Guest has supplementary group authority")
		}
	}
	clientIssuerPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("Guest own-client issuer unavailable")
	}
	defer clear(clientIssuerPEM)
	serverRootPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("Guest Product server root unavailable")
	}
	defer clear(serverRootPEM)
	clientIssuerRoots, serverRoots := x509.NewCertPool(), x509.NewCertPool()
	if !clientIssuerRoots.AppendCertsFromPEM(clientIssuerPEM) || !serverRoots.AppendCertsFromPEM(serverRootPEM) {
		return nil, nil, errors.New("Guest Product trust anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: guest.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, errors.New("Guest TLS agent unavailable")
	}
	transportTLS, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientIssuerRoots, ServerRoots: serverRoots, ServerName: product.TLS.DNSNames[0],
		Identity: remotetls.Identity{URI: guest.TLS.URI, DNSNames: guest.TLS.DNSNames,
			Usages: guest.TLS.Usages, MaxTTL: time.Duration(guest.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: product.TLS.URI, DNSNames: product.TLS.DNSNames,
			Usages: product.TLS.Usages, MaxTTL: time.Duration(product.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, guest.PrincipalDigest, "outbound",
		agentClient, authority.OperationTimeout, time.Now)
	if err != nil || transportTLS.VerifyConnection == nil {
		return nil, nil, errors.New("Guest Product peer revocation boundary unavailable")
	}
	identityCheck := transportTLS.VerifyConnection
	transportTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if err := identityCheck(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	origin, err := url.Parse(authority.Origin)
	if err != nil || origin.Scheme != "wss" || origin.Host == "" {
		return nil, nil, errors.New("Guest Product origin invalid")
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
