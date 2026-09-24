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

type PrivateRoleBackendClientAuthority struct {
	Role             string
	Origin           string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// PrivateRoleBackendClient permits only the separately pinned role→backend
// edge. The backend never receives Provider keys, database access, or Docker
// authority through this transport.
func PrivateRoleBackendClient(profile phase6security.Profile, authority PrivateRoleBackendClientAuthority) (
	*http.Transport, *PeerCRLGuard, error) {
	edge, role, backend, serverAnchor, clientAnchor, err := profile.PrivateRoleBackendBoundary(authority.Role, authority.Origin)
	if err != nil || uint32(os.Getuid()) != role.UID || uint32(os.Getgid()) != role.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second ||
		edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 3600 {
		return nil, nil, errors.New("private role backend TLS authority does not match profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject(role.Name)
	if err != nil || subject.PrincipalDigest != role.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, errors.New("private role backend signer does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, errors.New("private role backend supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != role.GID {
			return nil, nil, errors.New("private role backend has supplementary group authority")
		}
	}
	clientIssuerPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("private role own-client issuer unavailable")
	}
	defer clear(clientIssuerPEM)
	serverRootPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("private role backend server root unavailable")
	}
	defer clear(serverRootPEM)
	clientIssuerRoots, serverRoots := x509.NewCertPool(), x509.NewCertPool()
	if !clientIssuerRoots.AppendCertsFromPEM(clientIssuerPEM) || !serverRoots.AppendCertsFromPEM(serverRootPEM) {
		return nil, nil, errors.New("private role backend trust anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: role.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, errors.New("private role backend TLS agent unavailable")
	}
	transportTLS, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientIssuerRoots, ServerRoots: serverRoots, ServerName: backend.TLS.DNSNames[0],
		Identity: remotetls.Identity{URI: role.TLS.URI, DNSNames: role.TLS.DNSNames,
			Usages: role.TLS.Usages, MaxTTL: time.Duration(role.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: backend.TLS.URI, DNSNames: backend.TLS.DNSNames,
			Usages: backend.TLS.Usages, MaxTTL: time.Duration(backend.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, nil, err
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, role.PrincipalDigest, "outbound",
		agentClient, authority.OperationTimeout, time.Now)
	if err != nil || transportTLS.VerifyConnection == nil {
		return nil, nil, errors.New("private role backend peer revocation boundary is unavailable")
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
		return nil, nil, errors.New("private role backend origin is invalid")
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
