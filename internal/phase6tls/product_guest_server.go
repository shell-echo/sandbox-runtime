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

type ProductGuestServerAuthority struct {
	ListenAddress    string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// ProductGuestServer is only the Product-owned private Guest /agent edge. It
// does not change the public Product TLS listener or admit a Provider peer.
func ProductGuestServer(profile phase6security.Profile, authority ProductGuestServerAuthority) (
	*tls.Config, func(context.Context) error, *PeerCRLGuard, time.Duration, error) {
	edge, guest, product, serverAnchor, clientAnchor, err := profile.GuestProductBoundary(
		"wss://" + authority.ListenAddress + "/agent")
	if err != nil || edge.TargetAddress != authority.ListenAddress ||
		uint32(os.Getuid()) != product.UID || uint32(os.Getgid()) != product.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second ||
		edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 3600 {
		return nil, nil, nil, 0, errors.New("Product Guest listener does not match security profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject(product.Name)
	if err != nil || subject.PrincipalDigest != product.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, nil, 0, errors.New("Product Guest signer does not match security profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, nil, 0, errors.New("Product supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != product.GID {
			return nil, nil, nil, 0, errors.New("Product has supplementary group authority")
		}
	}
	serverPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, nil, 0, errors.New("Product Guest server issuer unavailable")
	}
	defer clear(serverPEM)
	clientPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, nil, 0, errors.New("Product Guest client root unavailable")
	}
	defer clear(clientPEM)
	issuerRoots, clientRoots := x509.NewCertPool(), x509.NewCertPool()
	if !issuerRoots.AppendCertsFromPEM(serverPEM) || !clientRoots.AppendCertsFromPEM(clientPEM) {
		return nil, nil, nil, 0, errors.New("Product Guest trust anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: product.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, nil, 0, errors.New("Product Guest TLS agent unavailable")
	}
	transport, signerProbe, err := remotetls.NewServerWithProbe(remotetls.ServerOptions{
		IssuerRoots: issuerRoots, ClientRoots: clientRoots,
		Identity: remotetls.Identity{URI: product.TLS.URI, DNSNames: product.TLS.DNSNames,
			Usages: product.TLS.Usages, MaxTTL: time.Duration(product.TLS.TTLSeconds) * time.Second},
		Client: &remotetls.Identity{URI: guest.TLS.URI, DNSNames: guest.TLS.DNSNames,
			Usages: guest.TLS.Usages, MaxTTL: time.Duration(guest.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, nil, nil, 0, err
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, product.PrincipalDigest,
		"inbound", agentClient, authority.OperationTimeout, time.Now)
	if err != nil || transport.VerifyConnection == nil {
		return nil, nil, nil, 0, errors.New("Product Guest peer revocation unavailable")
	}
	identityCheck := transport.VerifyConnection
	transport.VerifyConnection = func(state tls.ConnectionState) error {
		if err := identityCheck(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	probe := func(ctx context.Context) error {
		if err := signerProbe(ctx); err != nil {
			return err
		}
		if err := guard.Bootstrap(ctx); err != nil || !guard.Ready() {
			return ErrPeerCRLUnavailable
		}
		return nil
	}
	return transport, probe, guard, time.Duration(edge.MaxConnectionSeconds) * time.Second, nil
}
