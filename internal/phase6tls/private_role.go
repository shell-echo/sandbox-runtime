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

type PrivateRoleServerAuthority struct {
	Role             string
	ListenAddress    string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// PrivateRoleServer binds one Browser/Desktop private listener to its own
// Provider instance, remote signer and inbound CRL source. It cannot be used
// for the separate role-to-backend edge or a coding-shell Provider alias.
func PrivateRoleServer(profile phase6security.Profile, authority PrivateRoleServerAuthority) (
	*tls.Config, func(context.Context) error, *PeerCRLGuard, time.Duration, error) {
	edge, provider, role, serverAnchor, clientAnchor, err := profile.PrivateRoleAttachBoundary(authority.Role, authority.ListenAddress)
	if err != nil || uint32(os.Getuid()) != role.UID || uint32(os.Getgid()) != role.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second ||
		edge.MaxConnectionSeconds < 1 || edge.MaxConnectionSeconds > 3600 {
		return nil, nil, nil, 0, errors.New("private role listener does not match security profile")
	}
	binding, agent, subject, err := profile.TLSAgentForSubject(role.Name)
	if err != nil || subject.PrincipalDigest != role.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, nil, nil, 0, errors.New("private role signer does not match security profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, nil, 0, errors.New("private role supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != role.GID {
			return nil, nil, nil, 0, errors.New("private role has supplementary group authority")
		}
	}
	issuerPEM, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, nil, nil, 0, errors.New("private role own-server issuer anchor unavailable")
	}
	defer clear(issuerPEM)
	clientPEM, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, nil, nil, 0, errors.New("private role client root unavailable")
	}
	defer clear(clientPEM)
	issuerRoots, clientRoots := x509.NewCertPool(), x509.NewCertPool()
	if !issuerRoots.AppendCertsFromPEM(issuerPEM) || !clientRoots.AppendCertsFromPEM(clientPEM) {
		return nil, nil, nil, 0, errors.New("private role trust anchors are invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: role.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, nil, 0, errors.New("private role TLS agent unavailable")
	}
	transport, probe, err := remotetls.NewServerWithProbe(remotetls.ServerOptions{
		IssuerRoots: issuerRoots, ClientRoots: clientRoots,
		Identity: remotetls.Identity{URI: role.TLS.URI, DNSNames: role.TLS.DNSNames,
			Usages: role.TLS.Usages, MaxTTL: time.Duration(role.TLS.TTLSeconds) * time.Second},
		Client: &remotetls.Identity{URI: provider.TLS.URI, DNSNames: provider.TLS.DNSNames,
			Usages: provider.TLS.Usages, MaxTTL: time.Duration(provider.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now,
	})
	if err != nil {
		return nil, nil, nil, 0, err
	}
	guard, err := NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, role.PrincipalDigest, "inbound",
		agentClient, authority.OperationTimeout, time.Now)
	if err != nil || transport.VerifyConnection == nil {
		return nil, nil, nil, 0, errors.New("private role peer revocation boundary is unavailable")
	}
	identityCheck := transport.VerifyConnection
	transport.VerifyConnection = func(state tls.ConnectionState) error {
		if err := identityCheck(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	readyProbe := func(ctx context.Context) error {
		if err := probe(ctx); err != nil {
			return err
		}
		if err := guard.Bootstrap(ctx); err != nil || !guard.Ready() {
			return ErrPeerCRLUnavailable
		}
		return nil
	}
	return transport, readyProbe, guard, time.Duration(edge.MaxConnectionSeconds) * time.Second, nil
}
