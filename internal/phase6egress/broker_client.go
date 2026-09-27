package phase6egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egressbroker"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type BrokerClientAuthority struct {
	PolicyID         string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// NewBrokerClient derives the only broker dial address from the reviewed
// role→broker TrustEdge. It cannot accept a second numeric endpoint, system
// root store, static TLS key or untracked wildcard listener as authority.
// The caller must bootstrap/start polling the returned guard for readiness.
func NewBrokerClient(profile phase6security.Profile, authority BrokerClientAuthority) (*egressbroker.Client, *phase6tls.PeerCRLGuard, error) {
	edge, caller, broker, _, err := profile.BrokerBoundaryForPolicy(authority.PolicyID)
	if err != nil || caller.TLS == nil || broker.TLS == nil ||
		uint32(os.Getuid()) != caller.UID || uint32(os.Getgid()) != caller.GID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second {
		return nil, nil, ErrUnavailable
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	for _, group := range groups {
		if uint32(group) != caller.GID {
			return nil, nil, ErrUnavailable
		}
	}
	binding, agent, subject, err := profile.TLSAgentForSubject(caller.Name)
	if err != nil || subject.PrincipalDigest != caller.PrincipalDigest ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != agent.UID ||
		authority.AgentGID != agent.GID {
		return nil, nil, ErrUnavailable
	}
	serverAnchor, clientAnchor, err := profile.EdgeTrustAnchors(edge.ID)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	serverPEM, err := trustanchor.Load(serverAnchor, time.Now().UTC())
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer clear(serverPEM)
	clientPEM, err := trustanchor.Load(clientAnchor, time.Now().UTC())
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer clear(clientPEM)
	serverRoots, clientRoots := x509.NewCertPool(), x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(serverPEM) || !clientRoots.AppendCertsFromPEM(clientPEM) {
		return nil, nil, ErrUnavailable
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: caller.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	tlsConfig, err := remotetls.NewClient(remotetls.ClientOptions{
		IssuerRoots: clientRoots, ServerRoots: serverRoots, ServerName: broker.TLS.DNSNames[0],
		Identity: remotetls.Identity{URI: caller.TLS.URI, DNSNames: caller.TLS.DNSNames,
			Usages: caller.TLS.Usages, MaxTTL: time.Duration(caller.TLS.TTLSeconds) * time.Second},
		Server: remotetls.Identity{URI: broker.TLS.URI, DNSNames: broker.TLS.DNSNames,
			Usages: broker.TLS.Usages, MaxTTL: time.Duration(broker.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now})
	if err != nil || tlsConfig.VerifyConnection == nil {
		return nil, nil, ErrUnavailable
	}
	guard, err := phase6tls.NewPeerCRLGuard(profile, authority.PeerCRLRole, edge.ID, caller.PrincipalDigest,
		"outbound", agentClient, authority.OperationTimeout, time.Now)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	verifyIdentity := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verifyIdentity(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	tlsConfig.NextProtos = []string{egressbroker.ProtocolID}
	var selected phase6security.EgressPolicy
	for _, policy := range profile.EgressPolicies {
		if policy.ID == authority.PolicyID {
			selected = policy
		}
	}
	registry, err := profile.PrincipalRegistry()
	if err != nil || caller.AuthorizationPrincipal == nil || broker.AuthorizationPrincipal == nil {
		return nil, nil, ErrUnavailable
	}
	targets := make([]egressbroker.Target, len(selected.Targets))
	for index, target := range selected.Targets {
		targets[index] = egressbroker.Target{Alias: target.Alias, Host: target.Host, Port: target.Port, Protocol: target.Protocol}
	}
	policy, err := egressbroker.NewPolicy(selected.ID, selected.Revision, registry, *caller.AuthorizationPrincipal,
		*broker.AuthorizationPrincipal, time.Duration(selected.LeaseSeconds)*time.Second, selected.DNSMaxAnswers, targets)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	client, err := egressbroker.NewProductionClient(egressbroker.ClientConfig{
		Address: edge.TargetAddress, TLSConfig: tlsConfig, Policy: policy,
		BrokerURI: broker.TLS.URI, BrokerDNSNames: broker.TLS.DNSNames, BrokerUsages: broker.TLS.Usages,
		OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	return client, guard, nil
}
