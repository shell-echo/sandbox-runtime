package executorbackend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

type ProductionTLSAuthority struct {
	DeploymentName   string
	ListenAddress    string
	PeerCRLRole      phase6security.PeerCRLRoleDocument
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

type ProductionTLSEndpoint struct {
	Config           *tls.Config
	Guard            *phase6tls.PeerCRLGuard
	SignerProbe      func(context.Context) error
	ConnectionMaxAge time.Duration
}

// ProductionServerTLS resolves signer and client admission from one verified
// Phase 6 profile. Neither backend command is allowed to hold a local key.
func ProductionServerTLS(profile phase6security.Profile, authority ProductionTLSAuthority) (ProductionTLSEndpoint, error) {
	_, portText, err := net.SplitHostPort(authority.ListenAddress)
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor listener is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor listener port is invalid")
	}
	binding, agent, subject, caller, err := profile.ExecutorTLSBoundary(authority.DeploymentName, port)
	if err != nil || subject.TLS == nil || caller.TLS == nil ||
		uint32(os.Getuid()) != subject.UID || uint32(os.Getgid()) != subject.GID ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != agent.UID || authority.AgentGID != agent.GID ||
		authority.AgentUID != binding.AgentUID || authority.AgentGID != binding.AgentGID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second {
		return ProductionTLSEndpoint{}, errors.New("executor TLS agent does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != subject.GID {
			return ProductionTLSEndpoint{}, errors.New("executor has supplementary group authority")
		}
	}
	edgeID := "executor-browser"
	if authority.DeploymentName == "desktop-executor-backend" {
		edgeID = "executor-desktop"
	}
	serverAnchor, clientAnchor, err := profile.EdgeTrustAnchors(edgeID)
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor trust anchors do not match profile")
	}
	serverCA, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor server CA unavailable")
	}
	defer clear(serverCA)
	clientCA, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor client CA unavailable")
	}
	defer clear(clientCA)
	serverRoots := x509.NewCertPool()
	clientRoots := x509.NewCertPool()
	if !serverRoots.AppendCertsFromPEM(serverCA) || !clientRoots.AppendCertsFromPEM(clientCA) {
		return ProductionTLSEndpoint{}, errors.New("executor trust anchor parse failed")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: subject.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor TLS agent unavailable")
	}
	clientIdentity := remotetls.Identity{URI: caller.TLS.URI, DNSNames: caller.TLS.DNSNames,
		Usages: caller.TLS.Usages, MaxTTL: time.Duration(caller.TLS.TTLSeconds) * time.Second}
	config, probe, err := remotetls.NewServerWithProbe(remotetls.ServerOptions{IssuerRoots: serverRoots, ClientRoots: clientRoots,
		Identity: remotetls.Identity{URI: subject.TLS.URI, DNSNames: subject.TLS.DNSNames,
			Usages: subject.TLS.Usages, MaxTTL: time.Duration(subject.TLS.TTLSeconds) * time.Second},
		Client: &clientIdentity, Source: agentClient.CertificateForHandshake, Now: time.Now})
	if err != nil || config.VerifyConnection == nil {
		return ProductionTLSEndpoint{}, errors.New("executor live signer is unavailable")
	}
	guard, err := phase6tls.NewPeerCRLGuard(profile, authority.PeerCRLRole, edgeID,
		subject.PrincipalDigest, "inbound", agentClient, authority.OperationTimeout, time.Now)
	if err != nil {
		return ProductionTLSEndpoint{}, errors.New("executor peer revocation boundary is unavailable")
	}
	identityCheck := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if err := identityCheck(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	connectionMaxAge := time.Duration(0)
	for _, edge := range profile.TrustEdges {
		if edge.ID == edgeID {
			connectionMaxAge = time.Duration(edge.MaxConnectionSeconds) * time.Second
			break
		}
	}
	if connectionMaxAge < time.Second || connectionMaxAge > time.Hour {
		return ProductionTLSEndpoint{}, errors.New("executor connection age is not profile bounded")
	}
	return ProductionTLSEndpoint{Config: config, Guard: guard, SignerProbe: probe,
		ConnectionMaxAge: connectionMaxAge}, nil
}
