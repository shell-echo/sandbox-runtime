package executorbackend

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

type ProductionTLSAuthority struct {
	DeploymentName   string
	ListenAddress    string
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// ProductionServerTLS resolves signer and client admission from one verified
// Phase 6 profile. Neither backend command is allowed to hold a local key.
func ProductionServerTLS(profile phase6security.Profile, authority ProductionTLSAuthority) (*tls.Config, error) {
	_, portText, err := net.SplitHostPort(authority.ListenAddress)
	if err != nil {
		return nil, errors.New("executor listener is invalid")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, errors.New("executor listener port is invalid")
	}
	binding, agent, subject, caller, err := profile.ExecutorTLSBoundary(authority.DeploymentName, port)
	if err != nil || subject.TLS == nil || caller.TLS == nil ||
		uint32(os.Getuid()) != subject.UID || uint32(os.Getgid()) != subject.GID ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != agent.UID || authority.AgentGID != agent.GID ||
		authority.AgentUID != binding.AgentUID || authority.AgentGID != binding.AgentGID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > time.Minute {
		return nil, errors.New("executor TLS agent does not match profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, errors.New("executor supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != subject.GID {
			return nil, errors.New("executor has supplementary group authority")
		}
	}
	edgeID := "executor-browser"
	if authority.DeploymentName == "desktop-executor-backend" {
		edgeID = "executor-desktop"
	}
	serverAnchor, clientAnchor, err := profile.EdgeTrustAnchors(edgeID)
	if err != nil {
		return nil, errors.New("executor trust anchors do not match profile")
	}
	serverCA, err := trustanchor.Load(serverAnchor, time.Now())
	if err != nil {
		return nil, errors.New("executor server CA unavailable")
	}
	defer clear(serverCA)
	clientCA, err := trustanchor.Load(clientAnchor, time.Now())
	if err != nil {
		return nil, errors.New("executor client CA unavailable")
	}
	defer clear(clientCA)
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: subject.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, errors.New("executor TLS agent unavailable")
	}
	return providerapi.LoadMTLSConfigRemote(serverCA, clientCA,
		providerapi.RemoteClientIdentity{URI: caller.TLS.URI, DNSNames: caller.TLS.DNSNames},
		providerapi.RemoteServerIdentity{URI: subject.TLS.URI,
			DNSNames: subject.TLS.DNSNames, MaxTTL: time.Duration(subject.TLS.TTLSeconds) * time.Second},
		agentClient.CertificateForHandshake, time.Now)
}
