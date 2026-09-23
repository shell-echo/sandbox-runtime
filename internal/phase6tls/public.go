// Package phase6tls composes profile-bound workload TLS without giving a
// runtime role access to its agent's private signing key.
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

type PublicServerAuthority struct {
	ListenerID       string
	Port             int
	AgentSocket      string
	AgentUID         uint32
	AgentGID         uint32
	OperationTimeout time.Duration
}

// PublicServer only constructs the Product/Gateway server-auth-only listener
// declared by the canonical profile. It does not weaken any private listener.
func PublicServer(profile phase6security.Profile, authority PublicServerAuthority) (*tls.Config, func(context.Context) error, error) {
	binding, agent, subject, anchor, err := profile.PublicTLSBoundary(authority.ListenerID, authority.Port)
	if err != nil || subject.TLS == nil || uint32(os.Getuid()) != subject.UID || uint32(os.Getgid()) != subject.GID ||
		authority.AgentSocket != binding.SocketPath || authority.AgentUID != binding.AgentUID ||
		authority.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID ||
		authority.OperationTimeout < time.Second || authority.OperationTimeout > 30*time.Second {
		return nil, nil, errors.New("public TLS listener does not match security profile")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return nil, nil, errors.New("public TLS supplementary groups unavailable")
	}
	for _, group := range groups {
		if uint32(group) != subject.GID {
			return nil, nil, errors.New("public TLS role has supplementary group authority")
		}
	}
	issuerPEM, err := trustanchor.Load(anchor, time.Now())
	if err != nil {
		return nil, nil, errors.New("public TLS issuer anchor unavailable")
	}
	defer clear(issuerPEM)
	issuerRoots := x509.NewCertPool()
	if !issuerRoots.AppendCertsFromPEM(issuerPEM) {
		return nil, nil, errors.New("public TLS issuer anchor invalid")
	}
	agentClient, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: authority.AgentSocket, ExpectedUID: authority.AgentUID, ExpectedGID: authority.AgentGID,
		RoleGID: subject.GID, OperationTimeout: authority.OperationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, errors.New("public TLS agent unavailable")
	}
	return remotetls.NewServerWithProbe(remotetls.ServerOptions{IssuerRoots: issuerRoots,
		Identity: remotetls.Identity{URI: subject.TLS.URI, DNSNames: subject.TLS.DNSNames,
			Usages: subject.TLS.Usages, MaxTTL: time.Duration(subject.TLS.TTLSeconds) * time.Second},
		Source: agentClient.CertificateForHandshake, Now: time.Now})
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
