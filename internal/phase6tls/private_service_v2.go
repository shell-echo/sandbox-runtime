package phase6tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

var ErrPrivateServiceV2 = errors.New("Profile-v2 private service TLS unavailable")

type PrivateServiceAuthorityV2 struct {
	Scope                           string
	Address                         string
	PeerCRLRole                     phase6security.PeerCRLRoleDocument
	SourceMappingDigest, RoleDigest string
	AgentSocket                     string
	AgentUID, AgentGID              uint32
	OperationTimeout                time.Duration
}

// PrivateServiceServerV2 always admits the full v2 profile and exact inbound
// role document before touching a signer or anchor. The public v2 hold stays.
func PrivateServiceServerV2(p phase6security.ProfileV2, a PrivateServiceAuthorityV2) (*tls.Config, func(context.Context) error, *PeerCRLGuard, error) {
	b, err := p.PrivateServiceBoundary(a.Scope, a.Address)
	if err != nil {
		return nil, nil, nil, ErrPrivateServiceV2
	}
	return privateServiceServerV2(p, a, b)
}

func privateServiceServerV2(p phase6security.ProfileV2, a PrivateServiceAuthorityV2, b phase6security.PrivateServiceBoundaryV2) (*tls.Config, func(context.Context) error, *PeerCRLGuard, error) {
	client, err := privateServiceSignerV2(p, a, b.Service, true)
	if err != nil {
		return nil, nil, nil, err
	}
	issuerRoots, peerRoots, err := privateServiceRoots(b.ServerAnchor, b.ClientAnchor)
	if err != nil {
		return nil, nil, nil, err
	}
	guard, err := NewPeerCRLGuardV2(p, a.PeerCRLRole, a.SourceMappingDigest, a.RoleDigest, b.Edge.ID, b.Service.PrincipalDigest, "inbound", client, a.OperationTimeout, time.Now)
	if err != nil {
		return nil, nil, nil, ErrPrivateServiceV2
	}
	return privateServiceServerTransport(b, client, issuerRoots, peerRoots, guard, nil)
}

// Private post-admission assembly; this is not a profile admission API.
func privateServiceServerTransport(b phase6security.PrivateServiceBoundaryV2, client *workloadtlsagent.Client, issuerRoots, peerRoots *x509.CertPool, guard *PeerCRLGuard, trustCheck func(context.Context) error) (*tls.Config, func(context.Context) error, *PeerCRLGuard, error) {
	if client == nil || guard == nil || b.Service.TLS == nil || b.Provider.TLS == nil {
		return nil, nil, nil, ErrPrivateServiceV2
	}
	source := client.CertificateForHandshake
	if trustCheck != nil {
		source = func(ctx context.Context) (tls.Certificate, error) {
			if err := trustCheck(ctx); err != nil {
				return tls.Certificate{}, err
			}
			return client.CertificateForHandshake(ctx)
		}
	}
	transport, probe, err := remotetls.NewServerWithProbe(remotetls.ServerOptions{IssuerRoots: issuerRoots, ClientRoots: peerRoots, Identity: privateServiceIdentity(b.Service), Client: privateServiceIdentityPointer(b.Provider), Source: source, Now: time.Now})
	if err != nil || transport.VerifyConnection == nil {
		return nil, nil, nil, ErrPrivateServiceV2
	}
	identity := transport.VerifyConnection
	transport.VerifyConnection = func(state tls.ConnectionState) error {
		if trustCheck != nil {
			if err := trustCheck(context.Background()); err != nil {
				return err
			}
		}
		if err := identity(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	ready := func(ctx context.Context) error {
		if err := probe(ctx); err != nil {
			return err
		}
		if err := guard.Bootstrap(ctx); err != nil || !guard.Ready() {
			return ErrPeerCRLUnavailable
		}
		return nil
	}
	return transport, ready, guard, nil
}

// PrivateServiceClientV2 returns the actual CRL-tracked, address-confined
// transport; consumers must not rebuild a dialer from its TLS configuration.
func PrivateServiceClientV2(p phase6security.ProfileV2, a PrivateServiceAuthorityV2) (*http.Transport, *PeerCRLGuard, error) {
	b, err := p.PrivateServiceBoundary(a.Scope, a.Address)
	if err != nil {
		return nil, nil, ErrPrivateServiceV2
	}
	client, err := privateServiceSignerV2(p, a, b.Provider, false)
	if err != nil {
		return nil, nil, err
	}
	issuerRoots, peerRoots, err := privateServiceRoots(b.ClientAnchor, b.ServerAnchor)
	if err != nil || b.Service.TLS == nil || len(b.Service.TLS.DNSNames) != 1 {
		return nil, nil, ErrPrivateServiceV2
	}
	guard, err := NewPeerCRLGuardV2(p, a.PeerCRLRole, a.SourceMappingDigest, a.RoleDigest, b.Edge.ID, b.Provider.PrincipalDigest, "outbound", client, a.OperationTimeout, time.Now)
	if err != nil {
		return nil, nil, ErrPrivateServiceV2
	}
	return privateServiceClientTransport(b, client, issuerRoots, peerRoots, guard, nil)
}

func privateServiceClientTransport(b phase6security.PrivateServiceBoundaryV2, client *workloadtlsagent.Client, issuerRoots, peerRoots *x509.CertPool, guard *PeerCRLGuard, trustCheck func(context.Context) error) (*http.Transport, *PeerCRLGuard, error) {
	if client == nil || guard == nil || b.Service.TLS == nil || b.Provider.TLS == nil || len(b.Service.TLS.DNSNames) != 1 {
		return nil, nil, ErrPrivateServiceV2
	}
	source := client.CertificateForHandshake
	if trustCheck != nil {
		source = func(ctx context.Context) (tls.Certificate, error) {
			if err := trustCheck(ctx); err != nil {
				return tls.Certificate{}, err
			}
			return client.CertificateForHandshake(ctx)
		}
	}
	transportTLS, err := remotetls.NewClient(remotetls.ClientOptions{IssuerRoots: issuerRoots, ServerRoots: peerRoots, ServerName: b.Service.TLS.DNSNames[0], Identity: privateServiceIdentity(b.Provider), Server: privateServiceIdentity(b.Service), Source: source, Now: time.Now})
	if err != nil || transportTLS.VerifyConnection == nil {
		return nil, nil, ErrPrivateServiceV2
	}
	baseIdentity := transportTLS.VerifyConnection
	identity := func(state tls.ConnectionState) error {
		if trustCheck != nil {
			if err := trustCheck(context.Background()); err != nil {
				return err
			}
		}
		return baseIdentity(state)
	}
	transportTLS.VerifyConnection = func(state tls.ConnectionState) error {
		if err := identity(state); err != nil {
			return err
		}
		return guard.CheckHandshake(context.Background(), state)
	}
	transport := guardedClientTransport(transportTLS, identity, guard, b.Edge.TargetAddress)
	dial := transport.DialTLSContext
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return newBoundedClientConn(c, time.Duration(b.Edge.MaxConnectionSeconds)*time.Second), nil
	}
	return transport, guard, nil
}

func privateServiceSignerV2(p phase6security.ProfileV2, a PrivateServiceAuthorityV2, local phase6security.Principal, server bool) (*workloadtlsagent.Client, error) {
	if a.OperationTimeout < time.Second || a.OperationTimeout > 30*time.Second || local.TLS == nil ||
		a.PeerCRLRole.Digest() != a.RoleDigest || a.PeerCRLRole.ValidateV2(p, a.SourceMappingDigest, local.PrincipalDigest) != nil {
		return nil, ErrPrivateServiceV2
	}
	binding, agent, subject, err := p.TLSAgentForSubject(local.Name)
	if err != nil || subject.PrincipalDigest != local.PrincipalDigest || a.AgentSocket != binding.SocketPath || a.AgentUID != binding.AgentUID || a.AgentGID != binding.AgentGID || agent.UID != binding.AgentUID || agent.GID != binding.AgentGID {
		return nil, ErrPrivateServiceV2
	}
	groups, err := os.Getgroups()
	var extra []uint32
	if server && local.Name == p.DockerControl.Deployment {
		extra = p.DockerControl.SupplementaryGIDs
	}
	if err != nil || !privateServiceProcessMatches(local.UID, local.GID, extra, os.Getuid(), os.Getgid(), groups) {
		return nil, ErrPrivateServiceV2
	}
	return workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{SocketPath: a.AgentSocket, ExpectedUID: a.AgentUID, ExpectedGID: a.AgentGID, RoleGID: local.GID, OperationTimeout: a.OperationTimeout, Now: time.Now})
}

func privateServiceProcessMatches(uid, gid uint32, extra []uint32, actualUID, actualGID int, groups []int) bool {
	if uid == 0 || gid == 0 || actualUID < 0 || actualGID < 0 || uint32(actualUID) != uid || uint32(actualGID) != gid {
		return false
	}
	if len(extra) > 1 || (len(extra) == 1 && extra[0] != 0) {
		return false
	}
	seenExtra := false
	for _, group := range groups {
		if group < 0 {
			return false
		}
		if uint32(group) == gid {
			continue
		}
		if len(extra) != 1 || uint32(group) != extra[0] {
			return false
		}
		seenExtra = true
	}
	return len(extra) == 0 || seenExtra
}

func privateServiceRoots(own, peer phase6security.TrustAnchor) (*x509.CertPool, *x509.CertPool, error) {
	ownPEM, err := trustanchor.Load(own, time.Now())
	if err != nil {
		return nil, nil, ErrPrivateServiceV2
	}
	defer clear(ownPEM)
	peerPEM, err := trustanchor.Load(peer, time.Now())
	if err != nil {
		return nil, nil, ErrPrivateServiceV2
	}
	defer clear(peerPEM)
	ownPool, peerPool := x509.NewCertPool(), x509.NewCertPool()
	if !ownPool.AppendCertsFromPEM(ownPEM) || !peerPool.AppendCertsFromPEM(peerPEM) {
		return nil, nil, ErrPrivateServiceV2
	}
	return ownPool, peerPool, nil
}
func privateServiceIdentity(p phase6security.Principal) remotetls.Identity {
	return remotetls.Identity{URI: p.TLS.URI, DNSNames: p.TLS.DNSNames, Usages: p.TLS.Usages, MaxTTL: time.Duration(p.TLS.TTLSeconds) * time.Second}
}
func privateServiceIdentityPointer(p phase6security.Principal) *remotetls.Identity {
	v := privateServiceIdentity(p)
	return &v
}
