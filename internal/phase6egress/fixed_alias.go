// Package phase6egress binds an external database or capacity client to one
// profile-selected alias-only broker tunnel. It never resolves or dials the
// external address itself.
package phase6egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/egressbroker"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
)

var ErrUnavailable = errors.New("Phase 6 egress authority unavailable")

type broker interface {
	Dial(context.Context, string, time.Duration) (net.Conn, error)
}

type tracker interface {
	Track(net.Conn, tls.ConnectionState) error
	Forget(net.Conn)
}

// FixedAlias is one immutable target binding. A PostgreSQL client uses
// TunnelDialContext with its own verified TLS negotiation; a Redis client
// uses TLSDialContext because go-redis custom dialers bypass TLSConfig.
type FixedAlias struct {
	broker    broker
	tracker   tracker
	principal string
	alias     string
	address   string
	protocol  string
	uri       string
	lease     time.Duration
	remote    *tls.Config
}

func NewFixedAlias(profile phase6security.Profile, principal, alias string, client *egressbroker.Client,
	guard *phase6tls.PeerCRLGuard, certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error),
	lease time.Duration) (*FixedAlias, error) {
	if client == nil || guard == nil || certificate == nil || profile.Validate() != nil {
		return nil, ErrUnavailable
	}
	target, _, _, err := selectTarget(profile, principal, alias)
	if err != nil {
		return nil, ErrUnavailable
	}
	var edgeID string
	switch {
	case principal == "gateway-runtime" && alias == "capacity":
		edgeID = "gateway-capacity-valkey"
	case principal == "browser-action-ingress-runtime" && alias == "capacity":
		edgeID = "browser-capacity-valkey"
	case principal == "browser-action-ingress-runtime" && alias == "action-history":
		edgeID = "browser-action-history-postgres"
	case principal == "provider-browser-runtime" && alias == "postgres",
		principal == "provider-desktop-runtime" && alias == "postgres":
		binding, _, _, _, authorityErr := profile.ProviderDatabaseAuthority(principal)
		if authorityErr != nil {
			return nil, ErrUnavailable
		}
		edgeID = binding.TrustEdgeID
	default:
		return nil, ErrUnavailable
	}
	anchor, clientAnchor, err := profile.EdgeTrustAnchors(edgeID)
	if err != nil || anchor.ID != "external-server-ca" || clientAnchor.ID != "" {
		return nil, ErrUnavailable
	}
	bundle, err := trustanchor.Load(anchor, time.Now().UTC())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(bundle)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return nil, ErrUnavailable
	}
	remote := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: roots, ServerName: target.Host, GetClientCertificate: certificate}
	return newFixedAlias(profile, principal, alias, client, guard, remote, lease)
}

func newFixedAlias(profile phase6security.Profile, principal, alias string, client broker,
	guard tracker, remote *tls.Config, lease time.Duration) (*FixedAlias, error) {
	if profile.Validate() != nil || client == nil || guard == nil || remote == nil {
		return nil, ErrUnavailable
	}
	target, service, maximumLease, err := selectTarget(profile, principal, alias)
	if err != nil || lease < time.Second || lease > maximumLease ||
		remote.MinVersion != tls.VersionTLS13 || remote.MaxVersion != tls.VersionTLS13 ||
		remote.InsecureSkipVerify || remote.RootCAs == nil || remote.ServerName != target.Host ||
		(len(remote.Certificates) == 0 && remote.GetClientCertificate == nil) {
		return nil, ErrUnavailable
	}
	return &FixedAlias{broker: client, tracker: guard, principal: principal, alias: alias,
		address: net.JoinHostPort(target.Host, fmt.Sprint(target.Port)), protocol: target.Protocol, uri: service.URI,
		lease: lease, remote: remote.Clone()}, nil
}

func selectTarget(profile phase6security.Profile, principal, alias string) (phase6security.EgressTarget, phase6security.ExternalService, time.Duration, error) {
	if principal != "gateway-runtime" && principal != "browser-action-ingress-runtime" &&
		principal != "provider-browser-runtime" && principal != "provider-desktop-runtime" {
		return phase6security.EgressTarget{}, phase6security.ExternalService{}, 0, ErrUnavailable
	}
	var policy phase6security.EgressPolicy
	for _, candidate := range profile.EgressPolicies {
		if candidate.Principal == principal {
			policy = candidate
		}
	}
	if policy.ID == "" {
		return phase6security.EgressTarget{}, phase6security.ExternalService{}, 0, ErrUnavailable
	}
	var target phase6security.EgressTarget
	for _, candidate := range policy.Targets {
		if candidate.Alias == alias {
			target = candidate
		}
	}
	var serviceName string
	switch {
	case principal == "gateway-runtime" && alias == "capacity", principal == "browser-action-ingress-runtime" && alias == "capacity":
		serviceName = "capacity-valkey"
	case principal == "browser-action-ingress-runtime" && alias == "action-history":
		serviceName = "action-history-postgres"
	case principal == "provider-browser-runtime" && alias == "postgres",
		principal == "provider-desktop-runtime" && alias == "postgres":
		binding, _, _, _, authorityErr := profile.ProviderDatabaseAuthority(principal)
		if authorityErr != nil || binding.EgressPolicyID != policy.ID || binding.BrokerDeployment != policy.Broker {
			return phase6security.EgressTarget{}, phase6security.ExternalService{}, 0, ErrUnavailable
		}
		serviceName = binding.ServiceName
	default:
		return phase6security.EgressTarget{}, phase6security.ExternalService{}, 0, ErrUnavailable
	}
	var service phase6security.ExternalService
	for _, candidate := range profile.External {
		if candidate.Name == serviceName {
			service = candidate
		}
	}
	protocol := "tls"
	if serviceName == "action-history-postgres" || serviceName == "postgres" {
		protocol = "postgres"
	}
	if len(service.DNSNames) != 1 || target.Host != service.DNSNames[0] || target.Protocol != protocol ||
		target.Port < 1 || target.Port > 65535 || policy.LeaseSeconds < 1 {
		return phase6security.EgressTarget{}, phase6security.ExternalService{}, 0, ErrUnavailable
	}
	return target, service, time.Duration(policy.LeaseSeconds) * time.Second, nil
}

// TunnelDialContext is a strict pgx DialFunc. The caller must set its pgx
// TLSConfig to ExternalTLSConfig and disable every fallback, Unix and
// alternate-host path. The broker connection remains tracked until close.
func (d *FixedAlias) TunnelDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.protocol != "postgres" {
		return nil, ErrUnavailable
	}
	return d.dialTunnel(ctx, network, address)
}

func (d *FixedAlias) dialTunnel(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || ctx == nil || network != "tcp" || address != d.address {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := d.broker.Dial(ctx, d.alias, d.lease)
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, ErrUnavailable
	}
	if connection == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	peer, ok := connection.(*tls.Conn)
	if !ok || d.tracker.Track(connection, peer.ConnectionState()) != nil {
		_ = connection.Close()
		return nil, ErrUnavailable
	}
	return &trackedTunnel{Conn: connection, tracker: d.tracker}, nil
}

// TLSDialContext supplies both the broker and external TLS layers for Redis.
func (d *FixedAlias) TLSDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.protocol != "tls" || d.remote == nil {
		return nil, ErrUnavailable
	}
	tunnel, err := d.dialTunnel(ctx, network, address)
	if err != nil {
		return nil, err
	}
	remote := tls.Client(tunnel, d.remote.Clone())
	if err := remote.HandshakeContext(ctx); err != nil ||
		egressbroker.ValidateTLSIdentity(remote.ConnectionState(), d.uri, []string{d.remote.ServerName}, []string{"server_auth"}) != nil {
		_ = remote.Close()
		return nil, ErrUnavailable
	}
	return remote, nil
}

func (d *FixedAlias) ExternalTLSConfig() *tls.Config {
	if d == nil {
		return nil
	}
	config := d.remote.Clone()
	identityCheck := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if identityCheck != nil {
			if err := identityCheck(state); err != nil {
				return err
			}
		}
		return d.verifyExternalPeerDuringHandshake(state)
	}
	return config
}

func (d *FixedAlias) verifyExternalPeerDuringHandshake(state tls.ConnectionState) error {
	if d == nil || d.remote == nil || state.Version != tls.VersionTLS13 ||
		len(state.VerifiedChains) != 1 || len(state.VerifiedChains[0]) < 2 ||
		len(state.PeerCertificates) < 1 {
		return ErrUnavailable
	}
	leaf := state.PeerCertificates[0]
	if leaf.Subject.String() != "" || len(leaf.URIs) != 1 || leaf.URIs[0].String() != d.uri ||
		!slices.Equal(leaf.DNSNames, []string{d.remote.ServerName}) ||
		len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		!slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
		leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrUnavailable
	}
	return nil
}

type trackedTunnel struct {
	net.Conn
	tracker tracker
	once    sync.Once
}

func (c *trackedTunnel) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.tracker.Forget(c.Conn) })
	return err
}
