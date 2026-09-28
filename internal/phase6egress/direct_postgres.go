package phase6egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/egressbroker"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/remotetls"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

// DirectPostgres has no broker or host-routing fallback. It binds the exact
// isolated bridge's local .2 address to the PostgreSQL service's .3 address;
// it cannot be constructed for Browser/Desktop's broker-only pool owners.
type DirectPostgres struct {
	authority phase6security.Slice6PostgresAuthority
	remote    *tls.Config
}

func NewDirectPostgres(ctx context.Context, profile phase6security.Profile, owner string,
	source remotetls.CertificateSource) (*DirectPostgres, error) {
	if ctx == nil || ctx.Err() != nil || source == nil {
		return nil, ErrUnavailable
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority(owner)
	if err != nil || authority.BrokerOnly || authority.Dialer != owner || authority.SourceAddress == "" ||
		authority.ServerAddress == "" || authority.ServerHost == "" || authority.ServerURI == "" {
		return nil, ErrUnavailable
	}
	_, target, _, principal, clientAnchor, err := profile.PostgresClientSignerForOwner(owner)
	if err != nil || principal.TLS == nil || target.DatabaseName != authority.Database ||
		target.SQLRole != authority.SQLRole {
		return nil, ErrUnavailable
	}
	clientPEM, err := trustanchor.Load(clientAnchor, time.Now().UTC())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(clientPEM)
	serverPEM, err := trustanchor.Load(authority.ServerAnchor, time.Now().UTC())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(serverPEM)
	clientRoots, serverRoots := x509.NewCertPool(), x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(clientPEM) || !serverRoots.AppendCertsFromPEM(serverPEM) {
		return nil, ErrUnavailable
	}
	certificate, err := newPostgresClientCertificate(ctx, clientRoots, workloadpki.PostgresClientIdentity{
		OwnerDeployment: owner, DatabaseName: authority.Database, RuntimeRole: authority.SQLRole,
		ServiceName: "postgres", URI: principal.TLS.URI, CommonName: authority.Signer.CommonName,
		MaxTTL: time.Duration(principal.TLS.TTLSeconds) * time.Second,
	}, source, time.Now)
	if err != nil {
		return nil, ErrUnavailable
	}
	remote := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: serverRoots, ServerName: authority.ServerHost, GetClientCertificate: certificate}
	remote.VerifyConnection = func(state tls.ConnectionState) error {
		if egressbroker.ValidateTLSIdentity(state, authority.ServerURI,
			[]string{authority.ServerHost}, []string{"server_auth"}) != nil {
			return ErrUnavailable
		}
		return nil
	}
	return &DirectPostgres{authority: authority, remote: remote}, nil
}

// Bind requires an already parsed exact DSN, then installs the fixed network
// dial and the CRL hook before pgx may open a single PostgreSQL connection.
func (d *DirectPostgres) Bind(config *pgxpool.Config, guard postgresPeerGuard) error {
	if d == nil || d.remote == nil || config == nil || config.ConnConfig == nil || guard == nil ||
		d.authority.BrokerOnly || RejectPostgresEnvironment() != nil ||
		config.ConnConfig.Host != d.authority.ServerHost || int(config.ConnConfig.Port) != d.authority.ServerPort ||
		config.ConnConfig.Database != d.authority.Database || config.ConnConfig.User != d.authority.SQLRole ||
		config.ConnConfig.Password == "" || config.ConnConfig.TLSConfig == nil ||
		config.ConnConfig.TLSConfig.InsecureSkipVerify || config.ConnConfig.TLSConfig.ServerName != d.authority.ServerHost ||
		len(config.ConnConfig.Fallbacks) != 0 || config.ConnConfig.AfterNetConnect != nil ||
		config.BeforeAcquire != nil || config.BeforeConnect != nil || config.AfterConnect != nil ||
		config.MaxConns < 1 || config.MaxConns > 64 ||
		(config.ConnConfig.SSLNegotiation != "" && config.ConnConfig.SSLNegotiation != "postgres") {
		return ErrUnavailable
	}
	config.ConnConfig.TLSConfig = d.remote.Clone()
	config.ConnConfig.DialFunc = d.DialContext
	config.ConnConfig.LookupFunc = func(ctx context.Context, host string) ([]string, error) {
		if ctx == nil || ctx.Err() != nil || host != d.authority.ServerHost {
			return nil, ErrUnavailable
		}
		return []string{host}, nil
	}
	return BindPostgresPeerGuard(config, d.authority, guard)
}

func (d *DirectPostgres) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || network != "tcp" ||
		address != net.JoinHostPort(d.authority.ServerHost, fmt.Sprint(d.authority.ServerPort)) ||
		d.authority.BrokerOnly {
		return nil, ErrUnavailable
	}
	clientIP, clientErr := netip.ParseAddr(d.authority.SourceAddress)
	serverIP, serverErr := netip.ParseAddr(d.authority.ServerAddress)
	if clientErr != nil || serverErr != nil || !clientIP.Is4() || !serverIP.Is4() || clientIP == serverIP {
		return nil, ErrUnavailable
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IP(clientIP.AsSlice())}}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(serverIP.String(), fmt.Sprint(d.authority.ServerPort)))
	if err != nil {
		return nil, ErrUnavailable
	}
	return connection, nil
}
