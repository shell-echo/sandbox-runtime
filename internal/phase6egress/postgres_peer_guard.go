package phase6egress

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type postgresPeerGuard interface {
	CheckHandshake(context.Context, tls.ConnectionState) error
	Track(net.Conn, tls.ConnectionState) error
	Forget(net.Conn)
	Ready() bool
}

// BindPostgresPeerGuard attaches the *inner* PostgreSQL TLS revocation check
// and tracks the actual post-handshake connection before the startup packet.
// The caller must first install its exact direct or broker DialFunc and TLS
// identity verifier. The outer broker guard, when present, remains separate.
func BindPostgresPeerGuard(config *pgxpool.Config, authority phase6security.Slice6PostgresAuthority,
	guard postgresPeerGuard) error {
	if config == nil || config.ConnConfig == nil || guard == nil || authority.Owner == "" ||
		authority.PeerEdgeID == "" || authority.ServerAnchor.ID != "external-server-ca" ||
		config.ConnConfig.Host != authority.ServerHost || int(config.ConnConfig.Port) != authority.ServerPort ||
		config.ConnConfig.Database != authority.Database || config.ConnConfig.User != authority.SQLRole ||
		config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.InsecureSkipVerify ||
		config.ConnConfig.TLSConfig.ServerName != authority.ServerHost || len(config.ConnConfig.Fallbacks) != 0 ||
		config.ConnConfig.DialFunc == nil || config.ConnConfig.AfterNetConnect != nil || config.BeforeAcquire != nil {
		return ErrUnavailable
	}
	// pgxpool gives BeforeConnect a per-connection configuration copy. Clone
	// the TLS config there so VerifyConnection retains this exact connection's
	// cancellation context instead of a detached Background context.
	config.BeforeConnect = func(ctx context.Context, connectionConfig *pgx.ConnConfig) error {
		if ctx == nil || ctx.Err() != nil || connectionConfig == nil || connectionConfig.TLSConfig == nil {
			return ErrUnavailable
		}
		remote := connectionConfig.TLSConfig.Clone()
		oldVerifier := remote.VerifyConnection
		remote.VerifyConnection = func(state tls.ConnectionState) error {
			if oldVerifier != nil {
				if err := oldVerifier(state); err != nil {
					return err
				}
			}
			return guard.CheckHandshake(ctx, state)
		}
		connectionConfig.TLSConfig = remote
		return nil
	}
	config.ConnConfig.AfterNetConnect = func(ctx context.Context, _ *pgconn.Config, connection net.Conn) (net.Conn, error) {
		if ctx == nil || ctx.Err() != nil || !guard.Ready() {
			return connection, ErrUnavailable
		}
		peer, ok := connection.(*tls.Conn)
		if !ok || peer.HandshakeContext(ctx) != nil || guard.Track(connection, peer.ConnectionState()) != nil {
			return connection, ErrUnavailable
		}
		return &trackedTunnel{Conn: connection, tracker: guard}, nil
	}
	config.BeforeAcquire = func(ctx context.Context, _ *pgx.Conn) bool {
		return ctx != nil && ctx.Err() == nil && guard.Ready()
	}
	return nil
}
