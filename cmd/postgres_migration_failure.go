package cmd

import (
	"context"
	"errors"
	"net"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
)

// These classes are local to the one-shot migration command. No third-party
// error, connection string, SQL text or endpoint is retained in a class.
type migrationConnectionClass string

const (
	migrationCallerCanceled  migrationConnectionClass = "caller-canceled"
	migrationCallerDeadline  migrationConnectionClass = "caller-deadline"
	migrationBeforeConnect   migrationConnectionClass = "before-connect"
	migrationExactDial       migrationConnectionClass = "exact-dial"
	migrationTLSOrGuard      migrationConnectionClass = "tls-or-guard"
	migrationAfterConnectSQL migrationConnectionClass = "after-connect-sql"
	migrationServerRejected  migrationConnectionClass = "server-rejected"
	migrationPoolAcquire     migrationConnectionClass = "pool-acquire"
	migrationPingQuery       migrationConnectionClass = "ping-query"
	migrationUnknown         migrationConnectionClass = "unknown"
	migrationPeerCRLPrefix   migrationConnectionClass = "peer-crl-"
)

type migrationConnectionFailure struct {
	class       migrationConnectionClass
	unavailable bool
	peer        bool
	canceled    bool
	deadline    bool
}

func (*migrationConnectionFailure) Error() string {
	return "migration PostgreSQL connection unavailable"
}

func (e *migrationConnectionFailure) Is(target error) bool {
	return target == phase6egress.ErrUnavailable && e.unavailable ||
		target == phase6tls.ErrPeerCRLUnavailable && e.peer ||
		target == context.Canceled && e.canceled ||
		target == context.DeadlineExceeded && e.deadline
}

func migrationCallerClass(caller context.Context) migrationConnectionClass {
	if caller == nil {
		return migrationUnknown
	}
	switch caller.Err() {
	case context.Canceled:
		return migrationCallerCanceled
	case context.DeadlineExceeded:
		return migrationCallerDeadline
	default:
		return ""
	}
}

func migrationPeerCRLClass(err error) migrationConnectionClass {
	if !errors.Is(err, phase6tls.ErrPeerCRLUnavailable) {
		return ""
	}
	switch class := phase6tls.PeerCRLFailureOf(err); class {
	case phase6tls.PeerCRLLocalGuardFailure, phase6tls.PeerCRLParentCanceledFailure,
		phase6tls.PeerCRLParentDeadlineFailure, phase6tls.PeerCRLInternalDeadlineFailure,
		phase6tls.PeerCRLRequestBuildFailure, phase6tls.PeerCRLSocketPeerFailure,
		phase6tls.PeerCRLTransportFailure, phase6tls.PeerCRLAgentResponseFailure,
		phase6tls.PeerCRLBindingFailure, phase6tls.PeerCRLSemanticFailure:
		return migrationPeerCRLPrefix + migrationConnectionClass(class)
	default:
		return migrationUnknown
	}
}

func newMigrationConnectionFailure(caller context.Context, class migrationConnectionClass, cause error) error {
	callerClass := migrationCallerClass(caller)
	if callerClass != "" {
		class = callerClass
	} else if peerClass := migrationPeerCRLClass(cause); peerClass != "" {
		class = peerClass
	}
	canceled, deadline := errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded)
	if callerClass != "" {
		canceled, deadline = callerClass == migrationCallerCanceled, callerClass == migrationCallerDeadline
	}
	return &migrationConnectionFailure{class: class,
		unavailable: errors.Is(cause, phase6egress.ErrUnavailable),
		peer:        errors.Is(cause, phase6tls.ErrPeerCRLUnavailable),
		canceled:    canceled, deadline: deadline}
}

// Bind only on the one-shot migration pool, after both revocation guards have
// installed their normal hooks. Wrappers execute each original hook once and
// return only a closed local failure if it rejects the connection.
func bindMigrationConnectionDiagnostic(caller context.Context, config *pgxpool.Config) error {
	if caller == nil || config == nil || config.ConnConfig == nil ||
		config.BeforeConnect == nil || config.ConnConfig.DialFunc == nil || config.AfterConnect == nil {
		return phase6egress.ErrUnavailable
	}
	priorDial := config.ConnConfig.DialFunc
	config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := priorDial(ctx, network, address)
		if err != nil {
			return connection, newMigrationConnectionFailure(caller, migrationExactDial, err)
		}
		return connection, nil
	}
	priorBefore := config.BeforeConnect
	config.BeforeConnect = func(ctx context.Context, connectionConfig *pgx.ConnConfig) error {
		if err := priorBefore(ctx, connectionConfig); err != nil {
			return newMigrationConnectionFailure(caller, migrationBeforeConnect, err)
		}
		if connectionConfig == nil || connectionConfig.AfterNetConnect == nil {
			return newMigrationConnectionFailure(caller, migrationBeforeConnect, phase6egress.ErrUnavailable)
		}
		priorAfterNet := connectionConfig.AfterNetConnect
		connectionConfig.AfterNetConnect = func(afterCtx context.Context, pgConfig *pgconn.Config,
			connection net.Conn) (net.Conn, error) {
			wrapped, err := priorAfterNet(afterCtx, pgConfig, connection)
			if err != nil {
				return wrapped, newMigrationConnectionFailure(caller, migrationTLSOrGuard, err)
			}
			return wrapped, nil
		}
		return nil
	}
	priorAfterConnect := config.AfterConnect
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		if err := priorAfterConnect(ctx, connection); err != nil {
			return newMigrationConnectionFailure(caller, migrationAfterConnectSQL, err)
		}
		return nil
	}
	return nil
}

func migrationConnectionFailureOf(caller context.Context, err error, fallback migrationConnectionClass) migrationConnectionClass {
	if class := migrationCallerClass(caller); class != "" {
		return class
	}
	var local *migrationConnectionFailure
	if errors.As(err, &local) {
		return local.class
	}
	if class := migrationPeerCRLClass(err); class != "" {
		return class
	}
	var server *pgconn.PgError
	if errors.As(err, &server) {
		return migrationServerRejected
	}
	return fallback
}

func migrationReadinessError(class migrationConnectionClass) error {
	return errors.New("migration v2 PostgreSQL readiness is unavailable: stage=ping: class=" + string(class))
}

type migrationProbeConnection interface {
	Ping(context.Context) error
	Release()
}

// pgxpool.Ping is precisely Acquire -> Release -> Conn.Ping in locked pgx
// v5.9.2. This private one-shot equivalent makes acquisition and query
// failures distinguishable without an extra connection, query or retry.
func probeMigrationConnection(caller context.Context,
	acquire func(context.Context) (migrationProbeConnection, error)) error {
	if caller == nil || acquire == nil {
		return migrationReadinessError(migrationUnknown)
	}
	if class := migrationCallerClass(caller); class != "" {
		return migrationReadinessError(class)
	}
	connection, err := acquire(caller)
	if err != nil || connection == nil {
		if connection != nil {
			connection.Release()
		}
		if err == nil {
			return migrationReadinessError(migrationUnknown)
		}
		return migrationReadinessError(migrationConnectionFailureOf(caller, err, migrationPoolAcquire))
	}
	defer connection.Release()
	if err := connection.Ping(caller); err != nil {
		return migrationReadinessError(migrationConnectionFailureOf(caller, err, migrationPingQuery))
	}
	return nil
}

func probeMigrationPool(caller context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return migrationReadinessError(migrationUnknown)
	}
	return probeMigrationConnection(caller, func(ctx context.Context) (migrationProbeConnection, error) {
		connection, err := pool.Acquire(ctx)
		if err != nil || connection == nil {
			return nil, err
		}
		return connection, nil
	})
}
