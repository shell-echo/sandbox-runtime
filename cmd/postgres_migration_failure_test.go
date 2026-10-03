package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
)

type migrationProbeFixture struct {
	pingErr  error
	pings    int
	releases int
}

func (f *migrationProbeFixture) Ping(context.Context) error { f.pings++; return f.pingErr }
func (f *migrationProbeFixture) Release()                   { f.releases++ }

func migrationProbeConfig(t *testing.T) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgres://product_migrator:fixture@postgres.sandbox-runtime.test:5432/product?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns, config.MinConns = 1, 0
	config.ConnConfig.ConnectTimeout = time.Second
	config.BeforeConnect = func(_ context.Context, connection *pgx.ConnConfig) error {
		connection.AfterNetConnect = func(_ context.Context, _ *pgconn.Config, socket net.Conn) (net.Conn, error) {
			return socket, nil
		}
		return nil
	}
	config.AfterConnect = func(context.Context, *pgx.Conn) error { return nil }
	return config
}

func TestMigrationConnectionDiagnosticHooksAreClosedAndSingleCall(t *testing.T) {
	const private = "postgres://secret:do-not-print@private/endpoint PRIVATE KEY SELECT secret"
	malicious := errors.New(private + strings.Repeat("x", 32768))
	config := migrationProbeConfig(t)
	dials := 0
	config.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, malicious
	}
	if err := bindMigrationConnectionDiagnostic(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	if socket, err := config.ConnConfig.DialFunc(t.Context(), "tcp", "postgres.sandbox-runtime.test:5432"); socket != nil || migrationConnectionFailureOf(t.Context(), err, migrationUnknown) != migrationExactDial || dials != 1 ||
		strings.Contains(err.Error(), private) {
		t.Fatal("exact dial did not classify one call without exposing private cause")
	}
	connection := config.ConnConfig.Copy()
	if err := config.BeforeConnect(t.Context(), connection); err != nil {
		t.Fatal(err)
	}
	if connection.AfterNetConnect == nil {
		t.Fatal("guard tracking hook disappeared")
	}
	if err := config.AfterConnect(t.Context(), nil); err != nil {
		t.Fatal(err)
	}

	beforeCalls := 0
	before := migrationProbeConfig(t)
	before.ConnConfig.DialFunc = config.ConnConfig.DialFunc
	before.BeforeConnect = func(context.Context, *pgx.ConnConfig) error { beforeCalls++; return malicious }
	if err := bindMigrationConnectionDiagnostic(t.Context(), before); err != nil {
		t.Fatal(err)
	}
	if err := before.BeforeConnect(t.Context(), before.ConnConfig.Copy()); beforeCalls != 1 ||
		migrationConnectionFailureOf(t.Context(), err, migrationUnknown) != migrationBeforeConnect ||
		strings.Contains(err.Error(), private) {
		t.Fatal("before-connect failure was lost or leaked")
	}

	afterNetCalls := 0
	tracking := migrationProbeConfig(t)
	tracking.ConnConfig.DialFunc = config.ConnConfig.DialFunc
	tracking.BeforeConnect = func(_ context.Context, connection *pgx.ConnConfig) error {
		connection.AfterNetConnect = func(_ context.Context, _ *pgconn.Config, socket net.Conn) (net.Conn, error) {
			afterNetCalls++
			return socket, malicious
		}
		return nil
	}
	if err := bindMigrationConnectionDiagnostic(t.Context(), tracking); err != nil {
		t.Fatal(err)
	}
	copy := tracking.ConnConfig.Copy()
	if err := tracking.BeforeConnect(t.Context(), copy); err != nil {
		t.Fatal(err)
	}
	_, err := copy.AfterNetConnect(t.Context(), nil, nil)
	if afterNetCalls != 1 || migrationConnectionFailureOf(t.Context(), err, migrationUnknown) != migrationTLSOrGuard ||
		strings.Contains(err.Error(), private) {
		t.Fatal("TLS/guard callback failure was lost or leaked")
	}

	afterConnectCalls := 0
	sql := migrationProbeConfig(t)
	sql.ConnConfig.DialFunc = config.ConnConfig.DialFunc
	sql.AfterConnect = func(context.Context, *pgx.Conn) error { afterConnectCalls++; return malicious }
	if err := bindMigrationConnectionDiagnostic(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if err := sql.AfterConnect(t.Context(), nil); afterConnectCalls != 1 ||
		migrationConnectionFailureOf(t.Context(), err, migrationUnknown) != migrationAfterConnectSQL ||
		strings.Contains(err.Error(), private) {
		t.Fatal("AfterConnect SQL failure was lost or leaked")
	}
}

func TestMigrationProbeClosedClassesAndExactRelease(t *testing.T) {
	const private = "postgres://private:secret@host/product SELECT password PRIVATE KEY"
	for _, candidate := range []struct {
		name string
		err  error
		want migrationConnectionClass
	}{
		{"server-rejected", errors.Join(errors.New("wrapper"), &pgconn.PgError{Code: "28P01", Message: private}), migrationServerRejected},
		{"untyped", errors.New(private), migrationPoolAcquire},
		{"typed-dial", newMigrationConnectionFailure(context.Background(), migrationExactDial, phase6egress.ErrUnavailable), migrationExactDial},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			calls := 0
			err := probeMigrationConnection(t.Context(), func(context.Context) (migrationProbeConnection, error) {
				calls++
				return nil, candidate.err
			})
			if calls != 1 || err == nil || !strings.HasSuffix(err.Error(), "class="+string(candidate.want)) ||
				strings.Contains(err.Error(), private) {
				t.Fatalf("acquire class/side effect: calls=%d err=%v", calls, err)
			}
		})
	}
	connection := &migrationProbeFixture{pingErr: errors.New(private)}
	err := probeMigrationConnection(t.Context(), func(context.Context) (migrationProbeConnection, error) {
		return connection, nil
	})
	if connection.pings != 1 || connection.releases != 1 || err == nil ||
		!strings.HasSuffix(err.Error(), "class=ping-query") || strings.Contains(err.Error(), private) {
		t.Fatalf("ping/release: pings=%d releases=%d err=%v", connection.pings, connection.releases, err)
	}
	connection = &migrationProbeFixture{}
	if err := probeMigrationConnection(t.Context(), func(context.Context) (migrationProbeConnection, error) {
		return connection, nil
	}); err != nil || connection.pings != 1 || connection.releases != 1 {
		t.Fatalf("successful probe changed pgxpool.Ping cardinality: %v", err)
	}
}

func TestMigrationProbeCallerDeadlineAndCancellationPriority(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := probeMigrationConnection(ctx, func(context.Context) (migrationProbeConnection, error) {
		called = true
		return nil, nil
	}); called || err == nil || !strings.HasSuffix(err.Error(), "class=caller-canceled") {
		t.Fatalf("pre-acquire cancellation: called=%t err=%v", called, err)
	}
	ctx, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if err := probeMigrationConnection(ctx, func(context.Context) (migrationProbeConnection, error) {
		called = true
		return nil, nil
	}); called || err == nil || !strings.HasSuffix(err.Error(), "class=caller-deadline") {
		t.Fatalf("pre-acquire deadline: called=%t err=%v", called, err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	connection := &migrationProbeFixture{pingErr: errors.New("unknown")}
	err := probeMigrationConnection(ctx, func(context.Context) (migrationProbeConnection, error) {
		cancel()
		return connection, nil
	})
	if err == nil || !strings.HasSuffix(err.Error(), "class=caller-canceled") ||
		connection.pings != 1 || connection.releases != 1 {
		t.Fatalf("in-progress parent cancellation: err=%v pings=%d releases=%d", err, connection.pings, connection.releases)
	}
	wrapped := newMigrationConnectionFailure(context.Background(), migrationExactDial, context.DeadlineExceeded)
	if !errors.Is(wrapped, context.DeadlineExceeded) || errors.Is(wrapped, context.Canceled) ||
		migrationConnectionFailureOf(context.Background(), wrapped, migrationUnknown) != migrationExactDial {
		t.Fatal("closed typed failure lost original context sentinel")
	}
	deadlineCtx, stopDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stopDeadline()
	priority := newMigrationConnectionFailure(deadlineCtx, migrationExactDial, context.Canceled)
	if migrationConnectionFailureOf(deadlineCtx, priority, migrationUnknown) != migrationCallerDeadline ||
		!errors.Is(priority, context.DeadlineExceeded) || errors.Is(priority, context.Canceled) {
		t.Fatal("caller deadline did not win over an inner cancellation")
	}
	unavailable := newMigrationConnectionFailure(context.Background(), migrationExactDial, phase6egress.ErrUnavailable)
	if !errors.Is(unavailable, phase6egress.ErrUnavailable) || errors.Is(unavailable, phase6tls.ErrPeerCRLUnavailable) {
		t.Fatal("closed typed failure lost or broadened availability sentinel")
	}
}

func TestMigrationProbeRealPoolCancelCloseAndNoPrivateCause(t *testing.T) {
	config := migrationProbeConfig(t)
	started := make(chan struct{})
	var once sync.Once
	config.ConnConfig.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if err := bindMigrationConnectionDiagnostic(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	caller, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- probeMigrationPool(caller, pool) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("pool constructor did not reach the exact dial hook")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil || !strings.HasSuffix(err.Error(), "class=caller-canceled") {
			t.Fatalf("canceled pool acquire: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not release pool acquisition")
	}
	closed := make(chan struct{})
	go func() { pool.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("pool close did not cancel detached constructor")
	}
}

func TestMigrationProbeRealPoolPreservesExactDialClass(t *testing.T) {
	config := migrationProbeConfig(t)
	config.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		return nil, phase6egress.ErrUnavailable
	}
	if err := bindMigrationConnectionDiagnostic(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := probeMigrationPool(ctx, pool); err == nil ||
		!strings.HasSuffix(err.Error(), "class=exact-dial") {
		t.Fatalf("real pgx pool did not preserve closed dial class: %v", err)
	}
}

func TestMigrationPeerCRLClassAndSentinelsRemainClosed(t *testing.T) {
	var guard *phase6tls.PeerCRLGuard
	peerErr := guard.CheckHandshake(t.Context(), tls.ConnectionState{})
	marked := newMigrationConnectionFailure(t.Context(), migrationTLSOrGuard, peerErr)
	if migrationConnectionFailureOf(t.Context(), marked, migrationUnknown) != "peer-crl-local-guard" ||
		!errors.Is(marked, phase6tls.ErrPeerCRLUnavailable) ||
		errors.Is(marked, phase6egress.ErrUnavailable) || strings.Contains(marked.Error(), "local-guard") {
		t.Fatal("existing peer-CRL class or sentinel was not retained without raw cause")
	}
}
