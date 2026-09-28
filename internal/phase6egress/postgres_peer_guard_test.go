package phase6egress

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type testPostgresPeerGuard struct {
	ready       bool
	handshakes  int
	tracked     int
	forgotten   int
	lastContext context.Context
}

func (g *testPostgresPeerGuard) CheckHandshake(ctx context.Context, _ tls.ConnectionState) error {
	g.handshakes++
	g.lastContext = ctx
	return ctx.Err()
}

func TestPostgresPeerHandshakeRetainsConnectionCancellation(t *testing.T) {
	config := testPostgresPeerConfig(t)
	authority := phase6security.Slice6PostgresAuthority{Owner: "product-runtime", PeerEdgeID: "product-postgres",
		ServerHost: "postgres.sandbox-runtime.test", ServerPort: 5432, Database: "product",
		SQLRole: "product_runtime", ServerAnchor: phase6security.TrustAnchor{ID: "external-server-ca"}}
	guard := &testPostgresPeerGuard{ready: true}
	if err := BindPostgresPeerGuard(config, authority, guard); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	connectionConfig := config.ConnConfig.Copy()
	if err := config.BeforeConnect(ctx, connectionConfig); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := connectionConfig.TLSConfig.VerifyConnection(tls.ConnectionState{}); !errors.Is(err, context.Canceled) ||
		guard.lastContext != ctx {
		t.Fatalf("PostgreSQL CRL pull lost connection cancellation: %v", err)
	}
}
func (g *testPostgresPeerGuard) Track(_ net.Conn, _ tls.ConnectionState) error {
	g.tracked++
	return nil
}
func (g *testPostgresPeerGuard) Forget(_ net.Conn) { g.forgotten++ }
func (g *testPostgresPeerGuard) Ready() bool       { return g.ready }

func testPostgresPeerConfig(t *testing.T) *pgxpool.Config {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgres://product_runtime:secret@postgres.sandbox-runtime.test:5432/product?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		return nil, ErrUnavailable
	}
	return config
}

func TestPostgresPeerGuardTracksInnerTLSBeforeStartupAndForgetsOnClose(t *testing.T) {
	config := testPostgresPeerConfig(t)
	authority := phase6security.Slice6PostgresAuthority{Owner: "product-runtime", PeerEdgeID: "product-postgres",
		ServerHost: "postgres.sandbox-runtime.test", ServerPort: 5432, Database: "product",
		SQLRole: "product_runtime", ServerAnchor: phase6security.TrustAnchor{ID: "external-server-ca"}}
	guard := &testPostgresPeerGuard{ready: true}
	oldChecks := 0
	config.ConnConfig.TLSConfig.VerifyConnection = func(tls.ConnectionState) error { oldChecks++; return nil }
	if err := BindPostgresPeerGuard(config, authority, guard); err != nil {
		t.Fatal(err)
	}
	if err := config.BeforeConnect(t.Context(), config.ConnConfig); err != nil {
		t.Fatal(err)
	}
	if err := config.ConnConfig.TLSConfig.VerifyConnection(tls.ConnectionState{}); err != nil ||
		oldChecks != 1 || guard.handshakes != 1 {
		t.Fatalf("inner handshake guards not both called: %v", err)
	}
	_, _, _, _, _, _, certificate := ownGuardFixture(t)
	client, server := net.Pipe()
	defer server.Close()
	serverTLS := tls.Server(server, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}})
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverTLS.Handshake() }()
	peer := tls.Client(client, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		InsecureSkipVerify: true}) // this unit test supplies a fake identity guard
	wrapped, err := config.ConnConfig.AfterNetConnect(t.Context(), nil, peer)
	if err != nil || wrapped == nil || guard.tracked != 1 {
		t.Fatalf("inner TLS was not tracked before PostgreSQL startup: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	if err := wrapped.Close(); guard.forgotten != 1 {
		t.Fatalf("inner TLS was not forgotten exactly once: %v", err)
	}
	_ = wrapped.Close()
	if guard.forgotten != 1 {
		t.Fatal("inner TLS was forgotten more than once")
	}
	guard.ready = false
	if config.BeforeAcquire(t.Context(), nil) {
		t.Fatal("unready CRL source admitted a pooled connection")
	}
	client, server = net.Pipe()
	defer server.Close()
	peer = tls.Client(client, &tls.Config{ServerName: authority.ServerHost})
	if returned, err := config.ConnConfig.AfterNetConnect(t.Context(), nil, peer); err == nil || returned != peer {
		t.Fatal("failed hook did not return its original connection for pgx cleanup")
	}
	_ = peer.Close()
}

func TestPostgresPeerGuardRejectsUnboundTargetAndDuplicateHook(t *testing.T) {
	authority := phase6security.Slice6PostgresAuthority{Owner: "product-runtime", PeerEdgeID: "product-postgres",
		ServerHost: "postgres.sandbox-runtime.test", ServerPort: 5432, Database: "product",
		SQLRole: "product_runtime", ServerAnchor: phase6security.TrustAnchor{ID: "external-server-ca"}}
	for name, mutate := range map[string]func(*pgxpool.Config, *phase6security.Slice6PostgresAuthority){
		"wrong database": func(c *pgxpool.Config, _ *phase6security.Slice6PostgresAuthority) { c.ConnConfig.Database = "provider" },
		"wrong user": func(c *pgxpool.Config, _ *phase6security.Slice6PostgresAuthority) {
			c.ConnConfig.User = "product_gateway"
		},
		"wrong TLS host": func(c *pgxpool.Config, _ *phase6security.Slice6PostgresAuthority) {
			c.ConnConfig.TLSConfig.ServerName = "other.test"
		},
		"missing peer edge": func(_ *pgxpool.Config, a *phase6security.Slice6PostgresAuthority) { a.PeerEdgeID = "" },
		"preexisting hook": func(c *pgxpool.Config, _ *phase6security.Slice6PostgresAuthority) {
			c.ConnConfig.AfterNetConnect = func(_ context.Context, _ *pgconn.Config, connection net.Conn) (net.Conn, error) {
				return connection, nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := testPostgresPeerConfig(t)
			candidate := authority
			mutate(config, &candidate)
			if err := BindPostgresPeerGuard(config, candidate, &testPostgresPeerGuard{ready: true}); err == nil {
				t.Fatal("unbound PostgreSQL peer guard admitted")
			}
		})
	}
}
