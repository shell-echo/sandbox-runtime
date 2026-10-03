//go:build integration

package cmd

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This uses a disposable locally pinned PostgreSQL server and synthetic
// credentials. It exercises pgx's actual lazy Acquire/AfterConnect/Ping path,
// not the Vault-backed Product migration or its certificate policy.
func TestMigrationClosedPingClassifierRealPostgres(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_MIGRATION_PING_CLASSIFIER_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_MIGRATION_PING_CLASSIFIER_INTEGRATION=1 for disposable PostgreSQL")
	}
	const image = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	const private = "fixture-password PRIVATE KEY SELECT private"
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	docker := func(arguments ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "docker", arguments...).CombinedOutput()
	}
	if _, err := docker("image", "inspect", image); err != nil {
		t.Fatal("pinned disposable PostgreSQL image unavailable")
	}
	name := "p6-migration-ping-classifier-" + strings.ReplaceAll(time.Now().UTC().Format("20060102T150405.000000000"), ".", "-")
	container, err := docker("run", "-d", "--rm", "--pull=never", "--name", name,
		"--restart=no", "--memory=256m", "--cpus=1", "--pids-limit=64",
		"-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=fixture-password",
		"-e", "POSTGRES_DB=postgres", image)
	if err != nil || len(strings.TrimSpace(string(container))) != 64 {
		t.Fatal("disposable PostgreSQL did not start")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
		if exec.CommandContext(cleanup, "docker", "inspect", name).Run() == nil {
			t.Error("exact disposable PostgreSQL container remains")
		}
	})
	portDocument, err := docker("port", name, "5432/tcp")
	_, port, splitErr := net.SplitHostPort(strings.TrimSpace(string(portDocument)))
	if err != nil || splitErr != nil {
		t.Fatal("disposable PostgreSQL loopback port unavailable")
	}
	initialized := false
	for attempt := 0; attempt < 80; attempt++ {
		logs, logErr := docker("logs", name)
		if logErr == nil && strings.Contains(string(logs), "PostgreSQL init process complete; ready for start up.") &&
			strings.Count(string(logs), "database system is ready to accept connections") >= 2 {
			initialized = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !initialized {
		t.Fatal("disposable PostgreSQL final init did not finish")
	}
	ready := false
	for attempt := 0; attempt < 80; attempt++ {
		if _, err := docker("exec", "-u", "postgres", name, "pg_isready", "-U", "postgres", "-d", "postgres"); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("disposable PostgreSQL did not become ready")
	}
	forwarded := false
	for attempt := 0; attempt < 80; attempt++ {
		connection, dialErr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			forwarded = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !forwarded {
		t.Fatal("disposable PostgreSQL loopback forwarding did not become ready")
	}
	probe := func(password string, afterConnect func(context.Context, *pgx.Conn) error) error {
		var before, dial, afterNet, afterSQL atomic.Int32
		defer func() {
			t.Logf("synthetic PostgreSQL hook counts: before=%d dial=%d after-net=%d after-connect=%d",
				before.Load(), dial.Load(), afterNet.Load(), afterSQL.Load())
		}()
		config, err := pgxpool.ParseConfig("postgres://postgres:" + password + "@127.0.0.1:" + port + "/postgres?sslmode=disable")
		if err != nil {
			return err
		}
		config.MaxConns, config.MinConns = 1, 0
		config.ConnConfig.ConnectTimeout = 2 * time.Second
		config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			dial.Add(1)
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		config.BeforeConnect = func(_ context.Context, connection *pgx.ConnConfig) error {
			before.Add(1)
			connection.AfterNetConnect = func(_ context.Context, _ *pgconn.Config, socket net.Conn) (net.Conn, error) {
				afterNet.Add(1)
				return socket, nil
			}
			return nil
		}
		config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
			afterSQL.Add(1)
			return afterConnect(ctx, connection)
		}
		if err := bindMigrationConnectionDiagnostic(ctx, config); err != nil {
			return err
		}
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			return err
		}
		defer pool.Close()
		pingCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		return probeMigrationConnection(pingCtx, func(acquireCtx context.Context) (migrationProbeConnection, error) {
			connection, acquireErr := pool.Acquire(acquireCtx)
			if acquireErr != nil {
				var server *pgconn.PgError
				var connect *pgconn.ConnectError
				var network *net.OpError
				var local *migrationConnectionFailure
				t.Logf("synthetic acquire typed failures: server=%t connect=%t network=%t EOF=%t deadline=%t canceled=%t closed=%t",
					errors.As(acquireErr, &server), errors.As(acquireErr, &connect),
					errors.As(acquireErr, &network), errors.Is(acquireErr, io.EOF),
					errors.Is(acquireErr, context.DeadlineExceeded), errors.Is(acquireErr, context.Canceled),
					errors.As(acquireErr, &local))
				return nil, acquireErr
			}
			return connection, nil
		})
	}
	if err := probe("fixture-password", func(context.Context, *pgx.Conn) error { return nil }); err != nil {
		t.Fatalf("healthy PostgreSQL Ping was rejected: %v", err)
	}
	if err := probe("fixture-password", func(context.Context, *pgx.Conn) error { return errors.New(private) }); err == nil || !strings.HasSuffix(err.Error(), "class=after-connect-sql") || strings.Contains(err.Error(), private) {
		t.Fatalf("real AfterConnect failure was not closed: %v", err)
	}
	if err := probe("wrong-password", func(context.Context, *pgx.Conn) error { return nil }); err == nil || !strings.HasSuffix(err.Error(), "class=server-rejected") || strings.Contains(err.Error(), "wrong-password") {
		t.Fatalf("real server rejection was not closed: %v", err)
	}
}
