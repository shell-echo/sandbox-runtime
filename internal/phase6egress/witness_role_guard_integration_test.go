//go:build integration

package phase6egress

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
)

func TestIntegrationWitnessRoleGuardDetectsGrantAndRejectsNewPhysicalConnection(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_ACTION_HISTORY_MUTABLE_ROLE_TEST") != "1" {
		t.Skip("requires a disposable PostgreSQL witness database")
	}
	admin := witnessRoleIntegrationPool(t, "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_ADMIN_URL", nil)
	runtime := witnessRoleIntegrationPool(t, "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_URL",
		func(expectedDatabase, expectedRole string) func(context.Context, *pgx.Conn) error {
			return func(ctx context.Context, connection *pgx.Conn) error {
				return rediscapacity.VerifyPostgresActionHistoryRuntimeConnection(ctx, connection, expectedDatabase, expectedRole)
			}
		})
	database, role := runtime.Config().ConnConfig.Database, runtime.Config().ConnConfig.User
	guard, err := NewWitnessRoleGuard(runtime, database, role, 100*time.Millisecond,
		time.Second, time.Second, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := guard.Refresh(context.Background()); err != nil {
		t.Fatalf("initial PostgreSQL ACL check refused: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	drained := make(chan struct{}, 1)
	done, err := guard.StartPolling(ctx, func() { close(drained) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()
	grant := `GRANT INSERT ON sandbox_runtime.action_history_witnesses TO ` + pgx.Identifier{role}.Sanitize()
	revoke := `REVOKE INSERT ON sandbox_runtime.action_history_witnesses FROM ` + pgx.Identifier{role}.Sanitize()
	if _, err := admin.Exec(context.Background(), grant); err != nil {
		t.Fatal("test-owned INSERT grant failed")
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, revoke); err != nil {
			t.Error("test-owned INSERT grant cleanup failed")
		}
	})
	runtime.Reset()
	failedConnectCtx, failedConnectCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer failedConnectCancel()
	if err := runtime.Ping(failedConnectCtx); err == nil {
		t.Fatal("new physical connection accepted newly overprivileged role")
	}
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("idle ACL drift did not drain inside declared budget")
	}
	<-done
	if guard.CheckReady() == nil {
		t.Fatal("drained guard accepted an action")
	}
	if _, err := admin.Exec(context.Background(), revoke); err != nil {
		t.Fatal("test-owned INSERT revoke failed")
	}
	runtime.Reset()
	recoveredCtx, recoveredCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer recoveredCancel()
	if err := runtime.Ping(recoveredCtx); err != nil {
		t.Fatal("physical connection did not recover after grant revoke")
	}
	if err := guard.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("terminal drift automatically unlocked: %v", err)
	}
}

func TestIntegrationWitnessRoleGuardPoolStarvationIsBounded(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_ACTION_HISTORY_MUTABLE_ROLE_TEST") != "1" {
		t.Skip("requires a disposable PostgreSQL witness database")
	}
	runtime := witnessRoleIntegrationPool(t, "SANDBOX_RUNTIME_ACTION_HISTORY_POSTGRES_URL", nil)
	connection, err := runtime.Acquire(context.Background())
	if err != nil {
		t.Fatal("acquire only pool connection failed")
	}
	defer connection.Release()
	guard, err := NewWitnessRoleGuard(runtime, runtime.Config().ConnConfig.Database,
		runtime.Config().ConnConfig.User, 100*time.Millisecond, time.Second, time.Second, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	started := time.Now()
	if err := guard.Refresh(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("starved ACL check accepted: %v", err)
	}
	if elapsed := time.Since(started); elapsed < time.Second || elapsed > 2*time.Second {
		t.Fatalf("starved ACL check duration = %s; want bounded timeout", elapsed)
	}
	if guard.CheckReady() == nil {
		t.Fatal("starved guard remained ready")
	}
}

func witnessRoleIntegrationPool(t *testing.T, variable string,
	makeHook func(string, string) func(context.Context, *pgx.Conn) error) *pgxpool.Pool {
	t.Helper()
	uri := os.Getenv(variable)
	if uri == "" {
		t.Fatalf("%s is required", variable)
	}
	config, err := pgxpool.ParseConfig(uri)
	if err != nil {
		t.Fatalf("invalid %s", variable)
	}
	config.MaxConns = 1
	config.MinConns = 0
	if makeHook != nil {
		config.AfterConnect = makeHook(config.ConnConfig.Database, config.ConnConfig.User)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("create %s pool failed", variable)
	}
	t.Cleanup(pool.Close)
	return pool
}
