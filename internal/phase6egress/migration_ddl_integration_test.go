//go:build integration

package phase6egress

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
)

// This component diagnostic proves the pre-DDL privilege check and complete
// Product/Provider migrations under schema-local CREATE. It is not the final
// Vault/TLS nine-job migration gate.
func TestRealMigrationPreDDLPrivilege(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_MIGRATION_DDL_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_MIGRATION_DDL_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := exec.CommandContext(ctx, "docker", "image", "inspect", postgresClientHBAImage).Output(); err != nil {
		t.Fatalf("pinned PostgreSQL image unavailable: %v", err)
	}
	name := fmt.Sprintf("p6-migration-ddl-%d-%d", os.Getpid(), time.Now().UnixNano())
	runPostgresDocker(t, ctx, "run", "-d", "--name", name, "-p", "127.0.0.1::5432",
		"-e", "POSTGRES_PASSWORD=admin-only", "-e", "POSTGRES_DB=product", postgresClientHBAImage)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", name).Run()
		if exec.CommandContext(cleanupCtx, "docker", "inspect", name).Run() == nil {
			t.Errorf("migration diagnostic container %s remains", name)
		}
	})
	portOutput := strings.TrimSpace(runPostgresDocker(t, ctx, "port", name, "5432/tcp"))
	_, port, err := net.SplitHostPort(portOutput)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 80; attempt++ {
		probe := exec.CommandContext(ctx, "docker", "exec", "-u", "postgres", name,
			"psql", "-At", "-d", "product", "-c", "SELECT 1")
		output, probeErr := probe.CombinedOutput()
		if probeErr == nil && strings.TrimSpace(string(output)) == "1" {
			break
		}
		if attempt == 79 {
			t.Fatalf("migration PostgreSQL did not start: %v %.512s", probeErr, output)
		}
		time.Sleep(250 * time.Millisecond)
	}
	for _, sql := range []string{
		"CREATE ROLE product_migrator LOGIN PASSWORD 'migration-secret'",
		"REVOKE CONNECT ON DATABASE product FROM PUBLIC",
		"REVOKE CREATE ON DATABASE product FROM PUBLIC",
		"GRANT CONNECT ON DATABASE product TO product_migrator",
		"CREATE SCHEMA sandbox_runtime_product",
		"REVOKE ALL ON SCHEMA sandbox_runtime_product FROM PUBLIC",
		"GRANT USAGE,CREATE ON SCHEMA sandbox_runtime_product TO product_migrator",
	} {
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-v", "ON_ERROR_STOP=1",
			"-d", "product", "-c", sql)
	}
	connection, err := pgx.Connect(ctx, "postgres://product_migrator:migration-secret@127.0.0.1:"+port+"/product?sslmode=disable")
	if err != nil {
		t.Fatalf("limited migration login failed: %v", err)
	}
	defer connection.Close(context.Background())
	if err := VerifyBoundMigrationDDLConnection(ctx, connection, "product", "product_migrator"); err != nil {
		t.Fatalf("pre-created schema limited DDL rejected: %v", err)
	}
	if err := VerifyBoundMigrationDDLConnection(ctx, connection, "provider", "product_migrator"); err == nil {
		t.Fatal("wrong migration database admitted")
	}
	if _, err := connection.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS sandbox_runtime_product"); err == nil {
		t.Fatal("legacy schema bootstrap unexpectedly succeeded without database-wide CREATE")
	}
	if _, err := connection.Exec(ctx, "CREATE TABLE sandbox_runtime_product.migration_precheck_probe(id bigint PRIMARY KEY)"); err != nil {
		t.Fatalf("limited schema DDL failed: %v", err)
	}
	if _, err := connection.Exec(ctx, "CREATE SCHEMA forbidden_extra_schema"); err == nil {
		t.Fatal("migration role could create an unreviewed database schema")
	}
	pool, err := pgxpool.New(ctx, "postgres://product_migrator:migration-secret@127.0.0.1:"+port+"/product?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := productpostgres.ApplyMigrationsPrecreatedSchema(ctx, pool); err != nil {
		t.Fatalf("limited Product full migration failed: %v", err)
	}
	if err := productpostgres.VerifySchemaCompatibility(ctx, pool); err != nil {
		t.Fatalf("limited Product migration ledger failed: %v", err)
	}
	for _, job := range []struct{ database, role string }{
		{database: "provider", role: "provider_migrator"},
		{database: "provider_browser", role: "browser_provider_migrator"},
		{database: "provider_desktop", role: "desktop_provider_migrator"},
	} {
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
			fmt.Sprintf("CREATE DATABASE %s", job.database))
		runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c",
			fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD 'migration-secret'", job.role))
		for _, sql := range []string{
			fmt.Sprintf("REVOKE CONNECT ON DATABASE %s FROM PUBLIC", job.database),
			fmt.Sprintf("REVOKE CREATE ON DATABASE %s FROM PUBLIC", job.database),
			fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", job.database, job.role),
		} {
			runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", sql)
		}
		for _, sql := range []string{
			"CREATE SCHEMA sandbox_runtime_provider",
			"REVOKE ALL ON SCHEMA sandbox_runtime_provider FROM PUBLIC",
			fmt.Sprintf("GRANT USAGE,CREATE ON SCHEMA sandbox_runtime_provider TO %s", job.role),
		} {
			runPostgresDocker(t, ctx, "exec", "-u", "postgres", name, "psql", "-v", "ON_ERROR_STOP=1", "-d", job.database, "-c", sql)
		}
		jobPool, err := pgxpool.New(ctx, fmt.Sprintf("postgres://%s:migration-secret@127.0.0.1:%s/%s?sslmode=disable", job.role, port, job.database))
		if err != nil {
			t.Fatal(err)
		}
		jobConnection, err := jobPool.Acquire(ctx)
		if err != nil {
			jobPool.Close()
			t.Fatal(err)
		}
		if err := VerifyBoundMigrationDDLConnection(ctx, jobConnection.Conn(), job.database, job.role); err != nil {
			jobConnection.Release()
			jobPool.Close()
			t.Fatalf("%s pre-DDL check failed: %v", job.database, err)
		}
		jobConnection.Release()
		if err := providerpostgres.ApplyMigrationsPrecreatedSchema(ctx, jobPool); err != nil {
			jobPool.Close()
			t.Fatalf("%s full migration failed: %v", job.database, err)
		}
		if err := providerpostgres.VerifySchemaCompatibility(ctx, jobPool); err != nil {
			jobPool.Close()
			t.Fatalf("%s migration ledger failed: %v", job.database, err)
		}
		jobPool.Close()
	}
}
