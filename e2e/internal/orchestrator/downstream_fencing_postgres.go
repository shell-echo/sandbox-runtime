//go:build darwin || linux

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
)

type downstreamPostgres struct {
	containerID         string
	name                string
	runtimeURL          string
	runtimePool         *pgxpool.Pool
	imageID             string
	platform            string
	runtimeRoleVerified bool
	sensitive           []string
}

func startDownstreamPostgres(
	ctx context.Context,
	runRoot string,
	providerRoot string,
	platform string,
	locked lock.PostgresControlledRestoreImage,
) (*downstreamPostgres, error) {
	if ctx == nil || runRoot == "" || providerRoot == "" || locked.SelectedPlatform != platform ||
		(platform != "linux/amd64" && platform != "linux/arm64") {
		return nil, errors.New("PostgreSQL controlled-restore input is invalid")
	}
	image := locked.Image + "@" + locked.IndexDigest
	pullPlatform := platform
	if platform == "linux/arm64" {
		pullPlatform = "linux/arm64/v8"
	}
	if _, err := runDockerCommand(ctx, "pull", "--platform", pullPlatform, image); err != nil {
		return nil, errors.New("pull locked PostgreSQL image")
	}
	inspection, err := runDockerCommand(ctx, "image", "inspect", image, "--format", "{{.Id}}|{{.Os}}/{{.Architecture}}")
	if err != nil {
		return nil, errors.New("inspect locked PostgreSQL image")
	}
	parts := strings.Split(strings.TrimSpace(inspection), "|")
	if len(parts) != 2 || parts[1] != platform || !strings.HasPrefix(parts[0], "sha256:") {
		return nil, errors.New("locked PostgreSQL image inspection is invalid")
	}
	migrationPath := filepath.Join(providerRoot, locked.MigrationPath)
	migrationDigest, err := fileSHA256(migrationPath)
	if err != nil || migrationDigest != locked.MigrationSHA256 {
		return nil, errors.New("PostgreSQL witness migration differs from the evidence lock")
	}
	migration, err := os.ReadFile(migrationPath)
	if err != nil || len(migration) == 0 || len(migration) > downstreamFileMaximum {
		return nil, errors.New("read bounded PostgreSQL witness migration")
	}

	adminPassword, err := randomSecret("")
	if err != nil {
		return nil, err
	}
	runtimePassword, err := randomSecret("")
	if err != nil {
		return nil, err
	}
	postgresRoot := filepath.Join(runRoot, "postgres")
	if err := os.MkdirAll(postgresRoot, 0o700); err != nil {
		return nil, err
	}
	adminPasswordPath := filepath.Join(postgresRoot, "admin-password")
	if err := os.WriteFile(adminPasswordPath, []byte(adminPassword), 0o600); err != nil {
		return nil, err
	}
	token, err := randomSecret("")
	if err != nil {
		return nil, err
	}
	name := "sandbox-runtime-postgres-restore-e2e-" + token[:16]
	mountPassword := "type=bind,src=" + adminPasswordPath + ",dst=/run/secrets/postgres-password,readonly"
	containerID, err := runDockerCommand(ctx,
		"run", "--detach", "--name", name,
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.owner=postgres-controlled-restore-e2e",
		"--publish", "127.0.0.1::5432",
		"--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=512m",
		"--mount", mountPassword,
		"--env", "POSTGRES_DB="+locked.Database,
		"--env", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password",
		image,
	)
	if err != nil {
		return nil, errors.New("start locked PostgreSQL container")
	}
	postgres := &downstreamPostgres{
		containerID: strings.TrimSpace(containerID), name: name, imageID: parts[0], platform: platform,
		sensitive: []string{adminPassword, runtimePassword},
	}
	cleanupFailure := func(cause error) (*downstreamPostgres, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return nil, errors.Join(cause, postgres.close(cleanupCtx))
	}
	portOutput, err := runDockerCommand(ctx, "port", name, "5432/tcp")
	if err != nil {
		return cleanupFailure(errors.New("inspect locked PostgreSQL port"))
	}
	address := strings.TrimSpace(portOutput)
	if host, port, splitErr := net.SplitHostPort(address); splitErr != nil || host != "127.0.0.1" || port == "" {
		return cleanupFailure(errors.New("locked PostgreSQL port is not bound to IPv4 loopback"))
	}
	adminURL := postgresConnectionURL("postgres", adminPassword, address, locked.Database)
	runtimeURL := postgresConnectionURL(locked.RuntimeRole, runtimePassword, address, locked.Database)
	postgres.runtimeURL = runtimeURL
	postgres.sensitive = append(postgres.sensitive, adminURL, runtimeURL)

	adminPool, err := openDownstreamPostgresPool(ctx, adminURL, true)
	if err != nil {
		return cleanupFailure(errors.New("construct PostgreSQL migration pool"))
	}
	if err := waitForDownstreamPostgres(ctx, adminPool, 15*time.Second); err != nil {
		adminPool.Close()
		return cleanupFailure(err)
	}
	if err := applyDownstreamPostgresMigration(ctx, adminPool, migration, locked.RuntimeRole, runtimePassword); err != nil {
		adminPool.Close()
		return cleanupFailure(err)
	}
	adminPool.Close()

	runtimePool, err := openDownstreamPostgresPool(ctx, runtimeURL, false)
	if err != nil {
		return cleanupFailure(errors.New("construct PostgreSQL runtime pool"))
	}
	postgres.runtimePool = runtimePool
	if err := waitForDownstreamPostgres(ctx, runtimePool, 5*time.Second); err != nil {
		return cleanupFailure(err)
	}
	verified, err := verifyDownstreamPostgresRuntimeRole(ctx, runtimePool, locked.RuntimeRole)
	if err != nil || !verified {
		return cleanupFailure(errors.New("verify PostgreSQL witness runtime role"))
	}
	postgres.runtimeRoleVerified = true
	return postgres, nil
}

func openDownstreamPostgresPool(ctx context.Context, endpoint string, simpleProtocol bool) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(endpoint)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 4
	if simpleProtocol {
		config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	}
	return pgxpool.NewWithConfig(ctx, config)
}

func waitForDownstreamPostgres(ctx context.Context, pool *pgxpool.Pool, maximum time.Duration) error {
	if ctx == nil || pool == nil || maximum <= 0 {
		return errors.New("wait for PostgreSQL witness")
	}
	deadline := time.NewTimer(maximum)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		operationCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := pool.Ping(operationCtx)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("PostgreSQL witness did not become ready")
		case <-ticker.C:
		}
	}
}

func applyDownstreamPostgresMigration(
	ctx context.Context,
	pool *pgxpool.Pool,
	migration []byte,
	runtimeRole string,
	runtimePassword string,
) error {
	operationCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := pool.Exec(operationCtx, string(migration)); err != nil {
		return errors.New("apply PostgreSQL witness migration")
	}
	for _, statement := range []string{
		"REVOKE ALL ON DATABASE witness FROM PUBLIC",
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
	} {
		if _, err := pool.Exec(operationCtx, statement); err != nil {
			return errors.New("harden PostgreSQL witness database")
		}
	}
	var createRole string
	if err := pool.QueryRow(operationCtx,
		"SELECT format('CREATE ROLE sandbox_runtime_witness LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', $1::text)",
		runtimePassword,
	).Scan(&createRole); err != nil || runtimeRole != "sandbox_runtime_witness" {
		return errors.New("prepare PostgreSQL witness runtime role")
	}
	if _, err := pool.Exec(operationCtx, createRole); err != nil {
		return errors.New("create PostgreSQL witness runtime role")
	}
	for _, statement := range []string{
		"GRANT CONNECT ON DATABASE witness TO sandbox_runtime_witness",
		"GRANT USAGE ON SCHEMA sandbox_runtime TO sandbox_runtime_witness",
		"GRANT SELECT ON TABLE sandbox_runtime.action_history_witnesses TO sandbox_runtime_witness",
		"GRANT INSERT (namespace_fingerprint, policy_fingerprint, format_version, sequence, token) ON TABLE sandbox_runtime.action_history_witnesses TO sandbox_runtime_witness",
		"GRANT UPDATE (sequence, token, updated_at) ON TABLE sandbox_runtime.action_history_witnesses TO sandbox_runtime_witness",
	} {
		if _, err := pool.Exec(operationCtx, statement); err != nil {
			return errors.New("grant PostgreSQL witness runtime privileges")
		}
	}
	return nil
}

func verifyDownstreamPostgresRuntimeRole(ctx context.Context, pool *pgxpool.Pool, role string) (bool, error) {
	operationCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var currentUser string
	var connect, usage, selectTable, insertColumns, updateColumns bool
	var createDatabase, temporaryDatabase, createSchema bool
	var deleteRows, truncateRows, referencesTable, triggerTable bool
	var insertUpdatedAt, updateIdentityColumns, ownsSchema, ownsTable bool
	var superuser, createDB, createRole, inherit, replication, bypassRLS bool
	err := pool.QueryRow(operationCtx, `SELECT current_user,
    has_database_privilege(current_user, current_database(), 'CONNECT'),
	 has_database_privilege(current_user, current_database(), 'CREATE'),
	 has_database_privilege(current_user, current_database(), 'TEMP'),
    has_schema_privilege(current_user, 'sandbox_runtime', 'USAGE'),
	 has_schema_privilege(current_user, 'sandbox_runtime', 'CREATE'),
    has_table_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'SELECT'),
    has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'namespace_fingerprint', 'INSERT')
      AND has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'policy_fingerprint', 'INSERT')
      AND has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'format_version', 'INSERT')
      AND has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'sequence', 'INSERT')
      AND has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'token', 'INSERT'),
    has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'sequence', 'UPDATE')
      AND has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'token', 'UPDATE')
      AND has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'updated_at', 'UPDATE'),
	 has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'updated_at', 'INSERT'),
	 has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'namespace_fingerprint', 'UPDATE')
	   OR has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'policy_fingerprint', 'UPDATE')
	   OR has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'format_version', 'UPDATE'),
    has_table_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'DELETE'),
    has_table_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'TRUNCATE'),
	 has_table_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'REFERENCES'),
	 has_table_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'TRIGGER'),
	 (SELECT oid FROM pg_roles WHERE rolname = current_user) =
	   (SELECT nspowner FROM pg_namespace WHERE nspname = 'sandbox_runtime'),
	 (SELECT oid FROM pg_roles WHERE rolname = current_user) =
	   (SELECT relowner FROM pg_class WHERE oid = 'sandbox_runtime.action_history_witnesses'::regclass),
	 (SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
	 (SELECT rolcreatedb FROM pg_roles WHERE rolname = current_user),
	 (SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user),
	 (SELECT rolinherit FROM pg_roles WHERE rolname = current_user),
	 (SELECT rolreplication FROM pg_roles WHERE rolname = current_user),
	 (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user)`).Scan(
		&currentUser, &connect, &createDatabase, &temporaryDatabase, &usage, &createSchema,
		&selectTable, &insertColumns, &updateColumns, &insertUpdatedAt, &updateIdentityColumns,
		&deleteRows, &truncateRows, &referencesTable, &triggerTable, &ownsSchema, &ownsTable,
		&superuser, &createDB, &createRole, &inherit, &replication, &bypassRLS,
	)
	if err != nil {
		return false, err
	}
	return currentUser == role && connect && usage && selectTable && insertColumns && updateColumns &&
		!createDatabase && !temporaryDatabase && !createSchema && !insertUpdatedAt && !updateIdentityColumns &&
		!deleteRows && !truncateRows && !referencesTable && !triggerTable && !ownsSchema && !ownsTable &&
		!superuser && !createDB && !createRole && !inherit && !replication && !bypassRLS, nil
}

func postgresConnectionURL(username, password, address, database string) string {
	endpoint := &url.URL{Scheme: "postgres", Host: address, Path: "/" + database, RawQuery: "sslmode=disable"}
	endpoint.User = url.UserPassword(username, password)
	return endpoint.String()
}

func postgresRuntimeURL(postgres *downstreamPostgres) string {
	if postgres == nil {
		return ""
	}
	return postgres.runtimeURL
}

func (p *downstreamPostgres) close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if p.runtimePool != nil {
		p.runtimePool.Close()
		p.runtimePool = nil
	}
	if p.name == "" {
		return nil
	}
	_, err := runDockerCommand(ctx, "rm", "--force", p.name)
	if err != nil && !strings.Contains(err.Error(), "No such container") {
		return err
	}
	p.name = ""
	return nil
}

func (p *downstreamPostgres) String() string {
	if p == nil {
		return "postgres-controlled-restore(unavailable)"
	}
	return fmt.Sprintf("postgres-controlled-restore(platform=%s, credentials=[redacted])", p.platform)
}
