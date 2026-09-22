package providerpostgres

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationLockID int64 = 73462734190263102

//go:embed migrations/0001_provider_control_state.sql
var providerControlStateMigration string

type migration struct {
	version int64
	name    string
	sql     string
}

var providerMigrations = []migration{{version: 1, name: "provider control state", sql: providerControlStateMigration}}

// CurrentSchemaVersion is the exact Provider schema version understood by the
// process. Runtime paths never attempt DDL or tolerate a newer ledger.
func CurrentSchemaVersion() int64 { return providerMigrations[len(providerMigrations)-1].version }

func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if ctx == nil || pool == nil {
		return errors.New("Provider PostgreSQL migration context and pool are required")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("begin Provider migration")
	}
	defer rollbackBounded(tx, 5*time.Second)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return errors.New("lock Provider migration")
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS sandbox_runtime_provider;
REVOKE ALL ON SCHEMA sandbox_runtime_provider FROM PUBLIC;
CREATE TABLE IF NOT EXISTS sandbox_runtime_provider.schema_migrations (
    version bigint PRIMARY KEY,
    digest text NOT NULL,
    applied_at timestamp with time zone NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT schema_migrations_version CHECK (version >= 1),
    CONSTRAINT schema_migrations_digest CHECK (digest ~ '^sha256:[0-9a-f]{64}$')
);
REVOKE ALL ON TABLE sandbox_runtime_provider.schema_migrations FROM PUBLIC;`); err != nil {
		return errors.New("prepare Provider migration ledger")
	}
	for _, item := range providerMigrations {
		digestBytes := sha256.Sum256([]byte(item.sql))
		digest := "sha256:" + hex.EncodeToString(digestBytes[:])
		var recorded string
		err = tx.QueryRow(ctx, `SELECT digest FROM sandbox_runtime_provider.schema_migrations WHERE version=$1`, item.version).Scan(&recorded)
		switch {
		case err == nil:
			if recorded != digest {
				return fmt.Errorf("Provider migration %d digest mismatch", item.version)
			}
		case errors.Is(err, pgx.ErrNoRows):
			if _, err := tx.Exec(ctx, item.sql); err != nil {
				return fmt.Errorf("apply Provider migration %d (%s)", item.version, item.name)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_provider.schema_migrations (version,digest) VALUES ($1,$2)`, item.version, digest); err != nil {
				return fmt.Errorf("record Provider migration %d", item.version)
			}
		default:
			return fmt.Errorf("read Provider migration %d ledger", item.version)
		}
	}
	var later int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_provider.schema_migrations WHERE version>$1`, CurrentSchemaVersion()).Scan(&later); err != nil || later != 0 {
		return errors.New("database Provider schema is newer than this binary")
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("commit Provider migration")
	}
	return nil
}

func VerifySchemaCompatibility(ctx context.Context, pool *pgxpool.Pool) error {
	if ctx == nil || pool == nil {
		return errors.New("Provider PostgreSQL schema context and pool are required")
	}
	rows, err := pool.Query(ctx, `SELECT version,digest FROM sandbox_runtime_provider.schema_migrations ORDER BY version`)
	if err != nil {
		return errors.New("read Provider schema compatibility ledger")
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var version int64
		var digest string
		if err := rows.Scan(&version, &digest); err != nil || index >= len(providerMigrations) {
			return errors.New("database Provider schema is incompatible with this binary")
		}
		expected := providerMigrations[index]
		digestBytes := sha256.Sum256([]byte(expected.sql))
		if version != expected.version || digest != "sha256:"+hex.EncodeToString(digestBytes[:]) {
			return errors.New("database Provider schema is incompatible with this binary")
		}
		index++
	}
	if rows.Err() != nil || index != len(providerMigrations) {
		return errors.New("database Provider schema is incompatible with this binary")
	}
	return nil
}

func VerifySeparatedRoles(ctx context.Context, migrationPool, runtimePool *pgxpool.Pool, migrationRole, runtimeRole string) error {
	if ctx == nil || migrationPool == nil || runtimePool == nil || migrationRole == "" || runtimeRole == "" || migrationRole == runtimeRole {
		return errors.New("Provider database role separation is invalid")
	}
	if err := VerifyMigrationRole(ctx, migrationPool, migrationRole); err != nil {
		return err
	}
	return VerifyRuntimeRole(ctx, runtimePool, runtimeRole)
}

func VerifyMigrationRole(ctx context.Context, migrationPool *pgxpool.Pool, migrationRole string) error {
	if ctx == nil || migrationPool == nil || migrationRole == "" {
		return errors.New("Provider migration database role is invalid")
	}
	var actualMigrationRole string
	if err := migrationPool.QueryRow(ctx, `SELECT current_user`).Scan(&actualMigrationRole); err != nil || actualMigrationRole != migrationRole {
		return errors.New("Provider migration database role does not match configuration")
	}
	var migrationCanCreate bool
	if err := migrationPool.QueryRow(ctx, `SELECT has_schema_privilege(current_user,'sandbox_runtime_provider','CREATE')`).Scan(&migrationCanCreate); err != nil || !migrationCanCreate {
		return errors.New("Provider migration database role lacks schema authority")
	}
	return nil
}

func VerifyRuntimeRole(ctx context.Context, runtimePool *pgxpool.Pool, runtimeRole string) error {
	if ctx == nil || runtimePool == nil || runtimeRole == "" {
		return errors.New("Provider runtime database role is invalid")
	}
	var actualRuntimeRole string
	if err := runtimePool.QueryRow(ctx, `SELECT current_user`).Scan(&actualRuntimeRole); err != nil || actualRuntimeRole != runtimeRole {
		return errors.New("Provider runtime database role does not match configuration")
	}
	var runtimeCanUse, runtimeCanCreate bool
	if err := runtimePool.QueryRow(ctx, `SELECT has_schema_privilege(current_user,'sandbox_runtime_provider','USAGE'),has_schema_privilege(current_user,'sandbox_runtime_provider','CREATE')`).Scan(&runtimeCanUse, &runtimeCanCreate); err != nil || !runtimeCanUse || runtimeCanCreate {
		return errors.New("Provider runtime database schema privileges are unsafe")
	}
	var ledgerRead, ledgerWrite, stateRead, stateUpdate, stateExtraWrite bool
	if err := runtimePool.QueryRow(ctx, `SELECT
has_table_privilege(current_user,'sandbox_runtime_provider.schema_migrations','SELECT'),
has_table_privilege(current_user,'sandbox_runtime_provider.schema_migrations','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'),
has_table_privilege(current_user,'sandbox_runtime_provider.control_state','SELECT'),
has_table_privilege(current_user,'sandbox_runtime_provider.control_state','UPDATE'),
has_table_privilege(current_user,'sandbox_runtime_provider.control_state','INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER')`).Scan(&ledgerRead, &ledgerWrite, &stateRead, &stateUpdate, &stateExtraWrite); err != nil || !ledgerRead || ledgerWrite || !stateRead || !stateUpdate || stateExtraWrite {
		return errors.New("Provider runtime table privileges are unsafe or incomplete")
	}
	return nil
}

func rollbackBounded(tx pgx.Tx, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = tx.Rollback(ctx)
}
