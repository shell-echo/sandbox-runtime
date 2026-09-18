package productpostgres

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

const migrationLockID int64 = 73462734190263101

//go:embed migrations/0001_product_kernel.sql
var productKernelMigration string

func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	if ctx == nil || pool == nil {
		return errors.New("product PostgreSQL migration context and pool are required")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin product migration: %w", err)
	}
	defer func() {
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rollbackCancel()
		_ = tx.Rollback(rollbackCtx)
	}()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockID); err != nil {
		return fmt.Errorf("lock product migration: %w", err)
	}
	if _, err := tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS sandbox_runtime_product;
REVOKE ALL ON SCHEMA sandbox_runtime_product FROM PUBLIC;
CREATE TABLE IF NOT EXISTS sandbox_runtime_product.schema_migrations (
    version bigint PRIMARY KEY,
    digest text NOT NULL,
    applied_at timestamp with time zone NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT schema_migrations_version CHECK (version >= 1),
    CONSTRAINT schema_migrations_digest CHECK (digest ~ '^sha256:[0-9a-f]{64}$')
);
REVOKE ALL ON TABLE sandbox_runtime_product.schema_migrations FROM PUBLIC;`); err != nil {
		return fmt.Errorf("prepare product migration ledger: %w", err)
	}

	digestBytes := sha256.Sum256([]byte(productKernelMigration))
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	var recorded string
	err = tx.QueryRow(ctx, `SELECT digest FROM sandbox_runtime_product.schema_migrations WHERE version = 1`).Scan(&recorded)
	switch {
	case err == nil:
		if recorded != digest {
			return errors.New("product migration 1 digest mismatch")
		}
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := tx.Exec(ctx, productKernelMigration); err != nil {
			return fmt.Errorf("apply product migration 1: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.schema_migrations (version, digest) VALUES (1, $1)`, digest); err != nil {
			return fmt.Errorf("record product migration 1: %w", err)
		}
	default:
		return fmt.Errorf("read product migration ledger: %w", err)
	}
	var later int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.schema_migrations WHERE version > 1`).Scan(&later); err != nil {
		return fmt.Errorf("read product migration version: %w", err)
	}
	if later != 0 {
		return errors.New("database product schema is newer than this binary")
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit product migration: %w", err)
	}
	return nil
}
