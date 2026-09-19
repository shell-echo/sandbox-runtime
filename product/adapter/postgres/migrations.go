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

//go:embed migrations/0002_product_phase3_authorities.sql
var productPhase3AuthoritiesMigration string

//go:embed migrations/0003_product_phase4_browser_session_authority.sql
var productPhase4BrowserSessionAuthorityMigration string

//go:embed migrations/0004_product_phase4_browser_slot_authority.sql
var productPhase4BrowserSlotAuthorityMigration string

//go:embed migrations/0005_product_phase4_browser_lifecycle.sql
var productPhase4BrowserLifecycleMigration string

//go:embed migrations/0006_product_phase4_browser_authority.sql
var productPhase4BrowserAuthorityMigration string

//go:embed migrations/0007_product_phase4_browser_recording.sql
var productPhase4BrowserRecordingMigration string

//go:embed migrations/0008_product_phase5_desktop_authority.sql
var productPhase5DesktopAuthorityMigration string

//go:embed migrations/0009_product_phase5_desktop_reconciliation.sql
var productPhase5DesktopReconciliationMigration string

//go:embed migrations/0010_product_phase5_desktop_grants.sql
var productPhase5DesktopGrantsMigration string

type migration struct {
	version int64
	name    string
	sql     string
}

var productMigrations = []migration{
	{version: 1, name: "product kernel", sql: productKernelMigration},
	{version: 2, name: "phase 3 authorities", sql: productPhase3AuthoritiesMigration},
	{version: 3, name: "phase 4 browser session authority", sql: productPhase4BrowserSessionAuthorityMigration},
	{version: 4, name: "phase 4 browser slot authority", sql: productPhase4BrowserSlotAuthorityMigration},
	{version: 5, name: "phase 4 browser lifecycle", sql: productPhase4BrowserLifecycleMigration},
	{version: 6, name: "phase 4 browser authority", sql: productPhase4BrowserAuthorityMigration},
	{version: 7, name: "phase 4 browser recording", sql: productPhase4BrowserRecordingMigration},
	{version: 8, name: "phase 5 desktop authority", sql: productPhase5DesktopAuthorityMigration},
	{version: 9, name: "phase 5 desktop reconciliation", sql: productPhase5DesktopReconciliationMigration},
	{version: 10, name: "phase 5 desktop grants", sql: productPhase5DesktopGrantsMigration},
}

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

	for _, item := range productMigrations {
		digestBytes := sha256.Sum256([]byte(item.sql))
		digest := "sha256:" + hex.EncodeToString(digestBytes[:])
		var recorded string
		err = tx.QueryRow(ctx, `SELECT digest FROM sandbox_runtime_product.schema_migrations WHERE version = $1`, item.version).Scan(&recorded)
		switch {
		case err == nil:
			if recorded != digest {
				return fmt.Errorf("product migration %d digest mismatch", item.version)
			}
		case errors.Is(err, pgx.ErrNoRows):
			if _, err := tx.Exec(ctx, item.sql); err != nil {
				return fmt.Errorf("apply product migration %d (%s): %w", item.version, item.name, err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.schema_migrations (version, digest) VALUES ($1, $2)`, item.version, digest); err != nil {
				return fmt.Errorf("record product migration %d: %w", item.version, err)
			}
		default:
			return fmt.Errorf("read product migration %d ledger: %w", item.version, err)
		}
	}
	var later int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.schema_migrations WHERE version > $1`, productMigrations[len(productMigrations)-1].version).Scan(&later); err != nil {
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
