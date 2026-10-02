//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
)

var slice6ProductMigrationFiles = [...]string{
	"0001_product_kernel.sql",
	"0002_product_phase3_authorities.sql",
	"0003_product_phase4_browser_session_authority.sql",
	"0004_product_phase4_browser_slot_authority.sql",
	"0005_product_phase4_browser_lifecycle.sql",
	"0006_product_phase4_browser_authority.sql",
	"0007_product_phase4_browser_recording.sql",
	"0008_product_phase5_desktop_authority.sql",
	"0009_product_phase5_desktop_reconciliation.sql",
	"0010_product_phase5_desktop_grants.sql",
	"0011_product_phase5_desktop_policy.sql",
	"0012_product_phase5_desktop_recovery.sql",
	"0013_product_phase5_development_environment.sql",
	"0014_product_phase6_browser_handoff_binding.sql",
}

// This operator-only readback runs after the one-shot migration PID1 exits.
// It never retries DDL: an unknown migration outcome must be inspected here
// before any new attempt. Runtime grants are made only after exact ledger and
// object ownership have been observed.
func slice6VerifyProductMigrationReadback(t *testing.T, ctx context.Context, run slice6DockerRun, postgresID string) {
	t.Helper()
	if productpostgres.CurrentSchemaVersion() != int64(len(slice6ProductMigrationFiles)) ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		t.Fatal("Product migration source or PostgreSQL identity drift")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	expected := make([]string, 0, len(slice6ProductMigrationFiles))
	for index, name := range slice6ProductMigrationFiles {
		source, readErr := os.ReadFile(filepath.Join(root, "product", "adapter", "postgres", "migrations", name))
		if readErr != nil || len(source) == 0 {
			t.Fatal("frozen Product migration SQL source unavailable")
		}
		digest := sha256.Sum256(source)
		expected = append(expected, fmt.Sprintf("%d|sha256:%s", index+1, hex.EncodeToString(digest[:])))
	}
	ledger, err := run.docker(ctx, "exec", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "product", "-At",
		"-c", "SELECT version::text||'|'||digest FROM sandbox_runtime_product.schema_migrations ORDER BY version")
	if err != nil || strings.TrimSpace(string(ledger)) != strings.Join(expected, "\n") {
		clear(ledger)
		t.Fatal("Product migration PID1 ledger is not the exact frozen 14-file SQL source")
	}
	clear(ledger)
	slice6ProductSQLExpect(t, ctx, run, postgresID, "product",
		"SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r' AND pg_catalog.pg_get_userbyid(c.relowner)<>'product_migrator'", "0")
	slice6ProductSQLExpect(t, ctx, run, postgresID, "product",
		"SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r' AND c.relname<>'schema_migrations'", "29")
	slice6ProductSQLExpect(t, ctx, run, postgresID, "product",
		"SELECT has_schema_privilege('product_runtime','sandbox_runtime_product','USAGE'),has_schema_privilege('product_runtime','sandbox_runtime_product','CREATE')", "f|f")
	slice6ProductSQLExpect(t, ctx, run, postgresID, "product",
		"SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='product_migrator'", "0")
	for _, statement := range []string{
		"GRANT USAGE ON SCHEMA sandbox_runtime_product TO product_runtime",
		"GRANT SELECT ON sandbox_runtime_product.schema_migrations TO product_runtime",
		"GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA sandbox_runtime_product TO product_runtime",
		"REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON sandbox_runtime_product.schema_migrations FROM product_runtime",
		"ALTER DEFAULT PRIVILEGES FOR ROLE product_migrator IN SCHEMA sandbox_runtime_product GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO product_runtime",
	} {
		slice6ProductSQLExec(t, ctx, run, postgresID, "product", statement)
	}
	slice6ProductSQLExpect(t, ctx, run, postgresID, "product",
		"SELECT has_schema_privilege('product_runtime','sandbox_runtime_product','USAGE'),has_schema_privilege('product_runtime','sandbox_runtime_product','CREATE'),has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','SELECT'),has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')", "t|f|t|f")
	slice6ProductSQLExpect(t, ctx, run, postgresID, "product",
		"SELECT bool_and(has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'SELECT') AND has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'INSERT') AND has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'UPDATE') AND has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'DELETE')) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r' AND c.relname<>'schema_migrations'", "t")
	t.Log("real Product migration v2 PID1 ledger, SQL ownership, zero active migration login and post-DDL runtime grants read back from the same PostgreSQL process")
}
