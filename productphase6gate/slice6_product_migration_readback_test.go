//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

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

var slice6ProductCreateTablePattern = regexp.MustCompile(`(?m)^CREATE TABLE sandbox_runtime_product\.([a-z][a-z0-9_]*) \($`)
var slice6ProductTableIdentifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Verification and post-success authorization are deliberately separate from
// failure observation. This runs only after the one-shot PID1 exited zero.
func slice6VerifyProductMigrationReadback(ctx context.Context, postgresID string) error {
	if productpostgres.CurrentSchemaVersion() != int64(len(slice6ProductMigrationFiles)) ||
		len(postgresID) != 64 || !lowerHexSlice6(postgresID) {
		return errors.New("Product migration source or PostgreSQL identity drift")
	}
	ledgerStatus, err := slice6ObserveProductMigrationDatabase(ctx, postgresID)
	if err != nil || ledgerStatus != "ledger-and-catalog-exact" {
		return errors.New("Product migration ledger or ownership is not exact")
	}
	expectedTables, err := slice6FrozenProductMigrationTables(ctx)
	if err != nil {
		return err
	}
	actualNames, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "table-names")
	if err != nil || !slices.Equal(strings.Split(actualNames, ","), expectedTables) {
		return errors.New("Product current table set differs from frozen R8 SQL")
	}
	preGrant, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "runtime-schema-before")
	if err != nil || preGrant != "false|false" {
		return errors.New("Product runtime SQL role had pre-migration schema authority")
	}
	if err := slice6GrantProductRuntimeCurrentTables(ctx, postgresID, expectedTables); err != nil {
		return err
	}
	postGrant, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "runtime-grants-after")
	if err != nil || postGrant != "true" {
		return errors.New("Product current-table runtime grants did not read back exactly")
	}
	return nil
}

func slice6FrozenProductMigrationTables(ctx context.Context) ([]string, error) {
	sourceRoot, err := filepath.EvalSymlinks(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT"))
	if err != nil || !absoluteCleanSlice6Path(sourceRoot) ||
		verifyCleanSlice6Source(ctx, sourceRoot, os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION")) != nil {
		return nil, errors.New("frozen Product migration table source unavailable")
	}
	var names []string
	for _, file := range slice6ProductMigrationFiles {
		document, readErr := os.ReadFile(filepath.Join(sourceRoot, "product", "adapter", "postgres", "migrations", file))
		if readErr != nil || len(document) == 0 || len(document) > 1<<20 {
			clear(document)
			return nil, errors.New("frozen Product migration table SQL unavailable")
		}
		for _, match := range slice6ProductCreateTablePattern.FindAllSubmatch(document, -1) {
			names = append(names, string(match[1]))
		}
		clear(document)
	}
	slices.Sort(names)
	if len(names) != 29 {
		return nil, errors.New("frozen Product migration table count drift")
	}
	for index := 1; index < len(names); index++ {
		if names[index] == names[index-1] {
			return nil, errors.New("frozen Product migration table name duplicate")
		}
	}
	return names, nil
}

const slice6ProductRuntimeRightsExpression = `
has_schema_privilege('product_runtime','sandbox_runtime_product','USAGE')
AND NOT has_schema_privilege('product_runtime','sandbox_runtime_product','CREATE')
AND has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','SELECT')
AND NOT has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','INSERT')
AND NOT has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','UPDATE')
AND NOT has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','DELETE')
AND NOT has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','TRUNCATE')
AND NOT has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','REFERENCES')
AND NOT has_table_privilege('product_runtime','sandbox_runtime_product.schema_migrations','TRIGGER')
AND (SELECT count(*)=29 AND bool_and(
    has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'SELECT')
    AND has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'INSERT')
    AND has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'UPDATE')
    AND has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'DELETE')
    AND NOT has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'TRUNCATE')
    AND NOT has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'REFERENCES')
    AND NOT has_table_privilege('product_runtime',format('%I.%I',n.nspname,c.relname),'TRIGGER'))
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r' AND c.relname<>'schema_migrations')
AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r' AND r.rolname='product_runtime' AND a.is_grantable)
AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
  CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl,acldefault('n',n.nspowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE n.nspname='sandbox_runtime_product' AND r.rolname='product_runtime' AND a.is_grantable)
AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_default_acl d
  WHERE d.defaclrole=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='product_migrator')
    AND (d.defaclnamespace=0 OR d.defaclnamespace=(SELECT oid FROM pg_catalog.pg_namespace WHERE nspname='sandbox_runtime_product')))`

func slice6GrantProductRuntimeCurrentTables(ctx context.Context, postgresID string, tables []string) error {
	input, err := slice6BuildProductRuntimeCurrentTableGrant(tables)
	if err != nil {
		return err
	}
	defer clear(input)
	output, err, overflow := slice6DockerBounded(ctx, 4096, input, "exec", "-i", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "product", "-f", "-")
	defer clear(output)
	if err != nil || overflow || len(strings.TrimSpace(string(output))) != 0 {
		return errors.New("single-transaction Product current-table grant or negative check failed")
	}
	return nil
}

func slice6BuildProductRuntimeCurrentTableGrant(tables []string) ([]byte, error) {
	if len(tables) != 29 || !slices.IsSorted(tables) {
		return nil, errors.New("Product current-table grant set unavailable")
	}
	var script strings.Builder
	script.WriteString("BEGIN;\nSET LOCAL statement_timeout='3000ms';\nSET LOCAL lock_timeout='1000ms';\n")
	script.WriteString("GRANT USAGE ON SCHEMA sandbox_runtime_product TO product_runtime;\n")
	script.WriteString("GRANT SELECT ON sandbox_runtime_product.schema_migrations TO product_runtime;\n")
	for index, table := range tables {
		if !slice6ProductTableIdentifierPattern.MatchString(table) || table == "schema_migrations" ||
			index > 0 && table == tables[index-1] {
			return nil, errors.New("Product current-table grant identifier invalid")
		}
		script.WriteString("GRANT SELECT,INSERT,UPDATE,DELETE ON sandbox_runtime_product.")
		script.WriteString(table)
		script.WriteString(" TO product_runtime;\n")
	}
	script.WriteString("DO $$ BEGIN IF NOT (")
	script.WriteString(slice6ProductRuntimeRightsExpression)
	script.WriteString(") THEN RAISE EXCEPTION 'Product post-grant privilege drift'; END IF; END $$;\nCOMMIT;\n")
	return []byte(script.String()), nil
}
