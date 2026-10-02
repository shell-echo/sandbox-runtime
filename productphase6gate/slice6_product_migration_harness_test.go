//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSlice6MigrationBoundedOutputAndClosedClassification(t *testing.T) {
	output := &slice6BoundedOutput{limit: 8}
	if count, err := output.Write([]byte("12345678")); err != nil || count != 8 {
		t.Fatal("bounded output rejected exact limit")
	}
	if count, err := output.Write([]byte("PRIVATE KEY")); count != 0 || !errors.Is(err, errSlice6OutputLimit) ||
		output.buffer.String() != "12345678" {
		t.Fatal("oversized secret output escaped the in-memory cap")
	}
	for _, secret := range []string{
		"postgres://user:password@host/db",
		"unknown\nPRIVATE KEY\n",
		"migration v2 PostgreSQL connection is unavailable\npassword=private\n",
		strings.Repeat("s", 128<<10),
	} {
		if got := slice6MigrationFailureCategory([]byte(secret)); got != "unknown" {
			t.Fatal("unknown or multiline private output was classified as a known stage")
		}
	}
}

func TestSlice6MigrationStateRequiresActualLifecycle(t *testing.T) {
	good := []byte(`{"Status":"exited","Running":false,"OOMKilled":false,"ExitCode":1,"Error":"","StartedAt":"2026-10-03T00:00:00Z","FinishedAt":"2026-10-03T00:00:01Z"}`)
	state, err := slice6ClassifyMigrationState(good, []byte("0\n"))
	if err != nil || state != "exited|1|false|0|started-set|finished-set|state-error-none" {
		t.Fatal("real exited process state not classified")
	}
	for _, value := range []string{
		`{"Status":"exited","Running":false,"ExitCode":1,"StartedAt":"0001-01-01T00:00:00Z","FinishedAt":"2026-10-03T00:00:01Z"}`,
		`{"Status":"running","Running":false,"ExitCode":0,"StartedAt":"2026-10-03T00:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"}`,
		`{"Status":"exited","Running":false,"ExitCode":1,"StartedAt":"2026-10-03T00:00:00Z","FinishedAt":"2026-10-03T00:00:01Z"}` + strings.Repeat("s", 2048),
	} {
		if _, err := slice6ClassifyMigrationState([]byte(value), []byte("0")); err == nil {
			t.Fatal("invalid or oversized Docker State admitted")
		}
	}
	secret := []byte(`{"Status":"exited","Running":false,"ExitCode":1,"Error":"OCI runtime create failed password=private","StartedAt":"2026-10-03T00:00:00Z","FinishedAt":"2026-10-03T00:00:01Z"}`)
	state, err = slice6ClassifyMigrationState(secret, []byte("0"))
	if err != nil || !strings.HasSuffix(state, "state-error-unknown") || strings.Contains(state, "private") {
		t.Fatal("raw Docker State.Error escaped its closed classification")
	}
}

func TestSlice6ProductCurrentTableGrantIsAtomicAndClosed(t *testing.T) {
	tables := make([]string, 29)
	for index := range tables {
		tables[index] = fmt.Sprintf("table_%02d", index)
	}
	script, err := slice6BuildProductRuntimeCurrentTableGrant(tables)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(script)
	value := string(script)
	if !strings.HasPrefix(value, "BEGIN;\n") || !strings.HasSuffix(value, "COMMIT;\n") ||
		strings.Count(value, "GRANT SELECT,INSERT,UPDATE,DELETE ON sandbox_runtime_product.") != 29 ||
		strings.Count(value, "GRANT SELECT ON sandbox_runtime_product.schema_migrations") != 1 ||
		!strings.Contains(value, "DO $$ BEGIN IF NOT (") ||
		strings.Contains(value, "ALTER DEFAULT PRIVILEGES") || strings.Contains(value, "ON ALL TABLES") ||
		strings.Contains(value, "REVOKE") || strings.Contains(value, "GRANT OPTION") {
		t.Fatal("Product grant script exceeds current-table atomic boundary")
	}
	for _, candidate := range [][]string{
		tables[:28],
		append(slices.Clone(tables[:28]), "schema_migrations"),
		append(slices.Clone(tables[:28]), "table_00"),
		append(slices.Clone(tables[:28]), "table_28;DROP TABLE x"),
	} {
		if _, err := slice6BuildProductRuntimeCurrentTableGrant(candidate); err == nil {
			t.Fatal("invalid current-table grant set admitted")
		}
	}
}

func TestSlice6FrozenProductMigrationSourceTables(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT") == "" ||
		os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION") == "" {
		t.Skip("set exact clean Slice 6 source path and revision")
	}
	tables, err := slice6FrozenProductMigrationTables(t.Context())
	if err != nil || len(tables) != 29 {
		t.Fatal("frozen Product SQL has no exact 29-table source list")
	}
	ledger, err := slice6FrozenProductMigrationLedger(t.Context())
	if err != nil || len(ledger) != 14 {
		t.Fatal("frozen Product SQL has no exact 14-digest ledger")
	}
}

func TestSlice6ProductGrantRealSQLSyntaxProbe(t *testing.T) {
	id := os.Getenv("SANDBOX_RUNTIME_PHASE6_SQL_SYNTAX_PROBE_ID")
	if id == "" {
		t.Skip("set exact isolated disposable PostgreSQL syntax probe container")
	}
	if id != "sr-p6-psql-syntax-probe-20261003-r8" {
		t.Fatal("unreviewed PostgreSQL syntax probe target")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	runSQL := func(database, statement string) {
		t.Helper()
		input := []byte(statement)
		defer clear(input)
		output, err, overflow := slice6DockerBounded(ctx, 4096, input, "exec", "-i", "-u", "70:70", id,
			"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-f", "-")
		clear(output)
		if err != nil || overflow {
			t.Fatal("disposable PostgreSQL SQL syntax setup failed")
		}
	}
	runSQL("postgres", "CREATE ROLE product_migrator LOGIN;\nCREATE ROLE product_runtime LOGIN;\nCREATE DATABASE product;\n")
	var tables []string
	var setup strings.Builder
	setup.WriteString("BEGIN;\nCREATE SCHEMA sandbox_runtime_product AUTHORIZATION product_migrator;\nSET ROLE product_migrator;\n")
	setup.WriteString("CREATE TABLE sandbox_runtime_product.schema_migrations(version bigint,digest text);\n")
	for index := range 29 {
		table := fmt.Sprintf("table_%02d", index)
		tables = append(tables, table)
		if index < 28 {
			setup.WriteString("CREATE TABLE sandbox_runtime_product." + table + "(id bigint);\n")
		}
	}
	setup.WriteString("COMMIT;\n")
	runSQL("product", setup.String())
	status, observeErr := slice6ObserveProductMigrationDatabase(ctx, id)
	if observeErr != nil || status != "zero-committed-migrations-catalog-29-1-28-0" {
		t.Fatalf("bounded read-only partial catalog observation failed: status=%s err=%v", status, observeErr)
	}
	if err := slice6GrantProductRuntimeCurrentTables(ctx, id, tables); err == nil {
		t.Fatal("missing current table did not roll back the atomic grant")
	}
	preGrant, err := slice6ProductMigrationCatalogQuery(ctx, id, "runtime-schema-before")
	if err != nil || preGrant != "false|false" {
		t.Fatalf("failed grant transaction leaked schema authority or readback failed: value=%q err=%v", preGrant, err)
	}
	runSQL("product", "SET ROLE product_migrator;\nCREATE TABLE sandbox_runtime_product.table_28(id bigint);\n")
	status, observeErr = slice6ObserveProductMigrationDatabase(ctx, id)
	if observeErr != nil || status != "zero-committed-migrations-catalog-30-1-29-0" {
		t.Fatalf("bounded read-only zero-ledger observation failed: status=%s err=%v", status, observeErr)
	}
	if err := slice6GrantProductRuntimeCurrentTables(ctx, id, tables); err != nil {
		t.Fatal("exact current-table grant SQL failed on isolated PostgreSQL")
	}
	postGrant, err := slice6ProductMigrationCatalogQuery(ctx, id, "runtime-grants-after")
	if err != nil || postGrant != "true" {
		t.Fatal("exact grant and negative privilege readback failed on isolated PostgreSQL")
	}
}
