//go:build phase6slice6gate

package productphase6gate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

var slice6MigrationCountPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})$`)
var slice6MigrationLedgerRowPattern = regexp.MustCompile(`^[1-9][0-9]?\|sha256:[0-9a-f]{64}$`)

// This observer uses only fixed, bounded catalog SQL inside explicit READ
// ONLY transactions. It cannot infer "no DDL was attempted" from an absent
// ledger; any mismatch remains an unknown/partial transaction outcome.
func slice6ObserveFailedProductMigration(run slice6DockerRun, id, postgresID string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	state, stateErr := slice6InspectMigrationState(ctx, id)
	if stateErr != nil {
		return "unavailable", "outcome-unknown", errors.New("bounded migration process state unavailable")
	}
	if strings.HasPrefix(state, "running|") {
		return state, "outcome-unknown-active", errors.New("migration process did not exit before read-only observation")
	}
	status, err := slice6ObserveProductMigrationDatabase(ctx, postgresID)
	return state, status, err
}

func slice6InspectMigrationState(ctx context.Context, id string) (string, error) {
	stateDocument, stateErr, stateOverflow := slice6DockerBounded(ctx, 2048, nil, "inspect", "--format", "{{json .State}}", id)
	defer clear(stateDocument)
	if stateErr != nil || stateOverflow {
		return "", errors.New("migration Docker State is unavailable")
	}
	restartDocument, restartErr, restartOverflow := slice6DockerBounded(ctx, 32, nil,
		"inspect", "--format", "{{.RestartCount}}", id)
	defer clear(restartDocument)
	if restartErr != nil || restartOverflow {
		return "", errors.New("migration Docker restart count unavailable")
	}
	return slice6ClassifyMigrationState(stateDocument, restartDocument)
}

func slice6ClassifyMigrationState(stateDocument, restartDocument []byte) (string, error) {
	if len(stateDocument) == 0 || len(stateDocument) > 2048 || len(restartDocument) == 0 || len(restartDocument) > 32 {
		return "", errors.New("bounded migration state input invalid")
	}
	var state struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		OOMKilled  bool   `json:"OOMKilled"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	}
	if json.Unmarshal(stateDocument, &state) != nil ||
		!slices.Contains([]string{"created", "running", "exited", "dead"}, state.Status) ||
		state.ExitCode < 0 || state.ExitCode > 255 || state.Running != (state.Status == "running") {
		return "", errors.New("migration Docker State is invalid")
	}
	started, startErr := time.Parse(time.RFC3339Nano, state.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, state.FinishedAt)
	if startErr != nil || finishErr != nil {
		return "", errors.New("migration Docker event timestamps invalid")
	}
	startedClass, finishedClass := "zero", "zero"
	if !started.IsZero() {
		startedClass = "set"
	}
	if !finished.IsZero() {
		finishedClass = "set"
	}
	if state.Status == "created" && startedClass != "zero" ||
		state.Status == "exited" && (startedClass != "set" || finishedClass != "set") {
		return "", errors.New("migration Docker lifecycle timestamps drift")
	}
	restarts := strings.TrimSpace(string(restartDocument))
	if !slice6MigrationCountPattern.MatchString(restarts) {
		return "", errors.New("migration Docker restart count invalid")
	}
	stateErrorClass := "none"
	if state.Error != "" {
		stateErrorClass = "unknown"
		if len(state.Error) <= 256 && !strings.ContainsAny(state.Error, "\n\r\x00") {
			switch state.Error {
			case "OCI runtime create failed":
				stateErrorClass = "oci-runtime"
			case "executable file not found":
				stateErrorClass = "entrypoint"
			}
		}
	}
	return fmt.Sprintf("%s|%d|%t|%s|started-%s|finished-%s|state-error-%s",
		state.Status, state.ExitCode, state.OOMKilled, restarts,
		startedClass, finishedClass, stateErrorClass), nil
}

func slice6ObserveProductMigrationDatabase(ctx context.Context, postgresID string) (string, error) {
	active, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "activity")
	if err != nil || !slice6MigrationCountPattern.MatchString(active) || active != "0" {
		return "outcome-unknown-active-login", errors.New("migration SQL login is active or unobservable")
	}
	schema, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "schema")
	if err != nil || schema != "1" {
		return "outcome-unknown-schema", errors.New("Product schema is absent or unobservable")
	}
	catalog, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "catalog")
	if err != nil || !regexp.MustCompile(`^[0-9]{1,2}\|[0-9]{1,2}\|[0-9]{1,2}\|[0-9]{1,2}$`).MatchString(catalog) {
		return "outcome-unknown-catalog", errors.New("Product catalog is unobservable")
	}
	ledgerExists, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "ledger-exists")
	if err != nil || ledgerExists != "0" && ledgerExists != "1" {
		return "outcome-unknown-ledger", errors.New("migration ledger existence is unobservable")
	}
	if ledgerExists == "0" {
		return "ledger-absent-catalog-" + strings.ReplaceAll(catalog, "|", "-"), nil
	}
	ledger, err := slice6ProductMigrationCatalogQuery(ctx, postgresID, "ledger")
	if err != nil {
		return "outcome-unknown-ledger", errors.New("migration ledger rows are unobservable")
	}
	if ledger == "" {
		return "zero-committed-migrations-catalog-" + strings.ReplaceAll(catalog, "|", "-"), nil
	}
	rows := strings.Split(ledger, "\n")
	if len(rows) > len(slice6ProductMigrationFiles) {
		return "ledger-inconsistent", nil
	}
	for _, row := range rows {
		if !slice6MigrationLedgerRowPattern.MatchString(row) {
			return "ledger-inconsistent", nil
		}
	}
	expected, expectedErr := slice6FrozenProductMigrationLedger(ctx)
	if expectedErr != nil {
		return "outcome-unknown-source", expectedErr
	}
	for index, row := range rows {
		if row != expected[index] {
			return "ledger-inconsistent", nil
		}
	}
	if len(rows) != len(expected) {
		return fmt.Sprintf("partial-ledger-%d", len(rows)), nil
	}
	if catalog != "30|1|29|0" {
		return "ledger-exact-catalog-inconsistent", nil
	}
	return "ledger-and-catalog-exact", nil
}

func slice6FrozenProductMigrationLedger(ctx context.Context) ([]string, error) {
	sourceRoot, err := filepath.EvalSymlinks(os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_ROOT"))
	revision := os.Getenv("SANDBOX_RUNTIME_PHASE6_SLICE6_SOURCE_REVISION")
	if err != nil || !absoluteCleanSlice6Path(sourceRoot) || revision == "" ||
		verifyCleanSlice6Source(ctx, sourceRoot, revision) != nil {
		return nil, errors.New("frozen Product migration source unavailable")
	}
	result := make([]string, 0, len(slice6ProductMigrationFiles))
	for index, name := range slice6ProductMigrationFiles {
		document, readErr := os.ReadFile(filepath.Join(sourceRoot, "product", "adapter", "postgres", "migrations", name))
		if readErr != nil || len(document) == 0 || len(document) > 1<<20 {
			clear(document)
			return nil, errors.New("frozen Product migration SQL unavailable")
		}
		digest := sha256.Sum256(document)
		clear(document)
		result = append(result, fmt.Sprintf("%d|sha256:%s", index+1, hex.EncodeToString(digest[:])))
	}
	return result, nil
}

func slice6ProductMigrationCatalogQuery(ctx context.Context, postgresID, kind string) (string, error) {
	var query string
	switch kind {
	case "activity":
		query = "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE usename='product_migrator' AND pid<>pg_backend_pid()"
	case "schema":
		query = "SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname='sandbox_runtime_product'"
	case "catalog":
		query = "SELECT count(*)::text||'|'||count(*) FILTER (WHERE c.relname='schema_migrations')::text||'|'||count(*) FILTER (WHERE c.relname<>'schema_migrations')::text||'|'||count(*) FILTER (WHERE pg_catalog.pg_get_userbyid(c.relowner)<>'product_migrator')::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r'"
	case "ledger-exists":
		query = "SELECT CASE WHEN to_regclass('sandbox_runtime_product.schema_migrations') IS NULL THEN 0 ELSE 1 END"
	case "ledger":
		query = "SELECT version::text||'|'||digest FROM sandbox_runtime_product.schema_migrations ORDER BY version"
	case "table-names":
		query = "SELECT string_agg(c.relname,',' ORDER BY c.relname) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r' AND c.relname<>'schema_migrations'"
	case "runtime-schema-before":
		query = "SELECT has_schema_privilege('product_runtime','sandbox_runtime_product','USAGE')::text||'|'||has_schema_privilege('product_runtime','sandbox_runtime_product','CREATE')::text"
	case "runtime-grants-after":
		query = "SELECT (" + slice6ProductRuntimeRightsExpression + ")::text"
	default:
		return "", errors.New("unreviewed Product migration observation query")
	}
	script := []byte("BEGIN READ ONLY;\nSET LOCAL statement_timeout='3000ms';\nSET LOCAL lock_timeout='1000ms';\n" + query + ";\nCOMMIT;\n")
	defer clear(script)
	output, err, overflow := slice6DockerBounded(ctx, 4096, script, "exec", "-i", "-u", "70:70", postgresID,
		"psql", "-X", "-w", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "product", "-f", "-")
	defer clear(output)
	if err != nil || overflow {
		return "", errors.New("bounded read-only Product migration catalog query failed")
	}
	return strings.TrimSpace(string(output)), nil
}
