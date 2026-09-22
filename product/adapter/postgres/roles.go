package productpostgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifySeparatedRoles proves that migration and runtime pools use the exact
// distinct roles selected by the operator and that the runtime role has only
// schema usage, migration-ledger read, and application-table DML authority.
func VerifySeparatedRoles(ctx context.Context, migrationPool, runtimePool *pgxpool.Pool, migrationRole, runtimeRole string) error {
	if ctx == nil || migrationPool == nil || runtimePool == nil || migrationRole == "" || runtimeRole == "" || migrationRole == runtimeRole {
		return errors.New("Product database role separation is invalid")
	}
	if err := VerifyMigrationRole(ctx, migrationPool, migrationRole); err != nil {
		return err
	}
	return VerifyRuntimeRole(ctx, runtimePool, runtimeRole)
}

// VerifyMigrationRole is used only by the one-shot Product migration process.
func VerifyMigrationRole(ctx context.Context, migrationPool *pgxpool.Pool, migrationRole string) error {
	if ctx == nil || migrationPool == nil || migrationRole == "" {
		return errors.New("Product migration database role is invalid")
	}
	var actualMigrationRole string
	if err := migrationPool.QueryRow(ctx, `SELECT current_user`).Scan(&actualMigrationRole); err != nil || actualMigrationRole != migrationRole {
		return errors.New("Product migration database role does not match configuration")
	}
	var migrationCanCreate bool
	if err := migrationPool.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'sandbox_runtime_product', 'CREATE')`).Scan(&migrationCanCreate); err != nil || !migrationCanCreate {
		return errors.New("Product migration database role lacks schema authority")
	}
	return nil
}

// VerifyRuntimeRole proves the long-running Product role has no schema or
// migration-ledger write authority while retaining application DML.
func VerifyRuntimeRole(ctx context.Context, runtimePool *pgxpool.Pool, runtimeRole string) error {
	if ctx == nil || runtimePool == nil || runtimeRole == "" {
		return errors.New("Product runtime database role is invalid")
	}
	var actualRuntimeRole string
	if err := runtimePool.QueryRow(ctx, `SELECT current_user`).Scan(&actualRuntimeRole); err != nil || actualRuntimeRole != runtimeRole {
		return errors.New("Product runtime database role does not match configuration")
	}
	var runtimeCanUse, runtimeCanCreate bool
	if err := runtimePool.QueryRow(ctx, `SELECT has_schema_privilege(current_user, 'sandbox_runtime_product', 'USAGE'), has_schema_privilege(current_user, 'sandbox_runtime_product', 'CREATE')`).Scan(&runtimeCanUse, &runtimeCanCreate); err != nil || !runtimeCanUse || runtimeCanCreate {
		return errors.New("Product runtime database schema privileges are unsafe")
	}
	var ledgerRead, ledgerWrite bool
	if err := runtimePool.QueryRow(ctx, `SELECT
has_table_privilege(current_user, 'sandbox_runtime_product.schema_migrations', 'SELECT'),
has_table_privilege(current_user, 'sandbox_runtime_product.schema_migrations', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`).Scan(&ledgerRead, &ledgerWrite); err != nil || !ledgerRead || ledgerWrite {
		return errors.New("Product runtime migration-ledger privileges are unsafe")
	}
	var tableCount int
	var allDML bool
	if err := runtimePool.QueryRow(ctx, `SELECT count(*), COALESCE(bool_and(
has_table_privilege(current_user, format('%I.%I', n.nspname, c.relname), 'SELECT') AND
has_table_privilege(current_user, format('%I.%I', n.nspname, c.relname), 'INSERT') AND
has_table_privilege(current_user, format('%I.%I', n.nspname, c.relname), 'UPDATE') AND
has_table_privilege(current_user, format('%I.%I', n.nspname, c.relname), 'DELETE')
), false)
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='sandbox_runtime_product' AND c.relkind='r' AND c.relname <> 'schema_migrations'`).Scan(&tableCount, &allDML); err != nil || tableCount < 1 || !allDML {
		return errors.New("Product runtime application-table privileges are incomplete")
	}
	return nil
}
