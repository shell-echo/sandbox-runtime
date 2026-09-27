package rediscapacity

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type actionHistoryRoleQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// VerifyPostgresActionHistoryRuntimeRole checks the effective authority of the
// long-running action-ingress account on one live PostgreSQL connection. It
// rejects a role that could provision or replace a witness row, assume a more
// privileged role, or change the witness schema. An operator must still keep
// this role separate from the one-shot provisioner and migration owner.
func VerifyPostgresActionHistoryRuntimeRole(ctx context.Context, pool *pgxpool.Pool, expectedDatabase, expectedRole string) error {
	if ctx == nil || ctx.Err() != nil || pool == nil || expectedDatabase == "" || expectedRole == "" {
		return ErrActionHistoryUnavailable
	}
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return postgresActionHistoryUnavailable("runtime role")
	}
	defer connection.Release()
	return verifyPostgresActionHistoryRuntimeQueryer(ctx, connection, expectedDatabase, expectedRole)
}

// VerifyPostgresActionHistoryRuntimeConnection is safe to call from a pgxpool
// AfterConnect callback: it uses only the just-opened physical connection and
// never re-enters the pool while the pool is creating that connection.
func VerifyPostgresActionHistoryRuntimeConnection(ctx context.Context, connection *pgx.Conn, expectedDatabase, expectedRole string) error {
	if ctx == nil || ctx.Err() != nil || connection == nil || expectedDatabase == "" || expectedRole == "" {
		return ErrActionHistoryUnavailable
	}
	return verifyPostgresActionHistoryRuntimeQueryer(ctx, connection, expectedDatabase, expectedRole)
}

func verifyPostgresActionHistoryRuntimeQueryer(ctx context.Context, connection actionHistoryRoleQueryer, expectedDatabase, expectedRole string) error {
	var current, session, database string
	var canConnect, canUse, canSelect, canUpdateSequence, canUpdateToken, canUpdateTimestamp bool
	err := connection.QueryRow(ctx, `SELECT current_user, session_user, current_database(),
has_database_privilege(current_user, current_database(), 'CONNECT'),
has_schema_privilege(current_user, 'sandbox_runtime', 'USAGE'),
has_table_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'SELECT'),
has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'sequence', 'UPDATE'),
has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'token', 'UPDATE'),
has_column_privilege(current_user, 'sandbox_runtime.action_history_witnesses', 'updated_at', 'UPDATE')`).Scan(
		&current, &session, &database, &canConnect, &canUse, &canSelect,
		&canUpdateSequence, &canUpdateToken, &canUpdateTimestamp)
	if err != nil || current != expectedRole || session != expectedRole || database != expectedDatabase ||
		!canConnect || !canUse || !canSelect || !canUpdateSequence || !canUpdateToken || !canUpdateTimestamp {
		return postgresActionHistoryUnavailable("runtime role")
	}
	var unsafe bool
	err = connection.QueryRow(ctx, `SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles AS role
  CROSS JOIN pg_catalog.pg_database AS db
  CROSS JOIN pg_catalog.pg_namespace AS witness_schema
  CROSS JOIN pg_catalog.pg_class AS witness_table
  WHERE db.datname = current_database()
    AND witness_schema.nspname = 'sandbox_runtime'
    AND witness_table.relnamespace = witness_schema.oid
    AND witness_table.relname = 'action_history_witnesses'
	    AND pg_catalog.pg_has_role(current_user::regrole::oid, role.oid, 'MEMBER')
    AND (
      role.rolsuper OR role.rolcreaterole OR role.rolcreatedb OR
      role.rolreplication OR role.rolbypassrls OR
      role.oid IN (db.datdba, witness_schema.nspowner, witness_table.relowner) OR
      pg_catalog.has_database_privilege(role.oid, db.oid, 'CREATE') OR
      pg_catalog.has_database_privilege(role.oid, db.oid, 'TEMP') OR
      pg_catalog.has_database_privilege(role.oid, db.oid, 'CONNECT WITH GRANT OPTION') OR
      pg_catalog.has_schema_privilege(role.oid, witness_schema.oid, 'CREATE') OR
      pg_catalog.has_schema_privilege(role.oid, witness_schema.oid, 'USAGE WITH GRANT OPTION') OR
      EXISTS (SELECT 1 FROM pg_catalog.pg_namespace AS other_schema
        WHERE pg_catalog.has_schema_privilege(role.oid, other_schema.oid, 'CREATE')) OR
      pg_catalog.has_table_privilege(role.oid, witness_table.oid, 'SELECT WITH GRANT OPTION') OR
      pg_catalog.has_table_privilege(role.oid, witness_table.oid,
        'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'namespace_fingerprint', 'INSERT,UPDATE') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'policy_fingerprint', 'INSERT,UPDATE') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'format_version', 'INSERT,UPDATE') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'sequence', 'INSERT') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'token', 'INSERT') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'updated_at', 'INSERT') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'sequence', 'UPDATE WITH GRANT OPTION') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'token', 'UPDATE WITH GRANT OPTION') OR
      pg_catalog.has_column_privilege(role.oid, witness_table.oid, 'updated_at', 'UPDATE WITH GRANT OPTION')
    )
)`).Scan(&unsafe)
	if err != nil || unsafe {
		return postgresActionHistoryUnavailable("runtime role")
	}
	return nil
}
