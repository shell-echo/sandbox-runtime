package phase6egress

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// VerifyBoundMigrationDDLConnection runs after TLS/authentication but before
// ApplyMigrations can issue its first DDL statement. The controlled service
// operator must pre-create the schema: migration roles may CREATE objects in
// only that schema, not create arbitrary database schemas or other roles.
func VerifyBoundMigrationDDLConnection(ctx context.Context, connection *pgx.Conn,
	database, role string) error {
	if ctx == nil || connection == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	schema := ""
	switch {
	case database == "product" && role == "product_migrator":
		schema = "sandbox_runtime_product"
	case database == "provider" && role == "provider_migrator",
		database == "provider_browser" && role == "browser_provider_migrator",
		database == "provider_desktop" && role == "desktop_provider_migrator":
		schema = "sandbox_runtime_provider"
	default:
		return ErrUnavailable
	}
	var actualDatabase, actualRole, sessionRole string
	if connection.QueryRow(ctx, `SELECT current_database(),current_user,session_user`).Scan(
		&actualDatabase, &actualRole, &sessionRole) != nil ||
		actualDatabase != database || actualRole != role || sessionRole != role {
		return ErrUnavailable
	}
	var elevated, member, databaseCreate bool
	if connection.QueryRow(ctx, `SELECT
    rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls,
    EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=pg_catalog.pg_roles.oid),
    has_database_privilege(current_user,current_database(),'CREATE')
FROM pg_catalog.pg_roles WHERE rolname=current_user`).Scan(&elevated, &member, &databaseCreate) != nil ||
		elevated || member || databaseCreate {
		return ErrUnavailable
	}
	var schemaExists bool
	if connection.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1)`, schema).Scan(&schemaExists) != nil ||
		!schemaExists {
		return ErrUnavailable
	}
	var schemaCreate bool
	if connection.QueryRow(ctx, `SELECT has_schema_privilege(current_user,$1,'CREATE')`, schema).Scan(&schemaCreate) != nil ||
		!schemaCreate {
		return ErrUnavailable
	}
	return nil
}
