//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This operator-only bootstrap runs on a fresh isolated PostgreSQL process.
// It creates no Product schema object: the first business DDL remains the
// independent product migrate v2 command, not this administrator connection.
type slice6ProductPostgresDSNs struct {
	Migration []byte
	Runtime   []byte
}

func (d *slice6ProductPostgresDSNs) clear() {
	clear(d.Migration)
	clear(d.Runtime)
	d.Migration, d.Runtime = nil, nil
}

func slice6BootstrapProductPostgres(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID string, profile phase6security.Profile) slice6ProductPostgresDSNs {
	t.Helper()
	migration, migrationErr := profile.ResolveSlice6FinalPostgresAuthority("product-migration-job")
	runtime, runtimeErr := profile.ResolveSlice6FinalPostgresAuthority("product-runtime")
	if migrationErr != nil || runtimeErr != nil || !migration.Migration || runtime.Migration ||
		migration.BrokerOnly || runtime.BrokerOnly ||
		migration.Database != "product" || runtime.Database != "product" ||
		migration.SQLRole != "product_migrator" || runtime.SQLRole != "product_runtime" ||
		migration.ServerHost != slice6PostgresServerDNS || runtime.ServerHost != migration.ServerHost ||
		migration.ServerPort != 5432 || runtime.ServerPort != migration.ServerPort ||
		len(serverID) != 64 || !lowerHexSlice6(serverID) {
		t.Fatal("Product PostgreSQL bootstrap is not bound to the final Profile")
	}
	// A local peer superuser is the only SQL bootstrap authority. No SQL
	// password, DSN or SCRAM verifier is passed as an argv/env value.
	slice6ProductSQLExpect(t, ctx, run, serverID, "postgres",
		"SELECT count(*) FROM pg_database WHERE datname='product'", "0")
	slice6ProductSQLExpect(t, ctx, run, serverID, "postgres",
		"SELECT count(*) FROM pg_roles WHERE rolname IN ('product_migrator','product_runtime')", "0")
	for _, statement := range []string{
		"CREATE DATABASE product",
		"REVOKE ALL ON DATABASE product FROM PUBLIC",
		"REVOKE ALL ON DATABASE postgres FROM PUBLIC",
		"REVOKE ALL ON DATABASE template1 FROM PUBLIC",
	} {
		slice6ProductSQLExec(t, ctx, run, serverID, "postgres", statement)
	}
	for _, statement := range []string{
		"CREATE SCHEMA sandbox_runtime_product AUTHORIZATION postgres",
		"REVOKE ALL ON SCHEMA sandbox_runtime_product FROM PUBLIC",
		"REVOKE ALL ON SCHEMA public FROM PUBLIC",
	} {
		slice6ProductSQLExec(t, ctx, run, serverID, "product", statement)
	}
	migrationPassword := slice6RandomProductSQLPassword(t)
	runtimePassword := slice6RandomProductSQLPassword(t)
	defer clear(migrationPassword)
	defer clear(runtimePassword)
	if bytes.Equal(migrationPassword, runtimePassword) {
		t.Fatal("Product migration/runtime SQL passwords collided")
	}
	expiry := time.Now().UTC().Add(30 * time.Minute)
	for _, role := range []struct {
		name, limit string
		password    []byte
	}{
		{"product_migrator", "1", migrationPassword},
		{"product_runtime", "4", runtimePassword},
	} {
		if err := slice6CreateProductSQLRole(ctx, serverID, role.name, role.limit, role.password, expiry); err != nil {
			t.Fatal("create one exact Product SQL login through native encrypted password setup")
		}
	}
	for _, statement := range []string{
		"GRANT CONNECT ON DATABASE product TO product_migrator",
		"GRANT CONNECT ON DATABASE product TO product_runtime",
	} {
		slice6ProductSQLExec(t, ctx, run, serverID, "postgres", statement)
	}
	slice6ProductSQLExec(t, ctx, run, serverID, "product",
		"GRANT USAGE,CREATE ON SCHEMA sandbox_runtime_product TO product_migrator")
	slice6VerifyProductSQLBootstrap(t, ctx, run, serverID)
	dsns := slice6ProductPostgresDSNs{
		Migration: slice6ProductBoundDSN(migration.ServerHost, migration.ServerPort, migration.Database,
			migration.SQLRole, migrationPassword),
		Runtime: slice6ProductBoundDSN(runtime.ServerHost, runtime.ServerPort, runtime.Database,
			runtime.SQLRole, runtimePassword),
	}
	for _, item := range []struct {
		bytes  []byte
		target phase6egress.BoundPostgresTarget
	}{
		{dsns.Migration, phase6egress.BoundPostgresTarget{Host: migration.ServerHost,
			Port: migration.ServerPort, Database: migration.Database, User: migration.SQLRole}},
		{dsns.Runtime, phase6egress.BoundPostgresTarget{Host: runtime.ServerHost,
			Port: runtime.ServerPort, Database: runtime.Database, User: runtime.SQLRole}},
	} {
		config, err := phase6egress.ParseBoundPostgresDSN(item.bytes, item.target)
		if err != nil || config == nil || config.ConnConfig == nil {
			dsns.clear()
			t.Fatal("Product SQL login did not produce a canonical Profile-bound DSN")
		}
		config.ConnConfig.Password = ""
	}
	return dsns
}

func slice6RandomProductSQLPassword(t *testing.T) []byte {
	t.Helper()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal("generate Product SQL password")
	}
	password := make([]byte, hex.EncodedLen(len(random)))
	hex.Encode(password, random)
	clear(random)
	return password
}

func slice6CreateProductSQLRole(ctx context.Context, serverID, role, connectionLimit string,
	password []byte, validUntil time.Time) error {
	if ctx == nil || ctx.Err() != nil || len(serverID) != 64 || !lowerHexSlice6(serverID) ||
		(role != "product_migrator" && role != "product_runtime") ||
		(role == "product_migrator" && connectionLimit != "1") ||
		(role == "product_runtime" && connectionLimit != "4") || len(password) != 64 ||
		validUntil.Before(time.Now().UTC().Add(10*time.Minute)) ||
		validUntil.After(time.Now().UTC().Add(time.Hour)) {
		return errors.New("invalid Product SQL role bootstrap input")
	}
	for _, value := range password {
		if value < '0' || value > '9' && (value < 'a' || value > 'f') {
			return errors.New("invalid Product SQL password representation")
		}
	}
	input := make([]byte, 0, 2*(len(password)+1))
	input = append(input, password...)
	input = append(input, '\n')
	input = append(input, password...)
	input = append(input, '\n')
	defer clear(input)
	command := exec.CommandContext(ctx, "docker", "exec", "-i", "-u", "70:70", serverID,
		"createuser", "--pwprompt", "--no-superuser", "--no-createdb", "--no-createrole",
		"--no-replication", "--no-bypassrls", "--no-inherit", "--login",
		"--connection-limit="+connectionLimit,
		"--valid-until="+validUntil.Format("2006-01-02 15:04:05+00"),
		"--host=/var/run/postgresql", "--username=postgres", "--no-password", role)
	command.Stdin = bytes.NewReader(input)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Run() != nil {
		return errors.New("native Product SQL role creation failed")
	}
	return nil
}

func slice6ProductBoundDSN(host string, port int, database, role string, password []byte) []byte {
	var document []byte
	document = append(document, "postgres://"...)
	document = append(document, role...)
	document = append(document, ':')
	document = append(document, password...)
	document = append(document, '@')
	document = append(document, host...)
	document = append(document, ':')
	document = append(document, strconv.Itoa(port)...)
	document = append(document, '/')
	document = append(document, database...)
	document = append(document, "?sslmode=verify-full"...)
	return document
}

func slice6ProductSQLExec(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, database, statement string) {
	t.Helper()
	if _, err := run.docker(ctx, "exec", "-u", "70:70", serverID,
		"psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
		"-d", database, "-c", statement); err != nil {
		t.Fatal("fixed operator PostgreSQL bootstrap SQL failed")
	}
}

func slice6ProductSQLExpect(t *testing.T, ctx context.Context, run slice6DockerRun,
	serverID, database, statement, expected string) {
	t.Helper()
	actual, err := run.docker(ctx, "exec", "-u", "70:70", serverID,
		"psql", "-X", "-w", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
		"-d", database, "-At", "-c", statement)
	if err != nil || strings.TrimSpace(string(actual)) != expected {
		t.Fatal("fixed operator PostgreSQL bootstrap readback drifted")
	}
}

func slice6VerifyProductSQLBootstrap(t *testing.T, ctx context.Context,
	run slice6DockerRun, serverID string) {
	t.Helper()
	for _, role := range []string{"product_migrator", "product_runtime"} {
		slice6ProductSQLExpect(t, ctx, run, serverID, "postgres",
			"SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolinherit,rolconnlimit FROM pg_roles WHERE rolname='"+role+"'",
			map[string]string{"product_migrator": "t|f|f|f|f|f|f|1", "product_runtime": "t|f|f|f|f|f|f|4"}[role])
		slice6ProductSQLExpect(t, ctx, run, serverID, "postgres",
			"SELECT rolpassword LIKE 'SCRAM-SHA-256$%' AND rolvaliduntil>now() FROM pg_authid WHERE rolname='"+role+"'", "t")
		slice6ProductSQLExpect(t, ctx, run, serverID, "postgres",
			"SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='"+role+"') OR roleid=(SELECT oid FROM pg_roles WHERE rolname='"+role+"')", "0")
		slice6ProductSQLExpect(t, ctx, run, serverID, "postgres",
			"SELECT has_database_privilege('"+role+"','product','CONNECT'),has_database_privilege('"+role+"','product','CREATE'),has_database_privilege('"+role+"','product','TEMP')", "t|f|f")
		for _, other := range []string{"postgres", "template1"} {
			slice6ProductSQLExpect(t, ctx, run, serverID, "postgres",
				"SELECT has_database_privilege('"+role+"','"+other+"','CONNECT')", "f")
		}
		slice6ProductSQLExpect(t, ctx, run, serverID, "product",
			"SELECT has_schema_privilege('"+role+"','public','CREATE')", "f")
	}
	slice6ProductSQLExpect(t, ctx, run, serverID, "product",
		"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='product'", "postgres")
	slice6ProductSQLExpect(t, ctx, run, serverID, "product",
		"SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='sandbox_runtime_product'", "postgres")
	slice6ProductSQLExpect(t, ctx, run, serverID, "product",
		"SELECT has_schema_privilege('product_migrator','sandbox_runtime_product','USAGE'),has_schema_privilege('product_migrator','sandbox_runtime_product','CREATE')", "t|t")
	slice6ProductSQLExpect(t, ctx, run, serverID, "product",
		"SELECT has_schema_privilege('product_runtime','sandbox_runtime_product','USAGE'),has_schema_privilege('product_runtime','sandbox_runtime_product','CREATE')", "f|f")
	slice6ProductSQLExpect(t, ctx, run, serverID, "product",
		"SELECT count(*) FROM pg_catalog.aclexplode((SELECT datacl FROM pg_database WHERE datname='product')) WHERE grantee=0", "0")
	slice6ProductSQLExpect(t, ctx, run, serverID, "product",
		"SELECT count(*) FROM pg_catalog.aclexplode((SELECT nspacl FROM pg_namespace WHERE nspname='sandbox_runtime_product')) WHERE grantee=0", "0")
}

func TestSlice6ProductSQLRoleInputFailsBeforeDocker(t *testing.T) {
	server := strings.Repeat("a", 64)
	password := []byte(strings.Repeat("b", 64))
	expiry := time.Now().UTC().Add(30 * time.Minute)
	for _, candidate := range []struct {
		server, role, limit string
		password            []byte
		expiry              time.Time
	}{
		{"container", "product_migrator", "1", password, expiry},
		{server, "postgres", "1", password, expiry},
		{server, "product_migrator", "4", password, expiry},
		{server, "product_runtime", "1", password, expiry},
		{server, "product_runtime", "4", []byte("not-a-password"), expiry},
		{server, "product_runtime", "4", []byte(strings.Repeat("g", 64)), expiry},
		{server, "product_runtime", "4", password, time.Now().UTC().Add(time.Minute)},
	} {
		if err := slice6CreateProductSQLRole(t.Context(), candidate.server, candidate.role,
			candidate.limit, candidate.password, candidate.expiry); err == nil {
			t.Fatal("unsafe SQL role input reached Docker")
		}
	}
}
