//go:build integration

package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
)

const productProcessPostgresImage = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"

func TestProductProcessDevelopmentIntegration(t *testing.T) {
	if os.Getenv("SANDBOX_RUNTIME_PRODUCT_PROCESS_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PRODUCT_PROCESS_INTEGRATION=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	runID := fmt.Sprintf("phase6-product-%d-%d", time.Now().UnixNano(), os.Getpid())
	container := "sandbox-runtime-" + runID
	removeContainer := func() { _ = exec.Command("docker", "rm", "-f", container).Run() }
	t.Cleanup(removeContainer)

	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container,
		"-e", "POSTGRES_PASSWORD=phase6", "-e", "POSTGRES_DB=phase6",
		"-p", "127.0.0.1::5432", productProcessPostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start PostgreSQL: %v: %s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, postgresPort, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	dsn := "postgres://postgres:phase6@127.0.0.1:" + postgresPort + "/phase6?sslmode=disable"
	waitForPostgres(t, ctx, dsn)

	directory := t.TempDir()
	dsnPath := filepath.Join(directory, "postgres.dsn")
	identityPath := filepath.Join(directory, "identities.json")
	configPath := filepath.Join(directory, "config.toml")
	logPath := filepath.Join(directory, "product.log")
	binaryPath := filepath.Join(directory, "sandbox-runtime")
	productPort := reserveLoopbackPort(t)
	token := "phase6-product-process-token-000001"
	writePrivateIntegrationFile(t, dsnPath, dsn+"\n")
	identity := fmt.Sprintf(`{"version":"sandbox-runtime-product-static-identities-v1","bindings":[{"token":%q,"tenant_id":"tenant-phase6","actor_type":"human","actor_id":"actor-phase6","role":"owner"}]}`, token)
	writePrivateIntegrationFile(t, identityPath, identity)
	configuration := fmt.Sprintf(`[application]
mode = "development"

[logger]
level = "error"

[product_process]
schema_version = "sandbox-runtime.product-process.legacy-development.v1"
enabled = true
deployment_level = "development"

[product_process.api]
host = "127.0.0.1"
port = %d

[product_process.postgres]
dsn_file = %q
startup_timeout_seconds = 10
operation_timeout_seconds = 2
max_connections = 4
min_connections = 1

[product_process.identity]
bindings_file = %q
`, productPort, dsnPath, identityPath)
	writePrivateIntegrationFile(t, configPath, configuration)

	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, "..").CombinedOutput(); err != nil {
		t.Fatalf("build Product process: %v: %s", err, output)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process := exec.CommandContext(ctx, binaryPath, "product", "serve", "-c", configPath)
	process.Stdout = logFile
	process.Stderr = logFile
	if err := process.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	t.Cleanup(func() {
		if process.Process != nil {
			_ = process.Process.Kill()
		}
		select {
		case <-processDone:
		default:
		}
		_ = logFile.Close()
	})

	baseURL := "http://127.0.0.1:" + strconv.Itoa(productPort)
	waitForHTTPStatus(t, processDone, baseURL+"/livez", "", http.StatusOK)
	waitForHTTPStatus(t, processDone, baseURL+"/readyz", "", http.StatusOK)
	status, body := productRequest(t, http.MethodGet, baseURL+"/api/v1/capabilities", token, "", "")
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"capabilities":[]`)) {
		t.Fatalf("capabilities status=%d body=%s", status, body)
	}
	createBody := `{"display_name":"denied","lifetime_seconds":3600,"primary_slot":{"slot_key":"primary-code","kind":"code","profile_id":"coding-shell-v1","required_capabilities":[{"capability_id":"sandbox.exec","version":"1.0.0","profile_id":"exec-v1"}],"desired_state":"ready"}}`
	status, body = productRequest(t, http.MethodPost, baseURL+"/api/v1/workspaces", token, "phase6-create-1", createBody)
	if status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte(`"code":"PRODUCT_CAPABILITY_UNSUPPORTED"`)) {
		t.Fatalf("create status=%d body=%s", status, body)
	}
	assertProductProcessDatabaseState(t, ctx, dsn)

	if output, err := exec.CommandContext(ctx, "docker", "stop", "--time", "5", container).CombinedOutput(); err != nil {
		t.Fatalf("stop PostgreSQL: %v: %s", err, output)
	}
	waitForHTTPStatus(t, processDone, baseURL+"/readyz", "", http.StatusServiceUnavailable)

	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("Product process exit: %v; log=%s", err, readIntegrationLog(logPath))
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Product process did not stop; log=%s", readIntegrationLog(logPath))
	}
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	removeContainer()
	output, err = exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/"+container+"$", "--format", "{{.Names}}").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("PostgreSQL container retained: err=%v output=%s", err, output)
	}
}

func TestProductProcessProductionKernelIntegration(t *testing.T) { //nolint:maintidx
	if os.Getenv("SANDBOX_RUNTIME_PRODUCT_PROCESS_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PRODUCT_PROCESS_INTEGRATION=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	runID := fmt.Sprintf("phase6-product-production-%d-%d", time.Now().UnixNano(), os.Getpid())
	container := "sandbox-runtime-" + runID
	removeContainer := func() { _ = exec.Command("docker", "rm", "-f", container).Run() }
	t.Cleanup(removeContainer)
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container,
		"-e", "POSTGRES_PASSWORD=phase6-production", "-e", "POSTGRES_DB=phase6",
		"-p", "127.0.0.1::5432", productProcessPostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start PostgreSQL: %v: %s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, postgresPort, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := "postgres://postgres:phase6-production@127.0.0.1:" + postgresPort + "/phase6?sslmode=disable"
	waitForPostgres(t, ctx, adminDSN)
	adminPool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	if _, err := adminPool.Exec(ctx, `CREATE ROLE product_migrator LOGIN PASSWORD 'migration-secret'; CREATE ROLE product_runtime LOGIN PASSWORD 'runtime-secret'; GRANT CREATE ON DATABASE phase6 TO product_migrator`); err != nil {
		t.Fatal(err)
	}
	migrationDSN := "postgres://product_migrator:migration-secret@127.0.0.1:" + postgresPort + "/phase6?sslmode=disable"
	runtimeDSN := "postgres://product_runtime:runtime-secret@127.0.0.1:" + postgresPort + "/phase6?sslmode=disable"

	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.toml")
	migrationConfigPath := filepath.Join(directory, "migration.toml")
	logPath := filepath.Join(directory, "product.log")
	migrationLogPath := filepath.Join(directory, "migration.log")
	binaryPath := filepath.Join(directory, "sandbox-runtime")
	fixturePath := filepath.Join(directory, "workload-material-agent-static-fixture")
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, "..").CombinedOutput(); err != nil {
		t.Fatalf("build Product process: %v: %s", err, output)
	}
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", fixturePath, "./workload-material-agent-static-fixture").CombinedOutput(); err != nil {
		t.Fatalf("build workload material fixture: %v: %s", err, output)
	}
	rootPool, tokenPrivateKey, certificatePEM, privateKeyPEM, keyRing := productionIdentityMaterial(t)
	allMaterials := productIntegrationMaterials(t, migrationDSN+"\n", runtimeDSN+"\n", certificatePEM, privateKeyPEM, keyRing)
	migrationMaterials := selectProductIntegrationMaterials(t, allMaterials, secretref.PurposePostgresMigrationDSN)
	runtimeMaterials := selectProductIntegrationMaterials(t, allMaterials, secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey, secretref.PurposePostgresRuntimeDSN, secretref.PurposeIdentityKeyRing)
	migrationAgentDirectory := shortProductAgentDirectory(t)
	runtimeAgentDirectory := shortProductAgentDirectory(t)
	migrationAgentSocket := filepath.Join(migrationAgentDirectory, "migration.sock")
	runtimeAgentSocket := filepath.Join(runtimeAgentDirectory, "runtime.sock")
	productPort := reserveLoopbackPort(t)
	configuration := fmt.Sprintf(`[application]
mode = "production"

[logger]
level = "error"

[product_process]
schema_version = %q
enabled = true
deployment_level = "production"

[product_process.api]
host = "127.0.0.1"
port = %d

[product_process.tls]
certificate_binding_id = "product-tls-certificate"
private_key_binding_id = "product-tls-private-key"
expected_server_name = "product.example.test"

[product_process.postgres]
runtime_dsn_binding_id = "product-runtime-dsn"
runtime_role = "product_runtime"
startup_timeout_seconds = 10
operation_timeout_seconds = 2
max_connections = 2
min_connections = 1

[product_process.identity]
issuer = "https://identity.product.example.test"
audience = "https://api.product.example.test"
key_ring_binding_id = "product-identity-key-ring"
clock_skew_seconds = 30
max_token_lifetime_seconds = 900

[product_process.materials.provider]
type = %q
alias = "product-material-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 1

%s`, config.ProductProductionSchemaV2, productPort, config.ProductUnixMaterialProviderV1, runtimeAgentSocket, os.Getuid(), os.Getgid(), productIntegrationBindingsTOML(t, "product_process", "product-material-agent", runtimeMaterials))
	writePrivateIntegrationFile(t, configPath, configuration)
	migrationConfiguration := fmt.Sprintf(`[application]
mode = "production"

[logger]
level = "error"

[product_migration]
schema_version = %q
enabled = true

[product_migration.postgres]
dsn_binding_id = "product-migration-dsn"
role = "product_migrator"
startup_timeout_seconds = 10
max_connections = 1

[product_migration.materials.provider]
type = %q
alias = "product-migration-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 0

%s`, config.ProductMigrationSchemaV1, config.ProductUnixMaterialProviderV1, migrationAgentSocket, os.Getuid(), os.Getgid(), productIntegrationBindingsTOML(t, "product_migration", "product-migration-agent", migrationMaterials))
	writePrivateIntegrationFile(t, migrationConfigPath, migrationConfiguration)

	preMigrationAgent := startStaticProductMaterialAgent(t, ctx, fixturePath, runtimeAgentSocket, runtimeMaterials, 0)
	assertProductAgentRejectsBinding(t, runtimeAgentSocket, migrationMaterials[0].Binding)
	assertProductServeFailsBeforeBind(t, ctx, binaryPath, configPath, productPort)
	preMigrationAgent.stop(t)
	migrationAgent := startStaticProductMaterialAgent(t, ctx, fixturePath, migrationAgentSocket, migrationMaterials, 1)
	assertProductAgentRejectsBinding(t, migrationAgentSocket, runtimeMaterials[0].Binding)
	runProductMigrationProcess(t, ctx, binaryPath, migrationConfigPath, migrationLogPath, migrationAgent)
	migrationAgent.waitOneShot(t)
	assertNoMigrationRoleConnection(t, ctx, adminPool)
	if _, err := workloadagent.NewProduction(workloadagent.Config{SocketPath: migrationAgentSocket, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: secretref.RoleProduct, OperationTimeout: time.Second, Now: time.Now}); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("migration agent reconnect error = %v", err)
	}
	if _, err := adminPool.Exec(ctx, `GRANT USAGE ON SCHEMA sandbox_runtime_product TO product_runtime;
GRANT SELECT ON sandbox_runtime_product.schema_migrations TO product_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sandbox_runtime_product TO product_runtime;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON sandbox_runtime_product.schema_migrations FROM product_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE product_migrator IN SCHEMA sandbox_runtime_product GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO product_runtime`); err != nil {
		t.Fatal(err)
	}
	assertRuntimeRoleCannotMigrate(t, ctx, runtimeDSN)
	assertRuntimePoolExhaustionIsBounded(t, ctx, runtimeDSN)
	assertSchemaCompatibilityRejectsNewer(t, ctx, migrationDSN, runtimeDSN)
	agent := startStaticProductMaterialAgent(t, ctx, fixturePath, runtimeAgentSocket, runtimeMaterials, 0)
	t.Cleanup(func() { agent.stop(t) })
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process, processDone := startProductIntegrationProcess(t, ctx, binaryPath, configPath, logFile)
	t.Cleanup(func() {
		if process.Process != nil {
			_ = process.Process.Kill()
		}
		select {
		case <-processDone:
		default:
		}
		_ = logFile.Close()
	})

	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: rootPool, ServerName: "product.example.test",
	}}}
	baseURL := "https://127.0.0.1:" + strconv.Itoa(productPort)
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/livez", "", http.StatusOK)
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/readyz", "", http.StatusOK)
	token := signProductionToken(t, tokenPrivateKey, time.Now())
	status, body := productRequestWithClient(t, client, http.MethodPost, baseURL+"/api/v1/workspaces", "invalid", "bad", `{"unknown":true}`)
	if status != http.StatusUnauthorized || !bytes.Contains(body, []byte(`"code":"PRODUCT_UNAUTHENTICATED"`)) {
		t.Fatalf("auth precedence status=%d body=%s", status, body)
	}
	status, body = productRequestWithClient(t, client, http.MethodGet, baseURL+"/api/v1/capabilities", token, "", "")
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"capability_id":"product.workspace"`)) || !bytes.Contains(body, []byte(`"readiness":"unavailable"`)) {
		t.Fatalf("capabilities status=%d body=%s", status, body)
	}
	createBody := `{"display_name":"denied","lifetime_seconds":3600,"primary_slot":{"slot_key":"primary-code","kind":"code","profile_id":"coding-shell-v1","required_capabilities":[{"capability_id":"sandbox.exec","version":"1.0.0","profile_id":"exec-v1"}],"desired_state":"ready"}}`
	status, body = productRequestWithClient(t, client, http.MethodPost, baseURL+"/api/v1/workspaces", token, "phase6-production-create-1", createBody)
	if status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte(`"code":"PRODUCT_CAPABILITY_UNSUPPORTED"`)) {
		t.Fatalf("create status=%d body=%s", status, body)
	}
	assertProductProcessDatabaseState(t, ctx, adminDSN)
	assertNoMigrationRoleConnection(t, ctx, adminPool)
	if status, _ := productRequestWithClient(t, http.DefaultClient, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(productPort)+"/livez", "", "", ""); status != 0 && status != http.StatusBadRequest {
		t.Fatalf("plaintext Product request status=%d, want TLS transport rejection", status)
	}

	if output, err := exec.CommandContext(ctx, "docker", "pause", container).CombinedOutput(); err != nil {
		t.Fatalf("pause PostgreSQL: %v: %s", err, output)
	}
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/readyz", "", http.StatusServiceUnavailable)
	if output, err := exec.CommandContext(ctx, "docker", "unpause", container).CombinedOutput(); err != nil {
		t.Fatalf("unpause PostgreSQL: %v: %s", err, output)
	}
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/readyz", "", http.StatusOK)
	agent.stop(t)
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/readyz", "", http.StatusServiceUnavailable)
	agent = startStaticProductMaterialAgent(t, ctx, fixturePath, runtimeAgentSocket, runtimeMaterials, 0)
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/readyz", "", http.StatusOK)
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("Product process pre-restart exit: %v; log=%s", err, readIntegrationLog(logPath))
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Product process pre-restart did not stop; log=%s", readIntegrationLog(logPath))
	}
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	logFile, err = os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process, processDone = startProductIntegrationProcess(t, ctx, binaryPath, configPath, logFile)
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/livez", "", http.StatusOK)
	waitForHTTPStatusWithClient(t, processDone, client, baseURL+"/readyz", "", http.StatusOK)
	status, body = productRequestWithClient(t, client, http.MethodGet, baseURL+"/api/v1/capabilities", token, "", "")
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"readiness":"unavailable"`)) {
		t.Fatalf("post-restart capabilities status=%d body=%s", status, body)
	}
	assertNoMigrationRoleConnection(t, ctx, adminPool)

	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-processDone:
		if err != nil {
			t.Fatalf("Product process exit: %v; log=%s", err, readIntegrationLog(logPath))
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Product process did not stop; log=%s", readIntegrationLog(logPath))
	}
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	logDocument, _ := os.ReadFile(logPath)
	migrationLogDocument, _ := os.ReadFile(migrationLogPath)
	for _, forbidden := range []string{"phase6-production", "migration-secret", "runtime-secret", token, "PRIVATE KEY"} {
		if bytes.Contains(logDocument, []byte(forbidden)) || bytes.Contains(migrationLogDocument, []byte(forbidden)) {
			t.Fatalf("Product log disclosed protected material %q", forbidden)
		}
	}
	agent.stop(t)
	removeContainer()
	output, err = exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/"+container+"$", "--format", "{{.Names}}").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("PostgreSQL container retained: err=%v output=%s", err, output)
	}
}

func waitForPostgres(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			err = pool.Ping(ctx)
			pool.Close()
		}
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("PostgreSQL did not become ready")
}

func reserveLoopbackPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func writePrivateIntegrationFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForHTTPStatus(t *testing.T, processDone <-chan error, endpoint, token string, want int) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-processDone:
			t.Fatalf("Product process stopped while waiting for %s: %v", endpoint, err)
		default:
		}
		status, _ := productRequest(t, http.MethodGet, endpoint, token, "", "")
		if status == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s status %d", endpoint, want)
}

func productRequest(t *testing.T, method, endpoint, token, idempotencyKey, body string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, responseBody
}

func assertProductProcessDatabaseState(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var migrations, workspaces int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sandbox_runtime_product.workspaces`).Scan(&workspaces); err != nil {
		t.Fatal(err)
	}
	if migrations != 13 || workspaces != 0 {
		t.Fatalf("migrations=%d workspaces=%d, want 13/0", migrations, workspaces)
	}
}

func readIntegrationLog(path string) string {
	document, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	var decoded any
	if json.Unmarshal(document, &decoded) == nil {
		return "<structured log omitted>"
	}
	return string(document)
}

func startProductIntegrationProcess(t *testing.T, ctx context.Context, binaryPath, configPath string, logFile *os.File) (*exec.Cmd, <-chan error) {
	t.Helper()
	process := exec.CommandContext(ctx, binaryPath, "product", "serve", "-c", configPath)
	process.Stdout = logFile
	process.Stderr = logFile
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- process.Wait() }()
	return process, processDone
}

func runProductMigrationProcess(t *testing.T, ctx context.Context, binaryPath, configPath, logPath string, agent *runningStaticProductAgent) {
	t.Helper()
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process := exec.CommandContext(ctx, binaryPath, "product", "migrate", "-c", configPath)
	process.Stdout = logFile
	process.Stderr = logFile
	if err := process.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	if agent == nil || agent.command == nil || agent.command.Process == nil || process.Process.Pid == agent.command.Process.Pid {
		_ = process.Process.Kill()
		_ = logFile.Close()
		t.Fatal("Product migration and migration agent are not distinct OS processes")
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			_ = logFile.Close()
			t.Fatalf("Product migration process exit: %v; log=%s", err, readIntegrationLog(logPath))
		}
	case <-time.After(20 * time.Second):
		_ = process.Process.Kill()
		_ = logFile.Close()
		t.Fatal("Product migration process did not stop")
	}
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	t.Log("migration agent and migration job used distinct OS processes; distinct_os_uid_established=false")
}

func assertProductServeFailsBeforeBind(t *testing.T, ctx context.Context, binaryPath, configPath string, port int) {
	t.Helper()
	command := exec.CommandContext(ctx, binaryPath, "product", "serve", "-c", configPath)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("Product runtime started before the explicit migration job")
	}
	for _, forbidden := range []string{"migration-secret", "runtime-secret", "PRIVATE KEY"} {
		if bytes.Contains(output, []byte(forbidden)) {
			t.Fatalf("failed Product startup disclosed protected material %q", forbidden)
		}
	}
	connection, dialErr := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
	if dialErr == nil {
		_ = connection.Close()
		t.Fatal("Product listener bound before schema migration")
	}
}

func assertProductAgentRejectsBinding(t *testing.T, socketPath string, binding secretref.Binding) {
	t.Helper()
	client, err := workloadagent.NewProduction(workloadagent.Config{
		SocketPath: socketPath, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		OperationTimeout: time.Second, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResolveSecret(context.Background(), binding); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("cross-purpose Product agent binding error = %v", err)
	}
}

func waitForHTTPStatusWithClient(t *testing.T, processDone <-chan error, client *http.Client, endpoint, token string, want int) {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-processDone:
			t.Fatalf("Product process stopped while waiting for %s: %v", endpoint, err)
		default:
		}
		status, _ := productRequestWithClient(t, client, http.MethodGet, endpoint, token, "", "")
		if status == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s status %d", endpoint, want)
}

func productRequestWithClient(t *testing.T, client *http.Client, method, endpoint, token, idempotencyKey, body string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, responseBody
}

func assertRuntimeRoleCannotMigrate(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TABLE sandbox_runtime_product.runtime_must_not_create (id bigint)`); err == nil {
		t.Fatal("runtime database role retained DDL authority")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sandbox_runtime_product.schema_migrations(version,digest) VALUES (999,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err == nil {
		t.Fatal("runtime database role retained migration-ledger write authority")
	}
}

func assertRuntimePoolExhaustionIsBounded(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	configuration, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	configuration.MaxConns = 1
	configuration.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	connection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	acquireContext, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := pool.Acquire(acquireContext); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exhausted pool acquisition error = %v", err)
	}
}

func assertSchemaCompatibilityRejectsNewer(t *testing.T, ctx context.Context, migrationDSN, runtimeDSN string) {
	t.Helper()
	migrationPool, err := pgxpool.New(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationPool.Close()
	runtimePool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimePool.Close()
	if _, err := migrationPool.Exec(ctx, `INSERT INTO sandbox_runtime_product.schema_migrations(version,digest) VALUES (999,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err != nil {
		t.Fatal(err)
	}
	if err := productpostgres.VerifySchemaCompatibility(ctx, runtimePool); err == nil {
		t.Fatal("runtime accepted a newer Product schema")
	}
	if _, err := migrationPool.Exec(ctx, `DELETE FROM sandbox_runtime_product.schema_migrations WHERE version=999`); err != nil {
		t.Fatal(err)
	}
	if err := productpostgres.VerifySchemaCompatibility(ctx, runtimePool); err != nil {
		t.Fatalf("runtime rejected restored exact Product schema: %v", err)
	}
}

func assertNoMigrationRoleConnection(t *testing.T, ctx context.Context, adminPool *pgxpool.Pool) {
	t.Helper()
	var count int
	if err := adminPool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename='product_migrator'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("migration role connections retained after startup: %d", count)
	}
}

func productionIdentityMaterial(t *testing.T) (*x509.CertPool, ed25519.PrivateKey, []byte, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Product integration CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "product.example.test"},
		DNSNames: []string{"product.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, serverPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	encodedPrivateKey, err := x509.MarshalPKCS8PrivateKey(serverPrivate)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivateKey})
	rootPool := x509.NewCertPool()
	rootPool.AddCert(caCertificate)
	tokenPublic, tokenPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyRing, err := json.Marshal(map[string]any{
		"version": "sandbox-runtime-product-access-key-ring-v1",
		"keys": []map[string]any{{"kid": "product-integration-2026-09", "alg": "EdDSA", "public_key": base64.RawURLEncoding.EncodeToString(tokenPublic),
			"not_before": now.Add(-time.Hour).Format(time.RFC3339), "not_after": now.Add(time.Hour).Format(time.RFC3339)}},
		"revoked_key_ids": []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rootPool, tokenPrivate, certificatePEM, privateKeyPEM, keyRing
}

func productIntegrationMaterials(t *testing.T, migrationDSN, runtimeDSN string, certificatePEM, privateKeyPEM, keyRing []byte) []secretref.SecretMaterial {
	t.Helper()
	bindings := []secretref.Binding{
		{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-tls-certificate", Version: "v1", Purpose: secretref.PurposeTLSCertificate, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-tls-private-key", Version: "v1", Purpose: secretref.PurposeTLSPrivateKey, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-migration-dsn", Version: "v1", Purpose: secretref.PurposePostgresMigrationDSN, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-runtime-dsn", Version: "v1", Purpose: secretref.PurposePostgresRuntimeDSN, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
		{Schema: secretref.BindingSchema, Kind: secretref.KindSecret, Reference: "secret://vault/kv/product-identity-key-ring", Version: "v1", Purpose: secretref.PurposeIdentityKeyRing, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct},
	}
	values := [][]byte{certificatePEM, privateKeyPEM, []byte(migrationDSN), []byte(runtimeDSN), keyRing}
	now := time.Now().UTC()
	materials := make([]secretref.SecretMaterial, 0, len(bindings))
	for index, binding := range bindings {
		if err := binding.Validate(); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(values[index])
		materials = append(materials, secretref.SecretMaterial{
			Binding: binding, Bytes: append([]byte(nil), values[index]...), Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1",
			Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive},
		})
	}
	return materials
}

func selectProductIntegrationMaterials(t *testing.T, materials []secretref.SecretMaterial, purposes ...secretref.Purpose) []secretref.SecretMaterial {
	t.Helper()
	selected := make([]secretref.SecretMaterial, 0, len(purposes))
	for _, purpose := range purposes {
		found := false
		for _, material := range materials {
			if material.Binding.Purpose == purpose {
				copy := material
				copy.Bytes = append([]byte(nil), material.Bytes...)
				selected = append(selected, copy)
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing Product integration material purpose %q", purpose)
		}
	}
	return selected
}

func productIntegrationBindingsTOML(t *testing.T, section, provider string, materials []secretref.SecretMaterial) string {
	t.Helper()
	var builder strings.Builder
	for _, material := range materials {
		bindingID := productIntegrationBindingID(t, material.Binding.Purpose)
		document, err := json.Marshal(material.Binding)
		if err != nil {
			t.Fatal(err)
		}
		builder.WriteString("[[")
		builder.WriteString(section)
		builder.WriteString(".materials.bindings]]\nid = ")
		encodedID, _ := json.Marshal(bindingID)
		builder.Write(encodedID)
		builder.WriteString("\nprovider = ")
		encodedProvider, _ := json.Marshal(provider)
		builder.Write(encodedProvider)
		builder.WriteString("\ndocument = '")
		builder.Write(document)
		builder.WriteString("'\n\n")
	}
	return builder.String()
}

func productIntegrationBindingID(t *testing.T, purpose secretref.Purpose) string {
	t.Helper()
	switch purpose {
	case secretref.PurposeTLSCertificate:
		return "product-tls-certificate"
	case secretref.PurposeTLSPrivateKey:
		return "product-tls-private-key"
	case secretref.PurposePostgresMigrationDSN:
		return "product-migration-dsn"
	case secretref.PurposePostgresRuntimeDSN:
		return "product-runtime-dsn"
	case secretref.PurposeIdentityKeyRing:
		return "product-identity-key-ring"
	default:
		t.Fatalf("unsupported Product integration material purpose %q", purpose)
		return ""
	}
}

type staticAgentInput struct {
	Protocol          string                `json:"protocol"`
	SocketPath        string                `json:"socket_path"`
	ExpectedClientUID uint32                `json:"expected_client_uid"`
	ExpectedClientGID uint32                `json:"expected_client_gid"`
	Role              secretref.Role        `json:"role"`
	MaxConnections    int                   `json:"max_connections"`
	MaxResolutions    int                   `json:"max_resolutions"`
	Materials         []staticAgentMaterial `json:"materials"`
}

type staticAgentMaterial struct {
	Binding   secretref.Binding  `json:"binding"`
	Revision  string             `json:"revision"`
	Digest    string             `json:"digest"`
	State     secretref.KeyState `json:"state"`
	NotBefore string             `json:"not_before"`
	NotAfter  string             `json:"not_after"`
	Material  []byte             `json:"material"`
}

type runningStaticProductAgent struct {
	command *exec.Cmd
	done    chan error
	stderr  *bytes.Buffer
	socket  string
	stopped bool
}

func startStaticProductMaterialAgent(t *testing.T, parent context.Context, binary, socketPath string, materials []secretref.SecretMaterial, maxResolutions int) *runningStaticProductAgent {
	t.Helper()
	input := staticAgentInput{
		Protocol: "sandbox-runtime.workload-material-static-fixture.v1", SocketPath: socketPath,
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		MaxConnections: 8, MaxResolutions: maxResolutions, Materials: make([]staticAgentMaterial, 0, len(materials)),
	}
	for _, material := range materials {
		input.Materials = append(input.Materials, staticAgentMaterial{
			Binding: material.Binding, Revision: material.Revision, Digest: material.Digest, State: material.Window.State,
			NotBefore: material.Window.NotBefore.UTC().Format(time.RFC3339Nano), NotAfter: material.Window.NotAfter.UTC().Format(time.RFC3339Nano),
			Material: append([]byte(nil), material.Bytes...),
		})
	}
	document, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for index := range input.Materials {
		clear(input.Materials[index].Material)
	}
	command := exec.CommandContext(parent, binary)
	stdin, err := command.StdinPipe()
	if err != nil {
		clear(document)
		t.Fatal(err)
	}
	stderr := new(bytes.Buffer)
	command.Stdout = io.Discard
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		clear(document)
		t.Fatal(err)
	}
	if _, err := stdin.Write(document); err != nil {
		clear(document)
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	clear(document)
	if err := stdin.Close(); err != nil {
		_ = command.Process.Kill()
		t.Fatal(err)
	}
	agent := &runningStaticProductAgent{command: command, done: make(chan error, 1), stderr: stderr, socket: socketPath}
	go func() { agent.done <- command.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if info, statErr := os.Lstat(socketPath); statErr == nil && info.Mode()&os.ModeSocket != 0 {
			return agent
		}
		select {
		case processErr := <-agent.done:
			agent.stopped = true
			t.Fatalf("static Product material agent exited before ready: %v; stderr=%s", processErr, agent.stderr.String())
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = command.Process.Kill()
	t.Fatal("static Product material agent did not create its socket")
	return nil
}

func (a *runningStaticProductAgent) stop(t *testing.T) {
	t.Helper()
	if a == nil || a.stopped {
		return
	}
	if err := a.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-a.done:
		if err != nil {
			t.Fatalf("Product material agent exit: %v; stderr=%s", err, a.stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Product material agent did not stop")
	}
	a.stopped = true
	if _, err := os.Lstat(a.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Product material agent socket cleanup = %v", err)
	}
}

func (a *runningStaticProductAgent) waitOneShot(t *testing.T) {
	t.Helper()
	if a == nil || a.stopped {
		return
	}
	select {
	case err := <-a.done:
		if err != nil {
			t.Fatalf("one-shot Product migration agent exit: %v; stderr=%s", err, a.stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("one-shot Product migration agent did not exit")
	}
	a.stopped = true
	if _, err := os.Lstat(a.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("one-shot Product migration socket cleanup = %v", err)
	}
}

func shortProductAgentDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-product-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	return directory
}

func signProductionToken(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "product-integration-2026-09", "typ": "sandbox-runtime-product-access+jwt"})
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://identity.product.example.test", "aud": "https://api.product.example.test", "sub": "actor-production",
		"tenant_id": "tenant-production", "actor_type": "human", "actor_id": "actor-production", "role": "owner",
		"iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": "phase6-production-jti-0001",
	})
	first := base64.RawURLEncoding.EncodeToString(header)
	second := base64.RawURLEncoding.EncodeToString(claims)
	signature := ed25519.Sign(privateKey, []byte(first+"."+second))
	return first + "." + second + "." + base64.RawURLEncoding.EncodeToString(signature)
}
