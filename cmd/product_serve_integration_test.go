//go:build integration

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
