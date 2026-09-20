//go:build integration

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const providerProcessCodingImage = "ghcr.io/shell-echo/sandbox-runtime-coding-shell@sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1"

func TestProviderProcessProductionIntegration(t *testing.T) { //nolint:maintidx
	if os.Getenv("SANDBOX_RUNTIME_PROVIDER_PROCESS_INTEGRATION") != "1" {
		t.Skip("set SANDBOX_RUNTIME_PROVIDER_PROCESS_INTEGRATION=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is required")
	}
	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatal("true executable is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	runID := fmt.Sprintf("phase6-provider-%d-%d", time.Now().UnixNano(), os.Getpid())
	container := "sandbox-runtime-" + runID
	removeContainer := func() { _ = exec.Command("docker", "rm", "-f", container).Run() }
	t.Cleanup(removeContainer)
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container,
		"-e", "POSTGRES_PASSWORD=phase6-provider", "-e", "POSTGRES_DB=provider",
		"-p", "127.0.0.1::5432", productProcessPostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start PostgreSQL: %v: %s", err, output)
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, postgresPort, err := netSplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := "postgres://postgres:phase6-provider@127.0.0.1:" + postgresPort + "/provider?sslmode=disable"
	waitForPostgres(t, ctx, adminDSN)
	adminPool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	if _, err := adminPool.Exec(ctx, `CREATE ROLE provider_migrator LOGIN PASSWORD 'provider-migration-secret'; CREATE ROLE provider_runtime LOGIN PASSWORD 'provider-runtime-secret'; GRANT CREATE ON DATABASE provider TO provider_migrator`); err != nil {
		t.Fatal(err)
	}
	migrationDSN := "postgres://provider_migrator:provider-migration-secret@127.0.0.1:" + postgresPort + "/provider?sslmode=disable"
	runtimeDSN := "postgres://provider_runtime:provider-runtime-secret@127.0.0.1:" + postgresPort + "/provider?sslmode=disable"
	migrationPool, err := pgxpool.New(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := providerpostgres.ApplyMigrations(ctx, migrationPool); err != nil {
		migrationPool.Close()
		t.Fatal(err)
	}
	migrationPool.Close()
	if _, err := adminPool.Exec(ctx, `GRANT USAGE ON SCHEMA sandbox_runtime_provider TO provider_runtime;
GRANT SELECT ON sandbox_runtime_provider.schema_migrations TO provider_runtime;
GRANT SELECT,UPDATE ON sandbox_runtime_provider.control_state TO provider_runtime;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON sandbox_runtime_provider.schema_migrations FROM provider_runtime`); err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	migrationPath := filepath.Join(directory, "migration.dsn")
	runtimePath := filepath.Join(directory, "runtime.dsn")
	serverCertificatePath := filepath.Join(directory, "provider.crt")
	serverPrivateKeyPath := filepath.Join(directory, "provider.key")
	clientCAPath := filepath.Join(directory, "client-ca.pem")
	admissionKeyPath := filepath.Join(directory, "admission.pem")
	configPath := filepath.Join(directory, "config.toml")
	logPath := filepath.Join(directory, "provider.log")
	binaryPath := filepath.Join(directory, "sandbox-runtime")
	dataRoot := filepath.Join(directory, "runtime")
	stagingRoot := filepath.Join(directory, "staging")
	writePrivateIntegrationFile(t, migrationPath, migrationDSN+"\n")
	writePrivateIntegrationFile(t, runtimePath, runtimeDSN+"\n")
	rootPool, clientCertificate := writeProviderMTLSMaterial(t, serverCertificatePath, serverPrivateKeyPath, clientCAPath)
	writeProviderAdmissionPublicKey(t, admissionKeyPath)
	providerPort, probePort := reserveLoopbackPort(t), reserveLoopbackPort(t)
	configuration := fmt.Sprintf(`[application]
mode = "production"

[logger]
level = "error"

[provider_process]
enabled = true
deployment_level = "production"
profile = "coding_shell"

[provider_process.transport]
enabled = true
server_certificate_file = %q
server_private_key_file = %q
client_ca_bundle_file = %q
allowed_client_uri_identities = ["spiffe://product.example.test/provider-client"]

[provider_process.transport.address]
host = "127.0.0.1"
port = %d

[provider_process.probe]
host = "127.0.0.1"
port = %d

[provider_process.capability]
provider_revision_id = "provider-production-revision-1"

[provider_process.capability.limits]
max_cpu_millis = 1000
max_memory_bytes = 1073741824
max_ephemeral_storage_bytes = 1073741824
max_lease_seconds = 3600
max_exec_seconds = 300

[[provider_process.capability.snapshot_restore_profiles]]
profile_id = "sandbox-snapshot-workspace-v1"
level = "workspace"
suite_id = "sandbox-provider"
suite_version = "1.0.0"
suite_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[provider_process.protected_admission]
issuer = "https://product.example.test"
provider_instance_audience = "urn:shell-echo:sandbox-runtime:provider-instance:production-1"

[[provider_process.protected_admission.trusted_verification_keys]]
id = "product-ed25519-1"
algorithm = "EdDSA"
public_key_file = %q

[provider_process.postgres]
migration_dsn_file = %q
runtime_dsn_file = %q
migration_role = "provider_migrator"
runtime_role = "provider_runtime"
startup_timeout_seconds = 10
operation_timeout_seconds = 2
migration_max_connections = 1
max_connections = 4
min_connections = 1

[provider_process.reconciliation]
interval_seconds = 1
timeout_seconds = 2

[provider_process.coding.lifecycle]
image = %q
pull_policy = "never"
memory_bytes = 536870912
nano_cpus = 1000000000
pids_limit = 256
tmpfs_bytes = 67108864
operation_timeout_seconds = 30
pull_timeout_seconds = 30
stop_timeout_seconds = 5
user = "65532:65532"
command = ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]
data_root = %q
namespace = "provider-production"
controller_id = "provider-controller-1"

[provider_process.coding.terminal]
runtime_profile_id = "sandbox-runtime-coding-shell-v1"
capability_profile_id = "terminal-v1"
broker_path = "/usr/local/libexec/sandbox-runtime/terminal-broker"
shell_path = "/bin/sh"
max_sessions_per_sandbox = 4
max_sessions_per_controller = 64
shutdown_cleanup_seconds = 5

[provider_process.coding.artifact]
staging_root = %q
active_content_command = [%q]
malware_command = [%q]
`, serverCertificatePath, serverPrivateKeyPath, clientCAPath, providerPort, probePort, admissionKeyPath,
		migrationPath, runtimePath, providerProcessCodingImage, dataRoot, stagingRoot, truePath, truePath)
	writePrivateIntegrationFile(t, configPath, configuration)
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, "..").CombinedOutput(); err != nil {
		t.Fatalf("build Provider process: %v: %s", err, output)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process, processDone := startProviderIntegrationProcess(t, ctx, binaryPath, configPath, logFile)
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

	probeURL := "http://127.0.0.1:" + strconv.Itoa(probePort)
	waitForProviderHTTPStatus(t, processDone, http.DefaultClient, probeURL+"/livez", http.StatusNoContent, logPath)
	waitForProviderHTTPStatus(t, processDone, http.DefaultClient, probeURL+"/readyz", http.StatusNoContent, logPath)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: rootPool, ServerName: "provider.example.test", Certificates: []tls.Certificate{clientCertificate},
	}}
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	providerURL := "https://127.0.0.1:" + strconv.Itoa(providerPort)
	waitForProviderHTTPStatus(t, processDone, client, providerURL+"/v1/capabilities", http.StatusOK, logPath)
	assertProviderProcessCapability(t, client, providerURL+"/v1/capabilities")
	assertProviderNoLocalAPI(t, client, providerURL, probeURL)
	assertProviderTLSClosed(t, rootPool, providerURL)
	assertProviderRuntimeRole(t, ctx, runtimeDSN)
	assertNoProviderMigrationConnection(t, ctx, adminPool)

	if output, err := exec.CommandContext(ctx, "docker", "pause", container).CombinedOutput(); err != nil {
		t.Fatalf("pause PostgreSQL: %v: %s", err, output)
	}
	waitForProviderHTTPStatus(t, processDone, http.DefaultClient, probeURL+"/readyz", http.StatusServiceUnavailable, logPath)
	if output, err := exec.CommandContext(ctx, "docker", "unpause", container).CombinedOutput(); err != nil {
		t.Fatalf("unpause PostgreSQL: %v: %s", err, output)
	}
	waitForProviderHTTPStatus(t, processDone, http.DefaultClient, probeURL+"/readyz", http.StatusNoContent, logPath)
	stopProviderIntegrationProcess(t, process, processDone, logPath)
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	logFile, err = os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process, processDone = startProviderIntegrationProcess(t, ctx, binaryPath, configPath, logFile)
	waitForProviderHTTPStatus(t, processDone, http.DefaultClient, probeURL+"/readyz", http.StatusNoContent, logPath)
	assertProviderProcessCapability(t, client, providerURL+"/v1/capabilities")
	assertNoProviderMigrationConnection(t, ctx, adminPool)
	stopProviderIntegrationProcess(t, process, processDone, logPath)
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	logDocument, _ := os.ReadFile(logPath)
	for _, forbidden := range []string{"phase6-provider", "provider-migration-secret", "provider-runtime-secret", "PRIVATE KEY", dataRoot, stagingRoot} {
		if bytes.Contains(logDocument, []byte(forbidden)) {
			t.Fatalf("Provider log disclosed protected material %q", forbidden)
		}
	}
	removeContainer()
	output, err = exec.CommandContext(ctx, "docker", "ps", "-a", "--filter", "name=^/"+container+"$", "--format", "{{.Names}}").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "" {
		t.Fatalf("PostgreSQL container retained: err=%v output=%s", err, output)
	}
}

func netSplitHostPort(value string) (string, string, error) { return net.SplitHostPort(value) }

func startProviderIntegrationProcess(t *testing.T, ctx context.Context, binaryPath, configPath string, logFile *os.File) (*exec.Cmd, <-chan error) {
	t.Helper()
	process := exec.CommandContext(ctx, binaryPath, "provider", "serve", "-c", configPath)
	process.Stdout, process.Stderr = logFile, logFile
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	return process, done
}

func stopProviderIntegrationProcess(t *testing.T, process *exec.Cmd, done <-chan error, logPath string) {
	t.Helper()
	if err := process.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Provider process exit: %v; log=%s", err, readIntegrationLog(logPath))
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("Provider process did not stop; log=%s", readIntegrationLog(logPath))
	}
}

func waitForProviderHTTPStatus(t *testing.T, processDone <-chan error, client *http.Client, endpoint string, want int, logPath string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-processDone:
			t.Fatalf("Provider process stopped while waiting for %s: %v; log=%s", endpoint, err, readIntegrationLog(logPath))
		default:
		}
		response, err := client.Get(endpoint)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == want {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s status %d; log=%s", endpoint, want, readIntegrationLog(logPath))
}

func assertProviderProcessCapability(t *testing.T, client *http.Client, endpoint string) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var document providerv1.Capabilities
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(document.Capabilities))
	for index := range document.Capabilities {
		got[index] = string(document.Capabilities[index].ID)
	}
	sort.Strings(got)
	want := []string{"sandbox.exec", "sandbox.lifecycle-control", "sandbox.terminal", "sandbox.terminal-connect", "sandbox.terminal-control"}
	if !reflect.DeepEqual(got, want) || len(document.RuntimeProfiles) != 1 || document.RuntimeProfiles[0].ID != "sandbox-runtime-coding-shell-v1" {
		t.Fatalf("Provider capability advertisement = %#v / %#v", got, document.RuntimeProfiles)
	}
}

func assertProviderNoLocalAPI(t *testing.T, client *http.Client, providerURL, probeURL string) {
	t.Helper()
	for _, endpoint := range []string{providerURL + "/instances", probeURL + "/instances", probeURL + "/v1/capabilities"} {
		requestClient := client
		if strings.HasPrefix(endpoint, "http://") {
			requestClient = http.DefaultClient
		}
		response, err := requestClient.Get(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("unexpected route %s returned %d", endpoint, response.StatusCode)
		}
	}
}

func assertProviderTLSClosed(t *testing.T, roots *x509.CertPool, providerURL string) {
	t.Helper()
	withoutClient := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "provider.example.test"}}}
	if response, err := withoutClient.Get(providerURL + "/v1/capabilities"); err == nil {
		_ = response.Body.Close()
		t.Fatal("Provider accepted a request without a client certificate")
	}
	tls12 := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "provider.example.test"}}}
	if response, err := tls12.Get(providerURL + "/v1/capabilities"); err == nil {
		_ = response.Body.Close()
		t.Fatal("Provider accepted a TLS 1.2 downgrade")
	}
}

func assertProviderRuntimeRole(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TABLE sandbox_runtime_provider.unsafe(id bigint)`); err == nil {
		t.Fatal("Provider runtime role retained DDL authority")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sandbox_runtime_provider.schema_migrations(version,digest) VALUES(999,'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`); err == nil {
		t.Fatal("Provider runtime role retained migration-ledger write authority")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM sandbox_runtime_provider.control_state`); err == nil {
		t.Fatal("Provider runtime role retained destructive control-state authority")
	}
}

func assertNoProviderMigrationConnection(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE usename='provider_migrator'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("Provider process retained %d migration-role connections", count)
	}
}

func writeProviderMTLSMaterial(t *testing.T, certificatePath, keyPath, caPath string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "provider-integration-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(name string, usage x509.ExtKeyUsage, dns []string, uris []*url.URL) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: dns, URIs: uris}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	server := issue("provider.example.test", x509.ExtKeyUsageServerAuth, []string{"provider.example.test"}, nil)
	clientURI, _ := url.Parse("spiffe://product.example.test/provider-client")
	client := issue("product-client", x509.ExtKeyUsageClientAuth, nil, []*url.URL{clientURI})
	keyDER, err := x509.MarshalECPrivateKey(server.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	writePrivateIntegrationFile(t, certificatePath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate[0]})))
	writePrivateIntegrationFile(t, keyPath, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	writePrivateIntegrationFile(t, caPath, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return roots, client
}

func writeProviderAdmissionPublicKey(t *testing.T, path string) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writePrivateIntegrationFile(t, path, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})))
}
