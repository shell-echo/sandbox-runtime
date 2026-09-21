//go:build phase6slicegate

package productphase6gate

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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/productphase5evidence"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

const (
	gateEnabledEnv  = "SANDBOX_RUNTIME_PHASE6_SLICE4_GATE"
	candidateEnv    = "SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST"
	evidencePathEnv = "SANDBOX_RUNTIME_PHASE6_SLICE4_EVIDENCE"

	providerRevision = "provider-phase6-slice4-revision-1"
	providerAudience = "urn:shell-echo:sandbox-runtime:provider-instance:phase6-slice4"
	providerIssuer   = "https://phase6-controller.example.test"
	providerCaller   = "spiffe://phase6.example.test/provider-controller"
	providerKeyID    = "phase6-controller-ed25519-1"
	gateTenantID     = "tenant-phase6-slice4"
	gateWorkOrderID  = "work-order-phase6-slice4"
	gateSandboxID    = "sandbox-phase6-slice4"
)

type gateProcess struct {
	name      string
	command   string
	cmd       *exec.Cmd
	logPath   string
	log       *os.File
	done      chan error
	startedAt time.Time
	finished  time.Time
	exitCode  int
	ready     bool
	mu        sync.Mutex
}

func startGateProcess(t *testing.T, ctx context.Context, name, command, logPath string, arguments ...string) *gateProcess {
	t.Helper()
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	process := &gateProcess{name: name, command: strings.Join(append([]string{command}, arguments...), " "), logPath: logPath, log: log, done: make(chan error, 1), startedAt: time.Now().UTC()}
	process.cmd = exec.CommandContext(ctx, command, arguments...)
	process.cmd.Stdout, process.cmd.Stderr = log, log
	if err := process.cmd.Start(); err != nil {
		_ = log.Close()
		t.Fatalf("start %s: %v", name, err)
	}
	go func() {
		err := process.cmd.Wait()
		process.mu.Lock()
		process.finished = time.Now().UTC()
		process.exitCode = 0
		if process.cmd.ProcessState != nil {
			process.exitCode = process.cmd.ProcessState.ExitCode()
		}
		process.mu.Unlock()
		process.done <- err
		close(process.done)
	}()
	return process
}

func stopGateProcess(t *testing.T, process *gateProcess, timeout time.Duration) {
	t.Helper()
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return
	}
	select {
	case err := <-process.done:
		if err != nil {
			t.Fatalf("%s exited early: %v; log=%s", process.name, err, gateLog(process))
		}
		return
	default:
	}
	if err := process.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal %s: %v", process.name, err)
	}
	select {
	case err := <-process.done:
		if err != nil {
			t.Fatalf("%s exit: %v; log=%s", process.name, err, gateLog(process))
		}
	case <-time.After(timeout):
		_ = process.cmd.Process.Kill()
		<-process.done
		t.Fatalf("%s did not drain within %s; log=%s", process.name, timeout, gateLog(process))
	}
	if err := process.log.Close(); err != nil {
		t.Fatal(err)
	}
}

func killGateProcess(t *testing.T, process *gateProcess) {
	t.Helper()
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return
	}
	select {
	case <-process.done:
		return
	default:
	}
	if err := process.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-process.done
	_ = process.log.Close()
}

func bestEffortStopGateProcess(process *gateProcess) {
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return
	}
	select {
	case <-process.done:
		_ = process.log.Close()
		return
	default:
	}
	_ = process.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-process.done:
	case <-time.After(20 * time.Second):
		_ = process.cmd.Process.Kill()
		<-process.done
	}
	_ = process.log.Close()
}

func gateLog(process *gateProcess) string {
	if process == nil {
		return "<nil>"
	}
	document, err := os.ReadFile(process.logPath)
	if err != nil {
		return err.Error()
	}
	if len(document) > 16<<10 {
		document = document[len(document)-(16<<10):]
	}
	return string(document)
}

func markReady(process *gateProcess) {
	process.mu.Lock()
	process.ready = true
	process.mu.Unlock()
}

func freePort(t *testing.T) int {
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

func waitHTTPStatus(t *testing.T, process *gateProcess, client *http.Client, endpoint string, wanted int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-process.done:
			t.Fatalf("%s stopped while waiting for %s: %v; log=%s", process.name, endpoint, err, gateLog(process))
		default:
		}
		request, _ := http.NewRequest(http.MethodGet, endpoint, nil)
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode == wanted {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s status %d; process=%s log=%s", endpoint, wanted, process.name, gateLog(process))
}

func waitFor(t *testing.T, timeout time.Duration, label string, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", label)
}

func writePrivate(t *testing.T, path string, document []byte) {
	t.Helper()
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writePrivateJSON(t *testing.T, path string, value any) {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, path, document)
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type gateCA struct {
	t              *testing.T
	directory      string
	certificate    *x509.Certificate
	privateKey     ed25519.PrivateKey
	certificatePEM []byte
	serial         int64
}

func newGateCA(t *testing.T, directory string) *gateCA {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase6-slice4-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &gateCA{t: t, directory: directory, certificate: certificate, privateKey: privateKey, certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial: 2}
}

func (c *gateCA) writeCA(name string) string {
	c.t.Helper()
	path := filepath.Join(c.directory, name+"-ca.pem")
	writePrivate(c.t, path, c.certificatePEM)
	return path
}

func (c *gateCA) issue(name string, serverNames []string, ipAddresses []net.IP, clientURI string, client, server bool) (string, string, tls.Certificate) {
	c.t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		c.t.Fatal(err)
	}
	c.serial++
	usage := make([]x509.ExtKeyUsage, 0, 2)
	if client {
		usage = append(usage, x509.ExtKeyUsageClientAuth)
	}
	if server {
		usage = append(usage, x509.ExtKeyUsageServerAuth)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(c.serial), Subject: pkix.Name{CommonName: name}, DNSNames: serverNames, IPAddresses: ipAddresses, NotBefore: time.Now().UTC().Add(-time.Minute), NotAfter: time.Now().UTC().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usage}
	if clientURI != "" {
		parsed, err := url.Parse(clientURI)
		if err != nil {
			c.t.Fatal(err)
		}
		template.URIs = []*url.URL{parsed}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.certificate, publicKey, c.privateKey)
	if err != nil {
		c.t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		c.t.Fatal(err)
	}
	certificatePath := filepath.Join(c.directory, name+".pem")
	privateKeyPath := filepath.Join(c.directory, name+".key")
	certificateDocument := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), c.certificatePEM...)
	privateKeyDocument := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	writePrivate(c.t, certificatePath, certificateDocument)
	writePrivate(c.t, privateKeyPath, privateKeyDocument)
	loaded, err := tls.X509KeyPair(certificateDocument, privateKeyDocument)
	if err != nil {
		c.t.Fatal(err)
	}
	return certificatePath, privateKeyPath, loaded
}

func (c *gateCA) client(serverName string, certificate tls.Certificate) *http.Client {
	c.t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(c.certificate)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName, Certificates: []tls.Certificate{certificate}}}}
}

func (c *gateCA) publicClient(serverName string) *http.Client {
	c.t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(c.certificate)
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName}}}
}

type postgresAuthority struct {
	container     string
	adminDSN      string
	migrationDSN  string
	runtimeDSN    string
	migrationRole string
	runtimeRole   string
	admin         *pgxpool.Pool
}

func startPostgresAuthority(t *testing.T, ctx context.Context, runID, database, migrationRole, runtimeRole string, migrate func(context.Context, *pgxpool.Pool) error, grants string) *postgresAuthority {
	t.Helper()
	container := "sr-phase6-" + runID + "-postgres"
	password := "phase6-" + runID
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", container, "-e", "POSTGRES_PASSWORD="+password, "-e", "POSTGRES_DB="+database, "-p", "127.0.0.1::5432", productphase5evidence.PostgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start %s PostgreSQL: %v: %s", runID, err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	portDocument, err := exec.CommandContext(ctx, "docker", "port", container, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portDocument)))
	if err != nil {
		t.Fatal(err)
	}
	adminDSN := fmt.Sprintf("postgres://postgres:%s@127.0.0.1:%s/%s?sslmode=disable", password, port, database)
	waitFor(t, 30*time.Second, runID+" PostgreSQL", func() bool {
		pool, poolErr := pgxpool.New(ctx, adminDSN)
		if poolErr != nil {
			return false
		}
		defer pool.Close()
		return pool.Ping(ctx) == nil
	})
	admin, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	migrationPassword := runID + "-migration-secret"
	runtimePassword := runID + "-runtime-secret"
	statement := fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s; CREATE ROLE %s LOGIN PASSWORD %s; GRANT CREATE ON DATABASE %s TO %s", migrationRole, quoteSQLLiteral(migrationPassword), runtimeRole, quoteSQLLiteral(runtimePassword), database, migrationRole)
	if _, err := admin.Exec(ctx, statement); err != nil {
		t.Fatal(err)
	}
	migrationDSN := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable", migrationRole, migrationPassword, port, database)
	runtimeDSN := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable", runtimeRole, runtimePassword, port, database)
	migrationPool, err := pgxpool.New(ctx, migrationDSN)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate(ctx, migrationPool); err != nil {
		migrationPool.Close()
		t.Fatal(err)
	}
	migrationPool.Close()
	if _, err := admin.Exec(ctx, grants); err != nil {
		t.Fatal(err)
	}
	return &postgresAuthority{container: container, adminDSN: adminDSN, migrationDSN: migrationDSN, runtimeDSN: runtimeDSN, migrationRole: migrationRole, runtimeRole: runtimeRole, admin: admin}
}

func startProductPostgres(t *testing.T, ctx context.Context, runID string) *postgresAuthority {
	return startPostgresAuthority(t, ctx, runID, "product", "product_migrator", "product_runtime", productpostgres.ApplyMigrations, `GRANT USAGE ON SCHEMA sandbox_runtime_product TO product_runtime;
GRANT SELECT ON sandbox_runtime_product.schema_migrations TO product_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA sandbox_runtime_product TO product_runtime;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON sandbox_runtime_product.schema_migrations FROM product_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE product_migrator IN SCHEMA sandbox_runtime_product GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO product_runtime`)
}

func startProviderPostgres(t *testing.T, ctx context.Context, runID string) *postgresAuthority {
	return startPostgresAuthority(t, ctx, runID, "provider", "provider_migrator", "provider_runtime", providerpostgres.ApplyMigrations, `GRANT USAGE ON SCHEMA sandbox_runtime_provider TO provider_runtime;
GRANT SELECT ON sandbox_runtime_provider.schema_migrations TO provider_runtime;
GRANT SELECT, UPDATE ON sandbox_runtime_provider.control_state TO provider_runtime;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON sandbox_runtime_provider.schema_migrations FROM provider_runtime`)
}

func quoteSQLLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func pauseContainer(t *testing.T, ctx context.Context, name string, pause bool) {
	t.Helper()
	operation := "pause"
	if !pause {
		operation = "unpause"
	}
	if output, err := exec.CommandContext(ctx, "docker", operation, name).CombinedOutput(); err != nil {
		t.Fatalf("docker %s %s: %v: %s", operation, name, err, output)
	}
}

type protectedClient struct {
	client     *http.Client
	origin     string
	privateKey ed25519.PrivateKey
	issuer     string
	keyID      string
	caller     string
	audience   string
	revision   string
	tenantID   string
	workOrder  string
	sequence   int64
}

type protectedRequest struct {
	Method      string
	Path        string
	Operation   admission.Operation
	SandboxID   string
	OperationID string
	AttemptID   string
	Fence       int64
	Deadline    time.Time
	Body        map[string]any
}

func (c *protectedClient) do(t *testing.T, request protectedRequest) (int, []byte) {
	t.Helper()
	now := time.Now().UTC()
	request.Deadline = request.Deadline.UTC()
	var document []byte
	var requestDigest string
	profile := admission.DigestProfileFullDocument
	contractID := descriptorContract(request.Operation)
	if request.Method == http.MethodPost {
		profile = admission.DigestProfileRequestExcludingDigest
		contractID = mutationContract(request.Operation)
		withoutDigest, err := json.Marshal(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := jcs.Transform(withoutDigest)
		if err != nil {
			t.Fatal(err)
		}
		requestDigest = sha256Digest(canonical)
		request.Body["request_digest"] = requestDigest
		document, err = json.Marshal(request.Body)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		descriptor := map[string]any{"operation": string(request.Operation), "sandbox_id": request.SandboxID, "operation_id": request.OperationID, "attempt_id": request.AttemptID, "fencing_token": request.Fence}
		encoded, err := json.Marshal(descriptor)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := jcs.Transform(encoded)
		if err != nil {
			t.Fatal(err)
		}
		requestDigest = sha256Digest(canonical)
	}
	contextValue := admission.AdmissionContext{
		ContextContractID: admission.AdmissionContextContractID, ContextDigestProfile: admission.AdmissionContextDigestProfile,
		ControllerSubject: c.caller, ProviderRevisionID: c.revision, ProviderInstanceAudience: c.audience,
		TenantID: c.tenantID, WorkOrderID: c.workOrder, PolicyDigest: sha256Digest([]byte("phase6-slice4-policy")),
		PolicyDecidedAt: now.Add(-10 * time.Second).Format(time.RFC3339Nano), Operation: request.Operation,
		SandboxID: request.SandboxID, OperationID: request.OperationID, AttemptID: request.AttemptID, FencingToken: request.Fence,
		DeadlineAt: request.Deadline.Format(time.RFC3339Nano), RequestContractID: contractID, RequestDigestProfile: profile,
		RequestDigest: requestDigest, HTTPTarget: admission.AdmissionTarget{Method: request.Method, Path: request.Path, NormalizedQuery: []admission.AdmissionQuery{}},
	}
	contextDigest, err := admission.DigestForAdmissionContext(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	contextValue.ContextDigest = contextDigest
	c.sequence++
	claims := admission.TokenClaims{
		JTI: fmt.Sprintf("phase6-slice4-jti-%016d", c.sequence), Issuer: c.issuer, Subject: c.caller, Audience: c.audience,
		IssuedAt: now.Add(-2 * time.Second).Unix(), NotBefore: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
		Operation: request.Operation, ProviderRevisionID: c.revision, SandboxID: request.SandboxID, OperationID: request.OperationID,
		AttemptID: request.AttemptID, FencingToken: request.Fence, TenantID: c.tenantID, WorkOrderID: c.workOrder,
		PolicyDigest: contextValue.PolicyDigest, PolicyDecidedAt: contextValue.PolicyDecidedAt, RequestContractID: contractID,
		RequestDigestProfile: profile, RequestDigest: requestDigest, DeadlineAt: contextValue.DeadlineAt,
		AdmissionContextContractID: admission.AdmissionContextContractID, AdmissionContextDigestProfile: admission.AdmissionContextDigestProfile,
		AdmissionContextDigest: contextDigest,
	}
	if expiration := request.Deadline.Add(-time.Second).Unix(); claims.ExpiresAt > expiration {
		claims.ExpiresAt = expiration
	}
	bearer := signAdmission(t, c.privateKey, c.keyID, claims)
	contextDocument, err := json.Marshal(contextValue)
	if err != nil {
		t.Fatal(err)
	}
	httpRequest, err := http.NewRequest(request.Method, c.origin+request.Path, bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	if request.Method == http.MethodPost {
		httpRequest.Header.Set("Content-Type", "application/json")
	}
	httpRequest.Header.Set("Authorization", "Bearer "+bearer)
	httpRequest.Header.Set(admission.AdmissionContextHeader, base64.RawURLEncoding.EncodeToString(contextDocument))
	response, err := c.client.Do(httpRequest)
	if err != nil {
		t.Fatalf("protected %s %s: %v", request.Method, request.Path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

func signAdmission(t *testing.T, privateKey ed25519.PrivateKey, keyID string, claims admission.TokenClaims) string {
	t.Helper()
	header, err := json.Marshal(admission.JWSHeader{Algorithm: admission.AlgorithmEdDSA, KeyID: admission.KeyID(keyID), Type: "agent-sandbox-operation-admission+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	first := base64.RawURLEncoding.EncodeToString(header)
	second := base64.RawURLEncoding.EncodeToString(payload)
	input := first + "." + second
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(input)))
}

func sha256Digest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func mutationContract(operation admission.Operation) string {
	contracts := map[admission.Operation]string{
		admission.OperationCreate:              "urn:shell-echo:sandbox-runtime:request:create:v1",
		admission.OperationOpenDesktopSession:  "urn:shell-echo:sandbox-runtime:request:open-desktop-session:v1",
		admission.OperationCloseDesktopSession: "urn:shell-echo:sandbox-runtime:request:close-desktop-session:v1",
		admission.OperationTerminate:           "urn:shell-echo:sandbox-runtime:request:terminate:v1",
	}
	return contracts[operation]
}

func descriptorContract(operation admission.Operation) string {
	contracts := map[admission.Operation]string{
		admission.OperationReadSandbox:        "urn:shell-echo:sandbox-runtime:descriptor:status:v1",
		admission.OperationReadOperation:      "urn:shell-echo:sandbox-runtime:descriptor:operation:v1",
		admission.OperationReadDesktopSession: "urn:shell-echo:sandbox-runtime:descriptor:desktop-session:v1",
	}
	return contracts[operation]
}

func generateAdmissionKey(t *testing.T, path string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
	return publicKey, privateKey
}

func generateBridgeKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, path, privateKey)
	return privateKey
}

func rootPoolFromCA(t *testing.T, caDocument []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caDocument) {
		t.Fatal("append gate CA")
	}
	return pool
}

func assertNoSecretLog(t *testing.T, process *gateProcess, forbidden ...string) {
	t.Helper()
	document, err := os.ReadFile(process.logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range forbidden {
		if value != "" && bytes.Contains(document, []byte(value)) {
			t.Fatalf("%s log contains protected value %q", process.name, value)
		}
	}
}

func requireStatus(t *testing.T, got int, body []byte, wanted int) {
	t.Helper()
	if got != wanted {
		t.Fatalf("status=%d, want %d body=%s", got, wanted, body)
	}
}

func decodeJSON[T any](t *testing.T, document []byte) T {
	t.Helper()
	var value T
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %T: %v document=%s", value, err, document)
	}
	return value
}

func processPID(process *gateProcess) string {
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return ""
	}
	return strconv.Itoa(process.cmd.Process.Pid)
}

func errorsIsProcessDone(process *gateProcess) bool {
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

var _ = errors.Is
