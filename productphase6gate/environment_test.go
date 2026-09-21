//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	"github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
	"github.com/shell-echo/sandbox-runtime/roleprocess"
)

const chromiumImage = "chromedp/headless-shell@sha256:2fc473f3f926ccae8dbfedf60897937dece94ff7bbdfab20457ebfc732c2b162"

type rolePorts struct {
	product, provider, providerPrivate, providerProbe int
	gateway, gatewayProbe                             int
	guestProbe                                        int
	browser, browserProbe, browserBackend             int
	desktop, desktopProbe, desktopBackend             int
}

type gateTLSMaterial struct {
	ca *gateCA

	productCert, productKey                                       string
	providerCert, providerKey                                     string
	providerPrivateCert, providerPrivateKey                       string
	controllerCA, controllerCert, controllerKey                   string
	gatewayProviderCA, gatewayProviderCert, gatewayProviderKey    string
	providerExecutorCA, providerExecutorCert, providerExecutorKey string
	gatewayCert, gatewayKey                                       string
	browserRoleCert, browserRoleKey                               string
	browserRoleClientCert, browserRoleClientKey                   string
	browserBackendCert, browserBackendKey                         string
	desktopRoleCert, desktopRoleKey                               string
	desktopRoleClientCert, desktopRoleClientKey                   string
	desktopBackendCert, desktopBackendKey                         string
	guestClientCert, guestClientKey                               string
	guestServerCert, guestServerKey                               string

	controllerClient     tls.Certificate
	privateGatewayClient tls.Certificate
}

type gatePaths struct {
	directory          string
	binary             string
	browserBackendBin  string
	desktopBackendBin  string
	productConfig      string
	providerConfig     string
	gatewayConfig      string
	guestConfig        string
	browserConfig      string
	desktopConfig      string
	browserBackendAuth string
	desktopBackendAuth string
	brokerDirectory    string
	brokerSocket       string
	productRuntimeDSN  string
	providerRuntimeDSN string
	bridgeKey          string
	admissionKey       string
	productIdentityKey string
}

type gateEnvironment struct {
	runID         string
	root          string
	paths         gatePaths
	ports         rolePorts
	tls           gateTLSMaterial
	candidate     desktopcandidate.Manifest
	productDB     *postgresAuthority
	providerDB    *postgresAuthority
	admissionKey  ed25519.PrivateKey
	productToken  ed25519.PrivateKey
	gatewayImage  string
	uplinkNetwork string
	chromiumName  string
	chromiumURL   string
	guest         *guestFixture
	dependencies  []*gateProcess
	roles         map[string]*gateProcess
	roleHistory   map[string][]*gateProcess
	scenarios     map[string]scenarioObservation
	repository    productphase6evidence.RepositoryBinding
	stress        productphase6evidence.StressMeasurements
	desktopMedia  productphase6evidence.DesktopMediaMeasurements
}

func prepareGateEnvironment(t *testing.T, ctx context.Context) *gateEnvironment { //nolint:maintidx
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := os.Getenv(candidateEnv)
	candidate, err := desktopcandidate.Load(candidatePath)
	if err != nil {
		t.Fatalf("load current local Desktop candidate %q: %v", candidatePath, err)
	}
	repository, err := productphase6evidence.BindRuntimeCandidate(candidate, root)
	if err != nil {
		t.Fatalf("bind local Desktop candidate to evidence tools %q: %v", candidatePath, err)
	}
	runID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	directory := t.TempDir()
	brokerDirectory, err := os.MkdirTemp("/tmp", "sr-phase6-mux-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(brokerDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(brokerDirectory) })
	environment := &gateEnvironment{
		runID: runID, root: root, candidate: candidate, repository: repository, roles: make(map[string]*gateProcess), roleHistory: make(map[string][]*gateProcess), scenarios: make(map[string]scenarioObservation),
		paths: gatePaths{directory: directory, binary: filepath.Join(directory, "sandbox-runtime"), browserBackendBin: filepath.Join(directory, "browser-executor-backend"), desktopBackendBin: filepath.Join(directory, "desktop-executor-backend"), brokerDirectory: brokerDirectory, brokerSocket: filepath.Join(brokerDirectory, "desktop-broker-11111111111111111111111111111111.sock")},
		ports: rolePorts{product: freePort(t), provider: freePort(t), providerPrivate: freePort(t), providerProbe: freePort(t), gateway: freePort(t), gatewayProbe: freePort(t), guestProbe: freePort(t), browser: freePort(t), browserProbe: freePort(t), browserBackend: freePort(t), desktop: freePort(t), desktopProbe: freePort(t), desktopBackend: freePort(t)},
	}
	buildGateBinaries(t, ctx, environment)
	environment.productDB = startProductPostgres(t, ctx, "product-"+runID)
	environment.providerDB = startProviderPostgres(t, ctx, "provider-"+runID)
	environment.tls = writeGateTLS(t, directory)
	environment.paths.productRuntimeDSN = filepath.Join(directory, "product-runtime.dsn")
	productMigrationDSN := filepath.Join(directory, "product-migration.dsn")
	writePrivate(t, productMigrationDSN, []byte(environment.productDB.migrationDSN+"\n"))
	writePrivate(t, environment.paths.productRuntimeDSN, []byte(environment.productDB.runtimeDSN+"\n"))
	environment.paths.providerRuntimeDSN = filepath.Join(directory, "provider-runtime.dsn")
	providerMigrationDSN := filepath.Join(directory, "provider-migration.dsn")
	writePrivate(t, providerMigrationDSN, []byte(environment.providerDB.migrationDSN+"\n"))
	writePrivate(t, environment.paths.providerRuntimeDSN, []byte(environment.providerDB.runtimeDSN+"\n"))
	environment.paths.admissionKey = filepath.Join(directory, "provider-admission-public.pem")
	_, environment.admissionKey = generateAdmissionKey(t, environment.paths.admissionKey)
	environment.paths.bridgeKey = filepath.Join(directory, "desktop-bridge.key")
	_ = generateBridgeKey(t, environment.paths.bridgeKey)
	environment.paths.productIdentityKey = filepath.Join(directory, "product-identity-keys.json")
	environment.productToken = writeProductIdentity(t, environment.paths.productIdentityKey)
	environment.gatewayImage = buildGatewayImage(t, ctx, root, runID)
	environment.uplinkNetwork = createUplinkNetwork(t, ctx, runID)
	environment.chromiumName, environment.chromiumURL = startChromium(t, ctx, runID)
	environment.guest = startGuestFixture(t, ctx, environment)
	writeGateAuthorities(t, environment)
	writeGateConfigs(t, environment, productMigrationDSN, providerMigrationDSN)
	t.Cleanup(func() { bestEffortPhase6NamespaceCleanup() })
	return environment
}

func bestEffortPhase6NamespaceCleanup() {
	containerOutput, err := exec.Command("docker", "ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4").Output()
	if err == nil {
		for _, identifier := range strings.Fields(string(containerOutput)) {
			_ = exec.Command("docker", "rm", "-f", identifier).Run()
		}
	}
	networkOutput, err := exec.Command("docker", "network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4").Output()
	if err == nil {
		for _, identifier := range strings.Fields(string(networkOutput)) {
			_ = exec.Command("docker", "network", "rm", identifier).Run()
		}
	}
}

func buildGateBinaries(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	builds := []struct{ output, target string }{
		{environment.paths.binary, "."},
		{environment.paths.browserBackendBin, "./cmd/browser-executor-backend"},
		{environment.paths.desktopBackendBin, "./cmd/desktop-executor-backend"},
	}
	for _, build := range builds {
		command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", build.output, build.target)
		command.Dir = environment.root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", build.target, err, output)
		}
	}
}

func writeGateTLS(t *testing.T, directory string) gateTLSMaterial {
	t.Helper()
	ca := newGateCA(t, directory)
	material := gateTLSMaterial{ca: ca}
	material.productCert, material.productKey, _ = ca.issue("product-server", []string{"product.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.providerCert, material.providerKey, _ = ca.issue("provider-server", []string{"provider.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.providerPrivateCert, material.providerPrivateKey, _ = ca.issue("provider-private-server", []string{"provider-private.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.controllerCA = ca.writeCA("provider-controller")
	material.controllerCert, material.controllerKey, material.controllerClient = ca.issue("provider-controller-client", nil, nil, providerCaller, true, false)
	material.gatewayProviderCA = ca.writeCA("gateway-provider")
	material.gatewayProviderCert, material.gatewayProviderKey, material.privateGatewayClient = ca.issue("gateway-provider-client", nil, nil, "spiffe://phase6.example.test/gateway", true, false)
	material.providerExecutorCA = ca.writeCA("provider-executor")
	material.providerExecutorCert, material.providerExecutorKey, _ = ca.issue("provider-executor-client", nil, nil, "spiffe://phase6.example.test/provider-executor", true, false)
	material.gatewayCert, material.gatewayKey, _ = ca.issue("gateway-public-server", []string{"gateway.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.browserRoleCert, material.browserRoleKey, _ = ca.issue("browser-role-server", []string{"browser-role.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.browserRoleClientCert, material.browserRoleClientKey, _ = ca.issue("browser-role-client", nil, nil, "spiffe://phase6.example.test/browser-role", true, false)
	material.browserBackendCert, material.browserBackendKey, _ = ca.issue("browser-backend-server", []string{"browser-backend.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.desktopRoleCert, material.desktopRoleKey, _ = ca.issue("desktop-role-server", []string{"desktop-role.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.desktopRoleClientCert, material.desktopRoleClientKey, _ = ca.issue("desktop-role-client", nil, nil, "spiffe://phase6.example.test/desktop-role", true, false)
	material.desktopBackendCert, material.desktopBackendKey, _ = ca.issue("desktop-backend-server", []string{"desktop-backend.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	material.guestClientCert, material.guestClientKey, _ = ca.issue("guest-client", nil, nil, "spiffe://phase6.example.test/guest", true, false)
	material.guestServerCert, material.guestServerKey, _ = ca.issue("guest-server", []string{"guest-agent.phase6.test"}, []net.IP{net.ParseIP("127.0.0.1")}, "", false, true)
	return material
}

func writeProductIdentity(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	document := map[string]any{
		"version":         "sandbox-runtime-product-access-key-ring-v1",
		"keys":            []map[string]any{{"kid": "phase6-product-access-1", "alg": "EdDSA", "public_key": base64.RawURLEncoding.EncodeToString(publicKey), "not_before": now.Add(-time.Hour).Format(time.RFC3339), "not_after": now.Add(time.Hour).Format(time.RFC3339)}},
		"revoked_key_ids": []string{},
	}
	writePrivateJSON(t, path, document)
	return privateKey
}

func buildGatewayImage(t *testing.T, ctx context.Context, root, runID string) string {
	t.Helper()
	tag := "sandbox-runtime-phase6-gateway:" + strings.ReplaceAll(runID, ".", "-")
	command := exec.CommandContext(ctx, "docker", "build", "--provenance=false", "--file", "profiles/browser/gateway/Dockerfile", "--tag", tag, ".")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build local gateway image: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "-f", tag).Run() })
	output, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", tag).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(output))
}

func createUplinkNetwork(t *testing.T, ctx context.Context, runID string) string {
	t.Helper()
	runDigest := strings.TrimPrefix(sha256Digest([]byte(runID)), "sha256:")
	name := "sr-phase6-uplink-" + runDigest[:12]
	output, err := exec.CommandContext(ctx, "docker", "network", "create", "--driver", "bridge", "--label", "io.github.shell-echo.sandbox-runtime.managed=true", "--label", "io.github.shell-echo.sandbox-runtime.owner="+docker.UplinkRole, "--label", "io.github.shell-echo.sandbox-runtime.namespace=phase6-slice4", name).CombinedOutput()
	if err != nil {
		t.Fatalf("create Desktop uplink: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })
	return name
}

func startChromium(t *testing.T, ctx context.Context, runID string) (string, string) {
	t.Helper()
	name := "sr-phase6-chromium-" + fmt.Sprintf("%x", time.Now().UnixNano())
	// The pinned headless-shell image owns its internal 9223 Chromium listener
	// and publishes it through a 9222 socat relay. Supplying another remote
	// debugging port makes Chromium race the relay for the same socket.
	output, err := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "-p", "127.0.0.1::9222", chromiumImage).CombinedOutput()
	if err != nil {
		t.Fatalf("start Chromium: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	portDocument, err := exec.CommandContext(ctx, "docker", "port", name, "9222/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portDocument)))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	waitFor(t, 30*time.Second, "real Chromium CDP", func() bool {
		response, requestErr := (&http.Client{Timeout: time.Second}).Get("http://127.0.0.1:" + port + "/json/version")
		if requestErr != nil {
			return false
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil {
			return false
		}
		return result.WebSocketDebuggerURL != ""
	})
	// Docker returns a container-local host in some versions. Preserve the
	// browser path and bind it to the observed host port.
	parsedPath := result.WebSocketDebuggerURL
	if index := strings.Index(parsedPath, "/devtools/"); index >= 0 {
		parsedPath = "ws://127.0.0.1:" + port + parsedPath[index:]
	}
	return name, parsedPath
}

func writeGateAuthorities(t *testing.T, environment *gateEnvironment) { //nolint:maintidx
	t.Helper()
	directory := environment.paths.directory
	authorityPath := func(role, kind string) string { return filepath.Join(directory, role+"-"+kind+".json") }
	grantKey := filepath.Join(directory, "gateway-grant.key")
	writePrivate(t, grantKey, randomBytes(t, 32))

	gatewayCredential := roleprocess.GatewayCredentialAuthority{Version: 2, Role: "gateway", ProductRuntimeDSNFile: environment.paths.productRuntimeDSN, GrantKeyID: "phase6-gateway-grant-1", GrantKeyFile: grantKey, ProviderOrigin: fmt.Sprintf("wss://127.0.0.1:%d/desktop", environment.ports.providerPrivate), ProviderCABundleFile: environment.tls.gatewayProviderCA, ProviderClientCertificateFile: environment.tls.gatewayProviderCert, ProviderClientPrivateKeyFile: environment.tls.gatewayProviderKey}
	gatewayDependency := roleprocess.GatewayDependencyAuthority{Version: 2, Role: "gateway", OperationTimeoutMillis: 5000, MaxConnections: 8, MaxConnectionsPerSession: 2, OriginPatterns: []string{"https://product.phase6.test"}}
	gatewayPolicy := roleprocess.GatewayPolicyAuthority{Version: 2, Role: "gateway", Terminal: "enabled", BrowserAutomation: "authority_unavailable", BrowserLive: "authority_unavailable", DesktopLive: "authority_unavailable", DeferredAuthorityReason: "phase6-slice5-6-authority-required"}
	writePrivateJSON(t, authorityPath("gateway", "credential"), gatewayCredential)
	writePrivateJSON(t, authorityPath("gateway", "dependency"), gatewayDependency)
	writePrivateJSON(t, authorityPath("gateway", "policy"), gatewayPolicy)

	guestPrivateKey := environment.guest.privateKey
	guestKeyPath := filepath.Join(directory, "guest-signing.key")
	writePrivate(t, guestKeyPath, guestPrivateKey)
	workspaceRoot, stateRoot := filepath.Join(directory, "guest-workspace"), filepath.Join(directory, "guest-state")
	for _, path := range []string{workspaceRoot, stateRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writePrivateJSON(t, authorityPath("guest", "credential"), roleprocess.GuestCredentialAuthority{Version: 1, Role: "guest", GuestID: environment.guest.guestID, BindingGeneration: 1, PrivateKeyFile: guestKeyPath})
	writePrivateJSON(t, authorityPath("guest", "dependency"), roleprocess.GuestDependencyAuthority{Version: 1, Role: "guest", WorkspaceRoot: workspaceRoot, StateRoot: stateRoot, Mounts: environment.guest.mounts(), Toolchains: environment.guest.toolchains()})
	writePrivateJSON(t, authorityPath("guest", "policy"), roleprocess.GuestPolicyAuthority{Version: 1, Role: "guest", ReconnectBackoffMillis: 100})

	for _, value := range []struct {
		role       string
		backendURL string
		executorID string
	}{
		{role: "browser", backendURL: fmt.Sprintf("wss://127.0.0.1:%d/executor", environment.ports.browserBackend), executorID: "executor-browser-1"},
		{role: "desktop", backendURL: fmt.Sprintf("wss://127.0.0.1:%d/executor", environment.ports.desktopBackend), executorID: "executor-desktop-1"},
	} {
		writePrivateJSON(t, authorityPath(value.role, "credential"), roleprocess.ExecutorCredentialAuthority{Version: 1, Role: value.role, ExecutorID: value.executorID, ProviderOrigin: "spiffe://phase6.example.test/provider/" + value.role})
		writePrivateJSON(t, authorityPath(value.role, "dependency"), roleprocess.ExecutorDependencyAuthority{Version: 1, Role: value.role, BackendURL: value.backendURL})
		writePrivateJSON(t, authorityPath(value.role, "policy"), roleprocess.ExecutorPolicyAuthority{Version: 1, Role: value.role, OperationTimeoutMillis: 10000, MaxSessions: 1})
	}

	environment.paths.browserBackendAuth = filepath.Join(directory, "browser-backend-authority.json")
	writePrivateJSON(t, environment.paths.browserBackendAuth, map[string]any{"version": 1, "role": "browser", "listen_address": fmt.Sprintf("127.0.0.1:%d", environment.ports.browserBackend), "upstream_url": environment.chromiumURL, "server_certificate_file": environment.tls.browserBackendCert, "server_private_key_file": environment.tls.browserBackendKey, "client_ca_bundle_file": environment.tls.ca.writeCA("browser-backend"), "allowed_client_identities": []string{"spiffe://phase6.example.test/browser-role"}, "max_sessions": 1, "operation_timeout_millis": 10000})
	environment.paths.desktopBackendAuth = filepath.Join(directory, "desktop-backend-authority.json")
	writePrivateJSON(t, environment.paths.desktopBackendAuth, map[string]any{"version": 1, "role": "desktop", "listen_address": fmt.Sprintf("127.0.0.1:%d", environment.ports.desktopBackend), "broker_socket_path": environment.paths.brokerSocket, "executor_identity": "executor-desktop-1", "server_certificate_file": environment.tls.desktopBackendCert, "server_private_key_file": environment.tls.desktopBackendKey, "client_ca_bundle_file": environment.tls.ca.writeCA("desktop-backend"), "allowed_client_identities": []string{"spiffe://phase6.example.test/desktop-role"}, "max_sessions": 1, "operation_timeout_millis": 10000})
}

func writeGateConfigs(t *testing.T, environment *gateEnvironment, productMigrationDSN, providerMigrationDSN string) { //nolint:maintidx
	t.Helper()
	directory, ports, material := environment.paths.directory, environment.ports, environment.tls
	authorityPath := func(role, kind string) string { return filepath.Join(directory, role+"-"+kind+".json") }
	write := func(name, document string) string {
		path := filepath.Join(directory, name+".toml")
		writePrivate(t, path, []byte(document))
		return path
	}
	environment.paths.productConfig = write("product", fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[product_process]
enabled = true
deployment_level = "production"
[product_process.api]
host = "127.0.0.1"
port = %d
[product_process.tls]
certificate_file = %q
private_key_file = %q
[product_process.postgres]
migration_dsn_file = %q
runtime_dsn_file = %q
migration_role = "product_migrator"
runtime_role = "product_runtime"
startup_timeout_seconds = 10
operation_timeout_seconds = 2
migration_max_connections = 1
max_connections = 4
min_connections = 1
[product_process.identity]
issuer = "https://identity.product.phase6.test"
audience = "https://api.product.phase6.test"
key_ring_file = %q
clock_skew_seconds = 30
max_token_lifetime_seconds = 900
`, ports.product, material.productCert, material.productKey, productMigrationDSN, environment.paths.productRuntimeDSN, environment.paths.productIdentityKey))

	environment.paths.providerConfig = write("provider", providerConfigDocument(environment, providerMigrationDSN))
	environment.paths.gatewayConfig = write("gateway", gatewayConfigDocument(environment, authorityPath))
	environment.paths.guestConfig = write("guest", guestConfigDocument(environment, authorityPath))
	environment.paths.browserConfig = write("browser", executorRoleConfigDocument(environment, "browser", ports.browser, ports.browserProbe, material.browserRoleCert, material.browserRoleKey, material.browserRoleClientCert, material.browserRoleClientKey, "spiffe://phase6.example.test/provider-executor", authorityPath))
	environment.paths.desktopConfig = write("desktop", executorRoleConfigDocument(environment, "desktop", ports.desktop, ports.desktopProbe, material.desktopRoleCert, material.desktopRoleKey, material.desktopRoleClientCert, material.desktopRoleClientKey, "spiffe://phase6.example.test/provider-executor", authorityPath))
}

func providerConfigDocument(environment *gateEnvironment, providerMigrationDSN string) string { //nolint:maintidx
	architecture := runtime.GOARCH
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[provider_process]
enabled = true
deployment_level = "local_candidate"
profile = "desktop"
[provider_process.transport]
enabled = true
server_certificate_file = %q
server_private_key_file = %q
client_ca_bundle_file = %q
allowed_client_uri_identities = [%q]
[provider_process.transport.address]
host = "127.0.0.1"
port = %d
[provider_process.transport.private]
enabled = true
server_certificate_file = %q
server_private_key_file = %q
client_ca_bundle_file = %q
allowed_client_uri_identities = ["spiffe://phase6.example.test/gateway"]
route_policy = ["desktop"]
read_header_timeout_millis = 5000
read_timeout_millis = 30000
write_timeout_millis = 30000
idle_timeout_millis = 60000
max_header_bytes = 32768
max_body_bytes = 262144
[provider_process.transport.private.address]
host = "127.0.0.1"
port = %d
[provider_process.probe]
host = "127.0.0.1"
port = %d
[provider_process.capability]
provider_revision_id = %q
[provider_process.capability.limits]
max_cpu_millis = 4000
max_memory_bytes = 4294967296
max_ephemeral_storage_bytes = 4294967296
max_lease_seconds = 3600
max_exec_seconds = 300
[[provider_process.capability.snapshot_restore_profiles]]
profile_id = "sandbox-snapshot-workspace-v1"
level = "workspace"
suite_id = "sandbox-provider"
suite_version = "1.0.0"
suite_digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[provider_process.protected_admission]
issuer = %q
provider_instance_audience = %q
[[provider_process.protected_admission.trusted_verification_keys]]
id = %q
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
max_connections = 8
min_connections = 1
[provider_process.reconciliation]
interval_seconds = 1
timeout_seconds = 2
[provider_process.desktop]
architecture = %q
executor_url = "wss://127.0.0.1:%d/executor"
broker_mux_socket_path = %q
executor_ca_bundle_file = %q
executor_certificate_file = %q
executor_private_key_file = %q
executor_identity = "executor-desktop-1"
executor_bridge_key_id = "provider-desktop-v2"
executor_bridge_private_key_file = %q
local_candidate_manifest_file = %q
usage_retention_seconds = 3600
shutdown_cleanup_seconds = 15
[provider_process.desktop.docker]
image = %q
pull_policy = "never"
memory_bytes = 1073741824
nano_cpus = 1000000000
pids_limit = 256
inputs_bytes = 16777216
tmpfs_bytes = 268435456
workspace_bytes = 268435456
outputs_bytes = 134217728
operation_timeout_seconds = 30
provenance_timeout_seconds = 30
pull_timeout_seconds = 30
stop_timeout_seconds = 10
data_root = %q
manifest_path = %q
namespace = "phase6-slice4"
controller_id = "phase6-controller-1"
network_policy_reference = "desktop-egress-policy-1"
max_sessions_per_sandbox = 1
max_sessions_per_controller = 4
[provider_process.desktop.restricted_network]
gateway_image = %q
uplink_network = %q
namespace = "phase6-slice4"
controller_id = "phase6-controller-1"
memory_bytes = 134217728
nano_cpus = 500000000
pids_limit = 64
operation_timeout_seconds = 30
stop_timeout_seconds = 10
[[provider_process.desktop.restricted_network.policies]]
reference = "desktop-egress-policy-1"
allowed_hosts = ["packages.example.test"]
`, environment.tls.providerCert, environment.tls.providerKey, environment.tls.controllerCA, providerCaller, environment.ports.provider,
		environment.tls.providerPrivateCert, environment.tls.providerPrivateKey, environment.tls.gatewayProviderCA, environment.ports.providerPrivate, environment.ports.providerProbe,
		providerRevision, providerIssuer, providerAudience, providerKeyID, environment.paths.admissionKey,
		providerMigrationDSN, environment.paths.providerRuntimeDSN, architecture, environment.ports.desktop, environment.paths.brokerSocket,
		environment.tls.providerExecutorCA, environment.tls.providerExecutorCert, environment.tls.providerExecutorKey, environment.paths.bridgeKey,
		os.Getenv(candidateEnv), environment.candidate.ImageDigest, filepath.Join(environment.paths.directory, "desktop-runtime"), filepath.Join(environment.root, "profiles/desktop/image/manifest.json"),
		environment.gatewayImage, environment.uplinkNetwork)
}

func gatewayConfigDocument(environment *gateEnvironment, authorityPath func(string, string) string) string {
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[gateway_process]
enabled = true
deployment_level = "production"
[gateway_process.public]
host = "127.0.0.1"
port = %d
[gateway_process.probe]
host = "127.0.0.1"
port = %d
[gateway_process.tls]
certificate_file = %q
private_key_file = %q
[gateway_process.authority]
credential_file = %q
dependency_file = %q
policy_file = %q
recording_key_reference = "kms://phase6/gateway-recording"
[gateway_process.drain]
grace_seconds = 5
reconnect_seconds = 5
dependency_timeout_seconds = 3
`, environment.ports.gateway, environment.ports.gatewayProbe, environment.tls.gatewayCert, environment.tls.gatewayKey,
		authorityPath("gateway", "credential"), authorityPath("gateway", "dependency"), authorityPath("gateway", "policy"))
}

func guestConfigDocument(environment *gateEnvironment, authorityPath func(string, string) string) string {
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[guest_process]
enabled = true
deployment_level = "production"
outbound_url = %q
[guest_process.probe]
host = "127.0.0.1"
port = %d
[guest_process.tls]
client_ca_bundle_file = %q
client_certificate_file = %q
client_private_key_file = %q
[guest_process.authority]
credential_file = %q
dependency_file = %q
policy_file = %q
recording_key_reference = "kms://phase6/guest-recording"
[guest_process.drain]
grace_seconds = 5
reconnect_seconds = 5
dependency_timeout_seconds = 3
`, environment.guest.url(), environment.ports.guestProbe, environment.tls.ca.writeCA("guest-client"), environment.tls.guestClientCert, environment.tls.guestClientKey,
		authorityPath("guest", "credential"), authorityPath("guest", "dependency"), authorityPath("guest", "policy"))
}

func executorRoleConfigDocument(environment *gateEnvironment, role string, listenerPort, probePort int, certificate, privateKey, clientCertificate, clientKey, allowedIdentity string, authorityPath func(string, string) string) string {
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[%s_process]
enabled = true
deployment_level = "production"
[%s_process.public]
host = "127.0.0.1"
port = %d
[%s_process.private]
host = "127.0.0.1"
port = %d
[%s_process.probe]
host = "127.0.0.1"
port = %d
[%s_process.tls]
certificate_file = %q
private_key_file = %q
client_ca_bundle_file = %q
client_certificate_file = %q
client_private_key_file = %q
allowed_client_identities = [%q]
[%s_process.authority]
credential_file = %q
dependency_file = %q
policy_file = %q
recording_key_reference = "kms://phase6/%s-recording"
[%s_process.drain]
grace_seconds = 5
reconnect_seconds = 5
dependency_timeout_seconds = 3
`, role, role, listenerPort, role, listenerPort, role, probePort, role, certificate, privateKey, environment.tls.ca.writeCA(role+"-role"), clientCertificate, clientKey, allowedIdentity,
		role, authorityPath(role, "credential"), authorityPath(role, "dependency"), authorityPath(role, "policy"), role, role)
}

func randomBytes(t *testing.T, count int) []byte {
	t.Helper()
	value := make([]byte, count)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func productClient(environment *gateEnvironment) *http.Client {
	return environment.tls.ca.publicClient("product.phase6.test")
}

func gatewayClient(environment *gateEnvironment) *http.Client {
	return environment.tls.ca.publicClient("gateway.phase6.test")
}

func providerClient(environment *gateEnvironment) *http.Client {
	client := environment.tls.ca.client("provider.phase6.test", environment.tls.controllerClient)
	client.Timeout = 2 * time.Minute
	return client
}

func providerPrivateClient(environment *gateEnvironment) *http.Client {
	return environment.tls.ca.client("provider-private.phase6.test", environment.tls.privateGatewayClient)
}

func signProductToken(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	now := time.Now().UTC()
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "kid": "phase6-product-access-1", "typ": "sandbox-runtime-product-access+jwt"})
	claims, _ := json.Marshal(map[string]any{"iss": "https://identity.product.phase6.test", "aud": "https://api.product.phase6.test", "sub": "actor-phase6", "tenant_id": gateTenantID, "actor_type": "human", "actor_id": "actor-phase6", "role": "owner", "iat": now.Add(-time.Minute).Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(), "jti": "phase6-product-jti-00000001"})
	first, second := base64.RawURLEncoding.EncodeToString(header), base64.RawURLEncoding.EncodeToString(claims)
	return first + "." + second + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(first+"."+second)))
}

func parseCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(document)
	if block == nil {
		t.Fatal("decode certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
