//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	slice5evidence "github.com/shell-echo/sandbox-runtime/internal/productphase6slice5evidence"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	desktopimage "github.com/shell-echo/sandbox-runtime/profiles/desktop/image"
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
	directory                  string
	binary                     string
	browserBackendBin          string
	desktopBackendBin          string
	materialAgentBin           string
	credentialControllerBin    string
	breakGlassControllerBin    string
	productConfig              string
	productMigrationConfig     string
	providerConfig             string
	providerMigrationConfig    string
	gatewayConfig              string
	guestConfig                string
	browserConfig              string
	desktopConfig              string
	browserBackendAuth         string
	desktopBackendAuth         string
	brokerDirectory            string
	brokerSocket               string
	productRuntimeDSN          string
	providerRuntimeDSN         string
	bridgeKey                  string
	admissionKey               string
	productIdentityKey         string
	materialSockets            map[string]string
	credentialSocket           string
	credentialLedger           string
	breakGlassControllerSocket string
	breakGlassLedger           string
	breakGlassAudit            string
	breakGlassSockets          map[string]string
}

type gateEnvironment struct {
	runID                   string
	root                    string
	paths                   gatePaths
	ports                   rolePorts
	tls                     gateTLSMaterial
	candidate               desktopcandidate.Manifest
	productDB               *postgresAuthority
	providerDB              *postgresAuthority
	admissionKey            ed25519.PrivateKey
	productToken            ed25519.PrivateKey
	gatewayImage            string
	uplinkNetwork           string
	chromiumName            string
	chromiumURL             string
	guest                   *guestFixture
	dependencies            []*gateProcess
	materialAgents          map[string]*gateProcess
	materialAgentHistory    []*gateProcess
	credentialController    *gateProcess
	breakGlassController    *gateProcess
	roles                   map[string]*gateProcess
	roleHistory             map[string][]*gateProcess
	scenarios               map[string]scenarioObservation
	repository              productphase6evidence.RepositoryBinding
	recordingEvidence       slice5evidence.RecordingTransitEvidence
	roleMaterialEvidence    slice5evidence.RoleMaterialAndCredentials
	stress                  productphase6evidence.StressMeasurements
	desktopMedia            productphase6evidence.DesktopMediaMeasurements
	materials               map[string][]secretref.SecretMaterial
	credentialBindings      map[string]secretref.Binding
	credentialKeys          map[string]ed25519.PrivateKey
	breakGlassKeys          map[string]ed25519.PrivateKey
	breakGlassControllerKey ed25519.PrivateKey
	vaultContainer          string
	vaultEndpoint           string
	vaultCA                 []byte
	vaultRootToken          string
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
	recordingEvidence, err := slice5evidence.VerifyRecordingFile(os.Getenv(recordingEvidenceEnv))
	if err != nil {
		t.Fatalf("load real recording Transit evidence: %v", err)
	}
	if recordingEvidence.RuntimeImplementationRevision != repository.RuntimeImplementationRevision ||
		recordingEvidence.RuntimeImplementationTreeDigest != repository.RuntimeImplementationTreeDigest ||
		recordingEvidence.EvidenceToolRevision != repository.EvidenceToolRevision ||
		recordingEvidence.EvidenceToolTreeDigest != repository.EvidenceToolTreeDigest {
		t.Fatal("recording Transit evidence does not bind the current immutable runtime/evidence revisions")
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
		runID: runID, root: root, candidate: candidate, repository: repository, recordingEvidence: recordingEvidence, roles: make(map[string]*gateProcess), roleHistory: make(map[string][]*gateProcess), scenarios: make(map[string]scenarioObservation), materialAgents: make(map[string]*gateProcess),
		paths: gatePaths{directory: directory, binary: filepath.Join(directory, "sandbox-runtime"), browserBackendBin: filepath.Join(directory, "browser-executor-backend"), desktopBackendBin: filepath.Join(directory, "desktop-executor-backend"), materialAgentBin: filepath.Join(directory, "workload-material-agent"), credentialControllerBin: filepath.Join(directory, "workload-credential-controller"), breakGlassControllerBin: filepath.Join(directory, "break-glass-controller"), brokerDirectory: brokerDirectory, brokerSocket: filepath.Join(brokerDirectory, "desktop-broker-11111111111111111111111111111111.sock"), materialSockets: make(map[string]string), breakGlassSockets: make(map[string]string)},
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
	prepareGateMaterials(t, environment, productMigrationDSN, providerMigrationDSN)
	prepareGateVault(t, ctx, environment)
	prepareGateBreakGlass(t, environment)
	writeGateConfigs(t, environment, productMigrationDSN, providerMigrationDSN)
	t.Cleanup(func() { bestEffortPhase6NamespaceCleanup() })
	return environment
}

func bestEffortPhase6NamespaceCleanup() {
	containerOutput, err := exec.Command("docker", "ps", "-aq", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5").Output()
	if err == nil {
		for _, identifier := range strings.Fields(string(containerOutput)) {
			_ = exec.Command("docker", "rm", "-f", identifier).Run()
		}
	}
	networkOutput, err := exec.Command("docker", "network", "ls", "-q", "--filter", "label=io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5").Output()
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
		{environment.paths.materialAgentBin, "./cmd/workload-material-agent"},
		{environment.paths.credentialControllerBin, "./cmd/workload-credential-controller"},
		{environment.paths.breakGlassControllerBin, "./cmd/break-glass-controller"},
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

func prepareGateMaterials(t *testing.T, environment *gateEnvironment, productMigrationDSN, providerMigrationDSN string) {
	t.Helper()
	read := func(path string) []byte {
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	ca := read(environment.tls.ca.writeCA("phase6-role-material"))
	environment.materials = map[string][]secretref.SecretMaterial{
		"product-migration": {
			gateMaterial(t, secretref.RoleProduct, "product-migration-dsn", secretref.PurposePostgresMigrationDSN, read(productMigrationDSN)),
		},
		"product-runtime": {
			gateMaterial(t, secretref.RoleProduct, "product-tls-certificate", secretref.PurposeTLSCertificate, read(environment.tls.productCert)),
			gateMaterial(t, secretref.RoleProduct, "product-tls-private-key", secretref.PurposeTLSPrivateKey, read(environment.tls.productKey)),
			gateMaterial(t, secretref.RoleProduct, "product-runtime-dsn", secretref.PurposePostgresRuntimeDSN, read(environment.paths.productRuntimeDSN)),
			gateMaterial(t, secretref.RoleProduct, "product-identity-key-ring", secretref.PurposeIdentityKeyRing, read(environment.paths.productIdentityKey)),
		},
		"provider-migration": {
			gateMaterial(t, secretref.RoleProvider, "provider-migration-dsn", secretref.PurposePostgresMigrationDSN, read(providerMigrationDSN)),
		},
		"provider-runtime": {
			gateMaterial(t, secretref.RoleProvider, "provider-contract-certificate", secretref.PurposeTLSCertificate, read(environment.tls.providerCert)),
			gateMaterial(t, secretref.RoleProvider, "provider-contract-private-key", secretref.PurposeTLSPrivateKey, read(environment.tls.providerKey)),
			gateMaterial(t, secretref.RoleProvider, "provider-controller-ca", secretref.PurposeCABundle, read(environment.tls.controllerCA)),
			gateMaterial(t, secretref.RoleProvider, "provider-private-certificate", secretref.PurposeTLSCertificate, read(environment.tls.providerPrivateCert)),
			gateMaterial(t, secretref.RoleProvider, "provider-private-key", secretref.PurposeTLSPrivateKey, read(environment.tls.providerPrivateKey)),
			gateMaterial(t, secretref.RoleProvider, "provider-gateway-ca", secretref.PurposeCABundle, read(environment.tls.gatewayProviderCA)),
			gateMaterial(t, secretref.RoleProvider, "provider-runtime-dsn", secretref.PurposePostgresRuntimeDSN, read(environment.paths.providerRuntimeDSN)),
			gateMaterial(t, secretref.RoleProvider, "provider-admission-key", secretref.PurposeAdmissionVerification, read(environment.paths.admissionKey)),
			gateMaterial(t, secretref.RoleProvider, "provider-executor-ca", secretref.PurposeCABundle, read(environment.tls.providerExecutorCA)),
			gateMaterial(t, secretref.RoleProvider, "provider-executor-certificate", secretref.PurposeTLSCertificate, read(environment.tls.providerExecutorCert)),
			gateMaterial(t, secretref.RoleProvider, "provider-executor-private-key", secretref.PurposeExecutorClientKey, read(environment.tls.providerExecutorKey)),
			gateMaterial(t, secretref.RoleProvider, "provider-executor-bridge-key", secretref.PurposeExecutorBridgeKey, read(environment.paths.bridgeKey)),
		},
		"gateway": {
			gateMaterial(t, secretref.RoleGateway, "gateway-server-certificate", secretref.PurposeTLSCertificate, read(environment.tls.gatewayCert)),
			gateMaterial(t, secretref.RoleGateway, "gateway-server-private-key", secretref.PurposeTLSPrivateKey, read(environment.tls.gatewayKey)),
			gateMaterial(t, secretref.RoleGateway, "gateway-product-runtime-dsn", secretref.PurposePostgresRuntimeDSN, read(environment.paths.productRuntimeDSN)),
			gateMaterial(t, secretref.RoleGateway, "gateway-grant-key", secretref.PurposeGatewayGrantKey, randomBytes(t, 32)),
			gateMaterial(t, secretref.RoleGateway, "gateway-provider-ca", secretref.PurposeCABundle, read(environment.tls.gatewayProviderCA)),
			gateMaterial(t, secretref.RoleGateway, "gateway-provider-certificate", secretref.PurposeTLSCertificate, read(environment.tls.gatewayProviderCert)),
			gateMaterial(t, secretref.RoleGateway, "gateway-provider-private-key", secretref.PurposeTLSPrivateKey, read(environment.tls.gatewayProviderKey)),
		},
		"guest": {
			gateMaterial(t, secretref.RoleGuest, "guest-server-ca", secretref.PurposeCABundle, ca),
			gateMaterial(t, secretref.RoleGuest, "guest-client-certificate", secretref.PurposeTLSCertificate, read(environment.tls.guestClientCert)),
			gateMaterial(t, secretref.RoleGuest, "guest-client-private-key", secretref.PurposeTLSPrivateKey, read(environment.tls.guestClientKey)),
			gateMaterial(t, secretref.RoleGuest, "guest-signing-key", secretref.PurposeGuestSigningKey, environment.guest.privateKey),
		},
		"browser": executorGateMaterials(t, secretref.RoleBrowser, "browser", ca, read(environment.tls.browserRoleCert), read(environment.tls.browserRoleKey), read(environment.tls.browserRoleClientCert), read(environment.tls.browserRoleClientKey)),
		"desktop": executorGateMaterials(t, secretref.RoleDesktop, "desktop", ca, read(environment.tls.desktopRoleCert), read(environment.tls.desktopRoleKey), read(environment.tls.desktopRoleClientCert), read(environment.tls.desktopRoleClientKey)),
	}
	for name := range environment.materials {
		directory, err := os.MkdirTemp("/tmp", "sr-p6-"+strings.ReplaceAll(name, "-", "")+"-")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
			t.Fatal("prepare role material socket directory")
		}
		t.Cleanup(func() { _ = os.RemoveAll(directory) })
		environment.paths.materialSockets[name] = filepath.Join(directory, "agent.sock")
	}
}

func executorGateMaterials(t *testing.T, role secretref.Role, prefix string, ca, serverCertificate, serverKey, clientCertificate, clientKey []byte) []secretref.SecretMaterial {
	return []secretref.SecretMaterial{
		gateMaterial(t, role, prefix+"-server-certificate", secretref.PurposeTLSCertificate, serverCertificate),
		gateMaterial(t, role, prefix+"-server-private-key", secretref.PurposeTLSPrivateKey, serverKey),
		gateMaterial(t, role, prefix+"-ca", secretref.PurposeCABundle, ca),
		gateMaterial(t, role, prefix+"-client-certificate", secretref.PurposeTLSCertificate, clientCertificate),
		gateMaterial(t, role, prefix+"-client-private-key", secretref.PurposeTLSPrivateKey, clientKey),
	}
}

func gateMaterial(t *testing.T, role secretref.Role, id string, purpose secretref.Purpose, value []byte) secretref.SecretMaterial {
	t.Helper()
	binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: secretref.Reference("secret://phase6/kv/" + id), Version: "v1", Purpose: purpose,
		TenantID: secretref.SystemTenant, Role: role}
	if err := binding.Validate(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(value)
	now := time.Now().UTC()
	return secretref.SecretMaterial{Binding: binding, Bytes: append([]byte(nil), value...), Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1", Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * time.Minute), State: secretref.KeyActive}}
}

func gateMaterialBindingsTOML(t *testing.T, section, provider string, materials []secretref.SecretMaterial) string {
	t.Helper()
	var builder strings.Builder
	for _, material := range materials {
		id := strings.TrimPrefix(material.Binding.Reference.String(), "secret://phase6/kv/")
		document, err := json.Marshal(material.Binding)
		if err != nil {
			t.Fatal(err)
		}
		builder.WriteString("[[" + section + ".materials.bindings]]\n")
		encodedID, _ := json.Marshal(id)
		encodedProvider, _ := json.Marshal(provider)
		builder.WriteString("id = " + string(encodedID) + "\nprovider = " + string(encodedProvider) + "\ndocument = '")
		builder.Write(document)
		builder.WriteString("'\n\n")
	}
	return builder.String()
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
	output, err := exec.CommandContext(ctx, "docker", "network", "create", "--driver", "bridge", "--label", "io.github.shell-echo.sandbox-runtime.managed=true", "--label", "io.github.shell-echo.sandbox-runtime.owner="+docker.UplinkRole, "--label", "io.github.shell-echo.sandbox-runtime.namespace=phase6-slice5", name).CombinedOutput()
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
		request, requestErr := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/json/version", nil)
		if requestErr != nil {
			return false
		}
		request.Close = true
		response, requestErr := (&http.Client{Timeout: time.Second}).Do(request)
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

	gatewayCredential := roleprocess.GatewayCredentialAuthority{Version: 3, Role: "gateway", ProductRuntimeDSNBindingID: "gateway-product-runtime-dsn", GrantKeyID: "phase6-gateway-grant-1", GrantKeyBindingID: "gateway-grant-key", ProviderOrigin: fmt.Sprintf("wss://127.0.0.1:%d/desktop", environment.ports.providerPrivate), ProviderCABundleBindingID: "gateway-provider-ca", ProviderClientCertificateBindingID: "gateway-provider-certificate", ProviderClientPrivateKeyBindingID: "gateway-provider-private-key"}
	gatewayDependency := roleprocess.GatewayDependencyAuthority{Version: 2, Role: "gateway", OperationTimeoutMillis: 5000, MaxConnections: 8, MaxConnectionsPerSession: 2, OriginPatterns: []string{"https://product.phase6.test"}}
	gatewayPolicy := roleprocess.GatewayPolicyAuthority{Version: 2, Role: "gateway", Terminal: "enabled", BrowserAutomation: "authority_unavailable", BrowserLive: "authority_unavailable", DesktopLive: "authority_unavailable", DeferredAuthorityReason: "phase6-slice5-6-authority-required"}
	writePrivateJSON(t, authorityPath("gateway", "credential"), gatewayCredential)
	writePrivateJSON(t, authorityPath("gateway", "dependency"), gatewayDependency)
	writePrivateJSON(t, authorityPath("gateway", "policy"), gatewayPolicy)

	workspaceRoot, stateRoot := filepath.Join(directory, "guest-workspace"), filepath.Join(directory, "guest-state")
	for _, path := range []string{workspaceRoot, stateRoot} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writePrivateJSON(t, authorityPath("guest", "credential"), roleprocess.GuestCredentialAuthority{Version: 2, Role: "guest", GuestID: environment.guest.guestID, BindingGeneration: 1, PrivateKeyBindingID: "guest-signing-key"})
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
	directory, ports := environment.paths.directory, environment.ports
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
schema_version = %q
enabled = true
deployment_level = "production"
[product_process.api]
host = "127.0.0.1"
port = %d
[product_process.tls]
certificate_binding_id = "product-tls-certificate"
private_key_binding_id = "product-tls-private-key"
expected_server_name = "product.phase6.test"
[product_process.postgres]
runtime_dsn_binding_id = "product-runtime-dsn"
runtime_role = "product_runtime"
startup_timeout_seconds = 10
operation_timeout_seconds = 2
max_connections = 4
min_connections = 1
[product_process.identity]
issuer = "https://identity.product.phase6.test"
audience = "https://api.product.phase6.test"
key_ring_binding_id = "product-identity-key-ring"
clock_skew_seconds = 30
max_token_lifetime_seconds = 900
[product_process.materials.provider]
type = %q
alias = "product-runtime-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 1

%s`, config.ProductProductionSchemaV2, ports.product, config.UnixWorkloadMaterialProviderV1, environment.paths.materialSockets["product-runtime"], os.Getuid(), os.Getgid(), gateMaterialBindingsTOML(t, "product_process", "product-runtime-agent", environment.materials["product-runtime"])))

	environment.paths.productMigrationConfig = write("product-migration", fmt.Sprintf(`[application]
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

%s`, config.ProductMigrationSchemaV1, config.UnixWorkloadMaterialProviderV1, environment.paths.materialSockets["product-migration"], os.Getuid(), os.Getgid(), gateMaterialBindingsTOML(t, "product_migration", "product-migration-agent", environment.materials["product-migration"])))

	environment.paths.providerConfig = write("provider", providerConfigDocument(t, environment))
	environment.paths.providerMigrationConfig = write("provider-migration", providerMigrationConfigDocument(t, environment))
	environment.paths.gatewayConfig = write("gateway", gatewayConfigDocument(t, environment, authorityPath))
	environment.paths.guestConfig = write("guest", guestConfigDocument(t, environment, authorityPath))
	environment.paths.browserConfig = write("browser", executorRoleConfigDocument(t, environment, "browser", ports.browser, ports.browserProbe, "browser-role.phase6.test", "spiffe://phase6.example.test/provider-executor", authorityPath))
	environment.paths.desktopConfig = write("desktop", executorRoleConfigDocument(t, environment, "desktop", ports.desktop, ports.desktopProbe, "desktop-role.phase6.test", "spiffe://phase6.example.test/provider-executor", authorityPath))
}

func providerConfigDocument(t *testing.T, environment *gateEnvironment) string { //nolint:maintidx
	t.Helper()
	architecture := runtime.GOARCH
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[provider_process]
schema_version = %q
enabled = true
deployment_level = "local_candidate"
profile = "desktop"
[provider_process.transport]
enabled = true
server_certificate_binding_id = "provider-contract-certificate"
server_private_key_binding_id = "provider-contract-private-key"
client_ca_bundle_binding_id = "provider-controller-ca"
expected_server_name = "provider.phase6.test"
allowed_client_uri_identities = [%q]
[provider_process.transport.address]
host = "127.0.0.1"
port = %d
[provider_process.transport.private]
enabled = true
server_certificate_binding_id = "provider-private-certificate"
server_private_key_binding_id = "provider-private-key"
client_ca_bundle_binding_id = "provider-gateway-ca"
expected_server_name = "provider-private.phase6.test"
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
public_key_binding_id = "provider-admission-key"
[provider_process.postgres]
runtime_dsn_binding_id = "provider-runtime-dsn"
runtime_role = "provider_runtime"
startup_timeout_seconds = 10
operation_timeout_seconds = 2
max_connections = 8
min_connections = 1
[provider_process.reconciliation]
interval_seconds = 1
timeout_seconds = 2
[provider_process.desktop]
architecture = %q
executor_url = "wss://127.0.0.1:%d/executor"
broker_mux_socket_path = %q
executor_ca_bundle_binding_id = "provider-executor-ca"
executor_certificate_binding_id = "provider-executor-certificate"
executor_private_key_binding_id = "provider-executor-private-key"
executor_identity = "executor-desktop-1"
executor_bridge_key_id = "provider-desktop-v2"
executor_bridge_private_key_binding_id = "provider-executor-bridge-key"
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
local_candidate_image_manifest_path = %q
namespace = "phase6-slice5"
controller_id = "phase6-controller-1"
network_policy_reference = "desktop-egress-policy-1"
max_sessions_per_sandbox = 1
max_sessions_per_controller = 4
[provider_process.desktop.restricted_network]
gateway_image = %q
uplink_network = %q
namespace = "phase6-slice5"
controller_id = "phase6-controller-1"
memory_bytes = 134217728
nano_cpus = 500000000
pids_limit = 64
operation_timeout_seconds = 30
stop_timeout_seconds = 10
[[provider_process.desktop.restricted_network.policies]]
reference = "desktop-egress-policy-1"
allowed_hosts = ["packages.example.test"]

[provider_process.materials.provider]
type = %q
alias = "provider-runtime-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 1

%s`, config.ProviderProductionSchemaV2, providerCaller, environment.ports.provider,
		environment.ports.providerPrivate, environment.ports.providerProbe,
		providerRevision, providerIssuer, providerAudience, providerKeyID,
		architecture, environment.ports.desktop, environment.paths.brokerSocket,
		os.Getenv(candidateEnv), environment.candidate.ImageDigest, filepath.Join(environment.paths.directory, "desktop-runtime"), filepath.Join(environment.root, "profiles/desktop/image", desktopimage.LocalCandidateManifestPath),
		environment.gatewayImage, environment.uplinkNetwork,
		config.UnixWorkloadMaterialProviderV1, environment.paths.materialSockets["provider-runtime"], os.Getuid(), os.Getgid(), gateMaterialBindingsTOML(t, "provider_process", "provider-runtime-agent", environment.materials["provider-runtime"]))
}

func providerMigrationConfigDocument(t *testing.T, environment *gateEnvironment) string {
	t.Helper()
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[provider_migration]
schema_version = %q
enabled = true
[provider_migration.postgres]
dsn_binding_id = "provider-migration-dsn"
role = "provider_migrator"
startup_timeout_seconds = 10
max_connections = 1
[provider_migration.materials.provider]
type = %q
alias = "provider-migration-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 0

%s`, config.ProviderMigrationSchemaV1, config.UnixWorkloadMaterialProviderV1, environment.paths.materialSockets["provider-migration"], os.Getuid(), os.Getgid(), gateMaterialBindingsTOML(t, "provider_migration", "provider-migration-agent", environment.materials["provider-migration"]))
}

func gatewayConfigDocument(t *testing.T, environment *gateEnvironment, authorityPath func(string, string) string) string {
	t.Helper()
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[gateway_process]
schema_version = %q
enabled = true
deployment_level = "production"
[gateway_process.public]
host = "127.0.0.1"
port = %d
[gateway_process.probe]
host = "127.0.0.1"
port = %d
[gateway_process.tls]
certificate_binding_id = "gateway-server-certificate"
private_key_binding_id = "gateway-server-private-key"
expected_server_name = "gateway.phase6.test"
[gateway_process.authority]
credential_file = %q
dependency_file = %q
policy_file = %q
recording_key_reference = "kms://phase6/gateway-recording"
[gateway_process.drain]
grace_seconds = 5
reconnect_seconds = 5
dependency_timeout_seconds = 3

[gateway_process.materials.provider]
type = %q
alias = "gateway-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 1

%s`, config.DataPlaneProductionSchemaV2, environment.ports.gateway, environment.ports.gatewayProbe,
		authorityPath("gateway", "credential"), authorityPath("gateway", "dependency"), authorityPath("gateway", "policy"),
		config.UnixWorkloadMaterialProviderV1, environment.paths.materialSockets["gateway"], os.Getuid(), os.Getgid(), gateMaterialBindingsTOML(t, "gateway_process", "gateway-agent", environment.materials["gateway"]))
}

func guestConfigDocument(t *testing.T, environment *gateEnvironment, authorityPath func(string, string) string) string {
	t.Helper()
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[guest_process]
schema_version = %q
enabled = true
deployment_level = "production"
outbound_url = %q
[guest_process.probe]
host = "127.0.0.1"
port = %d
[guest_process.tls]
client_ca_bundle_binding_id = "guest-server-ca"
client_certificate_binding_id = "guest-client-certificate"
client_private_key_binding_id = "guest-client-private-key"
expected_server_name = "guest-agent.phase6.test"
[guest_process.authority]
credential_file = %q
dependency_file = %q
policy_file = %q
recording_key_reference = "kms://phase6/guest-recording"
[guest_process.drain]
grace_seconds = 5
reconnect_seconds = 5
dependency_timeout_seconds = 3

[guest_process.materials.provider]
type = %q
alias = "guest-agent"
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 1

%s`, config.DataPlaneProductionSchemaV2, environment.guest.url(), environment.ports.guestProbe,
		authorityPath("guest", "credential"), authorityPath("guest", "dependency"), authorityPath("guest", "policy"),
		config.UnixWorkloadMaterialProviderV1, environment.paths.materialSockets["guest"], os.Getuid(), os.Getgid(), gateMaterialBindingsTOML(t, "guest_process", "guest-agent", environment.materials["guest"]))
}

func executorRoleConfigDocument(t *testing.T, environment *gateEnvironment, role string, listenerPort, probePort int, expectedServerName, allowedIdentity string, authorityPath func(string, string) string) string {
	t.Helper()
	return fmt.Sprintf(`[application]
mode = "production"
[logger]
level = "error"
[%s_process]
schema_version = %q
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
certificate_binding_id = %q
private_key_binding_id = %q
client_ca_bundle_binding_id = %q
client_certificate_binding_id = %q
client_private_key_binding_id = %q
expected_server_name = %q
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

[%s_process.materials.provider]
type = %q
alias = %q
socket_path = %q
expected_uid = %d
expected_gid = %d
operation_timeout_seconds = 2
cache_seconds = 1

%s`, role, config.DataPlaneProductionSchemaV2, role, listenerPort, role, listenerPort, role, probePort, role,
		role+"-server-certificate", role+"-server-private-key", role+"-ca", role+"-client-certificate", role+"-client-private-key", expectedServerName, allowedIdentity,
		role, authorityPath(role, "credential"), authorityPath(role, "dependency"), authorityPath(role, "policy"), role, role,
		role, config.UnixWorkloadMaterialProviderV1, role+"-agent", environment.paths.materialSockets[role], os.Getuid(), os.Getgid(), gateMaterialBindingsTOML(t, role+"_process", role+"-agent", environment.materials[role]))
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
