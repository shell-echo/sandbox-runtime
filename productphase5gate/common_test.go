//go:build phase5desktopgate

package productphase5gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/productphase5evidence"
	"github.com/shell-echo/sandbox-runtime/product"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	phase5NodeRole       = "PRODUCT_PHASE5_NODE_ROLE"
	phase5NodeConfig     = "PRODUCT_PHASE5_NODE_CONFIG"
	phase5EvidenceOutput = "PRODUCT_PHASE5_EVIDENCE_OUTPUT"
	ownerBearer          = "phase5-release-owner-bearer-00000000000001"
	foreignBearer        = "phase5-release-foreign-bearer-0000000001"
	publicOrigin         = "https://product.example.test"
	releaseTenantID      = "tenant-phase5-release"
	releaseActorID       = "actor-phase5-release"
)

type nodeConfig struct {
	ProviderAddress        string    `json:"provider_address"`
	DesktopProviderAddress string    `json:"desktop_provider_address"`
	DesktopPrivateAddress  string    `json:"desktop_private_address"`
	DesktopControlAddress  string    `json:"desktop_control_address"`
	GatewayAddress         string    `json:"gateway_address"`
	ProductAddress         string    `json:"product_address"`
	DSN                    string    `json:"dsn"`
	ProviderSigning        string    `json:"provider_signing"`
	GrantKey               string    `json:"grant_key"`
	RecordingKey           string    `json:"recording_key"`
	RecordingRoot          string    `json:"recording_root"`
	BlobRoot               string    `json:"blob_root"`
	GateKey                string    `json:"gate_key"`
	CACertificate          string    `json:"ca_certificate"`
	DesktopCertificate     string    `json:"desktop_certificate"`
	DesktopKey             string    `json:"desktop_key"`
	GatewayCertificate     string    `json:"gateway_certificate"`
	GatewayKey             string    `json:"gateway_key"`
	EdgeCertificate        string    `json:"edge_certificate"`
	EdgeKey                string    `json:"edge_key"`
	DesktopContainer       string    `json:"desktop_container"`
	ExpiresAt              time.Time `json:"expires_at"`
	GuestID                string    `json:"guest_id,omitempty"`
	GuestGeneration        int64     `json:"guest_generation,omitempty"`
	GuestPrivateKey        string    `json:"guest_private_key,omitempty"`
	GuestRoot              string    `json:"guest_root,omitempty"`
	GuestState             string    `json:"guest_state,omitempty"`
}

type childNode struct {
	role    string
	cmd     *exec.Cmd
	log     bytes.Buffer
	done    chan struct{}
	waitMu  sync.Mutex
	waitErr error
}

func TestPhase5Node(t *testing.T) {
	role := os.Getenv(phase5NodeRole)
	if role == "" {
		t.Skip("separate-process node helper")
	}
	document, err := os.ReadFile(os.Getenv(phase5NodeConfig))
	if err != nil {
		t.Fatal(err)
	}
	var config nodeConfig
	if err := json.Unmarshal(document, &config); err != nil {
		t.Fatal(err)
	}
	switch role {
	case "provider":
		err = runProviderNode(config)
	case "desktop":
		err = runDesktopNode(config)
	case "gateway":
		err = runGatewayNode(config)
	case "product":
		err = runProductNode(config)
	case "guest":
		err = runGuestNode(config)
	default:
		err = fmt.Errorf("unknown Phase 5 node role %q", role)
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}

func startNode(t *testing.T, role, configPath string) *childNode {
	t.Helper()
	node := &childNode{role: role, done: make(chan struct{})}
	node.cmd = exec.Command(os.Args[0], "-test.run=^TestPhase5Node$", "-test.v")
	node.cmd.Env = append(os.Environ(), phase5NodeRole+"="+role, phase5NodeConfig+"="+configPath)
	node.cmd.Stdout, node.cmd.Stderr = &node.log, &node.log
	if err := node.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := node.cmd.Wait()
		node.waitMu.Lock()
		node.waitErr = err
		node.waitMu.Unlock()
		close(node.done)
	}()
	return node
}

func stopNode(node *childNode) bool {
	if node == nil || node.cmd == nil || node.cmd.Process == nil {
		return true
	}
	select {
	case <-node.done:
		node.waitMu.Lock()
		err := node.waitErr
		node.waitMu.Unlock()
		return err == nil && node.cmd.ProcessState != nil && node.cmd.ProcessState.Success()
	default:
	}
	if err := node.cmd.Process.Signal(os.Interrupt); err != nil {
		return false
	}
	select {
	case <-node.done:
		node.waitMu.Lock()
		err := node.waitErr
		node.waitMu.Unlock()
		return err == nil && node.cmd.ProcessState != nil && node.cmd.ProcessState.Success()
	case <-time.After(8 * time.Second):
		_ = node.cmd.Process.Kill()
		<-node.done
		return false
	}
}

func removeNode(nodes []*childNode, target *childNode) []*childNode {
	result := nodes[:0]
	for _, node := range nodes {
		if node != target {
			result = append(result, node)
		}
	}
	return result
}

func writeConfig(t *testing.T, path string, config nodeConfig) {
	t.Helper()
	document, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
}

func serveUntilSignal(address string, handler http.Handler, tlsConfig *tls.Config) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitHTTP(t *testing.T, ctx context.Context, client *http.Client, target string, wanted int, node *childNode) {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == wanted {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait %s: %v; node=%s", target, ctx.Err(), nodeLog(node))
		case <-node.done:
			t.Fatalf("node %s exited while waiting for %s: %s", node.role, target, nodeLog(node))
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, predicate func() bool, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", label)
}

func nodeLog(node *childNode) string {
	if node == nil {
		return "<nil>"
	}
	return node.log.String()
}

func startPostgres(t *testing.T, ctx context.Context, name string) (string, func()) {
	t.Helper()
	command := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=phase5", "-e", "POSTGRES_DB=phase5", "-p", "127.0.0.1::5432", productphase5evidence.PostgresImage)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("start pinned PostgreSQL: %v: %s", err, output)
	}
	remove := func() { _ = exec.Command("docker", "rm", "-f", name).Run() }
	portOutput, err := exec.CommandContext(ctx, "docker", "port", name, "5432/tcp").Output()
	if err != nil {
		remove()
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		remove()
		t.Fatal(err)
	}
	dsn := "postgres://postgres:phase5@127.0.0.1:" + port + "/phase5?sslmode=disable"
	waitFor(t, 20*time.Second, func() bool {
		pool, poolErr := pgxpool.New(ctx, dsn)
		if poolErr != nil {
			return false
		}
		defer pool.Close()
		return pool.Ping(ctx) == nil
	}, "fresh PostgreSQL")
	return dsn, remove
}

func writeCertificates(t *testing.T, directory string, config *nodeConfig) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase5-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(directory, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)
	config.CACertificate = caPath
	issue := func(name string, client bool) (string, string) {
		key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if client {
			usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: usage}
		der, createErr := x509.CreateCertificate(rand.Reader, template, caTemplate, &key.PublicKey, caKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		certPath, keyPath := filepath.Join(directory, name+".pem"), filepath.Join(directory, name+".key")
		writePEM(t, certPath, "CERTIFICATE", der)
		keyDER := x509.MarshalPKCS1PrivateKey(key)
		writePEM(t, keyPath, "RSA PRIVATE KEY", keyDER)
		return certPath, keyPath
	}
	config.DesktopCertificate, config.DesktopKey = issue("phase5-desktop", false)
	config.GatewayCertificate, config.GatewayKey = issue("phase5-gateway", true)
	config.EdgeCertificate, config.EdgeKey = issue("phase5-edge", false)
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatal(err)
	}
}

func serverTLS(certPath, keyPath, caPath string, requireClient bool) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	configuration := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	if requireClient {
		document, readErr := os.ReadFile(caPath)
		if readErr != nil {
			return nil, readErr
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(document) {
			return nil, errors.New("invalid CA")
		}
		configuration.ClientAuth, configuration.ClientCAs = tls.RequireAndVerifyClientCert, pool
	}
	return configuration, nil
}

func tlsClient(caPath, serverName string) *http.Client {
	document, err := os.ReadFile(caPath)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(document) {
		return nil
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: serverName}}}
}

func mutualTLSClient(config nodeConfig) *http.Client {
	certificate, err := tls.LoadX509KeyPair(config.GatewayCertificate, config.GatewayKey)
	if err != nil {
		return nil
	}
	document, err := os.ReadFile(config.CACertificate)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(document) {
		return nil
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{certificate}, ServerName: "phase5-desktop"}}}
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func releaseActor() product.ActorRef {
	return product.ActorRef{Type: product.ActorHuman, ID: releaseActorID}
}

func releaseArchitecture() providerv1.Architecture {
	if runtime.GOARCH == "arm64" {
		return providerv1.ArchitectureARM64
	}
	return providerv1.ArchitectureAMD64
}

func releasePlatform() (string, string) {
	if runtime.GOARCH == "arm64" {
		return "linux/arm64/v8", "sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505"
	}
	return "linux/amd64", "sha256:ae1b71855f879066caf73f1056039d52b796d936a19f4b34a58a5565dd89609b"
}

func releaseDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func api(t *testing.T, method, target, authorization, key, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requireStatus(t *testing.T, response *http.Response, wanted int) {
	t.Helper()
	if response.StatusCode != wanted {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		t.Fatalf("status=%d want=%d body=%s", response.StatusCode, wanted, body)
	}
}

func decode(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(response.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		t.Fatal(err)
	}
}

func waitWorkspace(t *testing.T, base, workspaceID, state string) productapiv1.Workspace {
	t.Helper()
	var result productapiv1.Workspace
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/workspaces/"+workspaceID, "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		decode(t, response, &result)
		return result.ObservedState == state
	}, "workspace "+state)
	return result
}

func waitOperation(t *testing.T, base, operationID, state string) productapiv1.ProductOperation {
	t.Helper()
	var result productapiv1.ProductOperation
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/operations/"+operationID, "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		decode(t, response, &result)
		return result.State == state
	}, "operation "+state)
	return result
}

func waitSession(t *testing.T, base, sessionID, state string) productapiv1.RuntimeSession {
	t.Helper()
	var result productapiv1.RuntimeSession
	waitFor(t, 15*time.Second, func() bool {
		response := api(t, http.MethodGet, base+"/api/v1/sessions/"+sessionID, "Bearer "+ownerBearer, "", "")
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			return false
		}
		decode(t, response, &result)
		return result.State == state
	}, "session "+state)
	return result
}

func base64Key(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawStdEncoding.EncodeToString(privateKey)
}
