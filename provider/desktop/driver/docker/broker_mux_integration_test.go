//go:build integration

package docker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopbridge"
	"github.com/shell-echo/sandbox-runtime/internal/desktopbroker"
	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/desktopmedia"
	"github.com/shell-echo/sandbox-runtime/internal/executorbackend"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
	providerdesktop "github.com/shell-echo/sandbox-runtime/provider/desktop"
	providerremote "github.com/shell-echo/sandbox-runtime/provider/desktop/driver/remote"
)

const (
	desktopMuxIntegrationEnv       = "SANDBOX_RUNTIME_DESKTOP_MUX_INTEGRATION"
	desktopMuxCandidateManifestEnv = "SANDBOX_RUNTIME_DESKTOP_CANDIDATE_MANIFEST"
)

type realMuxNetwork struct {
	name string
}

func (n realMuxNetwork) Ready(context.Context, string) error { return nil }
func (n realMuxNetwork) Acquire(_ context.Context, request NetworkRequest) (NetworkAttachment, error) {
	return NetworkAttachment{DockerName: n.name, GatewayContainer: "desktop-egress-gateway-1", GatewayAddress: "10.231.0.1", LeaseID: "desktop-network-lease-1", PolicyReference: request.PolicyReference, PolicyDigest: "sha256:" + strings.Repeat("a", 64), WorkloadIdentityDigest: "sha256:" + strings.Repeat("b", 64), EgressGateway: true}, nil
}
func (n realMuxNetwork) Inspect(context.Context, NetworkAttachment) error { return nil }
func (n realMuxNetwork) Release(context.Context, NetworkAttachment) error { return nil }

type realMuxAuthority struct {
	mu         sync.Mutex
	privateKey ed25519.PrivateKey
	last       *desktopbroker.SessionOpen
	ref        string
	allocation string
}

func (a *realMuxAuthority) Authorize(_ context.Context, open desktopbroker.SessionOpen) error {
	if open.HandoffReference != a.ref || open.AllocationReference != a.allocation {
		return errors.New("real mux authority mismatch")
	}
	copy := open
	bridge := *open.Bridge
	copy.Bridge = &bridge
	a.mu.Lock()
	a.last = &copy
	a.mu.Unlock()
	return nil
}

func (a *realMuxAuthority) Probe(context.Context) (desktopbroker.SessionOpen, error) {
	a.mu.Lock()
	if a.last == nil {
		a.mu.Unlock()
		return desktopbroker.SessionOpen{}, errors.New("no verified allocation")
	}
	open := *a.last
	a.mu.Unlock()
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return desktopbroker.SessionOpen{}, err
	}
	open.RequestID = "probe-" + hex.EncodeToString(nonceBytes)
	statement := open.Bridge.Statement
	statement.NotBefore = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	statement.Nonce = "probe-" + hex.EncodeToString(nonceBytes)
	statement.BrokerRequestDigest = statement.CalculateBrokerRequestDigest()
	bridge, err := desktopbridge.Sign(statement, a.privateKey)
	if err != nil {
		return desktopbroker.SessionOpen{}, err
	}
	open.Bridge = &bridge
	return open, nil
}

func TestDesktopMuxRealCandidateExecutorChain(t *testing.T) { //nolint:cyclop
	if os.Getenv(desktopMuxIntegrationEnv) != "1" {
		t.Skip("set " + desktopMuxIntegrationEnv + "=1 to run the real Desktop mux chain")
	}
	candidatePath := os.Getenv(desktopMuxCandidateManifestEnv)
	candidate, err := desktopcandidate.Load(candidatePath)
	if err != nil || candidate.VerifySource("../../../..") != nil {
		t.Fatalf("load current Desktop candidate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	suffixBytes := make([]byte, 6)
	if _, err := rand.Read(suffixBytes); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(suffixBytes)
	networkName := "sr-desktop-mux-" + suffix
	if output, err := exec.CommandContext(ctx, "docker", "network", "create", "--driver", "bridge", "--subnet", "10.231.0.0/24", "--gateway", "10.231.0.1", networkName).CombinedOutput(); err != nil {
		t.Fatalf("create integration network: %v: %s", err, output)
	}
	defer func() { _ = exec.Command("docker", "network", "rm", networkName).Run() }()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	imageRoot, err := filepath.Abs("../../../../profiles/desktop/image")
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Image: candidate.ImageDigest, PullPolicy: PullNever, MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256, InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20, OperationTimeoutSeconds: 30, ProvenanceTimeoutSeconds: 30, PullTimeoutSeconds: 30, StopTimeoutSeconds: 10, DataRoot: stateRoot, ManifestPath: filepath.Join(imageRoot, "manifest.json"), Namespace: "desktop-mux-" + suffix, ControllerID: "controller-" + suffix, NetworkPolicyReference: "desktop-egress-policy-1", MaxSessionsPerSandbox: 1, MaxSessionsPerController: 4, Clock: ClockFunc(func() time.Time { return time.Now().UTC() }), BridgeKeyID: "provider-desktop-v2", BridgePublicKey: publicKey}
	driver, err := NewLocalCandidate(ctx, options, candidate, realMuxNetwork{name: networkName})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	now := time.Now().UTC()
	allocation := providerdesktop.Allocation{Request: providerdesktop.AllocationRequest{SandboxID: "sandbox-" + suffix, DesktopSessionID: "desktop-" + suffix, OperationID: "operation-" + suffix, AttemptID: "attempt-" + suffix, FencingToken: 1, ExpectedGeneration: 1, RequestDigest: "sha256:" + strings.Repeat("a", 64), NetworkPolicyReference: options.NetworkPolicyReference, ExpiresAt: now.Add(3 * time.Minute)}, AllocatedAt: now}
	receipt, err := driver.Allocate(ctx, allocation)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			_ = driver.Cleanup(cleanupCtx, receipt)
		}
	}()

	runtimeDirectory, err := os.MkdirTemp("/tmp", "sr-real-mux-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runtimeDirectory)
	if err := os.Chmod(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(runtimeDirectory, "desktop-broker-11111111111111111111111111111111.sock")
	handoffReference := "ref:desktop-session:" + strings.Repeat("1", 32)
	authority := &realMuxAuthority{privateKey: privateKey, ref: handoffReference, allocation: receipt.Reference}
	mux, err := NewBrokerMux(driver, BrokerMuxOptions{SocketPath: socket, MaxSessions: 4, OperationTimeout: 10 * time.Second, Authority: authority})
	if err != nil {
		t.Fatal(err)
	}
	muxCtx, cancelMux := context.WithCancel(ctx)
	muxDone := make(chan error, 1)
	go func() { muxDone <- mux.Startup(muxCtx) }()
	waitRealMuxSocket(t, ctx, socket)

	tlsMaterial := writeRealMuxTLS(t, runtimeDirectory)
	backendAddress := freeRealMuxAddress(t)
	backend, err := executorbackend.NewDesktop(executorbackend.DesktopConfig{Role: "desktop", ListenAddress: backendAddress, BrokerSocketPath: socket, ExecutorIdentity: "executor-desktop-1", ServerCertificateFile: tlsMaterial.serverCertificate, ServerPrivateKeyFile: tlsMaterial.serverKey, ClientCABundleFile: tlsMaterial.caCertificate, AllowedClientIdentities: []string{"spiffe://sandbox-runtime/provider"}, MaxSessions: 4, OperationTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	backendCtx, cancelBackend := context.WithCancel(ctx)
	backendDone := make(chan error, 1)
	go func() { backendDone <- backend.Serve(backendCtx) }()
	waitRealTCP(t, ctx, backendAddress)

	client, err := providerremote.NewHTTPClient("wss://"+backendAddress+"/executor", tlsMaterial.caCertificate, tlsMaterial.clientCertificate, tlsMaterial.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := providerremote.New(providerremote.Options{URL: "wss://" + backendAddress + "/executor", HTTPClient: client, OperationTimeout: 20 * time.Second, BridgeKeyID: options.BridgeKeyID, ExecutorIdentity: "executor-desktop-1", BridgePrivateKey: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	policy := desktopmedia.MediaPolicy{VideoCodec: "video/VP8", Width: 1280, Height: 720, MaxFPS: 30, MaxVideoBitrateKbps: 2000, MaxQueuedFrames: desktopmedia.DefaultMaxQueuedFrames, MaxQueuedInputs: desktopmedia.DefaultMaxQueuedInputs, MaxInputBytes: desktopmedia.DefaultMaxInputBytes, RecordingMode: "metadata_only"}
	authorityExpiry := time.Now().UTC().Add(90 * time.Second)
	mediaAuthority := providerdesktop.MediaAuthority{TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("b", 64), ProviderRevisionID: "provider-revision-1", SandboxID: allocation.Request.SandboxID, DesktopSessionID: allocation.Request.DesktopSessionID, HandoffReference: handoffReference, HandoffReferenceDigest: handoffDigest(handoffReference), AllocationReference: receipt.Reference, ConnectionGeneration: receipt.ConnectionGeneration, ConnectionEpoch: "epoch-1", ControllerFence: strings.Repeat("c", handoff.MinFenceBytes), MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID, AuthorityExpiresAt: authorityExpiry, HandoffExpiresAt: receipt.ExpiresAt}
	attachment := providerdesktop.Attachment{DesktopSessionID: allocation.Request.DesktopSessionID, ConnectionGeneration: receipt.ConnectionGeneration, MediaProfileID: providerdesktop.MediaProfileID, ControlProfileID: providerdesktop.ControlProfileID}
	session, err := remote.OpenMedia(ctx, mediaAuthority, attachment, policy)
	if err != nil {
		t.Fatal(err)
	}
	frameContext, cancelFrame := context.WithTimeout(ctx, 30*time.Second)
	frame, err := session.ReadVideoRTP(frameContext)
	cancelFrame()
	if err != nil || len(frame) < 12 || frame[0]>>6 != 2 {
		t.Fatalf("real mux RTP len=%d err=%v", len(frame), err)
	}
	inputContext, cancelInput := context.WithTimeout(ctx, 10*time.Second)
	_, err = session.HandleInput(inputContext, desktopmedia.Input{Sequence: 1, Kind: "pointer", Event: "move", X: 123, Y: 234, ControlLeaseID: "lease-1", ControlFence: 1})
	cancelInput()
	if err != nil {
		t.Fatalf("real mux input: %v", err)
	}
	_ = session.Close()
	readyContext, cancelReady := context.WithTimeout(ctx, 30*time.Second)
	if err := backend.Ready(readyContext); err != nil {
		cancelReady()
		t.Fatalf("real signed broker readiness: %v", err)
	}
	cancelReady()
	cancelBackend()
	select {
	case err := <-backendDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("backend stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("backend did not stop")
	}
	cancelMux()
	select {
	case err := <-muxDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("mux stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mux did not stop")
	}
	cleanupContext, cancelCleanup := context.WithTimeout(ctx, 30*time.Second)
	if err := driver.Cleanup(cleanupContext, receipt); err != nil {
		cancelCleanup()
		t.Fatal(err)
	}
	cancelCleanup()
	cleaned = true
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mux socket remains: %v", err)
	}
	if exec.CommandContext(ctx, "docker", "inspect", containerName(allocation.Request.SandboxID, allocation.Request.DesktopSessionID)).Run() == nil {
		t.Fatal("Desktop candidate container remains after cleanup")
	}
}

func handoffDigest(value string) string {
	return fmt.Sprintf("sha256:%x", sha256Sum([]byte(value)))
}

func sha256Sum(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

type realMuxTLS struct {
	caCertificate, serverCertificate, serverKey, clientCertificate, clientKey string
}

func writeRealMuxTLS(t *testing.T, directory string) realMuxTLS {
	t.Helper()
	now := time.Now().UTC()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "phase6-mux-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	writeCertificate := func(name string, serial int64, server bool, identity string) (string, string) {
		publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.URIs = []*url.URL{{Scheme: "spiffe", Host: "sandbox-runtime", Path: "/provider"}}
			if identity != template.URIs[0].String() {
				t.Fatal("unexpected test identity")
			}
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, caTemplate, publicKey, caPrivate)
		if createErr != nil {
			t.Fatal(createErr)
		}
		certificatePath := filepath.Join(directory, name+".pem")
		keyPath := filepath.Join(directory, name+".key")
		if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		keyDocument, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDocument}), 0o600); err != nil {
			t.Fatal(err)
		}
		return certificatePath, keyPath
	}
	caPath := filepath.Join(directory, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	serverCertificate, serverKey := writeCertificate("server", 2, true, "")
	clientCertificate, clientKey := writeCertificate("client", 3, false, "spiffe://sandbox-runtime/provider")
	return realMuxTLS{caCertificate: caPath, serverCertificate: serverCertificate, serverKey: serverKey, clientCertificate: clientCertificate, clientKey: clientKey}
}

func freeRealMuxAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitRealMuxSocket(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	for {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func waitRealTCP(t *testing.T, ctx context.Context, address string) {
	t.Helper()
	for {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}
