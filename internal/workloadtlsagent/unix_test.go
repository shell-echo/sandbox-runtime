package workloadtlsagent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type unixFixture struct {
	manager *Manager
	issuer  *fakeCertificateClient
	server  *Server
	client  *Client
	cancel  context.CancelFunc
	done    chan error
	dir     string
	now     *time.Time
}

func newUnixFixture(t *testing.T, maximumConnections int) *unixFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	manager, issuer := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatalf("manager Bootstrap() = %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "wtlsa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := os.Chown(dir, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	server, err := Listen(ServerConfig{SocketPath: filepath.Join(dir, "agent.sock"), SocketUID: uid, SocketGID: gid,
		ExpectedClientUID: uid, ExpectedClientGID: gid, MaxConnections: maximumConnections, ReplayCapacity: 128,
		Now: func() time.Time { return now }}, manager)
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(ClientConfig{SocketPath: filepath.Join(dir, "agent.sock"), ExpectedUID: uid, ExpectedGID: gid,
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return now }, Random: rand.Reader})
	if err != nil {
		cancel()
		_ = server.Close()
		t.Fatalf("NewClient() = %v", err)
	}
	return &unixFixture{manager: manager, issuer: issuer, server: server, client: client, cancel: cancel, done: done, dir: dir, now: &now}
}

func (f *unixFixture) close(t *testing.T) {
	t.Helper()
	f.cancel()
	_ = f.server.Close()
	select {
	case err := <-f.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("Serve() error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("server did not stop")
	}
	if _, err := os.Lstat(filepath.Join(f.dir, "agent.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket remained after close: %v", err)
	}
	if err := f.manager.Close(context.Background()); err != nil {
		t.Errorf("manager Close() = %v", err)
	}
}

func TestUnixClientUsesRemoteSignerForTLSHandshake(t *testing.T) {
	fixture := newUnixFixture(t, 4)
	defer fixture.close(t)
	snapshot, err := fixture.client.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("remote signer"))
	signature, err := fixture.client.Sign(context.Background(), snapshot.Generation, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := x509.ParsePKIXPublicKey(snapshot.PublicKeyDER)
	if !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), digest[:], signature) {
		t.Fatal("remote signature did not verify")
	}
	snapshot.Destroy()
	certificate, err := fixture.client.Certificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(fixture.issuer.ca)
	serverConnection, clientConnection := net.Pipe()
	defer serverConnection.Close()
	defer clientConnection.Close()
	serverTLS := tls.Server(serverConnection, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	clientTLS := tls.Client(clientConnection, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "product.example.test"})
	serverResult := make(chan error, 1)
	go func() { serverResult <- serverTLS.Handshake() }()
	if err := clientTLS.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestUnixServerRejectsReplayPeerMismatchCapacityAndCancellation(t *testing.T) {
	fixture := newUnixFixture(t, 1)
	defer fixture.close(t)
	request, err := fixture.client.newRequest(context.Background(), SnapshotType, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.client.execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.client.execute(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("replay error = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.client.Snapshot(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Snapshot() error = %v", err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if _, err := NewClient(ClientConfig{SocketPath: filepath.Join(fixture.dir, "agent.sock"), ExpectedUID: uid + 1, ExpectedGID: gid,
		OperationTimeout: time.Second, Now: time.Now, Random: rand.Reader}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("peer mismatch NewClient() error = %v", err)
	}
	blocker, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(fixture.dir, "agent.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	deadline := time.Now().Add(time.Second)
	for len(fixture.server.capacity) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(fixture.server.capacity) != 1 {
		t.Fatal("server did not reserve the capacity slot")
	}
	if _, err := fixture.client.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("capacity Snapshot() error = %v", err)
	}
}
