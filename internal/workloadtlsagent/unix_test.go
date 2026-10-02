package workloadtlsagent

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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
	return newUnixFixtureWithPeer(t, maximumConnections, nil)
}

func newUnixFixtureWithPeer(t *testing.T, maximumConnections int, peer PeerCRLProvider) *unixFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	manager, issuer := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatalf("manager Bootstrap() = %v", err)
	}
	temporaryRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(temporaryRoot, "wtlsa-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := os.Chown(dir, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o710); err != nil {
		t.Fatal(err)
	}
	server, err := Listen(ServerConfig{SocketPath: filepath.Join(dir, "agent.sock"), SocketUID: uid, SocketGID: gid, AgentGID: gid,
		ExpectedClientUID: uid, ExpectedClientGID: gid, MaxConnections: maximumConnections, ReplayCapacity: 128,
		Now: func() time.Time { return now }, PeerCRLProvider: peer}, manager)
	if err != nil {
		t.Fatalf("Listen() = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(ClientConfig{SocketPath: filepath.Join(dir, "agent.sock"), ExpectedUID: uid, ExpectedGID: gid, RoleGID: gid,
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
	if certificate.Leaf == nil || !bytes.Equal(certificate.Leaf.Raw, certificate.Certificate[0]) {
		t.Fatal("remote TLS leaf aliases a destroyed snapshot instead of retained DER")
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
	if _, err := NewClient(ClientConfig{SocketPath: filepath.Join(fixture.dir, "agent.sock"), ExpectedUID: uid + 1, ExpectedGID: gid, RoleGID: gid,
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

func TestUnixSocketLayoutRejectsPermissionDrift(t *testing.T) {
	fixture := newUnixFixture(t, 2)
	defer fixture.close(t)
	path := filepath.Join(fixture.dir, "agent.sock")
	if err := os.Chmod(fixture.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.client.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("private v1 directory accepted: %v", err)
	}
	if err := os.Chmod(fixture.dir, 0o710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.client.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("private v1 socket accepted: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(ClientConfig{SocketPath: path, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		RoleGID: uint32(os.Getgid()) + 1, OperationTimeout: time.Second, Now: time.Now, Random: rand.Reader}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong role group accepted: %v", err)
	}
	alias := filepath.Join(filepath.Dir(fixture.dir), filepath.Base(fixture.dir)+"-alias")
	if err := os.Symlink(fixture.dir, alias); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(alias)
	if _, err := NewClient(ClientConfig{SocketPath: filepath.Join(alias, "agent.sock"), ExpectedUID: uint32(os.Getuid()),
		ExpectedGID: uint32(os.Getgid()), RoleGID: uint32(os.Getgid()), OperationTimeout: time.Second,
		Now: time.Now, Random: rand.Reader}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("symlinked parent accepted: %v", err)
	}
	if _, err := fixture.client.Snapshot(context.Background()); err != nil {
		t.Fatalf("restored v2 socket refused: %v", err)
	}
}

func TestUnixServerSlowFrameTimesOutAndReleasesCapacity(t *testing.T) {
	fixture := newUnixFixture(t, 1)
	defer fixture.close(t)
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(fixture.dir, "agent.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 100)
	if _, err := connection.Write(append(header[:], '{')); err != nil {
		t.Fatal(err)
	}
	occupied := time.Now().Add(time.Second)
	for len(fixture.server.capacity) != 1 && time.Now().Before(occupied) {
		time.Sleep(time.Millisecond)
	}
	if len(fixture.server.capacity) != 1 {
		t.Fatal("half-frame did not reserve capacity")
	}
	deadline := time.Now().Add(initialFrameTimeout + time.Second)
	for len(fixture.server.capacity) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(fixture.server.capacity) != 0 {
		t.Fatal("half-frame held the only capacity slot past its deadline")
	}
	if _, err := fixture.client.Snapshot(context.Background()); err != nil {
		t.Fatalf("capacity did not recover after slow frame: %v", err)
	}
}

func TestUnixServerCloseInterruptsIdleAuthorizedPeer(t *testing.T) {
	fixture := newUnixFixture(t, 1)
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(fixture.dir, "agent.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	deadline := time.Now().Add(time.Second)
	for len(fixture.server.capacity) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(fixture.server.capacity) != 1 {
		t.Fatal("idle peer did not reserve capacity")
	}
	fixture.cancel()
	closed := make(chan error, 1)
	go func() { closed <- fixture.server.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked on idle authorized peer")
	}
	select {
	case err := <-fixture.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve blocked on idle authorized peer")
	}
	if _, err := os.Lstat(filepath.Join(fixture.dir, "agent.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained after close: %v", err)
	}
	if err := fixture.manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestUnixServerRecoversOnlySameOwnerStaleSocket(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	manager, _ := testManager(t, &now)
	if err := manager.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	temporaryRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(temporaryRoot, "wtlsa-stale-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	defer manager.Close(context.Background())
	if err := os.Chmod(dir, 0o710); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	config := ServerConfig{SocketPath: path, SocketUID: uid, SocketGID: gid, AgentGID: gid,
		ExpectedClientUID: uid, ExpectedClientGID: gid, MaxConnections: 2, ReplayCapacity: 128, Now: time.Now}
	server, err := Listen(config, manager)
	if err != nil {
		t.Fatalf("same-owner stale socket not recovered: %v", err)
	}
	if _, err := Listen(config, manager); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("live listener replaced: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remained after close: %v", err)
	}
}
