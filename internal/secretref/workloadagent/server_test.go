package workloadagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type agentMaterialProvider struct {
	mu       sync.Mutex
	binding  secretref.Binding
	material secretref.SecretMaterial
	calls    int
}

func (p *agentMaterialProvider) ResolveSecret(_ context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if binding != p.binding {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	material := p.material
	material.Bytes = append([]byte(nil), material.Bytes...)
	return material, nil
}

func (p *agentMaterialProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func TestServerEnforcesBindingPeerAndExactCleanup(t *testing.T) {
	now := time.Now().UTC()
	binding := agentTestBinding(secretref.RoleProduct)
	value := []byte("server certificate material")
	digest := sha256.Sum256(value)
	provider := &agentMaterialProvider{binding: binding, material: secretref.SecretMaterial{
		Binding: binding, Bytes: value, Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive},
	}}
	directory := shortAgentDirectory(t)
	path := filepath.Join(directory, "agent.sock")
	server, err := Listen(ServerConfig{
		SocketPath: path, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		AllowedPurposes: []secretref.Purpose{secretref.PurposeTLSCertificate}, Bindings: []secretref.Binding{binding},
		MaxConnections: 4, Now: func() time.Time { return time.Now().UTC() },
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	client, err := New(Config{
		SocketPath: path, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		OperationTimeout: 2 * time.Second, Now: time.Now, Random: bytes.NewReader(bytes.Repeat([]byte{1}, nonceSize*2)),
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := client.ResolveSecret(context.Background(), binding)
	if err != nil || string(material.Bytes) != string(value) {
		t.Fatalf("ResolveSecret() = %#v, %v", material, err)
	}
	material.Destroy()
	unauthorized := binding
	unauthorized.Reference = "secret://workload-agent/other-certificate"
	if _, err := client.ResolveSecret(context.Background(), unauthorized); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("unauthorized binding error = %v", err)
	}
	if provider.callCount() != 1 {
		t.Fatalf("unauthorized binding reached provider, calls=%d", provider.callCount())
	}
	cancel()
	select {
	case err := <-serveResult:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent server did not drain")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("agent socket cleanup = %v", err)
	}
}

func TestServerRejectsClientPeerSubstitution(t *testing.T) {
	binding := agentTestBinding(secretref.RoleProduct)
	provider := &agentMaterialProvider{binding: binding}
	directory := shortAgentDirectory(t)
	path := filepath.Join(directory, "agent.sock")
	server, err := Listen(ServerConfig{
		SocketPath: path, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()) + 1, ExpectedClientGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		AllowedPurposes: []secretref.Purpose{secretref.PurposeTLSCertificate}, Bindings: []secretref.Binding{binding},
		MaxConnections: 1, Now: time.Now,
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(ctx) }()
	client, err := New(Config{
		SocketPath: path, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		OperationTimeout: time.Second, Now: time.Now, Random: bytes.NewReader(make([]byte, nonceSize)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ResolveSecret(context.Background(), binding); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("peer substitution error = %v", err)
	}
	if provider.callCount() != 0 {
		t.Fatal("peer substitution reached provider")
	}
	cancel()
	<-serveResult
}

func TestServerExternalCloseStopsWatcherAndCleansSocket(t *testing.T) {
	binding := agentTestBinding(secretref.RoleProduct)
	directory := shortAgentDirectory(t)
	path := filepath.Join(directory, "agent.sock")
	server, err := Listen(ServerConfig{
		SocketPath: path, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		AllowedPurposes: []secretref.Purpose{secretref.PurposeTLSCertificate}, Bindings: []secretref.Binding{binding},
		MaxConnections: 1, Now: time.Now,
	}, &agentMaterialProvider{binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(context.Background()) }()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("Serve() after external close = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("externally closed server retained its watcher")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("agent socket cleanup = %v", err)
	}
}

func TestServerOneShotResolutionClosesSocketAndRejectsReconnect(t *testing.T) {
	now := time.Now().UTC()
	binding := agentTestBinding(secretref.RoleProduct)
	value := []byte("one-shot migration DSN")
	digest := sha256.Sum256(value)
	provider := &agentMaterialProvider{binding: binding, material: secretref.SecretMaterial{
		Binding: binding, Bytes: value, Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive},
	}}
	directory := shortAgentDirectory(t)
	path := filepath.Join(directory, "migration.sock")
	server, err := Listen(ServerConfig{
		SocketPath: path, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		AllowedPurposes: []secretref.Purpose{secretref.PurposeTLSCertificate}, Bindings: []secretref.Binding{binding},
		MaxConnections: 1, MaxResolutions: 1, Now: time.Now,
	}, provider)
	if err != nil {
		t.Fatal(err)
	}
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(context.Background()) }()
	client, err := NewProduction(Config{
		SocketPath: path, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()), Role: secretref.RoleProduct,
		OperationTimeout: time.Second, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	material, err := client.ResolveSecret(context.Background(), binding)
	if err != nil || string(material.Bytes) != string(value) {
		t.Fatalf("one-shot ResolveSecret() = %#v, %v", material, err)
	}
	material.Destroy()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("one-shot Serve() = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("one-shot agent did not exit")
	}
	if _, err := client.ResolveSecret(context.Background(), binding); !errors.Is(err, secretref.ErrUnavailable) {
		t.Fatalf("one-shot reconnect error = %v", err)
	}
	if provider.callCount() != 1 {
		t.Fatalf("one-shot provider calls = %d", provider.callCount())
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("one-shot socket cleanup = %v", err)
	}
}

func shortAgentDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-was-")
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
