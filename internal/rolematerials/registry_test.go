package rolematerials

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
)

type fixedProvider struct {
	material secretref.SecretMaterial
}

func (p fixedProvider) ResolveSecret(_ context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	material := p.material
	material.Binding = binding
	material.Bytes = append([]byte(nil), p.material.Bytes...)
	return material, nil
}

func TestNewBuildsOneExactRoleRegistry(t *testing.T) {
	now := time.Now().UTC()
	binding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/kv/browser-server-key", Version: "v1", Purpose: secretref.PurposeTLSPrivateKey,
		TenantID: secretref.SystemTenant, Role: secretref.RoleBrowser,
	}
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/tmp", "sandbox-role-materials-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chown(directory, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "materials.sock")
	value := []byte("browser-private-key-material")
	digest := sha256.Sum256(value)
	server, err := workloadagent.Listen(workloadagent.ServerConfig{
		SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), Role: secretref.RoleBrowser,
		AllowedPurposes: []secretref.Purpose{secretref.PurposeTLSPrivateKey}, Bindings: []secretref.Binding{binding},
		MaxConnections: 2, Now: time.Now,
	}, fixedProvider{material: secretref.SecretMaterial{
		Bytes: value, Digest: "sha256:" + hex.EncodeToString(digest[:]), Revision: "revision-1",
		Window: secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute), State: secretref.KeyActive},
	}})
	if err != nil {
		t.Fatal(err)
	}
	serveContext, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(serveContext) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		<-serveDone
	})
	materials := config.RoleMaterialsConfig{
		Provider: config.RoleMaterialProviderConfig{
			Type: config.UnixWorkloadMaterialProviderV1, Alias: "browser-agent", SocketPath: socket,
			ExpectedUID: int64(os.Getuid()), ExpectedGID: int64(os.Getgid()), OperationTimeoutSeconds: 2, CacheSeconds: 1,
		},
		Bindings: []config.RoleMaterialBindingConfig{{ID: "browser-server-key", Provider: "browser-agent", Document: string(document)}},
	}
	registry, err := New(materials, secretref.RoleBrowser, []secretref.Purpose{secretref.PurposeTLSPrivateKey}, true, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	resolved, err := registry.Resolve(context.Background(), "browser-server-key", secretref.PurposeTLSPrivateKey, secretref.SystemTenant)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved.Bytes) != string(value) || resolved.Binding.Role != secretref.RoleBrowser {
		t.Fatalf("resolved material binding = %s", resolved.Binding.Redacted())
	}
	resolved.Destroy()
	if _, err := New(materials, secretref.RoleDesktop, []secretref.Purpose{secretref.PurposeTLSPrivateKey}, true, time.Now); err == nil {
		t.Fatal("Desktop registry accepted a Browser-scoped binding")
	}
}
