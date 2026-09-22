package workloadcredentialv2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/credentialbackend"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

type fakeBackend struct {
	mu          sync.Mutex
	now         *time.Time
	issues      []credentialbackend.IssueSpec
	revoked     []string
	failIssue   bool
	issueSerial int
}

func (f *fakeBackend) IssueScoped(_ context.Context, spec credentialbackend.IssueSpec) (credentialbackend.IssuedCredential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues = append(f.issues, spec)
	if f.failIssue {
		return credentialbackend.IssuedCredential{}, ErrUnavailable
	}
	f.issueSerial++
	return credentialbackend.IssuedCredential{Credential: []byte("token-" + string(rune('a'+f.issueSerial))),
		BackendLeaseID: "accessor-" + strings.Repeat(string(rune('a'+f.issueSerial)), 8), ExpiresAt: f.now.Add(spec.TTL)}, nil
}

func (f *fakeBackend) Verify(_ context.Context, issued credentialbackend.IssuedCredential) error {
	if len(issued.Credential) == 0 || !issued.ExpiresAt.After(*f.now) {
		return ErrUnavailable
	}
	return nil
}

func (f *fakeBackend) Revoke(_ context.Context, backendLeaseID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, backendLeaseID)
	return nil
}

func controllerPolicy(t *testing.T, registry *securityprincipal.Registry, kind securityprincipal.Kind, name string, role securityprincipal.Role, instanceByte string, renewable bool, uid, gid uint32) (Policy, ed25519.PrivateKey) {
	t.Helper()
	principal, err := registry.New(kind, name, role, "sha256:"+strings.Repeat(instanceByte, 64))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backendPolicy := strings.ReplaceAll(name, "_", "-")
	if name == "certificate_controller" {
		backendPolicy = "certificate-controller-pki"
	}
	return Policy{ID: "policy-" + strings.ReplaceAll(name, "_", "-"), Registry: registry, Principal: principal,
		Purpose: secretref.PurposeWorkloadCredential, BackendID: "vault-primary", BackendPolicy: backendPolicy, MaxTTL: 10 * time.Minute,
		Renewable: renewable, PublicKey: publicKey, ExpectedUID: uid, ExpectedGID: gid}, privateKey
}

func controllerRegistry(t *testing.T) *securityprincipal.Registry {
	t.Helper()
	registry, err := securityprincipal.NewRegistry("sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), nil)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestControllerV2PersistsCASRotationRevocationAndRestart(t *testing.T) {
	now := time.Now().UTC()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	policy, privateKey := controllerPolicy(t, controllerRegistry(t), securityprincipal.KindController, "certificate_controller", "", "c", true, uid, gid)
	backend := &fakeBackend{now: &now}
	directory := secureDirectory(t)
	config := ControllerConfig{LedgerPath: filepath.Join(directory, "ledger-v2.json"), Policies: []Policy{policy}, Issuer: backend,
		Overlap: 2 * time.Second, Now: func() time.Time { return now }, Random: bytes.NewReader(bytes.Repeat([]byte{7}, 64))}
	controller, err := NewController(config)
	if err != nil {
		t.Fatal(err)
	}
	issue := signedRequest(t, policy, privateKey, IssueType, "", 0, 5*time.Minute, now, 1)
	issued, err := controller.Handle(context.Background(), issue, uid, gid)
	if err != nil || issued.Status != StatusOK || issued.Revision != 1 {
		t.Fatalf("issue = %#v, %v", issued, err)
	}
	renew := signedRequest(t, policy, privateKey, RenewType, issued.LeaseID, issued.Revision, 5*time.Minute, now, 2)
	renewed, err := controller.Handle(context.Background(), renew, uid, gid)
	if err != nil || renewed.Revision != 2 || bytes.Equal(issued.Credential, renewed.Credential) {
		t.Fatalf("renew = %#v, %v", renewed, err)
	}
	if len(backend.issues) != 2 || backend.issues[0].SubjectDigest != policy.Principal.Digest() || backend.issues[0].PolicyDigest != policy.Digest() ||
		backend.issues[0].BackendPolicy != "certificate-controller-pki" {
		t.Fatalf("backend specs = %#v", backend.issues)
	}
	now = now.Add(3 * time.Second)
	if err := controller.Reap(context.Background()); err != nil || len(backend.revoked) != 1 {
		t.Fatalf("Reap() error=%v revoked=%#v", err, backend.revoked)
	}
	revoke := signedRequest(t, policy, privateKey, RevokeType, renewed.LeaseID, renewed.Revision, 0, now, 3)
	revoked, err := controller.Handle(context.Background(), revoke, uid, gid)
	if err != nil || revoked.Status != StatusOK || len(backend.revoked) != 2 {
		t.Fatalf("revoke = %#v, %v backend=%#v", revoked, err, backend.revoked)
	}
	controller, err = NewController(ControllerConfig{LedgerPath: config.LedgerPath, Policies: []Policy{policy}, Issuer: backend,
		Overlap: config.Overlap, Now: config.Now, Random: rand.Reader})
	if err != nil || len(controller.ledger.Leases) != 1 || controller.ledger.Leases[0].State != leaseRevoked {
		t.Fatalf("restart = %#v, %v", controller, err)
	}
	if info, err := os.Lstat(config.LedgerPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ledger mode = %#v, %v", info, err)
	}
}

func TestControllerV2RejectsCrossPrincipalReplayPeerSubstitutionAndBackendLoss(t *testing.T) {
	now := time.Now().UTC()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	registry := controllerRegistry(t)
	firstPolicy, firstKey := controllerPolicy(t, registry, securityprincipal.KindMaterialAgent, "product_runtime_agent", securityprincipal.RoleProduct, "c", true, uid, gid)
	secondPolicy, secondKey := controllerPolicy(t, registry, securityprincipal.KindMaterialAgent, "provider_runtime_agent", securityprincipal.RoleProvider, "d", true, uid, gid)
	backend := &fakeBackend{now: &now}
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(secureDirectory(t), "ledger-v2.json"), Policies: []Policy{firstPolicy, secondPolicy},
		Issuer: backend, Overlap: time.Second, Now: func() time.Time { return now }, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	first := signedRequest(t, firstPolicy, firstKey, IssueType, "", 0, time.Minute, now, 9)
	if denied, err := controller.Handle(context.Background(), first, uid+1, gid); !errors.Is(err, ErrDenied) || denied.Status != StatusDenied || len(controller.ledger.Replays) != 0 {
		t.Fatalf("peer substitution = %#v, %v", denied, err)
	}
	if _, err := controller.Handle(context.Background(), first, uid, gid); err != nil {
		t.Fatal(err)
	}
	second := signedRequest(t, secondPolicy, secondKey, IssueType, "", 0, time.Minute, now, 9)
	if denied, err := controller.Handle(context.Background(), second, uid, gid); !errors.Is(err, ErrDenied) || denied.Status != StatusDenied {
		t.Fatalf("cross-principal replay = %#v, %v", denied, err)
	}
	backend.failIssue = true
	failed := signedRequest(t, secondPolicy, secondKey, IssueType, "", 0, time.Minute, now, 10)
	if unavailable, err := controller.Handle(context.Background(), failed, uid, gid); !errors.Is(err, ErrUnavailable) || unavailable.Status != StatusUnavailable {
		t.Fatalf("backend loss = %#v, %v", unavailable, err)
	}
}

func TestMigrationAgentV2IsOneShotAndCannotRenew(t *testing.T) {
	now := time.Now().UTC()
	policy, privateKey := controllerPolicy(t, controllerRegistry(t), securityprincipal.KindMaterialAgent, "product_migration_agent", securityprincipal.RoleProduct, "c", false, 1, 1)
	issue := signedRequest(t, policy, privateKey, IssueType, "", 0, time.Minute, now, 1)
	if _, err := NewSignedRequest(policy, RenewType, "lease2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, time.Minute, now.Add(30*time.Second), issue.JTI, privateKey, now); !errors.Is(err, ErrDenied) {
		t.Fatalf("migration renew error = %v", err)
	}
}

func TestV2UnixClientRoundTripAndExactCleanup(t *testing.T) {
	now := time.Now().UTC()
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	policy, privateKey := controllerPolicy(t, controllerRegistry(t), securityprincipal.KindController, "certificate_controller", "", "c", true, uid, gid)
	backend := &fakeBackend{now: &now}
	directory := secureDirectory(t)
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(directory, "ledger-v2.json"), Policies: []Policy{policy}, Issuer: backend,
		Overlap: time.Second, Now: func() time.Time { return now }, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(directory, "controller.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uid, SocketGID: gid, ExpectedClientUID: uid, ExpectedClientGID: gid,
		MaxConnections: 2, ReapInterval: time.Second}, controller)
	if err != nil {
		t.Fatal(err)
	}
	serverContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(serverContext) }()
	client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: uid, ExpectedGID: gid, Policy: policy, PrivateKey: privateKey,
		OperationTimeout: 3 * time.Second, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	lease, err := client.Issue(context.Background(), 5*time.Minute)
	if err != nil || lease.Revision != 1 || len(lease.Credential) == 0 {
		t.Fatalf("Issue() = %#v, %v", lease, err)
	}
	renewed, err := client.Renew(context.Background(), lease, 5*time.Minute)
	if err != nil || renewed.Revision != 2 || renewed.ID != lease.ID {
		t.Fatalf("Renew() = %#v, %v", renewed, err)
	}
	if err := client.Status(context.Background(), renewed); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(context.Background(), renewed); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server exit = %v", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket cleanup = %v", err)
	}
}

func signedRequest(t *testing.T, policy Policy, privateKey ed25519.PrivateKey, operation, leaseID string, revision int64, ttl time.Duration, now time.Time, nonce byte) Request {
	t.Helper()
	request, err := NewSignedRequest(policy, operation, leaseID, revision, ttl, now.Add(30*time.Second),
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{nonce}, 32)), privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func secureDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "sr-credential-v2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if os.Chmod(directory, 0o700) != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare credential v2 directory")
	}
	return directory
}
