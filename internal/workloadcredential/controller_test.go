package workloadcredential

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(value time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(value)
	c.mu.Unlock()
}

type testIssuer struct {
	mu           sync.Mutex
	now          func() time.Time
	sequence     int
	active       map[string][]byte
	revoked      []string
	failIssue    bool
	failVerify   bool
	failRevoke   bool
	issuedBySpec []IssueSpec
}

func (i *testIssuer) Issue(_ context.Context, spec IssueSpec) (IssuedCredential, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.failIssue {
		return IssuedCredential{}, errors.New("backend unavailable")
	}
	i.sequence++
	backendLeaseID := "backend_" + strings.Repeat("a", 8) + string(rune('a'+i.sequence))
	credential := []byte("credential-" + backendLeaseID)
	i.active[backendLeaseID] = append([]byte(nil), credential...)
	i.issuedBySpec = append(i.issuedBySpec, spec)
	return IssuedCredential{Credential: credential, BackendLeaseID: backendLeaseID, ExpiresAt: i.now().Add(spec.TTL)}, nil
}

func (i *testIssuer) Verify(_ context.Context, credential IssuedCredential) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.failVerify || !bytes.Equal(i.active[credential.BackendLeaseID], credential.Credential) {
		return errors.New("credential unusable")
	}
	return nil
}

func (i *testIssuer) Revoke(_ context.Context, backendLeaseID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.failRevoke {
		return errors.New("backend unavailable")
	}
	if value, ok := i.active[backendLeaseID]; ok {
		clear(value)
		delete(i.active, backendLeaseID)
	}
	if !slices.Contains(i.revoked, backendLeaseID) {
		i.revoked = append(i.revoked, backendLeaseID)
	}
	return nil
}

type controllerFixture struct {
	clock      *testClock
	issuer     *testIssuer
	controller *Controller
	privateKey ed25519.PrivateKey
	policy     Policy
	ledgerPath string
}

func newControllerFixture(t *testing.T, migration bool) controllerFixture {
	t.Helper()
	now := time.Date(2026, 9, 22, 8, 0, 0, 0, time.UTC)
	clock := &testClock{now: now}
	issuer := &testIssuer{now: clock.Now, active: make(map[string][]byte)}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/tmp", "sr-wcc-")
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
	policy := Policy{ID: "product-runtime", AgentID: "product-runtime-agent", Role: secretref.RoleProduct,
		Purpose: secretref.PurposeWorkloadCredential, BindingDigest: "sha256:" + strings.Repeat("a", 64), BackendID: "vault-primary",
		MaxTTL: 30 * time.Second, Renewable: !migration, Migration: migration}
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(directory, "ledger.json"),
		Identities: map[string]ed25519.PublicKey{policy.AgentID: publicKey}, Policies: []Policy{policy}, Issuer: issuer,
		Overlap: 3 * time.Second, Now: clock.Now, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	return controllerFixture{clock: clock, issuer: issuer, controller: controller, privateKey: privateKey, policy: policy, ledgerPath: filepath.Join(directory, "ledger.json")}
}

func signedTestRequest(t *testing.T, fixture controllerFixture, operation, leaseID string, revision int64, ttl time.Duration) Request {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	request := Request{Type: operation, AgentID: fixture.policy.AgentID, Role: fixture.policy.Role, Purpose: fixture.policy.Purpose,
		PolicyID: fixture.policy.ID, BindingDigest: fixture.policy.BindingDigest, BackendID: fixture.policy.BackendID,
		LeaseID: leaseID, Revision: revision, RequestedTTL: int64(ttl / time.Second),
		Deadline: fixture.clock.Now().Add(10 * time.Second).Format(time.RFC3339Nano), JTI: base64.RawURLEncoding.EncodeToString(nonce)}
	clear(nonce)
	signed, err := NewSignedRequest(request, fixture.privateKey, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestControllerRotationPersistsCASReplayAndRevokesAfterOverlap(t *testing.T) {
	fixture := newControllerFixture(t, false)
	ctx := context.Background()
	issueRequest := signedTestRequest(t, fixture, IssueType, "", 0, 20*time.Second)
	issued, err := fixture.controller.Handle(ctx, issueRequest)
	if err != nil || issued.Status != StatusOK || issued.Revision != 1 || !issued.Renewable || string(issued.Credential) == "" {
		t.Fatalf("issue response=%#v error=%v", issued, err)
	}
	firstBackend := fixture.controller.ledger.Leases[0].BackendLeaseID
	if _, err := fixture.controller.Handle(ctx, issueRequest); !errors.Is(err, ErrDenied) {
		t.Fatalf("replay error=%v", err)
	}

	renewRequest := signedTestRequest(t, fixture, RenewType, issued.LeaseID, issued.Revision, 20*time.Second)
	renewed, err := fixture.controller.Handle(ctx, renewRequest)
	if err != nil || renewed.Revision != 2 || bytes.Equal(issued.Credential, renewed.Credential) {
		t.Fatalf("renew response=%#v error=%v", renewed, err)
	}
	fixture.issuer.mu.Lock()
	if _, ok := fixture.issuer.active[firstBackend]; !ok {
		fixture.issuer.mu.Unlock()
		t.Fatal("old credential was revoked before overlap elapsed")
	}
	fixture.issuer.mu.Unlock()

	stale := signedTestRequest(t, fixture, RenewType, issued.LeaseID, 1, 20*time.Second)
	if _, err := fixture.controller.Handle(ctx, stale); !errors.Is(err, ErrDenied) {
		t.Fatalf("stale revision error=%v", err)
	}
	fixture.clock.Advance(4 * time.Second)
	if err := fixture.controller.Reap(ctx); err != nil {
		t.Fatal(err)
	}
	fixture.issuer.mu.Lock()
	if _, ok := fixture.issuer.active[firstBackend]; ok || !slices.Contains(fixture.issuer.revoked, firstBackend) {
		fixture.issuer.mu.Unlock()
		t.Fatal("old credential was not revoked after overlap")
	}
	fixture.issuer.mu.Unlock()

	document, err := os.ReadFile(fixture.ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(document)
	if bytes.Contains(document, issued.Credential) || bytes.Contains(document, renewed.Credential) || !bytes.Contains(document, []byte("credential_digest")) {
		t.Fatal("ledger retained raw credential or omitted credential digest")
	}
}

func TestControllerRestartPreservesLeaseAndReplayAuthority(t *testing.T) {
	fixture := newControllerFixture(t, false)
	request := signedTestRequest(t, fixture, IssueType, "", 0, 20*time.Second)
	issued, err := fixture.controller.Handle(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := fixture.privateKey.Public().(ed25519.PublicKey)
	restarted, err := NewController(ControllerConfig{LedgerPath: fixture.ledgerPath,
		Identities: map[string]ed25519.PublicKey{fixture.policy.AgentID: publicKey}, Policies: []Policy{fixture.policy}, Issuer: fixture.issuer,
		Overlap: 3 * time.Second, Now: fixture.clock.Now, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Handle(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("restart replay error=%v", err)
	}
	status := signedTestRequest(t, fixture, StatusType, issued.LeaseID, issued.Revision, 0)
	response, err := restarted.Handle(context.Background(), status)
	if err != nil || response.Status != StatusOK || len(response.Credential) != 0 {
		t.Fatalf("restart status response=%#v error=%v", response, err)
	}
}

func TestControllerRejectsCrossAgentPolicyAndIssuerFailure(t *testing.T) {
	fixture := newControllerFixture(t, false)
	request := signedTestRequest(t, fixture, IssueType, "", 0, 20*time.Second)
	request.Role = secretref.RoleProvider
	request.RequestDigest = requestDigest(request)
	request.AgentSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.privateKey, []byte(request.RequestDigest)))
	if _, err := fixture.controller.Handle(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("cross-role error=%v", err)
	}
	fixture.issuer.failIssue = true
	request = signedTestRequest(t, fixture, IssueType, "", 0, 20*time.Second)
	if _, err := fixture.controller.Handle(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("issuer loss error=%v", err)
	}
}

func TestMigrationCredentialIsNonRenewableAndRevokedOnControllerClose(t *testing.T) {
	fixture := newControllerFixture(t, true)
	request := signedTestRequest(t, fixture, IssueType, "", 0, 20*time.Second)
	issued, err := fixture.controller.Handle(context.Background(), request)
	if err != nil || issued.Renewable {
		t.Fatalf("migration issue response=%#v error=%v", issued, err)
	}
	renew := signedTestRequest(t, fixture, RenewType, issued.LeaseID, issued.Revision, 20*time.Second)
	if _, err := fixture.controller.Handle(context.Background(), renew); !errors.Is(err, ErrDenied) {
		t.Fatalf("migration renew error=%v", err)
	}
	backendID := fixture.controller.ledger.Leases[0].BackendLeaseID
	if err := fixture.controller.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.issuer.mu.Lock()
	defer fixture.issuer.mu.Unlock()
	if _, ok := fixture.issuer.active[backendID]; ok || !slices.Contains(fixture.issuer.revoked, backendID) {
		t.Fatal("migration credential was not revoked on controller close")
	}
}

func TestUnixClientControllerLifecycleAndExactSocketCleanup(t *testing.T) {
	fixture := newControllerFixture(t, false)
	fixture.clock.mu.Lock()
	fixture.clock.now = time.Now().UTC()
	fixture.clock.mu.Unlock()
	directory, err := os.MkdirTemp("/tmp", "sr-wcs-")
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
	socket := filepath.Join(directory, "credential.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), MaxConnections: 4, ReapInterval: time.Second}, fixture.controller)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client, err := NewClient(ClientConfig{SocketPath: socket, ExpectedUID: uint32(os.Getuid()), ExpectedGID: uint32(os.Getgid()),
		AgentID: fixture.policy.AgentID, Role: fixture.policy.Role, Purpose: fixture.policy.Purpose, PolicyID: fixture.policy.ID,
		BindingDigest: fixture.policy.BindingDigest, BackendID: fixture.policy.BackendID, PrivateKey: fixture.privateKey,
		OperationTimeout: 5 * time.Second, Now: fixture.clock.Now, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := client.Issue(context.Background(), 20*time.Second)
	if err != nil || lease.ID == "" || len(lease.Credential) == 0 {
		t.Fatalf("client issue lease=%#v error=%v", lease, err)
	}
	if err := client.Status(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	client.Close()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server exit=%v", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket cleanup error=%v", err)
	}
}

func TestProtocolRejectsUnknownDuplicateAndNonCanonicalDocuments(t *testing.T) {
	fixture := newControllerFixture(t, false)
	request := signedTestRequest(t, fixture, IssueType, "", 0, 20*time.Second)
	document, err := EncodeSignedRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"unknown":      append(append([]byte(nil), document[:len(document)-1]...), []byte(`,"unknown":true}`)...),
		"duplicate":    bytes.Replace(document, []byte(`"protocol":`), []byte(`"protocol":"sandbox-runtime.workload-credential.v1","protocol":`), 1),
		"noncanonical": append([]byte(" "), document...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(candidate); !errors.Is(err, ErrDenied) {
				t.Fatalf("DecodeRequest() error=%v", err)
			}
		})
	}
}
