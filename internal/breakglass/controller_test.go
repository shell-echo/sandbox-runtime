package breakglass

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
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

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type actorKey struct {
	actor   Actor
	private ed25519.PrivateKey
}

type fixture struct {
	controller    *Controller
	clock         *testClock
	actors        map[string]actorKey
	ledgerPath    string
	auditPath     string
	controllerKey ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)}
	actors := make(map[string]actorKey)
	definitions := []struct{ id, kind string }{
		{"requester-a", ActorRequester}, {"approver-a", ActorApprover}, {"approver-b", ActorApprover},
		{"operator-a", ActorOperator}, {"product-runtime-agent", ActorTarget},
	}
	configured := make([]Actor, 0, len(definitions))
	for _, definition := range definitions {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		actor := Actor{ID: definition.id, Kind: definition.kind, PublicKey: publicKey}
		configured = append(configured, actor)
		actors[definition.id] = actorKey{actor: actor, private: privateKey}
	}
	_, controllerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.MkdirTemp("/tmp", "sr-bg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if os.Chmod(directory, 0o700) != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare break-glass state directory")
	}
	ledgerPath, auditPath := filepath.Join(directory, "authority.json"), filepath.Join(directory, "audit.ndjson")
	controller, err := New(Config{LedgerPath: ledgerPath, AuditPath: auditPath, Actors: configured,
		ControllerPrivateKey: controllerKey, MaxTTL: 15 * time.Minute, Now: clock.Now, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{controller: controller, clock: clock, actors: actors, ledgerPath: ledgerPath, auditPath: auditPath, controllerKey: controllerKey}
}

func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func jti(t *testing.T) string {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	return base64.RawURLEncoding.EncodeToString(value)
}

func accessRequest(t *testing.T, value fixture, purpose secretref.Purpose, ttl time.Duration) AccessRequest {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	request := AccessRequest{RequestID: "bgreq_" + hex.EncodeToString(raw), RequesterID: "requester-a", TargetAgentID: "product-runtime-agent",
		Role: secretref.RoleProduct, Purpose: purpose, BindingDigest: digestText("binding"), TenantID: "tenant-a", Operation: "material.resolve",
		ReasonDigest: digestText("emergency reason"), TicketDigest: digestText("ticket-123"), RequestedTTLSeconds: int64(ttl / time.Second),
		Deadline: value.clock.Now().Add(30 * time.Second).Format(time.RFC3339Nano), JTI: jti(t)}
	request, err := NewSignedAccessRequest(request, value.actors["requester-a"].private)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func approval(t *testing.T, value fixture, request AccessRequest, revision int64, actorID string) Approval {
	t.Helper()
	result := Approval{RequestID: request.RequestID, RequestDigest: request.RequestDigest, Revision: revision, ApproverID: actorID,
		Deadline: value.clock.Now().Add(30 * time.Second).Format(time.RFC3339Nano), JTI: jti(t)}
	result, err := NewSignedApproval(result, value.actors[actorID].private)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func command(t *testing.T, value fixture, operation, requestID string, revision int64) Command {
	t.Helper()
	result := Command{Type: operation, RequestID: requestID, Revision: revision, ActorID: "operator-a",
		Deadline: value.clock.Now().Add(30 * time.Second).Format(time.RFC3339Nano), JTI: jti(t)}
	result, err := NewSignedCommand(result, value.actors["operator-a"].private)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func approvedCapability(t *testing.T, value fixture, ttl time.Duration) (AccessRequest, Capability, int64) {
	t.Helper()
	request := accessRequest(t, value, secretref.PurposeTLSPrivateKey, ttl)
	revision, err := value.controller.Submit(context.Background(), request)
	if err != nil || revision != 1 {
		t.Fatalf("submit revision=%d error=%v", revision, err)
	}
	revision, err = value.controller.Approve(context.Background(), approval(t, value, request, revision, "approver-a"))
	if err != nil || revision != 2 {
		t.Fatalf("first approval revision=%d error=%v", revision, err)
	}
	revision, err = value.controller.Approve(context.Background(), approval(t, value, request, revision, "approver-b"))
	if err != nil || revision != 3 {
		t.Fatalf("second approval revision=%d error=%v", revision, err)
	}
	capability, err := value.controller.Issue(context.Background(), command(t, value, CommandIssue, request.RequestID, revision))
	if err != nil || capability.MaxUses != 1 || capability.TargetAgentID != request.TargetAgentID {
		t.Fatalf("issue capability=%#v error=%v", capability, err)
	}
	return request, capability, 4
}

func consume(t *testing.T, value fixture, capability Capability) Consume {
	t.Helper()
	result := Consume{Capability: capability, TargetAgentID: capability.TargetAgentID,
		Deadline: value.clock.Now().Add(30 * time.Second).Format(time.RFC3339Nano), JTI: jti(t)}
	result, err := NewSignedConsume(result, value.actors[capability.TargetAgentID].private)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDualApprovalCapabilityIsOnlineSingleUseAndRestartDurable(t *testing.T) {
	value := newFixture(t)
	request, capability, _ := approvedCapability(t, value, 10*time.Minute)
	first := consume(t, value, capability)
	if err := value.controller.Consume(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := consume(t, value, capability)
	if err := value.controller.Consume(context.Background(), second); !errors.Is(err, ErrConsumed) {
		t.Fatalf("second consume error=%v", err)
	}

	configured := make([]Actor, 0, len(value.actors))
	for _, actor := range value.actors {
		configured = append(configured, actor.actor)
	}
	restarted, err := New(Config{LedgerPath: value.ledgerPath, AuditPath: value.auditPath, Actors: configured,
		ControllerPrivateKey: value.controllerKey, MaxTTL: 15 * time.Minute, Now: value.clock.Now, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Consume(context.Background(), consume(t, value, capability)); !errors.Is(err, ErrConsumed) {
		t.Fatalf("restart consume error=%v", err)
	}
	for _, path := range []string{value.ledgerPath, value.auditPath} {
		document, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(document), "emergency reason") || strings.Contains(string(document), "ticket-123") || !strings.Contains(string(document), request.ReasonDigest) {
			t.Fatalf("%s did not preserve metadata-only audit", path)
		}
		clear(document)
	}
}

func TestApprovalMustBeTwoDistinctActorsAndSeparateFromRequesterTarget(t *testing.T) {
	value := newFixture(t)
	request := accessRequest(t, value, secretref.PurposeTLSCertificate, 5*time.Minute)
	revision, err := value.controller.Submit(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	first := approval(t, value, request, revision, "approver-a")
	revision, err = value.controller.Approve(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := approval(t, value, request, revision, "approver-a")
	if _, err := value.controller.Approve(context.Background(), duplicate); !errors.Is(err, ErrDenied) {
		t.Fatalf("duplicate approval error=%v", err)
	}
	if _, err := value.controller.Issue(context.Background(), command(t, value, CommandIssue, request.RequestID, revision)); !errors.Is(err, ErrDenied) {
		t.Fatalf("single-approval issue error=%v", err)
	}
}

func TestMigrationBindingIsAlwaysDenied(t *testing.T) {
	value := newFixture(t)
	request := accessRequest(t, value, secretref.PurposePostgresMigrationDSN, time.Minute)
	if _, err := value.controller.Submit(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("migration submit error=%v", err)
	}
}

func TestExpiryRevocationAndCapabilitySubstitutionFailClosed(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		value := newFixture(t)
		_, capability, _ := approvedCapability(t, value, time.Minute)
		value.clock.Advance(time.Minute)
		if err := value.controller.Consume(context.Background(), consume(t, value, capability)); !errors.Is(err, ErrExpired) {
			t.Fatalf("expiry consume error=%v", err)
		}
		if got := value.controller.ledger.Requests[0]; got.State != StateExpired || got.Uses != 0 || got.Revision != 5 {
			t.Fatalf("expired record=%#v", got)
		}
	})
	t.Run("revocation", func(t *testing.T) {
		value := newFixture(t)
		request, capability, revision := approvedCapability(t, value, 5*time.Minute)
		if err := value.controller.Revoke(context.Background(), command(t, value, CommandRevoke, request.RequestID, revision)); err != nil {
			t.Fatal(err)
		}
		if err := value.controller.Consume(context.Background(), consume(t, value, capability)); !errors.Is(err, ErrRevoked) {
			t.Fatalf("revoked consume error=%v", err)
		}
	})
	t.Run("substitution", func(t *testing.T) {
		value := newFixture(t)
		_, capability, _ := approvedCapability(t, value, 5*time.Minute)
		capability.Operation = "different.operation"
		if err := value.controller.Consume(context.Background(), consume(t, value, capability)); !errors.Is(err, ErrDenied) {
			t.Fatalf("substituted capability error=%v", err)
		}
	})
}

func TestAuditTamperPreventsControllerRestart(t *testing.T) {
	value := newFixture(t)
	_, _, _ = approvedCapability(t, value, 5*time.Minute)
	file, err := os.OpenFile(value.auditPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	configured := make([]Actor, 0, len(value.actors))
	for _, actor := range value.actors {
		configured = append(configured, actor.actor)
	}
	if _, err := New(Config{LedgerPath: value.ledgerPath, AuditPath: value.auditPath, Actors: configured,
		ControllerPrivateKey: value.controllerKey, MaxTTL: 15 * time.Minute, Now: value.clock.Now, Random: rand.Reader}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampered audit restart error=%v", err)
	}
}

func TestUnixControllerRequiresOnlineConsumeAndCleansSocket(t *testing.T) {
	value := newFixture(t)
	directory, err := os.MkdirTemp("/tmp", "sr-bgs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if os.Chmod(directory, 0o700) != nil || os.Chown(directory, os.Getuid(), os.Getgid()) != nil {
		t.Fatal("prepare break-glass socket directory")
	}
	socket := filepath.Join(directory, "controller.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()), MaxConnections: 4}, value.controller)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	call := func(request WireRequest) WireResponse {
		t.Helper()
		operationContext, operationCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer operationCancel()
		response, err := Call(operationContext, socket, uint32(os.Getuid()), uint32(os.Getgid()), request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	request := accessRequest(t, value, secretref.PurposeTLSPrivateKey, 5*time.Minute)
	response := call(WireRequest{Protocol: ProtocolID, Type: SubmitType, Request: &request})
	first := approval(t, value, request, response.Revision, "approver-a")
	response = call(WireRequest{Protocol: ProtocolID, Type: ApproveType, Approval: &first})
	second := approval(t, value, request, response.Revision, "approver-b")
	response = call(WireRequest{Protocol: ProtocolID, Type: ApproveType, Approval: &second})
	issue := command(t, value, CommandIssue, request.RequestID, response.Revision)
	response = call(WireRequest{Protocol: ProtocolID, Type: IssueType, Command: &issue})
	if response.Capability == nil {
		t.Fatal("controller omitted issued capability")
	}
	use := consume(t, value, *response.Capability)
	call(WireRequest{Protocol: ProtocolID, Type: ConsumeType, Consume: &use})
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("server exit=%v", err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket cleanup error=%v", err)
	}
}
