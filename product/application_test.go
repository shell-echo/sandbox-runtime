package product

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

type testStore struct {
	mu        sync.Mutex
	commands  []CreateWorkspaceCommand
	result    CreateWorkspaceResult
	err       error
	workspace Workspace
	operation Operation
}

func (s *testStore) CreateWorkspace(_ context.Context, command CreateWorkspaceCommand) (CreateWorkspaceResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, command)
	return s.result, s.err
}

func (s *testStore) GetWorkspace(context.Context, string, string) (Workspace, error) {
	return s.workspace, s.err
}

func (s *testStore) GetOperation(context.Context, string, string) (Operation, error) {
	return s.operation, s.err
}

type testPolicy struct{ err error }

func (p testPolicy) AuthorizePrimarySlot(context.Context, SlotSpec) error { return p.err }

type sequenceIDs struct {
	mu   sync.Mutex
	next int
}

func (g *sequenceIDs) NewID(prefix string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	return fmt.Sprintf("%s_%d", prefix, g.next), nil
}

func TestApplicationCreateWorkspaceBuildsAtomicCommand(t *testing.T) {
	store := &testStore{result: CreateWorkspaceResult{Operation: Operation{ID: "op_2"}}}
	application, err := NewApplication(store, testPolicy{}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := validCreateWorkspaceRequest()
	result, err := application.CreateWorkspace(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "request-1", request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Operation.ID != "op_2" || len(store.commands) != 1 {
		t.Fatalf("result = %#v; commands = %d", result, len(store.commands))
	}
	command := store.commands[0]
	if command.WorkspaceID != "wrk_1" || command.OperationID != "op_2" || command.EventID != "evt_3" || command.OutboxID != "out_4" ||
		command.Method != CreateWorkspaceMethod || command.Path != CreateWorkspacePath || command.IdempotencyKey != "request-1" ||
		command.RequestDigest == [32]byte{} || command.Lifetime.Seconds() != 3600 || !reflect.DeepEqual(command.PrimarySlot, request.PrimarySlot) {
		t.Fatalf("command = %#v", command)
	}
}

func TestApplicationCreateWorkspaceDigestIsSemanticAndStable(t *testing.T) {
	firstStore := &testStore{}
	secondStore := &testStore{}
	first, _ := NewApplication(firstStore, testPolicy{}, &sequenceIDs{})
	second, _ := NewApplication(secondStore, testPolicy{}, &sequenceIDs{})
	request := validCreateWorkspaceRequest()
	if _, err := first.CreateWorkspace(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "request-1", request); err != nil {
		t.Fatal(err)
	}
	if _, err := second.CreateWorkspace(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "request-1", request); err != nil {
		t.Fatal(err)
	}
	if firstStore.commands[0].RequestDigest != secondStore.commands[0].RequestDigest {
		t.Fatal("equal requests produced different digests")
	}
	request.DisplayName = "different"
	thirdStore := &testStore{}
	third, _ := NewApplication(thirdStore, testPolicy{}, &sequenceIDs{})
	if _, err := third.CreateWorkspace(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "request-1", request); err != nil {
		t.Fatal(err)
	}
	if firstStore.commands[0].RequestDigest == thirdStore.commands[0].RequestDigest {
		t.Fatal("different requests produced the same digest")
	}
}

func TestApplicationCreateWorkspaceRejectsBeforeStore(t *testing.T) {
	tests := []struct {
		name   string
		tenant string
		actor  ActorRef
		key    string
		mutate func(*CreateWorkspaceRequest)
	}{
		{name: "tenant", tenant: "bad tenant", actor: ActorRef{Type: ActorHuman, ID: "actor-1"}, key: "key"},
		{name: "actor", tenant: "tenant-1", actor: ActorRef{Type: ActorHuman, ID: "bad actor"}, key: "key"},
		{name: "key", tenant: "tenant-1", actor: ActorRef{Type: ActorHuman, ID: "actor-1"}, key: "bad key"},
		{name: "lifetime", tenant: "tenant-1", actor: ActorRef{Type: ActorHuman, ID: "actor-1"}, key: "key", mutate: func(request *CreateWorkspaceRequest) { request.LifetimeSeconds = 59 }},
		{name: "primary slot", tenant: "tenant-1", actor: ActorRef{Type: ActorHuman, ID: "actor-1"}, key: "key", mutate: func(request *CreateWorkspaceRequest) { request.PrimarySlot.SlotKey = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &testStore{}
			application, _ := NewApplication(store, testPolicy{}, &sequenceIDs{})
			request := validCreateWorkspaceRequest()
			if test.mutate != nil {
				test.mutate(&request)
			}
			if _, err := application.CreateWorkspace(context.Background(), test.tenant, test.actor, test.key, request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v", err)
			}
			if len(store.commands) != 0 {
				t.Fatal("store was called for invalid input")
			}
		})
	}
}

func TestApplicationCreateWorkspaceCapabilityFailureStopsBeforeIDsAndStore(t *testing.T) {
	store := &testStore{}
	ids := &sequenceIDs{}
	application, _ := NewApplication(store, testPolicy{err: ErrCapabilityUnsupported}, ids)
	if _, err := application.CreateWorkspace(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "key", validCreateWorkspaceRequest()); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("error = %v", err)
	}
	if ids.next != 0 || len(store.commands) != 0 {
		t.Fatal("capability rejection mutated command state")
	}
}

func TestApplicationCreateWorkspacePreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	application, _ := NewApplication(&testStore{}, testPolicy{}, &sequenceIDs{})
	if _, err := application.CreateWorkspace(ctx, "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "key", validCreateWorkspaceRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestApplicationCreateWorkspaceRejectsNilContext(t *testing.T) {
	application, _ := NewApplication(&testStore{}, testPolicy{}, &sequenceIDs{})
	if _, err := application.CreateWorkspace(nil, "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "key", validCreateWorkspaceRequest()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
}

func TestNewApplicationRejectsTypedNilDependencies(t *testing.T) {
	var store *testStore
	var ids *sequenceIDs
	if _, err := NewApplication(store, testPolicy{}, &sequenceIDs{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed nil store error = %v", err)
	}
	if _, err := NewApplication(&testStore{}, testPolicy{}, ids); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed nil ID generator error = %v", err)
	}
}

func TestCryptoIDGeneratorProducesBoundedDistinctIDs(t *testing.T) {
	first, err := (CryptoIDGenerator{}).NewID("wrk")
	if err != nil {
		t.Fatal(err)
	}
	second, err := (CryptoIDGenerator{}).NewID("wrk")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !validIdentifier(first) || !validIdentifier(second) {
		t.Fatalf("IDs = %q, %q", first, second)
	}
}

func TestApplicationReadsAreTenantActorScoped(t *testing.T) {
	actor := ActorRef{Type: ActorHuman, ID: "actor-1"}
	store := &testStore{
		workspace: Workspace{ID: "wrk_1", TenantID: "tenant-1", Owner: actor},
		operation: Operation{ID: "op_1", SubmittedBy: actor},
	}
	application, _ := NewApplication(store, testPolicy{}, &sequenceIDs{})
	if _, err := application.GetWorkspace(context.Background(), "tenant-1", actor, "wrk_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := application.GetOperation(context.Background(), "tenant-1", actor, "op_1"); err != nil {
		t.Fatal(err)
	}
	other := ActorRef{Type: ActorHuman, ID: "actor-2"}
	if _, err := application.GetWorkspace(context.Background(), "tenant-1", other, "wrk_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-actor workspace error = %v", err)
	}
	if _, err := application.GetOperation(context.Background(), "tenant-1", other, "op_1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-actor operation error = %v", err)
	}
}

func validCreateWorkspaceRequest() CreateWorkspaceRequest {
	return CreateWorkspaceRequest{
		DisplayName:     "workspace",
		LifetimeSeconds: 3600,
		PrimarySlot: SlotSpec{
			SlotKey: PrimarySlotKey, Kind: "code", ProfileID: "coding-shell-v1", DesiredState: "ready",
			RequiredCapabilities: []CapabilityRequirement{{CapabilityID: "sandbox.exec", Version: "1.0.0", ProfileID: "exec-v1"}},
		},
	}
}
