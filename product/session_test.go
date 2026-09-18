package product

import (
	"context"
	"errors"
	"testing"
)

type sessionStoreStub struct {
	command   SessionCommand
	operation Operation
	err       error
}

func (s *sessionStoreStub) CreateSession(_ context.Context, c SessionCommand) (Operation, bool, error) {
	s.command = c
	return s.operation, false, s.err
}
func (s *sessionStoreStub) CloseSession(_ context.Context, c SessionCommand) (Operation, bool, error) {
	s.command = c
	return s.operation, false, s.err
}
func (s *sessionStoreStub) GetSession(context.Context, string, string) (RuntimeSession, error) {
	return RuntimeSession{}, s.err
}
func (s *sessionStoreStub) ListSessions(context.Context, string, string, ActorRef, int) ([]RuntimeSession, error) {
	return nil, s.err
}

type sessionPolicyStub struct{ err error }

func (p sessionPolicyStub) AuthorizeSession(context.Context, string, string) error { return p.err }

func TestSessionServicePersistsIntentBeforeProviderWork(t *testing.T) {
	store := &sessionStoreStub{operation: Operation{ID: "op_2"}}
	service, err := NewSessionService(store, sessionPolicyStub{}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := CreateSessionRequest{ExpectedWorkspaceVersion: 2, SlotKey: PrimarySlotKey, Kind: "terminal", ProtocolProfile: "product-terminal.v1", ExpiresInSeconds: 3600, RecordingPolicy: "metadata_only"}
	operation, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "key-1", request)
	if err != nil || operation.ID != "op_2" {
		t.Fatalf("operation=%#v err=%v", operation, err)
	}
	if store.command.SessionID != "ses_1" || store.command.OperationID != "op_2" || store.command.EventID != "evt_3" || store.command.OutboxID != "out_4" || store.command.RequestDigest == [32]byte{} {
		t.Fatalf("command=%#v", store.command)
	}
}
func TestSessionServiceFailsClosedOnCapabilityAndResize(t *testing.T) {
	service, _ := NewSessionService(&sessionStoreStub{}, sessionPolicyStub{err: ErrCapabilityUnsupported}, &sequenceIDs{})
	request := CreateSessionRequest{ExpectedWorkspaceVersion: 1, SlotKey: PrimarySlotKey, Kind: "terminal", ProtocolProfile: "product-terminal.v1", ExpiresInSeconds: 30, RecordingPolicy: "disabled"}
	if _, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "key", request); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("err=%v", err)
	}
	if _, _, err := service.Resize(context.Background(), "tenant-1", ActorRef{}, "ses-1", "key", 1, 80, 24, "ctl-1", 1); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("resize err=%v", err)
	}
}
