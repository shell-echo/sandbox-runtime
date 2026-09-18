package product

import (
	"context"
	"errors"
	"testing"
)

type controlTestStore struct {
	command ControlLeaseCommand
	lease   ControlLease
	replay  bool
	err     error
}

func (s *controlTestStore) AcquireControlLease(_ context.Context, c ControlLeaseCommand) (ControlLease, bool, error) {
	s.command = c
	return s.lease, s.replay, s.err
}
func (s *controlTestStore) RenewControlLease(_ context.Context, c ControlLeaseCommand) (ControlLease, bool, error) {
	s.command = c
	return s.lease, s.replay, s.err
}
func (s *controlTestStore) ReleaseControlLease(_ context.Context, c ControlLeaseCommand) (bool, error) {
	s.command = c
	return s.replay, s.err
}

func TestControlServiceBuildsScopedCommands(t *testing.T) {
	store := &controlTestStore{lease: ControlLease{ID: "ctl-1"}}
	service, err := NewControlService(store, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	actor := ActorRef{Type: ActorHuman, ID: "actor-1"}
	request := AcquireControlLeaseRequest{ExpectedWorkspaceVersion: 2, Scope: ControlScope{Type: "workspace", ID: "wrk-1"}, DurationSeconds: 30}
	lease, _, err := service.Acquire(context.Background(), "tenant-1", actor, "wrk-1", "key-1", request)
	if err != nil || lease.ID != "ctl-1" {
		t.Fatalf("lease=%#v err=%v", lease, err)
	}
	if store.command.LeaseID != "ctl_1" || store.command.EventID != "evt_2" || store.command.AuditID != "aud_3" || store.command.RequestDigest == [32]byte{} || store.command.Duration.Seconds() != 30 {
		t.Fatalf("command=%#v", store.command)
	}
}

func TestControlServiceRejectsInvalidAndPreservesStoreErrors(t *testing.T) {
	store := &controlTestStore{err: ErrControlConflict}
	service, _ := NewControlService(store, &sequenceIDs{})
	actor := ActorRef{Type: ActorHuman, ID: "actor-1"}
	if _, _, err := service.Acquire(context.Background(), "tenant-1", actor, "wrk-1", "key", AcquireControlLeaseRequest{ExpectedWorkspaceVersion: 1, Scope: ControlScope{Type: "workspace", ID: "other"}, DurationSeconds: 30}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid err=%v", err)
	}
	if _, _, err := service.Acquire(context.Background(), "tenant-1", actor, "wrk-1", "key", AcquireControlLeaseRequest{ExpectedWorkspaceVersion: 1, Scope: ControlScope{Type: "workspace", ID: "wrk-1"}, DurationSeconds: 30}); !errors.Is(err, ErrControlConflict) {
		t.Fatalf("store err=%v", err)
	}
}
