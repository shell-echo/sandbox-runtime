package product

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type slotStoreStub struct {
	commands []SlotCommand
	slot     WorkspaceSlot
	err      error
}

func (s *slotStoreStub) PutSlot(_ context.Context, command SlotCommand) (Operation, bool, error) {
	s.commands = append(s.commands, command)
	return Operation{ID: command.OperationID, Type: "put_slot", WorkspaceID: command.WorkspaceID, SlotKey: command.SlotKey}, false, s.err
}
func (s *slotStoreStub) GetSlot(context.Context, string, ActorRef, string, string) (WorkspaceSlot, error) {
	return s.slot, s.err
}

type slotPolicyStub struct{ err error }

func (p slotPolicyStub) AuthorizeSlot(context.Context, SlotSpec) error { return p.err }

func TestSlotServiceBuildsStrictBrowserCommand(t *testing.T) {
	store := &slotStoreStub{}
	service, err := NewSlotService(store, slotPolicyStub{}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := validPutSlotRequest()
	operation, replay, err := service.Put(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "browser-main", "put-1", request)
	if err != nil || replay || operation.ID != "op_1" || len(store.commands) != 1 {
		t.Fatalf("operation=%#v replay=%v err=%v commands=%d", operation, replay, err, len(store.commands))
	}
	command := store.commands[0]
	if command.EventID != "evt_2" || command.OutboxID != "out_3" || command.Path != "/api/v1/workspaces/wrk-1/slots/browser-main" ||
		command.ExpectedWorkspaceVersion != 1 || command.RequestDigest == [32]byte{} || !reflect.DeepEqual(command.Spec.RequiredCapabilities, request.RequiredCapabilities) {
		t.Fatalf("command=%#v", command)
	}
}

func TestSlotServiceRejectsAnyNonLockedBrowserShape(t *testing.T) {
	tests := []struct {
		name    string
		slotKey string
		mutate  func(*PutSlotRequest)
	}{
		{name: "primary", slotKey: PrimarySlotKey},
		{name: "uppercase key", slotKey: "Browser-main"},
		{name: "kind", slotKey: "browser-main", mutate: func(r *PutSlotRequest) { r.Kind = "code" }},
		{name: "runtime profile", slotKey: "browser-main", mutate: func(r *PutSlotRequest) { r.ProfileID = "other" }},
		{name: "capability", slotKey: "browser-main", mutate: func(r *PutSlotRequest) { r.RequiredCapabilities[0].CapabilityID = "sandbox.exec" }},
		{name: "version", slotKey: "browser-main", mutate: func(r *PutSlotRequest) { r.RequiredCapabilities[0].Version = "2.0.0" }},
		{name: "profile", slotKey: "browser-main", mutate: func(r *PutSlotRequest) { r.RequiredCapabilities[0].ProfileID = "other" }},
		{name: "extra capability", slotKey: "browser-main", mutate: func(r *PutSlotRequest) {
			r.RequiredCapabilities = append(r.RequiredCapabilities, r.RequiredCapabilities[0])
		}},
		{name: "desired", slotKey: "browser-main", mutate: func(r *PutSlotRequest) { r.DesiredState = "active" }},
		{name: "workspace version", slotKey: "browser-main", mutate: func(r *PutSlotRequest) { r.ExpectedWorkspaceVersion = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &slotStoreStub{}
			service, _ := NewSlotService(store, slotPolicyStub{}, &sequenceIDs{})
			request := validPutSlotRequest()
			if test.mutate != nil {
				test.mutate(&request)
			}
			if _, _, err := service.Put(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", test.slotKey, "put-1", request); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
			if len(store.commands) != 0 {
				t.Fatal("invalid request reached store")
			}
		})
	}
}

func TestSlotServiceFailsClosedOnPolicyAndPreservesCancellation(t *testing.T) {
	store := &slotStoreStub{}
	ids := &sequenceIDs{}
	service, _ := NewSlotService(store, slotPolicyStub{err: ErrCapabilityUnsupported}, ids)
	if _, _, err := service.Put(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "browser-main", "put-1", validPutSlotRequest()); !errors.Is(err, ErrCapabilityUnsupported) {
		t.Fatalf("policy err=%v", err)
	}
	if ids.next != 0 || len(store.commands) != 0 {
		t.Fatal("policy rejection allocated identifiers or reached store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service, _ = NewSlotService(store, slotPolicyStub{}, ids)
	if _, _, err := service.Put(ctx, "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "browser-main", "put-1", validPutSlotRequest()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel err=%v", err)
	}
}

func TestSlotServiceBuildsOnlyExactDesktopAuthority(t *testing.T) {
	store := &slotStoreStub{}
	service, err := NewSlotService(store, slotPolicyStub{}, &sequenceIDs{})
	if err != nil {
		t.Fatal(err)
	}
	request := validDesktopPutSlotRequest()
	operation, replay, err := service.Put(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "desktop-main", "desktop-put-1", request)
	if err != nil || replay || operation.ID != "op_1" || len(store.commands) != 1 {
		t.Fatalf("operation=%#v replay=%v err=%v commands=%d", operation, replay, err, len(store.commands))
	}
	command := store.commands[0]
	if command.Spec.Kind != DesktopSlotKind || command.Spec.ProfileID != DesktopSlotProfile ||
		command.Spec.RequiredCapabilities[0].CapabilityID != DesktopCapabilityID || command.RequestDigest == [32]byte{} {
		t.Fatalf("command=%#v", command)
	}

	mutations := []func(*PutSlotRequest){
		func(r *PutSlotRequest) { r.Kind = BrowserSlotKind },
		func(r *PutSlotRequest) { r.ProfileID = BrowserSlotProfile },
		func(r *PutSlotRequest) { r.RequiredCapabilities[0].CapabilityID = BrowserCapabilityID },
		func(r *PutSlotRequest) { r.RequiredCapabilities[0].Version = "1.0.1" },
		func(r *PutSlotRequest) { r.RequiredCapabilities[0].ProfileID = BrowserCapabilityProfile },
		func(r *PutSlotRequest) {
			r.RequiredCapabilities = append(r.RequiredCapabilities, r.RequiredCapabilities[0])
		},
	}
	for index, mutate := range mutations {
		invalid := validDesktopPutSlotRequest()
		mutate(&invalid)
		if _, _, err := service.Put(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "wrk-1", "desktop-main", "desktop-invalid", invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("mutation %d err=%v", index, err)
		}
	}
	if len(store.commands) != 1 {
		t.Fatalf("invalid Desktop shapes reached store: commands=%d", len(store.commands))
	}
}

func validPutSlotRequest() PutSlotRequest {
	return PutSlotRequest{ExpectedWorkspaceVersion: 1, Kind: "browser", ProfileID: BrowserSlotProfile,
		RequiredCapabilities: []CapabilityRequirement{{CapabilityID: BrowserCapabilityID, Version: BrowserCapabilityVersion, ProfileID: BrowserCapabilityProfile}}, DesiredState: "ready"}
}

func validDesktopPutSlotRequest() PutSlotRequest {
	return PutSlotRequest{ExpectedWorkspaceVersion: 1, Kind: DesktopSlotKind, ProfileID: DesktopSlotProfile,
		RequiredCapabilities: []CapabilityRequirement{{CapabilityID: DesktopCapabilityID, Version: DesktopCapabilityVersion, ProfileID: DesktopCapabilityProfile}}, DesiredState: "ready"}
}
