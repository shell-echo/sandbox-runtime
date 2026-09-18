package product

import (
	"context"
	"errors"
	"testing"
	"time"
)

type grantStoreStub struct{ command ConnectionGrantCommand }

func (s *grantStoreStub) MintConnectionGrant(_ context.Context, command ConnectionGrantCommand) (ConnectionGrant, bool, error) {
	s.command = command
	return ConnectionGrant{ID: command.ConnectionID, AccessMode: command.Request.AccessMode}, false, nil
}
func (*grantStoreStub) ConsumeConnectionGrant(context.Context, string) (GatewayBinding, error) {
	return GatewayBinding{}, ErrNotFound
}
func (*grantStoreStub) CheckGatewayAuthority(context.Context, GatewayBinding) error { return nil }

func TestGrantServiceSeparatesViewerAndControllerAuthority(t *testing.T) {
	store := &grantStoreStub{}
	service, err := NewGrantService(store, &sequenceIDs{}, CryptoTicketGenerator{}, "wss://gateway.example.test/connect", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	view, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "ses-1", "view-key", CreateConnectionRequest{ExpectedSessionVersion: 1, ProtocolProfile: SessionProfileBrowserLive, AccessMode: GrantAccessView})
	if err != nil || view.AccessMode != GrantAccessView || store.command.Request.ControlLeaseID != "" {
		t.Fatalf("view=%#v command=%#v err=%v", view, store.command, err)
	}
	if _, _, err := service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "ses-1", "bad-view", CreateConnectionRequest{ExpectedSessionVersion: 1, ProtocolProfile: SessionProfileBrowserLive, AccessMode: GrantAccessView, ControlLeaseID: "ctl-1", ControlFence: 1}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer fence err=%v", err)
	}
	_, _, err = service.Create(context.Background(), "tenant-1", ActorRef{Type: ActorHuman, ID: "actor-1"}, "ses-1", "control-key", CreateConnectionRequest{ExpectedSessionVersion: 1, ProtocolProfile: SessionProfileBrowserLive, AccessMode: GrantAccessControl, ControlLeaseID: "ctl-1", ControlFence: 2})
	if err != nil || store.command.Request.AccessMode != GrantAccessControl {
		t.Fatalf("control command=%#v err=%v", store.command, err)
	}
}
