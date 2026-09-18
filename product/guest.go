package product

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"time"
)

type GuestBinding struct {
	TenantID, WorkspaceID, SlotKey, GuestID string
	SlotProfileID                           string
	SlotGeneration, BindingGeneration       int64
	ProtocolVersion                         string
	Capabilities                            []string
	ClientNonce                             string
	State                                   string
	ExpiresAt                               time.Time
}

type ProvisionGuestRequest struct {
	ExpectedWorkspaceVersion int64
	SlotKey                  string
	ProtocolVersion          string
	Capabilities             []string
	PublicKey                []byte
	LifetimeSeconds          int64
}

type GuestBindingCommand struct {
	TenantID, WorkspaceID, GuestID         string
	Actor                                  ActorRef
	EventID, AuditID, IdempotencyKey, Path string
	RequestDigest                          [32]byte
	Request                                ProvisionGuestRequest
}

type GuestAuthentication struct {
	GuestID, ProtocolVersion, ClientNonce string
	BindingGeneration                     int64
	OfferedCapabilities                   []string
	SigningBytes, Signature               []byte
}

type GuestBindingStore interface {
	ProvisionGuest(context.Context, GuestBindingCommand) (GuestBinding, bool, error)
	AuthenticateGuest(context.Context, GuestAuthentication) (GuestBinding, error)
	CheckGuestAuthority(context.Context, GuestBinding) error
	DisconnectGuest(context.Context, GuestBinding) error
	RevokeGuest(context.Context, string, string, string) error
}

type GuestService struct {
	store GuestBindingStore
	ids   IDGenerator
}

func NewGuestService(store GuestBindingStore, ids IDGenerator) (*GuestService, error) {
	if nilInterface(store) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &GuestService{store: store, ids: ids}, nil
}

func (s *GuestService) Provision(ctx context.Context, tenantID string, actor ActorRef, workspaceID, idempotencyKey string, request ProvisionGuestRequest) (GuestBinding, bool, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdempotencyKey(idempotencyKey) ||
		request.ExpectedWorkspaceVersion < 1 || !validIdentifier(request.SlotKey) || request.ProtocolVersion != "1.0.0" ||
		len(request.PublicKey) != ed25519.PublicKeySize || request.LifetimeSeconds < 60 || request.LifetimeSeconds > 86400 ||
		!validGuestCapabilities(request.Capabilities) {
		return GuestBinding{}, false, ErrInvalid
	}
	guestID, err := s.ids.NewID("gst")
	if err != nil {
		return GuestBinding{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return GuestBinding{}, false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return GuestBinding{}, false, ErrStoreUnavailable
	}
	request.PublicKey = append([]byte(nil), request.PublicKey...)
	request.Capabilities = append([]string(nil), request.Capabilities...)
	sort.Strings(request.Capabilities)
	encoded, err := json.Marshal(request)
	if err != nil {
		return GuestBinding{}, false, ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	return s.store.ProvisionGuest(ctx, GuestBindingCommand{
		TenantID: tenantID, WorkspaceID: workspaceID, GuestID: guestID, Actor: actor,
		EventID: eventID, AuditID: auditID, IdempotencyKey: idempotencyKey,
		Path: "/internal/v1/workspaces/" + workspaceID + "/guest-bindings", RequestDigest: digest, Request: request,
	})
}

func validGuestCapabilities(values []string) bool {
	if len(values) < 1 || len(values) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validIdentifier(value) {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
