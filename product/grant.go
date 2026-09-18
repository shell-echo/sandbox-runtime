package product

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"
)

type CreateConnectionRequest struct {
	ExpectedSessionVersion          int64
	ProtocolProfile, ControlLeaseID string
	ControlFence                    int64
	AccessMode                      string
}
type ConnectionGrant struct {
	ID, SessionID, ProtocolProfile, AccessMode, GatewayURI, Ticket string
	ExpiresAt                                                      time.Time
}
type GatewayBinding struct {
	ConnectionID, TenantID                           string
	Actor                                            ActorRef
	WorkspaceID, SlotKey, SessionID, ProtocolProfile string
	SlotGeneration                                   int64
	ControlLeaseID                                   string
	ControlFence                                     int64
	AccessMode                                       string
	ExpiresAt                                        time.Time
	ProviderRevisionID, SandboxID, HandoffReference  string
	ConnectionGeneration                             int64
	HandoffExpiresAt                                 time.Time
}
type ConnectionGrantCommand struct {
	TenantID                                                          string
	Actor                                                             ActorRef
	SessionID, ConnectionID, Ticket, GatewayURI, IdempotencyKey, Path string
	RequestDigest                                                     [32]byte
	Request                                                           CreateConnectionRequest
	Lifetime                                                          time.Duration
	AuditID                                                           string
}
type ConnectionGrantStore interface {
	MintConnectionGrant(context.Context, ConnectionGrantCommand) (ConnectionGrant, bool, error)
	ConsumeConnectionGrant(context.Context, string) (GatewayBinding, error)
	CheckGatewayAuthority(context.Context, GatewayBinding) error
}
type TicketGenerator interface{ NewTicket() (string, error) }
type CryptoTicketGenerator struct{}

func (CryptoTicketGenerator) NewTicket() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

type GrantService struct {
	store      ConnectionGrantStore
	ids        IDGenerator
	tickets    TicketGenerator
	gatewayURI string
	lifetime   time.Duration
}

func NewGrantService(store ConnectionGrantStore, ids IDGenerator, tickets TicketGenerator, gatewayURI string, lifetime time.Duration) (*GrantService, error) {
	parsed, err := url.Parse(gatewayURI)
	if nilInterface(store) || nilInterface(ids) || nilInterface(tickets) || err != nil || parsed.Host == "" || (parsed.Scheme != "wss" && parsed.Scheme != "https") || parsed.User != nil || parsed.Fragment != "" || lifetime < time.Second || lifetime > 60*time.Second {
		return nil, ErrInvalid
	}
	return &GrantService{store: store, ids: ids, tickets: tickets, gatewayURI: gatewayURI, lifetime: lifetime}, nil
}
func (s *GrantService) Create(ctx context.Context, tenantID string, actor ActorRef, sessionID, key string, request CreateConnectionRequest) (ConnectionGrant, bool, error) {
	if request.AccessMode == "" {
		request.AccessMode = GrantAccessControl
	}
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(sessionID) || !validIdempotencyKey(key) || request.ExpectedSessionVersion < 1 || !validIdentifier(request.ProtocolProfile) || (request.ControlLeaseID == "") != (request.ControlFence == 0) {
		return ConnectionGrant{}, false, ErrInvalid
	}
	if request.AccessMode != GrantAccessView && request.AccessMode != GrantAccessControl {
		return ConnectionGrant{}, false, ErrInvalid
	}
	if request.AccessMode == GrantAccessView && request.ControlLeaseID != "" {
		return ConnectionGrant{}, false, ErrForbidden
	}
	if request.ControlLeaseID != "" && (!validIdentifier(request.ControlLeaseID) || request.ControlFence < 1) {
		return ConnectionGrant{}, false, ErrInvalid
	}
	connectionID, err := s.ids.NewID("con")
	if err != nil {
		return ConnectionGrant{}, false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return ConnectionGrant{}, false, ErrStoreUnavailable
	}
	ticket, err := s.tickets.NewTicket()
	if err != nil || len(ticket) < 32 || strings.ContainsAny(ticket, " \t\r\n") {
		return ConnectionGrant{}, false, ErrStoreUnavailable
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return ConnectionGrant{}, false, ErrInvalid
	}
	digest := sha256.Sum256(encoded)
	return s.store.MintConnectionGrant(ctx, ConnectionGrantCommand{TenantID: tenantID, Actor: actor, SessionID: sessionID, ConnectionID: connectionID, Ticket: ticket, GatewayURI: s.gatewayURI, IdempotencyKey: key, Path: "/api/v1/sessions/" + sessionID + "/connections", RequestDigest: digest, Request: request, Lifetime: s.lifetime, AuditID: auditID})
}
