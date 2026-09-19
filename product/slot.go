package product

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
)

const PutSlotMethod = "PUT"

var auxiliarySlotKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)

type SlotPolicy interface {
	AuthorizeSlot(context.Context, SlotSpec) error
}

type PutSlotRequest struct {
	ExpectedWorkspaceVersion int64
	Kind                     string
	ProfileID                string
	RequiredCapabilities     []CapabilityRequirement
	DesiredState             string
}

type SlotCommand struct {
	TenantID, WorkspaceID, SlotKey                       string
	Actor                                                ActorRef
	OperationID, EventID, OutboxID, IdempotencyKey, Path string
	RequestDigest                                        [32]byte
	ExpectedWorkspaceVersion                             int64
	Spec                                                 SlotSpec
}

type SlotStore interface {
	PutSlot(context.Context, SlotCommand) (Operation, bool, error)
	GetSlot(context.Context, string, ActorRef, string, string) (WorkspaceSlot, error)
}

type SlotService struct {
	store  SlotStore
	policy SlotPolicy
	ids    IDGenerator
}

func NewSlotService(store SlotStore, policy SlotPolicy, ids IDGenerator) (*SlotService, error) {
	if nilInterface(store) || nilInterface(policy) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &SlotService{store: store, policy: policy, ids: ids}, nil
}

func (s *SlotService) Put(ctx context.Context, tenantID string, actor ActorRef, workspaceID, slotKey, key string, request PutSlotRequest) (Operation, bool, error) {
	if err := validateSlotInput(ctx, s, tenantID, actor, workspaceID, slotKey); err != nil {
		return Operation{}, false, err
	}
	if !validIdempotencyKey(key) {
		return Operation{}, false, ErrInvalid
	}
	spec := SlotSpec{SlotKey: slotKey, Kind: request.Kind, ProfileID: request.ProfileID, RequiredCapabilities: request.RequiredCapabilities, DesiredState: request.DesiredState}
	if request.ExpectedWorkspaceVersion < 1 || spec.validateAuxiliary() != nil {
		return Operation{}, false, ErrInvalid
	}
	if err := s.policy.AuthorizeSlot(ctx, spec); err != nil {
		if errors.Is(err, ErrCapabilityUnsupported) {
			return Operation{}, false, err
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return Operation{}, false, contextErr
		}
		return Operation{}, false, ErrStoreUnavailable
	}
	operationID, err := s.ids.NewID("op")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	outboxID, err := s.ids.NewID("out")
	if err != nil {
		return Operation{}, false, ErrStoreUnavailable
	}
	digestDocument := struct {
		ExpectedWorkspaceVersion int64                   `json:"expected_workspace_version"`
		Kind                     string                  `json:"kind"`
		ProfileID                string                  `json:"profile_id"`
		RequiredCapabilities     []CapabilityRequirement `json:"required_capabilities"`
		DesiredState             string                  `json:"desired_state"`
	}{request.ExpectedWorkspaceVersion, request.Kind, request.ProfileID, request.RequiredCapabilities, request.DesiredState}
	encoded, err := json.Marshal(digestDocument)
	if err != nil {
		return Operation{}, false, ErrInvalid
	}
	return s.store.PutSlot(ctx, SlotCommand{
		TenantID: tenantID, Actor: actor, WorkspaceID: workspaceID, SlotKey: slotKey,
		OperationID: operationID, EventID: eventID, OutboxID: outboxID,
		IdempotencyKey: key, Path: "/api/v1/workspaces/" + workspaceID + "/slots/" + slotKey,
		RequestDigest: sha256.Sum256(encoded), ExpectedWorkspaceVersion: request.ExpectedWorkspaceVersion, Spec: spec,
	})
}

func (s *SlotService) Get(ctx context.Context, tenantID string, actor ActorRef, workspaceID, slotKey string) (WorkspaceSlot, error) {
	if err := validateSlotInput(ctx, s, tenantID, actor, workspaceID, slotKey); err != nil {
		return WorkspaceSlot{}, err
	}
	return s.store.GetSlot(ctx, tenantID, actor, workspaceID, slotKey)
}

func validateSlotInput(ctx context.Context, service *SlotService, tenantID string, actor ActorRef, workspaceID, slotKey string) error {
	if service == nil || nilInterface(service.store) || nilInterface(service.policy) || nilInterface(service.ids) {
		return ErrStoreUnavailable
	}
	if ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) ||
		!auxiliarySlotKeyPattern.MatchString(slotKey) || slotKey == PrimarySlotKey {
		return ErrInvalid
	}
	return ctx.Err()
}

func (s SlotSpec) validateAuxiliary() error {
	if !auxiliarySlotKeyPattern.MatchString(s.SlotKey) || s.SlotKey == PrimarySlotKey ||
		(s.DesiredState != "ready" && s.DesiredState != "suspended" && s.DesiredState != "terminated") ||
		len(s.RequiredCapabilities) != 1 {
		return ErrInvalid
	}
	requirement := s.RequiredCapabilities[0]
	switch s.Kind {
	case BrowserSlotKind:
		if s.ProfileID == BrowserSlotProfile && requirement.CapabilityID == BrowserCapabilityID &&
			requirement.Version == BrowserCapabilityVersion && requirement.ProfileID == BrowserCapabilityProfile {
			return nil
		}
	case DesktopSlotKind:
		if s.ProfileID == DesktopSlotProfile && requirement.CapabilityID == DesktopCapabilityID &&
			requirement.Version == DesktopCapabilityVersion && requirement.ProfileID == DesktopCapabilityProfile {
			return nil
		}
	}
	return ErrInvalid
}
