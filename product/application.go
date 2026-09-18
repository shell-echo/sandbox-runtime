package product

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"
)

type Application struct {
	store  WorkspaceCommandStore
	policy PrimarySlotPolicy
	ids    IDGenerator
}

func NewApplication(store WorkspaceCommandStore, policy PrimarySlotPolicy, ids IDGenerator) (*Application, error) {
	if nilInterface(store) || nilInterface(policy) || nilInterface(ids) {
		return nil, fmt.Errorf("%w: product application dependencies", ErrInvalid)
	}
	return &Application{store: store, policy: policy, ids: ids}, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (a *Application) CreateWorkspace(
	ctx context.Context,
	tenantID string,
	actor ActorRef,
	idempotencyKey string,
	request CreateWorkspaceRequest,
) (CreateWorkspaceResult, error) {
	if a == nil || a.store == nil || a.policy == nil || a.ids == nil {
		return CreateWorkspaceResult{}, ErrStoreUnavailable
	}
	if ctx == nil {
		return CreateWorkspaceResult{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return CreateWorkspaceResult{}, err
	}
	if !validIdentifier(tenantID) || actor.Validate() != nil || !validIdempotencyKey(idempotencyKey) ||
		request.validate() != nil {
		return CreateWorkspaceResult{}, ErrInvalid
	}
	if err := a.policy.AuthorizePrimarySlot(ctx, request.PrimarySlot); err != nil {
		if errors.Is(err, ErrCapabilityUnsupported) {
			return CreateWorkspaceResult{}, err
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return CreateWorkspaceResult{}, contextErr
		}
		return CreateWorkspaceResult{}, ErrStoreUnavailable
	}

	workspaceID, err := a.ids.NewID("wrk")
	if err != nil {
		return CreateWorkspaceResult{}, ErrStoreUnavailable
	}
	operationID, err := a.ids.NewID("op")
	if err != nil {
		return CreateWorkspaceResult{}, ErrStoreUnavailable
	}
	eventID, err := a.ids.NewID("evt")
	if err != nil {
		return CreateWorkspaceResult{}, ErrStoreUnavailable
	}
	outboxID, err := a.ids.NewID("out")
	if err != nil {
		return CreateWorkspaceResult{}, ErrStoreUnavailable
	}

	digestDocument := struct {
		DisplayName     string   `json:"display_name"`
		LifetimeSeconds int64    `json:"lifetime_seconds"`
		PrimarySlot     SlotSpec `json:"primary_slot"`
	}{request.DisplayName, request.LifetimeSeconds, request.PrimarySlot}
	encoded, err := json.Marshal(digestDocument)
	if err != nil {
		return CreateWorkspaceResult{}, ErrInvalid
	}

	return a.store.CreateWorkspace(ctx, CreateWorkspaceCommand{
		TenantID: tenantID, Actor: actor, Method: CreateWorkspaceMethod, Path: CreateWorkspacePath,
		IdempotencyKey: idempotencyKey, RequestDigest: sha256.Sum256(encoded),
		WorkspaceID: workspaceID, OperationID: operationID, EventID: eventID, OutboxID: outboxID,
		DisplayName: request.DisplayName, Lifetime: time.Duration(request.LifetimeSeconds) * time.Second,
		PrimarySlot: request.PrimarySlot,
	})
}

func validIdempotencyKey(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
