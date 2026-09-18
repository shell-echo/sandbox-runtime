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

func (a *Application) GetWorkspace(ctx context.Context, tenantID string, actor ActorRef, workspaceID string) (Workspace, error) {
	if err := validateRead(ctx, a, tenantID, actor, workspaceID); err != nil {
		return Workspace{}, err
	}
	workspace, err := a.store.GetWorkspace(ctx, tenantID, workspaceID)
	if err != nil {
		return Workspace{}, err
	}
	if workspace.Owner != actor {
		return Workspace{}, ErrNotFound
	}
	return workspace, nil
}

func (a *Application) ListWorkspaces(ctx context.Context, tenantID string, actor ActorRef, cursor string, limit int) ([]Workspace, string, error) {
	if a == nil || a.store == nil {
		return nil, "", ErrStoreUnavailable
	}
	if ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || len(cursor) > 1024 || limit < 1 || limit > 200 {
		return nil, "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	return a.store.ListWorkspaces(ctx, tenantID, actor, cursor, limit)
}

func (a *Application) GetOperation(ctx context.Context, tenantID string, actor ActorRef, operationID string) (Operation, error) {
	if err := validateRead(ctx, a, tenantID, actor, operationID); err != nil {
		return Operation{}, err
	}
	operation, err := a.store.GetOperation(ctx, tenantID, operationID)
	if err != nil {
		return Operation{}, err
	}
	if operation.SubmittedBy != actor {
		return Operation{}, ErrNotFound
	}
	return operation, nil
}

func validateRead(ctx context.Context, application *Application, tenantID string, actor ActorRef, resourceID string) error {
	if application == nil || application.store == nil {
		return ErrStoreUnavailable
	}
	if ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(resourceID) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
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
