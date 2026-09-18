package product

import (
	"context"
	"time"
)

type PrimarySlotPolicy interface {
	AuthorizePrimarySlot(context.Context, SlotSpec) error
}

type IDGenerator interface {
	NewID(prefix string) (string, error)
}

type CreateWorkspaceCommand struct {
	TenantID       string
	Actor          ActorRef
	Method         string
	Path           string
	IdempotencyKey string
	RequestDigest  [32]byte

	WorkspaceID string
	OperationID string
	EventID     string
	OutboxID    string

	DisplayName string
	Lifetime    time.Duration
	PrimarySlot SlotSpec
}

type WorkspaceCommandStore interface {
	CreateWorkspace(context.Context, CreateWorkspaceCommand) (CreateWorkspaceResult, error)
	GetWorkspace(context.Context, string, string) (Workspace, error)
	GetOperation(context.Context, string, string) (Operation, error)
}
