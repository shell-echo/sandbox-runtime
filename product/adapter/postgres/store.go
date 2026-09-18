package productpostgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	minOperationTimeout  = 10 * time.Millisecond
	maxOperationTimeout  = 30 * time.Second
	idempotencyRetention = 30 * 24 * time.Hour
)

type Store struct {
	pool             *pgxpool.Pool
	operationTimeout time.Duration
}

func New(pool *pgxpool.Pool, operationTimeout time.Duration) (*Store, error) {
	if pool == nil || operationTimeout < minOperationTimeout || operationTimeout > maxOperationTimeout {
		return nil, product.ErrInvalid
	}
	return &Store{pool: pool, operationTimeout: operationTimeout}, nil
}

func (s *Store) CreateWorkspace(ctx context.Context, command product.CreateWorkspaceCommand) (product.CreateWorkspaceResult, error) {
	if s == nil || s.pool == nil || s.operationTimeout == 0 {
		return product.CreateWorkspaceResult{}, product.ErrStoreUnavailable
	}
	if ctx == nil {
		return product.CreateWorkspaceResult{}, product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return product.CreateWorkspaceResult{}, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)

	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	inserted, err := reserveIdempotency(opCtx, tx, command, now)
	if err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	if !inserted {
		result, err := loadIdempotentResult(opCtx, tx, command)
		if err != nil {
			return product.CreateWorkspaceResult{}, err
		}
		if err := tx.Rollback(opCtx); err != nil {
			return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
		}
		result.Replay = true
		return result, nil
	}
	if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 7346273419))`, command.TenantID); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	var workspaceCount, workspaceLimit int
	if err := tx.QueryRow(opCtx, `SELECT
    (SELECT count(*) FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND desired_state <> 'terminated'),
    COALESCE((SELECT max_workspaces FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),100)`, command.TenantID).Scan(&workspaceCount, &workspaceLimit); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	if workspaceCount >= workspaceLimit {
		return product.CreateWorkspaceResult{}, product.ErrQuotaExceeded
	}

	capabilities, err := json.Marshal(command.PrimarySlot.RequiredCapabilities)
	if err != nil {
		return product.CreateWorkspaceResult{}, product.ErrInvalid
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspaces
    (tenant_id, workspace_id, owner_actor_type, owner_actor_id, display_name, primary_slot_key,
     desired_state, observed_state, version, lease_expires_at, next_event_sequence, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, 'primary-code', 'active', 'requested', 1, $6, 2, $7, $7)`,
		command.TenantID, command.WorkspaceID, string(command.Actor.Type), command.Actor.ID,
		command.DisplayName, now.Add(command.Lifetime), now); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_slots
    (tenant_id, workspace_id, slot_key, kind, profile_id, required_capabilities, desired_state,
     observed_state, generation, observed_generation, version, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'requested', 1, 0, 1, $8, $8)`,
		command.TenantID, command.WorkspaceID, command.PrimarySlot.SlotKey, command.PrimarySlot.Kind,
		command.PrimarySlot.ProfileID, capabilities, command.PrimarySlot.DesiredState, now); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.product_operations
    (tenant_id, operation_id, operation_type, workspace_id, submitted_actor_type, submitted_actor_id,
     state, reconciliation_status, version, accepted_at, updated_at)
VALUES ($1, $2, 'create_workspace', $3, $4, $5, 'accepted', 'pending', 1, $6, $6)`,
		command.TenantID, command.OperationID, command.WorkspaceID, string(command.Actor.Type), command.Actor.ID, now); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	eventAttributes, _ := json.Marshal(map[string]any{
		"primary_slot_key": command.PrimarySlot.SlotKey,
		"profile_id":       command.PrimarySlot.ProfileID,
	})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events
    (tenant_id, workspace_id, sequence, event_id, event_type, subject_type, subject_id,
     operation_id, actor_type, actor_id, occurred_at, attributes)
VALUES ($1, $2, 1, $3, 'workspace.create_accepted', 'workspace', $2, $4, $5, $6, $7, $8)`,
		command.TenantID, command.WorkspaceID, command.EventID, command.OperationID,
		string(command.Actor.Type), command.Actor.ID, now, eventAttributes); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	outboxPayload, _ := json.Marshal(map[string]any{
		"workspace_id": command.WorkspaceID,
		"operation_id": command.OperationID,
		"slot_key":     command.PrimarySlot.SlotKey,
		"generation":   1,
	})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.outbox
    (tenant_id, outbox_id, workspace_id, operation_id, message_type, payload, state,
     attempt_count, available_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, 'workspace.reconcile', $5, 'pending', 0, $6, $6, $6)`,
		command.TenantID, command.OutboxID, command.WorkspaceID, command.OperationID, outboxPayload, now); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}

	operation := product.Operation{
		ID: command.OperationID, Type: "create_workspace", WorkspaceID: command.WorkspaceID,
		SubmittedBy: command.Actor, State: "accepted", ReconciliationStatus: "pending", Version: 1,
		AcceptedAt: now, UpdatedAt: now,
	}
	if err := insertAudit(opCtx, tx, "aud-"+command.OperationID, command.TenantID, command.Actor,
		"workspace.create", "workspace", command.WorkspaceID, "allowed", "authorized", now); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.CreateWorkspaceResult{}, storeError(ctx, opCtx, err, true)
	}
	return product.CreateWorkspaceResult{Operation: operation}, nil
}

func (s *Store) GetWorkspace(ctx context.Context, tenantID, workspaceID string) (product.Workspace, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return product.Workspace{}, product.ErrStoreUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return product.Workspace{}, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var workspace product.Workspace
	var actorType string
	err = tx.QueryRow(opCtx, `SELECT workspace_id, tenant_id, owner_actor_type, owner_actor_id,
       display_name, primary_slot_key, desired_state, observed_state, version, lease_expires_at,
       created_at, updated_at
FROM sandbox_runtime_product.workspaces WHERE tenant_id = $1 AND workspace_id = $2`, tenantID, workspaceID).Scan(
		&workspace.ID, &workspace.TenantID, &actorType, &workspace.Owner.ID,
		&workspace.DisplayName, &workspace.PrimarySlotKey, &workspace.DesiredState, &workspace.ObservedState,
		&workspace.Version, &workspace.LeaseExpiresAt, &workspace.CreatedAt, &workspace.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.Workspace{}, product.ErrNotFound
	}
	if err != nil {
		return product.Workspace{}, storeError(ctx, opCtx, err, false)
	}
	workspace.Owner.Type = product.ActorType(actorType)
	rows, err := tx.Query(opCtx, `SELECT slot_key, kind, profile_id, required_capabilities,
       desired_state, observed_state, generation, observed_generation, version, created_at, updated_at
FROM sandbox_runtime_product.workspace_slots
WHERE tenant_id = $1 AND workspace_id = $2 ORDER BY slot_key`, tenantID, workspaceID)
	if err != nil {
		return product.Workspace{}, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	for rows.Next() {
		var slot product.WorkspaceSlot
		var capabilities []byte
		if err := rows.Scan(&slot.SlotKey, &slot.Kind, &slot.ProfileID, &capabilities, &slot.DesiredState,
			&slot.ObservedState, &slot.Generation, &slot.ObservedGeneration, &slot.Version,
			&slot.CreatedAt, &slot.UpdatedAt); err != nil {
			return product.Workspace{}, storeError(ctx, opCtx, err, false)
		}
		if err := json.Unmarshal(capabilities, &slot.RequiredCapabilities); err != nil {
			return product.Workspace{}, product.ErrStoreUnavailable
		}
		workspace.Slots = append(workspace.Slots, slot)
	}
	if err := rows.Err(); err != nil {
		return product.Workspace{}, storeError(ctx, opCtx, err, false)
	}
	if len(workspace.Slots) == 0 {
		return product.Workspace{}, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.Workspace{}, storeError(ctx, opCtx, err, false)
	}
	return workspace, nil
}

func (s *Store) GetOperation(ctx context.Context, tenantID, operationID string) (product.Operation, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return product.Operation{}, product.ErrStoreUnavailable
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var operation product.Operation
	var actorType string
	err := s.pool.QueryRow(opCtx, `SELECT operation_id, operation_type, workspace_id,
       submitted_actor_type, submitted_actor_id, state, reconciliation_status, version,
       accepted_at, updated_at
FROM sandbox_runtime_product.product_operations WHERE tenant_id = $1 AND operation_id = $2`, tenantID, operationID).Scan(
		&operation.ID, &operation.Type, &operation.WorkspaceID, &actorType, &operation.SubmittedBy.ID,
		&operation.State, &operation.ReconciliationStatus, &operation.Version, &operation.AcceptedAt,
		&operation.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.Operation{}, product.ErrNotFound
	}
	if err != nil {
		return product.Operation{}, storeError(ctx, opCtx, err, false)
	}
	operation.SubmittedBy.Type = product.ActorType(actorType)
	return operation, nil
}

func rollbackBounded(tx pgx.Tx, timeout time.Duration) {
	rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), timeout)
	defer rollbackCancel()
	_ = tx.Rollback(rollbackCtx)
}

func reserveIdempotency(
	ctx context.Context,
	tx pgx.Tx,
	command product.CreateWorkspaceCommand,
	now time.Time,
) (bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.idempotency_records
    (tenant_id, actor_type, actor_id, method, normalized_path, idempotency_key, request_digest,
     result_workspace_id, result_operation_id, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (tenant_id, actor_type, actor_id, method, normalized_path, idempotency_key) DO NOTHING`,
		command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Method, command.Path,
		command.IdempotencyKey, command.RequestDigest[:], command.WorkspaceID, command.OperationID,
		now, now.Add(idempotencyRetention))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

func loadIdempotentResult(
	ctx context.Context,
	tx pgx.Tx,
	command product.CreateWorkspaceCommand,
) (product.CreateWorkspaceResult, error) {
	var digest []byte
	var workspaceID string
	var actorType string
	var operation product.Operation
	err := tx.QueryRow(ctx, `SELECT i.request_digest, i.result_workspace_id,
       o.operation_id, o.operation_type, o.workspace_id, o.submitted_actor_type,
       o.submitted_actor_id, o.state, o.reconciliation_status, o.version, o.accepted_at, o.updated_at
FROM sandbox_runtime_product.idempotency_records AS i
JOIN sandbox_runtime_product.product_operations AS o
  ON o.tenant_id = i.tenant_id AND o.operation_id = i.result_operation_id
WHERE i.tenant_id = $1 AND i.actor_type = $2 AND i.actor_id = $3 AND i.method = $4
  AND i.normalized_path = $5 AND i.idempotency_key = $6`,
		command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Method, command.Path,
		command.IdempotencyKey).Scan(
		&digest, &workspaceID, &operation.ID, &operation.Type, &operation.WorkspaceID,
		&actorType, &operation.SubmittedBy.ID, &operation.State,
		&operation.ReconciliationStatus, &operation.Version, &operation.AcceptedAt, &operation.UpdatedAt,
	)
	if err != nil {
		return product.CreateWorkspaceResult{}, product.ErrStoreUnavailable
	}
	if len(digest) != len(command.RequestDigest) || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 ||
		workspaceID != operation.WorkspaceID {
		return product.CreateWorkspaceResult{}, product.ErrIdempotencyConflict
	}
	operation.SubmittedBy.Type = product.ActorType(actorType)
	return product.CreateWorkspaceResult{Operation: operation}, nil
}

func storeError(parent context.Context, operation context.Context, err error, commit bool) error {
	if parentErr := parent.Err(); parentErr != nil {
		return parentErr
	}
	if operationErr := operation.Err(); operationErr != nil {
		return errors.Join(product.ErrStoreUnavailable, operationErr)
	}
	if commit {
		return product.ErrStoreOutcomeUnknown
	}
	return fmt.Errorf("%w", product.ErrStoreUnavailable)
}
