package productpostgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) PutSlot(ctx context.Context, command product.SlotCommand) (product.Operation, bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return product.Operation{}, false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)

	now, inserted, err := reserveSlotMutation(opCtx, tx, command)
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if !inserted {
		operation, loadErr := loadSlotMutationOperation(opCtx, tx, command)
		if loadErr != nil {
			return product.Operation{}, false, loadErr
		}
		if err := tx.Rollback(opCtx); err != nil {
			return product.Operation{}, false, storeError(ctx, opCtx, err, false)
		}
		return operation, true, nil
	}

	var workspaceVersion int64
	var ownerType, ownerID, workspaceDesiredState string
	err = tx.QueryRow(opCtx, `SELECT version,owner_actor_type,owner_actor_id,desired_state
FROM sandbox_runtime_product.workspaces
WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE`, command.TenantID, command.WorkspaceID).Scan(
		&workspaceVersion, &ownerType, &ownerID, &workspaceDesiredState,
	)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.Operation{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if workspaceVersion != command.ExpectedWorkspaceVersion {
		return product.Operation{}, false, product.ErrVersionConflict
	}
	if workspaceDesiredState == "terminated" {
		return product.Operation{}, false, product.ErrControlStale
	}

	var currentKind, currentProfile, currentDesired, currentObserved string
	var currentCapabilities []byte
	var currentGeneration int64
	var currentBinding bool
	err = tx.QueryRow(opCtx, `SELECT kind,profile_id,required_capabilities,desired_state,observed_state,generation,
EXISTS(SELECT 1 FROM sandbox_runtime_product.provider_bindings b WHERE b.tenant_id=s.tenant_id AND b.workspace_id=s.workspace_id AND b.slot_key=s.slot_key AND b.current)
FROM sandbox_runtime_product.workspace_slots s
WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3 FOR UPDATE`, command.TenantID, command.WorkspaceID, command.SlotKey).Scan(
		&currentKind, &currentProfile, &currentCapabilities, &currentDesired, &currentObserved, &currentGeneration, &currentBinding,
	)
	newSlot := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !newSlot {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	encodedCapabilities, err := json.Marshal(command.Spec.RequiredCapabilities)
	if err != nil {
		return product.Operation{}, false, product.ErrInvalid
	}
	if !newSlot && (currentKind != command.Spec.Kind || currentProfile != command.Spec.ProfileID || !jsonBytesEqual(currentCapabilities, encodedCapabilities)) {
		return product.Operation{}, false, product.ErrVersionConflict
	}
	becomingActive := command.Spec.DesiredState != "terminated" && (newSlot || currentDesired == "terminated")
	if becomingActive {
		if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7346273421))`, command.TenantID); err != nil {
			return product.Operation{}, false, storeError(ctx, opCtx, err, false)
		}
		var count, limit int
		if err := tx.QueryRow(opCtx, `SELECT
    (SELECT count(*) FROM sandbox_runtime_product.workspace_slots WHERE tenant_id=$1 AND kind='browser' AND desired_state <> 'terminated'),
    COALESCE((SELECT max_browser_slots FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),4)`, command.TenantID).Scan(&count, &limit); err != nil {
			return product.Operation{}, false, storeError(ctx, opCtx, err, false)
		}
		if count >= limit {
			return product.Operation{}, false, product.ErrQuotaExceeded
		}
	}

	generation := currentGeneration + 1
	observedState := slotTransitionState(command.Spec.DesiredState)
	action := "provision"
	if !newSlot {
		switch command.Spec.DesiredState {
		case "suspended":
			action = "suspend"
		case "terminated":
			action = "terminate"
		case "ready":
			switch currentDesired {
			case "suspended":
				action = "resume"
			case "ready":
				if currentBinding {
					action = "replace"
				}
			}
		}
	}
	noop := newSlot && command.Spec.DesiredState != "ready"
	if noop {
		observedState = command.Spec.DesiredState
	}
	if newSlot {
		generation = 1
		if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_slots
    (tenant_id,workspace_id,slot_key,kind,profile_id,required_capabilities,desired_state,observed_state,
     generation,observed_generation,version,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,0,1,$9,$9)`, command.TenantID, command.WorkspaceID, command.SlotKey,
			command.Spec.Kind, command.Spec.ProfileID, encodedCapabilities, command.Spec.DesiredState, observedState, now); err != nil {
			return product.Operation{}, false, storeError(ctx, opCtx, err, false)
		}
	} else if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.workspace_slots
SET desired_state=$1,observed_state=$2,generation=generation+1,version=version+1,updated_at=$3
WHERE tenant_id=$4 AND workspace_id=$5 AND slot_key=$6`, command.Spec.DesiredState, observedState, now,
		command.TenantID, command.WorkspaceID, command.SlotKey); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}

	operationState, reconciliation := "accepted", "pending"
	if noop {
		operationState, reconciliation = "succeeded", "complete"
	}
	operation := product.Operation{ID: command.OperationID, Type: "put_slot", WorkspaceID: command.WorkspaceID,
		SlotKey: command.SlotKey, SubmittedBy: command.Actor, State: operationState, ReconciliationStatus: reconciliation,
		Version: 1, AcceptedAt: now, UpdatedAt: now}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.product_operations
    (tenant_id,operation_id,operation_type,workspace_id,slot_key,submitted_actor_type,submitted_actor_id,
     state,reconciliation_status,version,accepted_at,updated_at)
VALUES($1,$2,'put_slot',$3,$4,$5,$6,$7,$8,1,$9,$9)`, command.TenantID, command.OperationID,
		command.WorkspaceID, command.SlotKey, string(command.Actor.Type), command.Actor.ID, operationState, reconciliation, now); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, command.WorkspaceID, "", now)
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	attributes, _ := json.Marshal(map[string]any{"slot_key": command.SlotKey, "kind": command.Spec.Kind,
		"profile_id": command.Spec.ProfileID, "desired_state": command.Spec.DesiredState, "generation": generation, "action": action})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events
    (tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,
     actor_type,actor_id,occurred_at,attributes)
VALUES($1,$2,$3,$4,'slot.put_accepted','slot',$5,$6,$7,$8,$9,$10)`, command.TenantID, command.WorkspaceID,
		sequence, command.EventID, command.SlotKey, command.OperationID, string(command.Actor.Type), command.Actor.ID, now, attributes); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if !noop {
		payload, _ := json.Marshal(map[string]any{"workspace_id": command.WorkspaceID, "operation_id": command.OperationID,
			"slot_key": command.SlotKey, "generation": generation, "previous_generation": currentGeneration,
			"desired_state": command.Spec.DesiredState, "action": action})
		if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.outbox
    (tenant_id,outbox_id,workspace_id,operation_id,message_type,payload,state,attempt_count,available_at,created_at,updated_at)
VALUES($1,$2,$3,$4,'slot.reconcile',$5,'pending',0,$6,$6,$6)`, command.TenantID, command.OutboxID,
			command.WorkspaceID, command.OperationID, payload, now); err != nil {
			return product.Operation{}, false, storeError(ctx, opCtx, err, false)
		}
	}
	if err := insertAudit(opCtx, tx, "aud-"+command.OperationID, command.TenantID, command.Actor,
		"slot.put", "slot", command.WorkspaceID+":"+command.SlotKey, "allowed", "authorized", now); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, true)
	}
	return operation, false, nil
}

func (s *Store) GetSlot(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID, slotKey string) (product.WorkspaceSlot, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return product.WorkspaceSlot{}, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var slot product.WorkspaceSlot
	var capabilities []byte
	err := s.pool.QueryRow(opCtx, `SELECT s.slot_key,s.kind,s.profile_id,s.required_capabilities,s.desired_state,
       s.observed_state,s.generation,s.observed_generation,s.version,s.created_at,s.updated_at
FROM sandbox_runtime_product.workspace_slots s
JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=s.tenant_id AND w.workspace_id=s.workspace_id
WHERE s.tenant_id=$1 AND s.workspace_id=$2 AND s.slot_key=$3
  AND w.owner_actor_type=$4 AND w.owner_actor_id=$5`, tenantID, workspaceID, slotKey,
		string(actor.Type), actor.ID).Scan(&slot.SlotKey, &slot.Kind, &slot.ProfileID, &capabilities, &slot.DesiredState,
		&slot.ObservedState, &slot.Generation, &slot.ObservedGeneration, &slot.Version, &slot.CreatedAt, &slot.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.WorkspaceSlot{}, product.ErrNotFound
	}
	if err != nil {
		return product.WorkspaceSlot{}, storeError(ctx, opCtx, err, false)
	}
	if err := json.Unmarshal(capabilities, &slot.RequiredCapabilities); err != nil {
		return product.WorkspaceSlot{}, product.ErrStoreUnavailable
	}
	return slot, nil
}

func reserveSlotMutation(ctx context.Context, tx pgx.Tx, command product.SlotCommand) (time.Time, bool, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, false, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.mutation_idempotency
    (tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)
VALUES($1,$2,$3,'PUT',$4,$5,$6,'product_operation',$7,$8,$9) ON CONFLICT DO NOTHING`, command.TenantID,
		string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:],
		command.OperationID, now, now.Add(idempotencyRetention))
	return now, tag.RowsAffected() == 1, err
}

func loadSlotMutationOperation(ctx context.Context, tx pgx.Tx, command product.SlotCommand) (product.Operation, error) {
	var digest []byte
	var operation product.Operation
	var actorType string
	err := tx.QueryRow(ctx, `SELECT i.request_digest,o.operation_id,o.operation_type,o.workspace_id,
       COALESCE(o.slot_key,''),o.submitted_actor_type,o.submitted_actor_id,o.state,o.reconciliation_status,
       o.version,o.accepted_at,o.updated_at
FROM sandbox_runtime_product.mutation_idempotency i
JOIN sandbox_runtime_product.product_operations o ON o.tenant_id=i.tenant_id AND o.operation_id=i.result_id
WHERE i.tenant_id=$1 AND i.actor_type=$2 AND i.actor_id=$3 AND i.method='PUT'
  AND i.normalized_path=$4 AND i.idempotency_key=$5`, command.TenantID, string(command.Actor.Type), command.Actor.ID,
		command.Path, command.IdempotencyKey).Scan(&digest, &operation.ID, &operation.Type, &operation.WorkspaceID,
		&operation.SlotKey, &actorType, &operation.SubmittedBy.ID, &operation.State, &operation.ReconciliationStatus,
		&operation.Version, &operation.AcceptedAt, &operation.UpdatedAt)
	if err != nil {
		return product.Operation{}, product.ErrStoreUnavailable
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 {
		return product.Operation{}, product.ErrIdempotencyConflict
	}
	operation.SubmittedBy.Type = product.ActorType(actorType)
	return operation, nil
}

func jsonBytesEqual(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil && json.Unmarshal(right, &rightValue) == nil &&
		jsonDeepEqual(leftValue, rightValue)
}

func jsonDeepEqual(left, right any) bool {
	leftEncoded, leftErr := json.Marshal(left)
	rightEncoded, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftEncoded) == string(rightEncoded)
}

func slotTransitionState(desired string) string {
	switch desired {
	case "suspended":
		return "suspending"
	case "terminated":
		return "terminating"
	default:
		return "requested"
	}
}
