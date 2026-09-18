package productpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) LeaseProviderObservations(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.ProviderObservationWork, error) {
	if s == nil || s.pool == nil || ctx == nil || workerID == "" || lease < time.Second || lease > time.Minute || limit < 1 || limit > 100 {
		return nil, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	rows, err := tx.Query(opCtx, `WITH candidates AS (
 SELECT a.tenant_id,a.operation_id,a.attempt_id
 FROM sandbox_runtime_product.product_operation_attempts AS a
 WHERE a.state IN ('dispatched','accepted','running','outcome_unknown')
   AND a.updated_at <= clock_timestamp()
   AND (a.reconcile_lease_owner IS NULL OR a.reconcile_lease_expires_at <= clock_timestamp())
 ORDER BY a.updated_at,a.operation_id,a.attempt_id FOR UPDATE SKIP LOCKED LIMIT $1
), leased AS (
 UPDATE sandbox_runtime_product.product_operation_attempts AS a
 SET reconcile_lease_owner=$2,reconcile_lease_expires_at=clock_timestamp()+$3::interval,updated_at=clock_timestamp()
 FROM candidates AS c
 WHERE a.tenant_id=c.tenant_id AND a.operation_id=c.operation_id AND a.attempt_id=c.attempt_id
 RETURNING a.*
)
SELECT l.tenant_id,l.workspace_id,l.operation_id,l.attempt_id,l.slot_key,l.slot_generation,
       b.runtime_profile_id,b.sandbox_id,COALESCE(l.provider_operation_id,''),l.provider_revision_id,l.reconcile_lease_owner
FROM leased AS l JOIN sandbox_runtime_product.provider_bindings AS b
 ON b.tenant_id=l.tenant_id AND b.workspace_id=l.workspace_id AND b.slot_key=l.slot_key
 AND b.slot_generation=l.slot_generation AND b.current
ORDER BY l.operation_id,l.attempt_id`, limit, workerID, lease.String())
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.ProviderObservationWork
	for rows.Next() {
		var item product.ProviderObservationWork
		if err := rows.Scan(&item.TenantID, &item.WorkspaceID, &item.OperationID, &item.AttemptID, &item.SlotKey, &item.SlotGeneration,
			&item.RuntimeProfileID, &item.SandboxID, &item.ProviderOperationID, &item.ProviderRevisionID, &item.LeaseOwner); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return nil, storeError(ctx, opCtx, err, true)
	}
	return result, nil
}

func (s *Store) RecordProviderObservation(ctx context.Context, work product.ProviderObservationWork, evidence product.ProviderOperationEvidence, eventID string) error {
	if s == nil || s.pool == nil || ctx == nil || eventID == "" {
		return product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var currentAttemptState string
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT state,clock_timestamp() FROM sandbox_runtime_product.product_operation_attempts
WHERE tenant_id=$1 AND operation_id=$2 AND attempt_id=$3 AND reconcile_lease_owner=$4
 AND reconcile_lease_expires_at>clock_timestamp() FOR UPDATE`, work.TenantID, work.OperationID, work.AttemptID, work.LeaseOwner).Scan(&currentAttemptState, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.ErrLeaseLost
	}
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if evidence.ProviderRevisionID != work.ProviderRevisionID || evidence.SandboxID != work.SandboxID ||
		(evidence.ProviderOperationID != "" && work.ProviderOperationID != "" && evidence.ProviderOperationID != work.ProviderOperationID) {
		return product.ErrStoreUnavailable
	}
	state := evidence.State
	switch state {
	case "accepted", "running", "succeeded", "failed", "cancelled", "outcome_unknown":
	default:
		return product.ErrStoreUnavailable
	}
	outcome := "pending"
	if state == "outcome_unknown" {
		outcome = "unknown"
	} else if state == "succeeded" || state == "failed" || state == "cancelled" {
		outcome = "known"
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.product_operation_attempts
SET state=$1,outcome=$2,error_code=NULLIF($3,''),observed_at=$4,reconcile_lease_owner=NULL,
reconcile_lease_expires_at=NULL,updated_at=$5 WHERE tenant_id=$6 AND operation_id=$7 AND attempt_id=$8`, state, outcome, evidence.ErrorCode, evidence.ObservedAt, now, work.TenantID, work.OperationID, work.AttemptID); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.provider_bindings SET observed_state=$1,last_observed_at=$2,updated_at=$3
WHERE tenant_id=$4 AND workspace_id=$5 AND slot_key=$6 AND slot_generation=$7 AND current`, providerBindingState(state), evidence.ObservedAt, now, work.TenantID, work.WorkspaceID, work.SlotKey, work.SlotGeneration); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if state == "accepted" || state == "running" || state == "outcome_unknown" {
		productState := "running"
		if state == "outcome_unknown" {
			productState = "outcome_unknown"
		}
		_, err = tx.Exec(opCtx, `UPDATE sandbox_runtime_product.product_operations SET state=$1,reconciliation_status='reconciling',
version=version+1,updated_at=$2 WHERE tenant_id=$3 AND operation_id=$4 AND state NOT IN ('succeeded','failed','cancelled')`, productState, now, work.TenantID, work.OperationID)
		if err != nil {
			return storeError(ctx, opCtx, err, false)
		}
		if err := tx.Commit(opCtx); err != nil {
			return storeError(ctx, opCtx, err, true)
		}
		return nil
	}
	var operationState string
	if err := tx.QueryRow(opCtx, `SELECT state FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1 AND operation_id=$2 FOR UPDATE`, work.TenantID, work.OperationID).Scan(&operationState); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if operationState == "succeeded" || operationState == "failed" || operationState == "cancelled" {
		if err := tx.Commit(opCtx); err != nil {
			return storeError(ctx, opCtx, err, true)
		}
		return nil
	}
	productState, slotState, workspaceState, eventType := "succeeded", "ready", "active", "slot.ready"
	if state != "succeeded" {
		productState, slotState, workspaceState, eventType = "failed", "failed", "failed", "slot.failed"
	}
	tag, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.workspace_slots SET observed_state=$1,observed_generation=$2,
version=version+1,updated_at=$3 WHERE tenant_id=$4 AND workspace_id=$5 AND slot_key=$6 AND generation=$2`, slotState, work.SlotGeneration, now, work.TenantID, work.WorkspaceID, work.SlotKey)
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() == 0 {
		if err := tx.Commit(opCtx); err != nil {
			return storeError(ctx, opCtx, err, true)
		}
		return nil
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.product_operations SET state=$1,reconciliation_status='complete',version=version+1,updated_at=$2
WHERE tenant_id=$3 AND operation_id=$4`, productState, now, work.TenantID, work.OperationID); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, work.TenantID, work.WorkspaceID, workspaceState, now)
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	attributes, _ := json.Marshal(map[string]any{"slot_key": work.SlotKey, "generation": work.SlotGeneration, "provider_outcome": state})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events
(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes)
VALUES($1,$2,$3,$4,$5,'slot',$6,$7,'service','product-reconciler',$8,$9)`, work.TenantID, work.WorkspaceID, sequence, eventID, eventType, work.SlotKey, work.OperationID, now, attributes); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return storeError(ctx, opCtx, err, true)
	}
	return nil
}

func (s *Store) RetryProviderObservation(ctx context.Context, work product.ProviderObservationWork, retry time.Duration) error {
	if s == nil || s.pool == nil || ctx == nil || retry < time.Millisecond {
		return product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tag, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.product_operation_attempts
SET reconcile_lease_owner=NULL,reconcile_lease_expires_at=NULL,updated_at=clock_timestamp()+$1::interval
WHERE tenant_id=$2 AND operation_id=$3 AND attempt_id=$4 AND reconcile_lease_owner=$5 AND reconcile_lease_expires_at>clock_timestamp()`, retry.String(), work.TenantID, work.OperationID, work.AttemptID, work.LeaseOwner)
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() != 1 {
		return product.ErrLeaseLost
	}
	return nil
}
