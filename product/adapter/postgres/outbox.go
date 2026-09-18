package productpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) LeaseReconcileWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.ReconcileWork, error) {
	if s == nil || s.pool == nil || ctx == nil || workerID == "" || lease < time.Second || lease > time.Minute || limit < 1 || limit > 100 {
		return nil, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	rows, err := tx.Query(opCtx, `WITH candidates AS (
    SELECT tenant_id, outbox_id
    FROM sandbox_runtime_product.outbox
    WHERE message_type = 'workspace.reconcile'
      AND available_at <= clock_timestamp()
      AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= clock_timestamp()))
    ORDER BY created_at, outbox_id
    FOR UPDATE SKIP LOCKED
    LIMIT $1
), leased AS (
    UPDATE sandbox_runtime_product.outbox AS o
    SET state = 'leased', lease_owner = $2, lease_expires_at = clock_timestamp() + $3::interval,
        attempt_count = o.attempt_count + 1, updated_at = clock_timestamp()
    FROM candidates AS c
    WHERE o.tenant_id = c.tenant_id AND o.outbox_id = c.outbox_id
    RETURNING o.tenant_id, o.outbox_id, o.workspace_id, o.operation_id, o.lease_owner
)
SELECT l.tenant_id, l.outbox_id, l.workspace_id, l.operation_id, l.lease_owner,
       s.slot_key, s.kind, s.profile_id, s.required_capabilities, s.desired_state,
       s.generation, w.lease_expires_at
FROM leased AS l
JOIN sandbox_runtime_product.workspaces AS w
  ON w.tenant_id = l.tenant_id AND w.workspace_id = l.workspace_id
JOIN sandbox_runtime_product.workspace_slots AS s
  ON s.tenant_id = l.tenant_id AND s.workspace_id = l.workspace_id AND s.slot_key = 'primary-code'
ORDER BY l.outbox_id`, limit, workerID, lease.String())
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.ReconcileWork
	for rows.Next() {
		var item product.ReconcileWork
		var capabilities []byte
		if err := rows.Scan(&item.TenantID, &item.OutboxID, &item.WorkspaceID, &item.OperationID, &item.LeaseOwner,
			&item.Slot.SlotKey, &item.Slot.Kind, &item.Slot.ProfileID, &capabilities, &item.Slot.DesiredState,
			&item.SlotGeneration, &item.WorkspaceExpiry); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		if err := json.Unmarshal(capabilities, &item.Slot.RequiredCapabilities); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		item.SlotKey = item.Slot.SlotKey
		item.AttemptID = item.OutboxID
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

func (s *Store) LeaseBrowserSlotWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.ReconcileWork, error) {
	if s == nil || s.pool == nil || ctx == nil || workerID == "" || lease < time.Second || lease > time.Minute || limit < 1 || limit > 100 {
		return nil, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	rows, err := tx.Query(opCtx, `WITH candidates AS (
    SELECT o.tenant_id,o.outbox_id
    FROM sandbox_runtime_product.outbox o
    JOIN sandbox_runtime_product.workspace_slots s
      ON s.tenant_id=o.tenant_id AND s.workspace_id=o.workspace_id AND s.slot_key=o.payload->>'slot_key'
    WHERE o.message_type='slot.reconcile' AND s.kind='browser' AND s.desired_state='ready'
      AND COALESCE(o.payload->>'action','provision')='provision'
      AND s.generation=(o.payload->>'generation')::bigint
      AND o.available_at<=clock_timestamp()
      AND (o.state='pending' OR (o.state='leased' AND o.lease_expires_at<=clock_timestamp()))
    ORDER BY o.created_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT $1
), leased AS (
    UPDATE sandbox_runtime_product.outbox o
    SET state='leased',lease_owner=$2,lease_expires_at=clock_timestamp()+$3::interval,
        attempt_count=o.attempt_count+1,updated_at=clock_timestamp()
    FROM candidates c WHERE o.tenant_id=c.tenant_id AND o.outbox_id=c.outbox_id
    RETURNING o.tenant_id,o.outbox_id,o.workspace_id,o.operation_id,o.lease_owner,o.payload
)
SELECT l.tenant_id,l.outbox_id,l.workspace_id,l.operation_id,l.lease_owner,
       s.slot_key,s.kind,s.profile_id,s.required_capabilities,s.desired_state,s.generation,w.lease_expires_at,
       COALESCE((l.payload->>'previous_generation')::bigint,0),COALESCE(l.payload->>'action','provision')
FROM leased l
JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=l.tenant_id AND w.workspace_id=l.workspace_id
JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=l.tenant_id AND s.workspace_id=l.workspace_id
 AND s.slot_key=l.payload->>'slot_key' AND s.generation=(l.payload->>'generation')::bigint
ORDER BY l.outbox_id`, limit, workerID, lease.String())
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.ReconcileWork
	for rows.Next() {
		var item product.ReconcileWork
		var capabilities []byte
		if err := rows.Scan(&item.TenantID, &item.OutboxID, &item.WorkspaceID, &item.OperationID, &item.LeaseOwner,
			&item.Slot.SlotKey, &item.Slot.Kind, &item.Slot.ProfileID, &capabilities, &item.Slot.DesiredState,
			&item.SlotGeneration, &item.WorkspaceExpiry, &item.PreviousGeneration, &item.Action); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		if err := json.Unmarshal(capabilities, &item.Slot.RequiredCapabilities); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		item.SlotKey = item.Slot.SlotKey
		item.AttemptID = item.OutboxID
		item.FencingToken = item.SlotGeneration
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

func (s *Store) LeaseBrowserLifecycleWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.ReconcileWork, error) {
	if s == nil || s.pool == nil || ctx == nil || workerID == "" || lease < time.Second || lease > time.Minute || limit < 1 || limit > 100 {
		return nil, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	rows, err := tx.Query(opCtx, `WITH candidates AS (
 SELECT o.tenant_id,o.outbox_id
 FROM sandbox_runtime_product.outbox o
 JOIN sandbox_runtime_product.workspace_slots s
   ON s.tenant_id=o.tenant_id AND s.workspace_id=o.workspace_id AND s.slot_key=o.payload->>'slot_key'
 JOIN sandbox_runtime_product.provider_bindings b
   ON b.tenant_id=s.tenant_id AND b.workspace_id=s.workspace_id AND b.slot_key=s.slot_key AND b.current
 WHERE o.message_type='slot.reconcile' AND s.kind='browser'
   AND o.payload->>'action' IN ('suspend','resume','terminate','replace')
   AND s.generation=(o.payload->>'generation')::bigint
   AND b.slot_generation=(o.payload->>'previous_generation')::bigint
   AND o.available_at<=clock_timestamp()
   AND (o.state='pending' OR (o.state='leased' AND o.lease_expires_at<=clock_timestamp()))
 ORDER BY o.created_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT $1
), leased AS (
 UPDATE sandbox_runtime_product.outbox o
 SET state='leased',lease_owner=$2,lease_expires_at=clock_timestamp()+$3::interval,
     attempt_count=o.attempt_count+1,updated_at=clock_timestamp()
 FROM candidates c WHERE o.tenant_id=c.tenant_id AND o.outbox_id=c.outbox_id
 RETURNING o.tenant_id,o.outbox_id,o.workspace_id,o.operation_id,o.lease_owner,o.payload
)
SELECT l.tenant_id,l.outbox_id,l.workspace_id,l.operation_id,l.lease_owner,
       s.slot_key,s.kind,s.profile_id,s.required_capabilities,s.desired_state,s.generation,w.lease_expires_at,
       (l.payload->>'previous_generation')::bigint,l.payload->>'action',b.provider_revision_id,b.sandbox_id,b.provider_generation
FROM leased l
JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=l.tenant_id AND w.workspace_id=l.workspace_id
JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=l.tenant_id AND s.workspace_id=l.workspace_id
 AND s.slot_key=l.payload->>'slot_key' AND s.generation=(l.payload->>'generation')::bigint
JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=s.tenant_id AND b.workspace_id=s.workspace_id
 AND b.slot_key=s.slot_key AND b.slot_generation=(l.payload->>'previous_generation')::bigint AND b.current
ORDER BY l.outbox_id`, limit, workerID, lease.String())
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.ReconcileWork
	for rows.Next() {
		var item product.ReconcileWork
		var capabilities []byte
		if err := rows.Scan(&item.TenantID, &item.OutboxID, &item.WorkspaceID, &item.OperationID, &item.LeaseOwner,
			&item.Slot.SlotKey, &item.Slot.Kind, &item.Slot.ProfileID, &capabilities, &item.Slot.DesiredState,
			&item.SlotGeneration, &item.WorkspaceExpiry, &item.PreviousGeneration, &item.Action,
			&item.ProviderRevisionID, &item.SandboxID, &item.ProviderGeneration); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		if err := json.Unmarshal(capabilities, &item.Slot.RequiredCapabilities); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		item.SlotKey, item.AttemptID, item.FencingToken = item.Slot.SlotKey, item.OutboxID, item.SlotGeneration
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

func (s *Store) RecordDispatchEvidence(ctx context.Context, work product.ReconcileWork, evidence product.ProviderOperationEvidence) error {
	if s == nil || s.pool == nil || ctx == nil {
		return product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var attemptCount int
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT attempt_count, clock_timestamp()
FROM sandbox_runtime_product.outbox
WHERE tenant_id=$1 AND outbox_id=$2 AND state='leased' AND lease_owner=$3 AND lease_expires_at > clock_timestamp()
FOR UPDATE`, work.TenantID, work.OutboxID, work.LeaseOwner).Scan(&attemptCount, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.ErrLeaseLost
	}
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	attemptState, outcome := evidence.State, "pending"
	providerAction := reconcileProviderAction(work)
	fencingToken := work.FencingToken
	if fencingToken < 1 {
		fencingToken = work.SlotGeneration
	}
	if attemptState == "" {
		attemptState = "failed"
	}
	switch attemptState {
	case "succeeded", "failed", "cancelled":
		outcome = "known"
	case "outcome_unknown":
		outcome = "unknown"
	case "accepted", "running":
	default:
		attemptState = "failed"
		outcome = "known"
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.product_operation_attempts
    (tenant_id, operation_id, attempt_id, workspace_id, slot_key, slot_generation, fencing_token,
     idempotency_key, request_digest, provider_revision_id, provider_operation_id, state, outcome,
     error_code, deadline_at, dispatched_at, observed_at, created_at, updated_at,provider_action)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),$12,$13,NULLIF($14,''),$15,$16,$17,$16,$16,$18)
ON CONFLICT (tenant_id, operation_id, attempt_id) DO UPDATE
SET request_digest=EXCLUDED.request_digest, provider_revision_id=EXCLUDED.provider_revision_id,
    provider_operation_id=EXCLUDED.provider_operation_id, state=EXCLUDED.state, outcome=EXCLUDED.outcome,
    error_code=EXCLUDED.error_code, observed_at=EXCLUDED.observed_at, updated_at=EXCLUDED.updated_at,
    provider_action=EXCLUDED.provider_action`,
		work.TenantID, work.OperationID, work.AttemptID, work.WorkspaceID, work.SlotKey, work.SlotGeneration, fencingToken,
		"product-"+work.AttemptID, nullable(evidence.RequestDigest), nullable(evidence.ProviderRevisionID), evidence.ProviderOperationID,
		attemptState, outcome, evidence.ErrorCode, work.WorkspaceExpiry, now, evidence.ObservedAt, providerAction); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if providerAction == "create" && evidence.SandboxID != "" && evidence.ProviderRevisionID != "" {
		if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.provider_bindings SET current=false,updated_at=$1
WHERE tenant_id=$2 AND workspace_id=$3 AND slot_key=$4 AND current`, now, work.TenantID, work.WorkspaceID, work.SlotKey); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
		if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.provider_bindings
    (tenant_id,workspace_id,slot_key,slot_generation,binding_generation,provider_revision_id,
     runtime_profile_id,sandbox_id,create_operation_id,create_attempt_id,provider_operation_id,
     observed_state,current,last_observed_at,created_at,updated_at,provider_generation)
VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$8,$9,NULLIF($10,''),$11,true,$12,$13,$13,1)
ON CONFLICT (tenant_id,workspace_id,slot_key,binding_generation) DO UPDATE
SET provider_operation_id=EXCLUDED.provider_operation_id, observed_state=EXCLUDED.observed_state,
    last_observed_at=EXCLUDED.last_observed_at, updated_at=EXCLUDED.updated_at`, work.TenantID, work.WorkspaceID,
			work.SlotKey, work.SlotGeneration, evidence.ProviderRevisionID, work.Slot.ProfileID, evidence.SandboxID,
			work.OperationID, work.AttemptID, evidence.ProviderOperationID, providerBindingState(attemptState), nullableTime(evidence.ObservedAt), now); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
	} else if providerAction != "create" && evidence.SandboxID != "" {
		bindingState := lifecycleBindingState(work.Action, attemptState)
		if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.provider_bindings
SET provider_operation_id=NULLIF($1,''),observed_state=$2,last_observed_at=$3,updated_at=$4
WHERE tenant_id=$5 AND workspace_id=$6 AND slot_key=$7 AND slot_generation=$8 AND current`,
			evidence.ProviderOperationID, bindingState, nullableTime(evidence.ObservedAt), now, work.TenantID, work.WorkspaceID,
			work.SlotKey, work.PreviousGeneration); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
	}
	productState, reconciliation, slotState, workspaceState, eventType := "running", "reconciling", "provisioning", "provisioning", "slot.dispatch_accepted"
	switch work.Action {
	case "suspend":
		slotState, eventType = "suspending", "slot.suspend_dispatch_accepted"
	case "resume":
		slotState, eventType = "provisioning", "slot.resume_dispatch_accepted"
	case "terminate", "replace":
		slotState, eventType = "terminating", "slot.terminate_dispatch_accepted"
	}
	if work.SlotKey != product.PrimarySlotKey {
		workspaceState = ""
	}
	if attemptState == "outcome_unknown" {
		productState, reconciliation, eventType = "outcome_unknown", "reconciling", "slot.dispatch_outcome_unknown"
	} else if attemptState == "failed" || attemptState == "cancelled" {
		productState, reconciliation, slotState, workspaceState, eventType = "failed", "complete", "failed", "failed", "slot.dispatch_failed"
		if work.SlotKey != product.PrimarySlotKey {
			workspaceState = ""
		}
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.product_operations
SET state=$1,reconciliation_status=$2,version=version+1,updated_at=$3
WHERE tenant_id=$4 AND operation_id=$5`, productState, reconciliation, now, work.TenantID, work.OperationID); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.workspace_slots
SET observed_state=$1,version=version+1,updated_at=$2
WHERE tenant_id=$3 AND workspace_id=$4 AND slot_key=$5 AND generation=$6`, slotState, now,
		work.TenantID, work.WorkspaceID, work.SlotKey, work.SlotGeneration); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, work.TenantID, work.WorkspaceID, workspaceState, now)
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	attributes, _ := json.Marshal(map[string]any{"slot_key": work.SlotKey, "generation": work.SlotGeneration, "outcome": outcome})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events
    (tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,
     actor_type,actor_id,occurred_at,attributes)
VALUES ($1,$2,$3,$4,$5,'slot',$6,$7,'service','product-reconciler',$8,$9)`, work.TenantID, work.WorkspaceID,
		sequence, fmt.Sprintf("evt-%s-%d", work.OutboxID, sequence), eventType, work.SlotKey, work.OperationID, now, attributes); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.outbox
SET state='delivered',lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,updated_at=$1
WHERE tenant_id=$2 AND outbox_id=$3`, now, work.TenantID, work.OutboxID); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return storeError(ctx, opCtx, err, true)
	}
	return nil
}

func reconcileProviderAction(work product.ReconcileWork) string {
	switch work.Action {
	case "suspend":
		return "suspend"
	case "resume":
		return "resume"
	case "terminate", "replace":
		return "terminate"
	default:
		return "create"
	}
}

func lifecycleBindingState(action, state string) string {
	if state == "failed" || state == "cancelled" {
		return "failed"
	}
	switch action {
	case "suspend":
		return "suspending"
	case "resume":
		return "resuming"
	case "terminate", "replace":
		return "terminating"
	default:
		return providerBindingState(state)
	}
}

func (s *Store) RetryReconcileWork(ctx context.Context, work product.ReconcileWork, errorCode string, retryBase time.Duration, maxAttempts int) error {
	if s == nil || s.pool == nil || ctx == nil || retryBase < time.Millisecond || maxAttempts < 1 {
		return product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var attempts int
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT attempt_count,clock_timestamp() FROM sandbox_runtime_product.outbox
WHERE tenant_id=$1 AND outbox_id=$2 AND state='leased' AND lease_owner=$3 AND lease_expires_at > clock_timestamp()
FOR UPDATE`, work.TenantID, work.OutboxID, work.LeaseOwner).Scan(&attempts, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.ErrLeaseLost
	}
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if attempts >= maxAttempts {
		if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.outbox SET state='dead_letter',lease_owner=NULL,
lease_expires_at=NULL,last_error_code=$1,updated_at=$2 WHERE tenant_id=$3 AND outbox_id=$4`, errorCode, now, work.TenantID, work.OutboxID); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
		if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.product_operations SET state='failed',
reconciliation_status='manual_review',version=version+1,updated_at=$1 WHERE tenant_id=$2 AND operation_id=$3`, now, work.TenantID, work.OperationID); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
	} else {
		delay := retryBase
		for index := 1; index < attempts && delay < time.Minute/2; index++ {
			delay *= 2
		}
		if delay > time.Minute {
			delay = time.Minute
		}
		if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.outbox SET state='pending',lease_owner=NULL,
lease_expires_at=NULL,last_error_code=$1,available_at=$2,updated_at=$3 WHERE tenant_id=$4 AND outbox_id=$5`,
			errorCode, now.Add(delay), now, work.TenantID, work.OutboxID); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
	}
	if err := tx.Commit(opCtx); err != nil {
		return storeError(ctx, opCtx, err, true)
	}
	return nil
}

func lockWorkspaceAndAdvance(ctx context.Context, tx pgx.Tx, tenantID, workspaceID, observedState string, now time.Time) (int64, error) {
	var sequence int64
	if err := tx.QueryRow(ctx, `SELECT next_event_sequence FROM sandbox_runtime_product.workspaces
WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE`, tenantID, workspaceID).Scan(&sequence); err != nil {
		return 0, err
	}
	var err error
	if observedState == "" {
		_, err = tx.Exec(ctx, `UPDATE sandbox_runtime_product.workspaces SET version=version+1,
next_event_sequence=next_event_sequence+1,updated_at=$1 WHERE tenant_id=$2 AND workspace_id=$3`, now, tenantID, workspaceID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE sandbox_runtime_product.workspaces SET observed_state=$1,version=version+1,
next_event_sequence=next_event_sequence+1,updated_at=$2 WHERE tenant_id=$3 AND workspace_id=$4`, observedState, now, tenantID, workspaceID)
	}
	return sequence, err
}

func providerBindingState(state string) string {
	switch state {
	case "succeeded":
		return "ready"
	case "failed", "cancelled":
		return "failed"
	default:
		return "provisioning"
	}
}
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
