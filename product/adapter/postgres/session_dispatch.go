package productpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) LeaseSessionWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.SessionControlWork, error) {
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
	rows, err := tx.Query(opCtx, `WITH candidates AS(SELECT tenant_id,outbox_id FROM sandbox_runtime_product.outbox WHERE message_type IN('session.open','session.close') AND available_at<=clock_timestamp() AND(state='pending' OR(state='leased' AND lease_expires_at<=clock_timestamp()))ORDER BY created_at,outbox_id FOR UPDATE SKIP LOCKED LIMIT $1),leased AS(UPDATE sandbox_runtime_product.outbox o SET state='leased',lease_owner=$2,lease_expires_at=clock_timestamp()+$3::interval,attempt_count=o.attempt_count+1,updated_at=clock_timestamp() FROM candidates c WHERE o.tenant_id=c.tenant_id AND o.outbox_id=c.outbox_id RETURNING o.*)SELECT l.tenant_id,l.outbox_id,l.lease_owner,l.workspace_id,l.operation_id,l.message_type,l.payload,s.session_id,s.slot_key,s.slot_generation,s.expires_at,COALESCE(s.provider_connection_generation,0),b.runtime_profile_id,b.sandbox_id,b.provider_revision_id,s.kind,s.protocol_profile FROM leased l JOIN sandbox_runtime_product.runtime_sessions s ON s.tenant_id=l.tenant_id AND s.workspace_id=l.workspace_id AND s.session_id=l.payload->>'session_id' JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=s.tenant_id AND b.workspace_id=s.workspace_id AND b.slot_key=s.slot_key AND b.slot_generation=s.slot_generation AND b.current ORDER BY l.outbox_id`, limit, workerID, lease.String())
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.SessionControlWork
	for rows.Next() {
		var item product.SessionControlWork
		var messageType string
		var payload []byte
		if err := rows.Scan(&item.TenantID, &item.OutboxID, &item.LeaseOwner, &item.WorkspaceID, &item.OperationID, &messageType, &payload, &item.SessionID, &item.SlotKey, &item.SlotGeneration, &item.ExpiresAt, &item.ConnectionGeneration, &item.RuntimeProfileID, &item.SandboxID, &item.ProviderRevisionID, &item.Kind, &item.ProtocolProfile); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		item.AttemptID = item.OutboxID
		if messageType == "session.open" {
			item.Action = "open"
		} else {
			item.Action = "close"
			var values struct {
				Reason string `json:"reason"`
			}
			_ = json.Unmarshal(payload, &values)
			item.Reason = values.Reason
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

func (s *Store) LeaseBrowserSessionWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.SessionControlWork, error) {
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
 SELECT o.tenant_id,o.outbox_id
 FROM sandbox_runtime_product.outbox o
 JOIN sandbox_runtime_product.runtime_sessions s ON s.tenant_id=o.tenant_id AND s.session_id=o.payload->>'session_id'
 WHERE o.message_type='browser_session.open' AND s.kind IN ('browser_automation','browser_live')
   AND o.available_at<=clock_timestamp()
   AND (o.state='pending' OR (o.state='leased' AND o.lease_expires_at<=clock_timestamp()))
 ORDER BY o.created_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT $1
), leased AS (
 UPDATE sandbox_runtime_product.outbox o
 SET state='leased',lease_owner=$2,lease_expires_at=clock_timestamp()+$3::interval,
     attempt_count=o.attempt_count+1,updated_at=clock_timestamp()
 FROM candidates c WHERE o.tenant_id=c.tenant_id AND o.outbox_id=c.outbox_id RETURNING o.*
)
SELECT l.tenant_id,l.outbox_id,l.lease_owner,l.workspace_id,l.operation_id,l.payload,
       s.session_id,s.slot_key,s.slot_generation,s.expires_at,COALESCE(s.provider_connection_generation,0),
       b.runtime_profile_id,b.sandbox_id,b.provider_revision_id,s.kind,s.protocol_profile
FROM leased l
JOIN sandbox_runtime_product.runtime_sessions s ON s.tenant_id=l.tenant_id AND s.session_id=l.payload->>'session_id'
JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=s.tenant_id AND b.workspace_id=s.workspace_id
 AND b.slot_key=s.slot_key AND b.slot_generation=s.slot_generation AND b.current
ORDER BY l.outbox_id`, limit, workerID, lease.String())
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.SessionControlWork
	for rows.Next() {
		var item product.SessionControlWork
		var payload []byte
		if err := rows.Scan(&item.TenantID, &item.OutboxID, &item.LeaseOwner, &item.WorkspaceID, &item.OperationID, &payload,
			&item.SessionID, &item.SlotKey, &item.SlotGeneration, &item.ExpiresAt, &item.ConnectionGeneration,
			&item.RuntimeProfileID, &item.SandboxID, &item.ProviderRevisionID, &item.Kind, &item.ProtocolProfile); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		item.AttemptID = item.OutboxID
		item.Action = "open"
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

func (s *Store) RecordSessionDispatch(ctx context.Context, work product.SessionControlWork, evidence product.ProviderOperationEvidence) error {
	if s == nil || s.pool == nil || ctx == nil {
		return product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT clock_timestamp() FROM sandbox_runtime_product.outbox WHERE tenant_id=$1 AND outbox_id=$2 AND state='leased' AND lease_owner=$3 AND lease_expires_at>clock_timestamp() FOR UPDATE`, work.TenantID, work.OutboxID, work.LeaseOwner).Scan(&now)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.ErrLeaseLost
	}
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	state := evidence.State
	if state == "" {
		state = "failed"
	}
	if work.Action == "open" && state == "succeeded" {
		state = "running"
	}
	outcome := "pending"
	if state == "outcome_unknown" {
		outcome = "unknown"
	} else if state == "succeeded" || state == "failed" || state == "cancelled" {
		outcome = "known"
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.product_operation_attempts(tenant_id,operation_id,attempt_id,workspace_id,slot_key,session_id,slot_generation,fencing_token,idempotency_key,request_digest,provider_revision_id,provider_operation_id,state,outcome,error_code,deadline_at,dispatched_at,observed_at,created_at,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8,$9,$10,NULLIF($11,''),$12,$13,NULLIF($14,''),$15,$16,$17,$16,$16)ON CONFLICT(tenant_id,operation_id,attempt_id)DO UPDATE SET provider_operation_id=EXCLUDED.provider_operation_id,state=EXCLUDED.state,outcome=EXCLUDED.outcome,error_code=EXCLUDED.error_code,observed_at=EXCLUDED.observed_at,updated_at=EXCLUDED.updated_at`, work.TenantID, work.OperationID, work.AttemptID, work.WorkspaceID, work.SlotKey, work.SessionID, work.SlotGeneration, "product-"+work.AttemptID, nullable(evidence.RequestDigest), evidence.ProviderRevisionID, evidence.ProviderOperationID, state, outcome, evidence.ErrorCode, work.ExpiresAt, now, nullableTime(evidence.ObservedAt)); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	opState, reconciliation, sessionState := "running", "reconciling", "provisioning"
	if work.Action == "close" {
		sessionState = "draining"
	}
	if state == "outcome_unknown" {
		opState = "outcome_unknown"
	}
	if state == "succeeded" {
		opState, reconciliation = "succeeded", "complete"
		if work.Action == "open" {
			sessionState = "ready"
		} else {
			sessionState = "closed"
		}
	} else if state == "failed" || state == "cancelled" {
		opState, reconciliation, sessionState = "failed", "complete", "failed"
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.product_operations SET state=$1,reconciliation_status=$2,version=version+1,updated_at=$3 WHERE tenant_id=$4 AND operation_id=$5`, opState, reconciliation, now, work.TenantID, work.OperationID); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.runtime_sessions SET state=$1,version=version+1,provider_runtime_session_id=$2,updated_at=$3 WHERE tenant_id=$4 AND session_id=$5`, sessionState, work.SessionID, now, work.TenantID, work.SessionID); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.outbox SET state='delivered',lease_owner=NULL,lease_expires_at=NULL,last_error_code=NULL,updated_at=$1 WHERE tenant_id=$2 AND outbox_id=$3`, now, work.TenantID, work.OutboxID); err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return storeError(ctx, opCtx, err, true)
	}
	return nil
}
func (s *Store) RetrySessionWork(ctx context.Context, work product.SessionControlWork, code string, retry time.Duration, maxAttempts int) error {
	return s.RetryReconcileWork(ctx, product.ReconcileWork{TenantID: work.TenantID, OutboxID: work.OutboxID, LeaseOwner: work.LeaseOwner, WorkspaceID: work.WorkspaceID, OperationID: work.OperationID, AttemptID: work.AttemptID, SlotKey: work.SlotKey, SlotGeneration: work.SlotGeneration}, code, retry, maxAttempts)
}
