package productpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) LeaseDesktopSlotWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.ReconcileWork, error) {
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
 WHERE o.message_type='slot.reconcile' AND s.kind='desktop' AND s.desired_state='ready'
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

func (s *Store) LeaseDesktopLifecycleWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.ReconcileWork, error) {
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
 WHERE o.message_type='slot.reconcile' AND s.kind='desktop'
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

func (s *Store) LeaseDesktopSessionWork(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.SessionControlWork, error) {
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
 WHERE o.message_type IN ('desktop_session.open','desktop_session.close') AND s.kind='desktop'
   AND ((o.message_type='desktop_session.open' AND s.state='requested')
        OR (o.message_type='desktop_session.close' AND s.state='draining'
            AND COALESCE(s.provider_connection_generation,0)>0))
   AND o.available_at<=clock_timestamp()
   AND (o.state='pending' OR (o.state='leased' AND o.lease_expires_at<=clock_timestamp()))
 ORDER BY o.created_at,o.outbox_id FOR UPDATE OF o SKIP LOCKED LIMIT $1
), leased AS (
 UPDATE sandbox_runtime_product.outbox o
 SET state='leased',lease_owner=$2,lease_expires_at=clock_timestamp()+$3::interval,
     attempt_count=o.attempt_count+1,updated_at=clock_timestamp()
 FROM candidates c WHERE o.tenant_id=c.tenant_id AND o.outbox_id=c.outbox_id RETURNING o.*
)
SELECT l.tenant_id,l.outbox_id,l.lease_owner,l.workspace_id,l.operation_id,l.message_type,l.payload,
       s.session_id,s.slot_key,s.slot_generation,s.expires_at,COALESCE(s.provider_connection_generation,0),
       b.runtime_profile_id,b.sandbox_id,b.provider_revision_id,b.provider_generation,s.kind,s.protocol_profile
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
		var messageType string
		var payload []byte
		if err := rows.Scan(&item.TenantID, &item.OutboxID, &item.LeaseOwner, &item.WorkspaceID, &item.OperationID, &messageType, &payload,
			&item.SessionID, &item.SlotKey, &item.SlotGeneration, &item.ExpiresAt, &item.ConnectionGeneration,
			&item.RuntimeProfileID, &item.SandboxID, &item.ProviderRevisionID, &item.ProviderGeneration,
			&item.Kind, &item.ProtocolProfile); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		item.AttemptID, item.FencingToken, item.Action = item.OutboxID, item.SlotGeneration, "open"
		if messageType == "desktop_session.close" {
			item.Action = "close"
			var values struct {
				Reason     string `json:"reason"`
				FinalState string `json:"final_state"`
			}
			if err := json.Unmarshal(payload, &values); err != nil {
				return nil, product.ErrStoreUnavailable
			}
			item.Reason, item.FinalState = values.Reason, values.FinalState
			if item.FinalState != "expired" {
				item.FinalState = "closed"
			}
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

func (s *Store) ListExpiredDesktopSessions(ctx context.Context, limit int) ([]product.DesktopExpiryCandidate, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 100 {
		return nil, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	rows, err := s.pool.Query(opCtx, `SELECT tenant_id,session_id,version
FROM sandbox_runtime_product.runtime_sessions
WHERE kind='desktop' AND state IN ('ready','active')
  AND COALESCE(provider_connection_generation,0)>0 AND expires_at<=clock_timestamp()
ORDER BY expires_at,session_id LIMIT $1`, limit)
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.DesktopExpiryCandidate
	for rows.Next() {
		var item product.DesktopExpiryCandidate
		if err := rows.Scan(&item.TenantID, &item.SessionID, &item.Version); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	return result, nil
}

func (s *Store) ExpireDesktopSession(ctx context.Context, command product.DesktopExpiryCommand) (bool, error) {
	if s == nil || s.pool == nil || ctx == nil || command.TenantID == "" || command.SessionID == "" || command.Version < 1 ||
		command.OperationID == "" || command.EventID == "" || command.OutboxID == "" {
		return false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var workspaceID, slotKey string
	var slotGeneration int64
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT workspace_id,slot_key,slot_generation,clock_timestamp()
FROM sandbox_runtime_product.runtime_sessions
WHERE tenant_id=$1 AND session_id=$2 AND version=$3 AND kind='desktop'
  AND state IN ('ready','active') AND COALESCE(provider_connection_generation,0)>0
  AND expires_at<=clock_timestamp()
FOR UPDATE`, command.TenantID, command.SessionID, command.Version).Scan(&workspaceID, &slotKey, &slotGeneration, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.runtime_sessions SET state='draining',version=version+1,updated_at=$1 WHERE tenant_id=$2 AND session_id=$3`, now, command.TenantID, command.SessionID); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.product_operations
(tenant_id,operation_id,operation_type,workspace_id,slot_key,session_id,submitted_actor_type,submitted_actor_id,state,reconciliation_status,version,accepted_at,updated_at)
VALUES($1,$2,'close_session',$3,$4,$5,'service','product-expiry','accepted','pending',1,$6,$6)`, command.TenantID, command.OperationID, workspaceID, slotKey, command.SessionID, now); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, workspaceID, "", now)
	if err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	attributes, _ := json.Marshal(map[string]any{"reason": "session_expired"})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events
(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes)
VALUES($1,$2,$3,$4,'session.expiry_accepted','session',$5,$6,'service','product-expiry',$7,$8)`, command.TenantID, workspaceID, sequence, command.EventID, command.SessionID, command.OperationID, now, attributes); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	payload, _ := json.Marshal(map[string]any{"session_id": command.SessionID, "workspace_id": workspaceID, "slot_key": slotKey,
		"slot_generation": slotGeneration, "reason": "session_expired", "final_state": "expired"})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.outbox
(tenant_id,outbox_id,workspace_id,operation_id,message_type,payload,state,attempt_count,available_at,created_at,updated_at)
VALUES($1,$2,$3,$4,'desktop_session.close',$5,'pending',0,$6,$6,$6)`, command.TenantID, command.OutboxID, workspaceID, command.OperationID, payload, now); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, "aud-"+command.OperationID, command.TenantID,
		product.ActorRef{Type: product.ActorService, ID: "product-expiry"}, "session.expire", "session", command.SessionID,
		"allowed", "expired", now); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return false, storeError(ctx, opCtx, err, true)
	}
	return true, nil
}
