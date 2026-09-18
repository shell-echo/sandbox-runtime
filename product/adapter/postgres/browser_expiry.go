package productpostgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) ListExpiredBrowserSessions(ctx context.Context, limit int) ([]product.BrowserExpiryCandidate, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 100 {
		return nil, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	rows, err := s.pool.Query(opCtx, `SELECT tenant_id,session_id,version
FROM sandbox_runtime_product.runtime_sessions
WHERE kind IN ('browser_automation','browser_live')
  AND state IN ('requested','provisioning','ready','active') AND expires_at<=clock_timestamp()
ORDER BY expires_at,session_id LIMIT $1`, limit)
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.BrowserExpiryCandidate
	for rows.Next() {
		var item product.BrowserExpiryCandidate
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

func (s *Store) ExpireBrowserSession(ctx context.Context, command product.BrowserExpiryCommand) (bool, error) {
	if s == nil || s.pool == nil || ctx == nil || command.TenantID == "" || command.SessionID == "" || command.Version < 1 || command.OperationID == "" || command.EventID == "" || command.OutboxID == "" {
		return false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var workspaceID, slotKey, kind string
	var slotGeneration int64
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT workspace_id,slot_key,slot_generation,kind,clock_timestamp()
FROM sandbox_runtime_product.runtime_sessions
WHERE tenant_id=$1 AND session_id=$2 AND version=$3
  AND kind IN ('browser_automation','browser_live')
  AND state IN ('requested','provisioning','ready','active') AND expires_at<=clock_timestamp()
FOR UPDATE`, command.TenantID, command.SessionID, command.Version).Scan(&workspaceID, &slotKey, &slotGeneration, &kind, &now)
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
	payload, _ := json.Marshal(map[string]any{"session_id": command.SessionID, "workspace_id": workspaceID, "slot_key": slotKey, "slot_generation": slotGeneration, "reason": "session_expired", "final_state": "expired"})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.outbox
(tenant_id,outbox_id,workspace_id,operation_id,message_type,payload,state,attempt_count,available_at,created_at,updated_at)
VALUES($1,$2,$3,$4,'browser_session.close',$5,'pending',0,$6,$6,$6)`, command.TenantID, command.OutboxID, workspaceID, command.OperationID, payload, now); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, "aud-"+command.OperationID, command.TenantID, product.ActorRef{Type: product.ActorService, ID: "product-expiry"}, "session.expire", "session", command.SessionID, "allowed", "expired", now); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return false, storeError(ctx, opCtx, err, true)
	}
	_ = kind
	return true, nil
}
