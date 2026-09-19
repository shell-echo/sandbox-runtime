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
	return s.leaseProviderObservations(ctx, workerID, lease, limit, false)
}

func (s *Store) LeaseDesktopProviderObservations(ctx context.Context, workerID string, lease time.Duration, limit int) ([]product.ProviderObservationWork, error) {
	return s.leaseProviderObservations(ctx, workerID, lease, limit, true)
}

func (s *Store) leaseProviderObservations(ctx context.Context, workerID string, lease time.Duration, limit int, desktopOnly bool) ([]product.ProviderObservationWork, error) {
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
   AND CASE WHEN $4::boolean THEN
       EXISTS (SELECT 1 FROM sandbox_runtime_product.workspace_slots AS ws
               WHERE ws.tenant_id=a.tenant_id AND ws.workspace_id=a.workspace_id
                 AND ws.slot_key=a.slot_key AND ws.kind='desktop')
       ELSE NOT EXISTS (SELECT 1 FROM sandbox_runtime_product.workspace_slots AS ws
                        WHERE ws.tenant_id=a.tenant_id AND ws.workspace_id=a.workspace_id
                          AND ws.slot_key=a.slot_key AND ws.kind='desktop')
       END
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
SELECT l.tenant_id,l.workspace_id,l.operation_id,l.attempt_id,l.slot_key,l.slot_generation,l.fencing_token,
       b.runtime_profile_id,b.sandbox_id,COALESCE(l.provider_operation_id,''),l.provider_revision_id,b.provider_generation,COALESCE(l.session_id,''),
       o.operation_type,l.reconcile_lease_owner,COALESCE(l.provider_action,''),COALESCE(s.kind,''),COALESCE(s.protocol_profile,''),
       COALESCE(s.expires_at,'epoch'::timestamptz),COALESCE(ob.payload->>'final_state','')
FROM leased AS l JOIN sandbox_runtime_product.provider_bindings AS b
 ON b.tenant_id=l.tenant_id AND b.workspace_id=l.workspace_id AND b.slot_key=l.slot_key
 AND b.current AND (l.provider_action <> 'create' OR b.slot_generation=l.slot_generation)
JOIN sandbox_runtime_product.product_operations AS o ON o.tenant_id=l.tenant_id AND o.operation_id=l.operation_id
LEFT JOIN sandbox_runtime_product.runtime_sessions AS s ON s.tenant_id=l.tenant_id AND s.session_id=l.session_id
LEFT JOIN sandbox_runtime_product.outbox AS ob ON ob.tenant_id=l.tenant_id AND ob.outbox_id=l.attempt_id
ORDER BY l.operation_id,l.attempt_id`, limit, workerID, lease.String(), desktopOnly)
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.ProviderObservationWork
	for rows.Next() {
		var item product.ProviderObservationWork
		if err := rows.Scan(&item.TenantID, &item.WorkspaceID, &item.OperationID, &item.AttemptID, &item.SlotKey, &item.SlotGeneration, &item.FencingToken,
			&item.RuntimeProfileID, &item.SandboxID, &item.ProviderOperationID, &item.ProviderRevisionID, &item.ProviderGeneration, &item.SessionID, &item.OperationType, &item.LeaseOwner,
			&item.ProviderAction, &item.SessionKind, &item.ProtocolProfile, &item.SessionExpiresAt, &item.SessionFinalState); err != nil {
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
	if work.SessionID != "" {
		if err := recordSessionObservation(opCtx, tx, work, evidence, eventID, state, now); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
		if err := tx.Commit(opCtx); err != nil {
			return storeError(ctx, opCtx, err, true)
		}
		return nil
	}
	if work.ProviderAction == "suspend" || work.ProviderAction == "resume" || work.ProviderAction == "terminate" {
		if err := recordAuxiliaryLifecycleObservation(opCtx, tx, work, evidence, eventID, state, now); err != nil {
			return storeError(ctx, opCtx, err, false)
		}
		if err := tx.Commit(opCtx); err != nil {
			return storeError(ctx, opCtx, err, true)
		}
		return nil
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
	if work.SlotKey != product.PrimarySlotKey {
		workspaceState = ""
	}
	if state != "succeeded" {
		productState, slotState, workspaceState, eventType = "failed", "failed", "failed", "slot.failed"
		if work.SlotKey != product.PrimarySlotKey {
			workspaceState = ""
		}
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

func recordAuxiliaryLifecycleObservation(ctx context.Context, tx pgx.Tx, work product.ProviderObservationWork, evidence product.ProviderOperationEvidence, eventID, state string, now time.Time) error {
	var operationState string
	if err := tx.QueryRow(ctx, `SELECT state FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1 AND operation_id=$2 FOR UPDATE`, work.TenantID, work.OperationID).Scan(&operationState); err != nil {
		return err
	}
	if operationState == "succeeded" || operationState == "failed" || operationState == "cancelled" {
		return nil
	}
	if state == "accepted" || state == "running" || state == "outcome_unknown" {
		productState := "running"
		if state == "outcome_unknown" {
			productState = "outcome_unknown"
		}
		_, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.product_operations SET state=$1,reconciliation_status='reconciling',version=version+1,updated_at=$2 WHERE tenant_id=$3 AND operation_id=$4`, productState, now, work.TenantID, work.OperationID)
		return err
	}
	if state != "succeeded" {
		if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.product_operations SET state='failed',reconciliation_status='complete',error_code=NULLIF($1,''),version=version+1,updated_at=$2 WHERE tenant_id=$3 AND operation_id=$4`, evidence.ErrorCode, now, work.TenantID, work.OperationID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.workspace_slots SET observed_state='failed',version=version+1,updated_at=$1 WHERE tenant_id=$2 AND workspace_id=$3 AND slot_key=$4 AND generation=$5`, now, work.TenantID, work.WorkspaceID, work.SlotKey, work.SlotGeneration)
		return err
	}
	var slotState, bindingState, eventType string
	switch work.ProviderAction {
	case "suspend":
		slotState, bindingState, eventType = "suspended", "suspended", "slot.suspended"
	case "resume":
		slotState, bindingState, eventType = "ready", "ready", "slot.ready"
	default:
		slotState, bindingState, eventType = "terminated", "terminated", "slot.terminated"
	}
	if work.ProviderAction == "terminate" {
		var desired string
		if err := tx.QueryRow(ctx, `SELECT desired_state FROM sandbox_runtime_product.workspace_slots WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3 AND generation=$4 FOR UPDATE`, work.TenantID, work.WorkspaceID, work.SlotKey, work.SlotGeneration).Scan(&desired); err != nil {
			return err
		}
		if desired == "ready" {
			slotState, eventType = "requested", "slot.replacement_requested"
			payload, _ := json.Marshal(map[string]any{"workspace_id": work.WorkspaceID, "operation_id": work.OperationID, "slot_key": work.SlotKey, "generation": work.SlotGeneration, "previous_generation": work.SlotGeneration - 1, "desired_state": "ready", "action": "provision"})
			if _, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.outbox(tenant_id,outbox_id,workspace_id,operation_id,message_type,payload,state,attempt_count,available_at,created_at,updated_at)
VALUES($1,$2,$3,$4,'slot.reconcile',$5,'pending',0,$6,$6,$6) ON CONFLICT(tenant_id,outbox_id) DO NOTHING`, work.TenantID, work.AttemptID+"-replacement", work.WorkspaceID, work.OperationID, payload, now); err != nil {
				return err
			}
			operationState = "running"
		} else {
			operationState = "succeeded"
		}
	} else {
		operationState = "succeeded"
	}
	current := work.ProviderAction != "terminate"
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.provider_bindings SET slot_generation=CASE WHEN $1 THEN $2 ELSE slot_generation END,provider_generation=provider_generation+1,observed_state=$3,current=$1,last_observed_at=$4,updated_at=$5 WHERE tenant_id=$6 AND workspace_id=$7 AND slot_key=$8 AND current`, current, work.SlotGeneration, bindingState, evidence.ObservedAt, now, work.TenantID, work.WorkspaceID, work.SlotKey); err != nil {
		return err
	}
	if work.ProviderAction == "terminate" {
		if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.runtime_sessions SET state=CASE WHEN state='draining' THEN state ELSE 'closed' END,version=version+1,updated_at=$1 WHERE tenant_id=$2 AND workspace_id=$3 AND slot_key=$4 AND state IN ('requested','provisioning','ready','active')`, now, work.TenantID, work.WorkspaceID, work.SlotKey); err != nil {
			return err
		}
	}
	observedGeneration := work.SlotGeneration
	if slotState == "requested" {
		observedGeneration = work.SlotGeneration - 1
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.workspace_slots SET observed_state=$1,observed_generation=$2,version=version+1,updated_at=$3 WHERE tenant_id=$4 AND workspace_id=$5 AND slot_key=$6 AND generation=$7`, slotState, observedGeneration, now, work.TenantID, work.WorkspaceID, work.SlotKey, work.SlotGeneration); err != nil {
		return err
	}
	reconciliation := "complete"
	if operationState == "running" {
		reconciliation = "reconciling"
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.product_operations SET state=$1,reconciliation_status=$2,version=version+1,updated_at=$3 WHERE tenant_id=$4 AND operation_id=$5`, operationState, reconciliation, now, work.TenantID, work.OperationID); err != nil {
		return err
	}
	sequence, err := lockWorkspaceAndAdvance(ctx, tx, work.TenantID, work.WorkspaceID, "", now)
	if err != nil {
		return err
	}
	attributes, _ := json.Marshal(map[string]any{"slot_key": work.SlotKey, "generation": work.SlotGeneration, "provider_outcome": state})
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes) VALUES($1,$2,$3,$4,$5,'slot',$6,$7,'service','product-reconciler',$8,$9)`, work.TenantID, work.WorkspaceID, sequence, eventID, eventType, work.SlotKey, work.OperationID, now, attributes)
	return err
}

func recordSessionObservation(ctx context.Context, tx pgx.Tx, work product.ProviderObservationWork, evidence product.ProviderOperationEvidence, eventID, state string, now time.Time) error {
	productState, reconciliation := "running", "reconciling"
	sessionState := "provisioning"
	closingBrowser := work.ProviderAction == "terminate_browser_session"
	closingDesktop := work.ProviderAction == "close_desktop_session"
	if work.OperationType == "close_session" {
		sessionState = "draining"
	}
	terminal := false
	eventType := ""
	switch state {
	case "outcome_unknown":
		productState = "outcome_unknown"
	case "succeeded":
		productState, reconciliation = "succeeded", "complete"
		terminal = true
		if work.OperationType == "close_session" {
			sessionState, eventType = "closed", "session.closed"
			if work.SessionFinalState == "expired" {
				sessionState, eventType = "expired", "session.expired"
			}
		} else {
			sessionState, eventType = "ready", "session.ready"
		}
	case "failed", "cancelled":
		productState, reconciliation, sessionState = "failed", "complete", "failed"
		terminal = true
		eventType = "session.failed"
	}
	var current string
	if err := tx.QueryRow(ctx, `SELECT state FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1 AND operation_id=$2 FOR UPDATE`, work.TenantID, work.OperationID).Scan(&current); err != nil {
		return err
	}
	if current == "succeeded" || current == "failed" || current == "cancelled" {
		return nil
	}
	var currentSessionState string
	if err := tx.QueryRow(ctx, `SELECT state FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2 FOR UPDATE`, work.TenantID, work.SessionID).Scan(&currentSessionState); err != nil {
		return err
	}
	if work.OperationType == "create_session" && currentSessionState != "requested" && currentSessionState != "provisioning" {
		_, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.product_operations SET state='cancelled',reconciliation_status='complete',error_code='session_superseded',version=version+1,updated_at=$1 WHERE tenant_id=$2 AND operation_id=$3`, now, work.TenantID, work.OperationID)
		return err
	}
	if work.OperationType == "close_session" && currentSessionState != "draining" {
		return nil
	}
	if closingBrowser && state == "succeeded" {
		return recordBrowserSessionCleanup(ctx, tx, work, evidence, eventID, sessionState, eventType, now)
	}
	if closingDesktop && state == "succeeded" {
		return recordDesktopSessionCleanup(ctx, tx, work, eventID, sessionState, eventType, now)
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.product_operations SET state=$1,reconciliation_status=$2,version=version+1,updated_at=$3 WHERE tenant_id=$4 AND operation_id=$5`, productState, reconciliation, now, work.TenantID, work.OperationID); err != nil {
		return err
	}
	if state == "succeeded" && work.OperationType == "create_session" &&
		(evidence.HandoffReference == "" || evidence.ConnectionGeneration < 1 || evidence.HandoffExpiresAt.IsZero()) {
		return product.ErrStoreUnavailable
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.runtime_sessions SET state=$1,version=version+1,
provider_handoff_reference=CASE WHEN $2='' THEN provider_handoff_reference ELSE $2 END,
provider_connection_generation=CASE WHEN $3<1 THEN provider_connection_generation ELSE $3 END,
provider_handoff_expires_at=COALESCE($4::timestamptz,provider_handoff_expires_at),updated_at=$5
	WHERE tenant_id=$6 AND session_id=$7 AND state=$8`, sessionState, evidence.HandoffReference, evidence.ConnectionGeneration,
		nullableTime(evidence.HandoffExpiresAt), now, work.TenantID, work.SessionID, currentSessionState); err != nil {
		return err
	}
	if !terminal {
		return nil
	}
	sequence, err := lockWorkspaceAndAdvance(ctx, tx, work.TenantID, work.WorkspaceID, "", now)
	if err != nil {
		return err
	}
	attributes, _ := json.Marshal(map[string]any{"provider_outcome": state})
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,$5,'session',$6,$7,'service','product-reconciler',$8,$9)`, work.TenantID, work.WorkspaceID, sequence, eventID, eventType, work.SessionID, work.OperationID, now, attributes)
	return err
}

func recordDesktopSessionCleanup(ctx context.Context, tx pgx.Tx, work product.ProviderObservationWork, eventID, sessionState, eventType string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.runtime_sessions
SET state=$1,version=version+1,provider_handoff_reference=NULL,provider_handoff_expires_at=NULL,updated_at=$2
WHERE tenant_id=$3 AND session_id=$4 AND state='draining'`, sessionState, now, work.TenantID, work.SessionID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.product_operations
SET state='succeeded',reconciliation_status='complete',version=version+1,updated_at=$1
WHERE tenant_id=$2 AND operation_id=$3`, now, work.TenantID, work.OperationID); err != nil {
		return err
	}
	sequence, err := lockWorkspaceAndAdvance(ctx, tx, work.TenantID, work.WorkspaceID, "", now)
	if err != nil {
		return err
	}
	attributes, _ := json.Marshal(map[string]any{"provider_outcome": "succeeded"})
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.workspace_events
(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes)
VALUES($1,$2,$3,$4,$5,'session',$6,$7,'service','product-reconciler',$8,$9)`, work.TenantID, work.WorkspaceID,
		sequence, eventID, eventType, work.SessionID, work.OperationID, now, attributes)
	return err
}

func recordBrowserSessionCleanup(ctx context.Context, tx pgx.Tx, work product.ProviderObservationWork, evidence product.ProviderOperationEvidence, eventID, sessionState, eventType string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.runtime_sessions SET state=$1,version=version+1,provider_handoff_reference=NULL,provider_handoff_expires_at=NULL,updated_at=$2 WHERE tenant_id=$3 AND session_id=$4 AND state='draining'`, sessionState, now, work.TenantID, work.SessionID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.connection_grants SET state='revoked' WHERE tenant_id=$1 AND session_id=$2 AND state IN ('issued','consumed')`, work.TenantID, work.SessionID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.provider_bindings SET observed_state='terminated',current=false,last_observed_at=$1,updated_at=$2 WHERE tenant_id=$3 AND workspace_id=$4 AND slot_key=$5 AND slot_generation=$6 AND current`, evidence.ObservedAt, now, work.TenantID, work.WorkspaceID, work.SlotKey, work.SlotGeneration); err != nil {
		return err
	}
	operationState, reconciliation := "succeeded", "complete"
	var desired string
	var generation int64
	err := tx.QueryRow(ctx, `SELECT desired_state,generation FROM sandbox_runtime_product.workspace_slots WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3 FOR UPDATE`, work.TenantID, work.WorkspaceID, work.SlotKey).Scan(&desired, &generation)
	if err != nil {
		return err
	}
	if desired == "ready" && generation == work.SlotGeneration {
		generation++
		if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.workspace_slots SET generation=$1,observed_state='requested',version=version+1,updated_at=$2 WHERE tenant_id=$3 AND workspace_id=$4 AND slot_key=$5`, generation, now, work.TenantID, work.WorkspaceID, work.SlotKey); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"workspace_id": work.WorkspaceID, "operation_id": work.OperationID, "slot_key": work.SlotKey, "generation": generation, "previous_generation": work.SlotGeneration, "desired_state": "ready", "action": "provision"})
		if _, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.outbox(tenant_id,outbox_id,workspace_id,operation_id,message_type,payload,state,attempt_count,available_at,created_at,updated_at)
VALUES($1,$2,$3,$4,'slot.reconcile',$5,'pending',0,$6,$6,$6) ON CONFLICT(tenant_id,outbox_id) DO NOTHING`, work.TenantID, work.AttemptID+"-replacement", work.WorkspaceID, work.OperationID, payload, now); err != nil {
			return err
		}
		operationState, reconciliation = "running", "reconciling"
	}
	if _, err := tx.Exec(ctx, `UPDATE sandbox_runtime_product.product_operations SET state=$1,reconciliation_status=$2,version=version+1,updated_at=$3 WHERE tenant_id=$4 AND operation_id=$5`, operationState, reconciliation, now, work.TenantID, work.OperationID); err != nil {
		return err
	}
	sequence, err := lockWorkspaceAndAdvance(ctx, tx, work.TenantID, work.WorkspaceID, "", now)
	if err != nil {
		return err
	}
	attributes, _ := json.Marshal(map[string]any{"provider_outcome": "succeeded", "replacement_generation": generation})
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes) VALUES($1,$2,$3,$4,$5,'session',$6,$7,'service','product-reconciler',$8,$9)`, work.TenantID, work.WorkspaceID, sequence, eventID, eventType, work.SessionID, work.OperationID, now, attributes)
	return err
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
