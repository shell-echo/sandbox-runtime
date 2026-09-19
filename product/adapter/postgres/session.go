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

func (s *Store) CreateSession(ctx context.Context, command product.SessionCommand) (product.Operation, bool, error) {
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
	now, inserted, err := reserveSessionMutation(opCtx, tx, command, "create_session", command.OperationID)
	if err != nil {
		return product.Operation{}, false, err
	}
	if !inserted {
		operation, err := loadSessionMutationOperation(opCtx, tx, command)
		return operation, true, err
	}
	var version int64
	var ownerType, ownerID string
	var workspaceExpiry time.Time
	err = tx.QueryRow(opCtx, `SELECT version,owner_actor_type,owner_actor_id,lease_expires_at FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE`, command.TenantID, command.WorkspaceID).Scan(&version, &ownerType, &ownerID, &workspaceExpiry)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.Operation{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if version != command.ExpectedVersion {
		return product.Operation{}, false, product.ErrVersionConflict
	}
	var slotGeneration int64
	var slotKind, slotDesiredState, slotState string
	var slotCapabilities []byte
	err = tx.QueryRow(opCtx, `SELECT generation,kind,desired_state,observed_state,required_capabilities FROM sandbox_runtime_product.workspace_slots WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3`, command.TenantID, command.WorkspaceID, command.SlotKey).Scan(&slotGeneration, &slotKind, &slotDesiredState, &slotState, &slotCapabilities)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.Operation{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if slotDesiredState != "ready" || slotState != "ready" {
		return product.Operation{}, false, product.ErrControlConflict
	}
	if err := authorizeSessionSlot(command.Kind, slotKind, slotCapabilities); err != nil {
		return product.Operation{}, false, err
	}
	if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7346273420))`, command.TenantID); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	var count, limit int
	if err := tx.QueryRow(opCtx, `SELECT (SELECT count(*) FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND state NOT IN ('closed','expired','failed')),COALESCE((SELECT max_sessions FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),1000)`, command.TenantID).Scan(&count, &limit); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if count >= limit {
		return product.Operation{}, false, product.ErrQuotaExceeded
	}
	if command.Kind == product.SessionKindDesktop {
		var desktopCount, desktopLimit int
		if err := tx.QueryRow(opCtx, `SELECT
    (SELECT count(*) FROM sandbox_runtime_product.runtime_sessions
     WHERE tenant_id=$1 AND kind='desktop' AND state NOT IN ('closed','expired','failed')),
    COALESCE((SELECT max_desktop_sessions FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),16)`, command.TenantID).Scan(&desktopCount, &desktopLimit); err != nil {
			return product.Operation{}, false, storeError(ctx, opCtx, err, false)
		}
		if desktopCount >= desktopLimit {
			return product.Operation{}, false, product.ErrQuotaExceeded
		}
	}
	expires := now.Add(command.Lifetime)
	if workspaceExpiry.Before(expires) {
		expires = workspaceExpiry
	}
	if !expires.After(now) {
		return product.Operation{}, false, product.ErrControlStale
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.runtime_sessions(tenant_id,session_id,workspace_id,slot_key,slot_generation,owner_actor_type,owner_actor_id,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'requested',true,$10,1,$11,$12,$12)`, command.TenantID, command.SessionID, command.WorkspaceID, command.SlotKey, slotGeneration, string(command.Actor.Type), command.Actor.ID, command.Kind, command.ProtocolProfile, command.RecordingPolicy, expires, now); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	operation := product.Operation{ID: command.OperationID, Type: "create_session", WorkspaceID: command.WorkspaceID, SlotKey: command.SlotKey, SessionID: command.SessionID, SubmittedBy: command.Actor, State: "accepted", ReconciliationStatus: "pending", Version: 1, AcceptedAt: now, UpdatedAt: now}
	if err := insertSessionOperation(opCtx, tx, operation, command.TenantID); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, command.WorkspaceID, "", now)
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	attributes, _ := json.Marshal(map[string]any{"slot_key": command.SlotKey, "session_kind": command.Kind, "protocol_profile": command.ProtocolProfile})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,'session.create_accepted','session',$5,$6,$7,$8,$9,$10)`, command.TenantID, command.WorkspaceID, sequence, command.EventID, command.SessionID, command.OperationID, string(command.Actor.Type), command.Actor.ID, now, attributes); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	payload, _ := json.Marshal(map[string]any{"session_id": command.SessionID, "workspace_id": command.WorkspaceID, "slot_key": command.SlotKey, "slot_generation": slotGeneration})
	if err := insertSessionOutbox(opCtx, tx, command, sessionOutboxType(command.Kind, "open"), payload, now); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, "aud-"+command.OperationID, command.TenantID, command.Actor, "session.create", "session", command.SessionID, "allowed", "authorized", now); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, true)
	}
	return operation, false, nil
}

func (s *Store) CloseSession(ctx context.Context, command product.SessionCommand) (product.Operation, bool, error) {
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
	now, inserted, err := reserveSessionMutation(opCtx, tx, command, "close_session", command.OperationID)
	if err != nil {
		return product.Operation{}, false, err
	}
	if !inserted {
		operation, err := loadSessionMutationOperation(opCtx, tx, command)
		return operation, true, err
	}
	var session product.RuntimeSession
	var ownerType, ownerID string
	var slotGeneration int64
	err = tx.QueryRow(opCtx, `SELECT session_id,workspace_id,slot_key,slot_generation,owner_actor_type,owner_actor_id,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2 FOR UPDATE`, command.TenantID, command.SessionID).Scan(&session.ID, &session.WorkspaceID, &session.SlotKey, &slotGeneration, &ownerType, &ownerID, &session.Kind, &session.ProtocolProfile, &session.State, &session.RequiresControlLease, &session.RecordingPolicy, &session.Version, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.Operation{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if session.Version != command.ExpectedVersion {
		return product.Operation{}, false, product.ErrVersionConflict
	}
	if !product.CanTransitionSession(session.State, product.SessionStateDraining) {
		return product.Operation{}, false, product.ErrControlStale
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.runtime_sessions SET state='draining',version=version+1,updated_at=$1 WHERE tenant_id=$2 AND session_id=$3`, now, command.TenantID, command.SessionID); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	operation := product.Operation{ID: command.OperationID, Type: "close_session", WorkspaceID: session.WorkspaceID, SlotKey: session.SlotKey, SessionID: session.ID, SubmittedBy: command.Actor, State: "accepted", ReconciliationStatus: "pending", Version: 1, AcceptedAt: now, UpdatedAt: now}
	if err := insertSessionOperation(opCtx, tx, operation, command.TenantID); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	command.WorkspaceID = session.WorkspaceID
	command.SlotKey = session.SlotKey
	command.Kind = session.Kind
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, session.WorkspaceID, "", now)
	if err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	attributes, _ := json.Marshal(map[string]any{"reason": command.Reason})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,operation_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,'session.close_accepted','session',$5,$6,$7,$8,$9,$10)`, command.TenantID, session.WorkspaceID, sequence, command.EventID, session.ID, command.OperationID, string(command.Actor.Type), command.Actor.ID, now, attributes); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	payload, _ := json.Marshal(map[string]any{"session_id": session.ID, "workspace_id": session.WorkspaceID, "slot_key": session.SlotKey, "slot_generation": slotGeneration, "reason": command.Reason, "final_state": "closed"})
	if err := insertSessionOutbox(opCtx, tx, command, sessionOutboxType(command.Kind, "close"), payload, now); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, "aud-"+command.OperationID, command.TenantID, command.Actor, "session.close", "session", command.SessionID, "allowed", "authorized", now); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.Operation{}, false, storeError(ctx, opCtx, err, true)
	}
	return operation, false, nil
}

func (s *Store) GetSession(ctx context.Context, tenantID, sessionID string) (product.RuntimeSession, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return product.RuntimeSession{}, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var session product.RuntimeSession
	err := s.pool.QueryRow(opCtx, `SELECT session_id,workspace_id,slot_key,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2`, tenantID, sessionID).Scan(&session.ID, &session.WorkspaceID, &session.SlotKey, &session.Kind, &session.ProtocolProfile, &session.State, &session.RequiresControlLease, &session.RecordingPolicy, &session.Version, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.RuntimeSession{}, product.ErrNotFound
	}
	if err != nil {
		return product.RuntimeSession{}, storeError(ctx, opCtx, err, false)
	}
	return session, nil
}
func (s *Store) ListSessions(ctx context.Context, tenantID, workspaceID string, actor product.ActorRef, limit int) ([]product.RuntimeSession, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return nil, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var authorized bool
	if err := s.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2 AND owner_actor_type=$3 AND owner_actor_id=$4)`, tenantID, workspaceID, string(actor.Type), actor.ID).Scan(&authorized); err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	if !authorized {
		return nil, product.ErrNotFound
	}
	rows, err := s.pool.Query(opCtx, `SELECT session_id,workspace_id,slot_key,kind,protocol_profile,state,requires_control_lease,recording_policy,version,expires_at,created_at,updated_at FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND workspace_id=$2 ORDER BY created_at,session_id LIMIT $3`, tenantID, workspaceID, limit)
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	var result []product.RuntimeSession
	for rows.Next() {
		var session product.RuntimeSession
		if err := rows.Scan(&session.ID, &session.WorkspaceID, &session.SlotKey, &session.Kind, &session.ProtocolProfile, &session.State, &session.RequiresControlLease, &session.RecordingPolicy, &session.Version, &session.ExpiresAt, &session.CreatedAt, &session.UpdatedAt); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		result = append(result, session)
	}
	return result, rows.Err()
}

func reserveSessionMutation(ctx context.Context, tx pgx.Tx, command product.SessionCommand, resultType, resultID string) (time.Time, bool, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, false, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.mutation_idempotency(tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)VALUES($1,$2,$3,'POST',$4,$5,$6,$7,$8,$9,$10)ON CONFLICT DO NOTHING`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:], resultType, resultID, now, now.Add(idempotencyRetention))
	if err != nil {
		return time.Time{}, false, err
	}
	return now, tag.RowsAffected() == 1, nil
}
func loadSessionMutationOperation(ctx context.Context, tx pgx.Tx, command product.SessionCommand) (product.Operation, error) {
	var digest []byte
	var resultID string
	if err := tx.QueryRow(ctx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='POST' AND normalized_path=$4 AND idempotency_key=$5`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey).Scan(&digest, &resultID); err != nil {
		return product.Operation{}, product.ErrStoreUnavailable
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 {
		return product.Operation{}, product.ErrIdempotencyConflict
	}
	var operation product.Operation
	var actorType string
	err := tx.QueryRow(ctx, `SELECT operation_id,operation_type,workspace_id,COALESCE(slot_key,''),COALESCE(session_id,''),submitted_actor_type,submitted_actor_id,state,reconciliation_status,version,accepted_at,updated_at FROM sandbox_runtime_product.product_operations WHERE tenant_id=$1 AND operation_id=$2`, command.TenantID, resultID).Scan(&operation.ID, &operation.Type, &operation.WorkspaceID, &operation.SlotKey, &operation.SessionID, &actorType, &operation.SubmittedBy.ID, &operation.State, &operation.ReconciliationStatus, &operation.Version, &operation.AcceptedAt, &operation.UpdatedAt)
	operation.SubmittedBy.Type = product.ActorType(actorType)
	return operation, err
}
func insertSessionOperation(ctx context.Context, tx pgx.Tx, operation product.Operation, tenantID string) error {
	_, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.product_operations(tenant_id,operation_id,operation_type,workspace_id,slot_key,session_id,submitted_actor_type,submitted_actor_id,state,reconciliation_status,version,accepted_at,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, tenantID, operation.ID, operation.Type, operation.WorkspaceID, operation.SlotKey, operation.SessionID, string(operation.SubmittedBy.Type), operation.SubmittedBy.ID, operation.State, operation.ReconciliationStatus, operation.Version, operation.AcceptedAt)
	return err
}
func insertSessionOutbox(ctx context.Context, tx pgx.Tx, command product.SessionCommand, messageType string, payload []byte, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.outbox(tenant_id,outbox_id,workspace_id,operation_id,message_type,payload,state,attempt_count,available_at,created_at,updated_at)VALUES($1,$2,$3,$4,$5,$6,'pending',0,$7,$7,$7)`, command.TenantID, command.OutboxID, command.WorkspaceID, command.OperationID, messageType, payload, now)
	return err
}

func authorizeSessionSlot(sessionKind, slotKind string, encodedCapabilities []byte) error {
	if sessionKind == product.SessionKindTerminal {
		if slotKind != "code" {
			return product.ErrCapabilityUnsupported
		}
		return nil
	}
	capabilityID, capabilityVersion, capabilityProfile := "", "", ""
	switch sessionKind {
	case product.SessionKindBrowserAutomation, product.SessionKindBrowserLive:
		if slotKind != product.BrowserSlotKind {
			return product.ErrCapabilityUnsupported
		}
		capabilityID, capabilityVersion, capabilityProfile = product.BrowserCapabilityID, product.BrowserCapabilityVersion, product.BrowserCapabilityProfile
	case product.SessionKindDesktop:
		if slotKind != product.DesktopSlotKind {
			return product.ErrCapabilityUnsupported
		}
		capabilityID, capabilityVersion, capabilityProfile = product.DesktopCapabilityID, product.DesktopCapabilityVersion, product.DesktopCapabilityProfile
	default:
		return product.ErrCapabilityUnsupported
	}
	var capabilities []product.CapabilityRequirement
	if err := json.Unmarshal(encodedCapabilities, &capabilities); err != nil {
		return product.ErrStoreUnavailable
	}
	for _, capability := range capabilities {
		if capability.CapabilityID == capabilityID && capability.Version == capabilityVersion && capability.ProfileID == capabilityProfile {
			return nil
		}
	}
	return product.ErrCapabilityUnsupported
}

func sessionOutboxType(kind, action string) string {
	if kind == product.SessionKindBrowserAutomation || kind == product.SessionKindBrowserLive {
		return "browser_session." + action
	}
	if kind == product.SessionKindDesktop {
		return "desktop_session." + action
	}
	return "session." + action
}
