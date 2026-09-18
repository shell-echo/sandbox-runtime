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

func (s *Store) AcquireControlLease(ctx context.Context, command product.ControlLeaseCommand) (product.ControlLease, bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return product.ControlLease{}, false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	now, inserted, err := reserveGenericMutation(opCtx, tx, command, "control_lease", command.LeaseID)
	if err != nil {
		return product.ControlLease{}, false, err
	}
	if !inserted {
		lease, err := loadControlLease(opCtx, tx, command.TenantID, command.Actor, command.Path, command.IdempotencyKey, command.RequestDigest)
		return lease, true, err
	}
	var version int64
	var ownerType, ownerID string
	var workspaceExpiry time.Time
	err = tx.QueryRow(opCtx, `SELECT version,owner_actor_type,owner_actor_id,lease_expires_at FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE`, command.TenantID, command.WorkspaceID).Scan(&version, &ownerType, &ownerID, &workspaceExpiry)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.ControlLease{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if version != command.ExpectedWorkspaceVersion {
		return product.ControlLease{}, false, product.ErrVersionConflict
	}
	authorityExpiry := workspaceExpiry
	if command.Scope.Type == "session" {
		var sessionWorkspace, ownerSessionType, ownerSessionID, sessionState string
		var sessionExpiry time.Time
		err = tx.QueryRow(opCtx, `SELECT workspace_id,owner_actor_type,owner_actor_id,state,expires_at FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2 FOR UPDATE`, command.TenantID, command.Scope.ID).Scan(&sessionWorkspace, &ownerSessionType, &ownerSessionID, &sessionState, &sessionExpiry)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (sessionWorkspace != command.WorkspaceID || ownerSessionType != string(command.Actor.Type) || ownerSessionID != command.Actor.ID) {
			return product.ControlLease{}, false, product.ErrNotFound
		}
		if err != nil {
			return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
		}
		if sessionState != "ready" && sessionState != "active" {
			return product.ControlLease{}, false, product.ErrControlStale
		}
		if sessionExpiry.Before(authorityExpiry) {
			authorityExpiry = sessionExpiry
		}
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.control_leases SET state='expired',updated_at=$1 WHERE tenant_id=$2 AND workspace_id=$3 AND scope_type=$4 AND scope_id=$5 AND state='active' AND expires_at<=$1`, now, command.TenantID, command.WorkspaceID, command.Scope.Type, command.Scope.ID); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.connection_grants SET state='revoked' WHERE tenant_id=$1 AND control_lease_id IN (SELECT lease_id FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1 AND state<>'active') AND state IN ('issued','consumed')`, command.TenantID); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	var active int
	if err := tx.QueryRow(opCtx, `SELECT count(*) FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1 AND workspace_id=$2 AND scope_type=$3 AND scope_id=$4 AND state='active'`, command.TenantID, command.WorkspaceID, command.Scope.Type, command.Scope.ID).Scan(&active); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if active != 0 {
		return product.ControlLease{}, false, product.ErrControlConflict
	}
	var fence int64
	err = tx.QueryRow(opCtx, `INSERT INTO sandbox_runtime_product.control_lease_fences(tenant_id,workspace_id,scope_type,scope_id,last_fence,updated_at)
VALUES($1,$2,$3,$4,1,$5) ON CONFLICT(tenant_id,workspace_id,scope_type,scope_id) DO UPDATE SET last_fence=sandbox_runtime_product.control_lease_fences.last_fence+1,updated_at=EXCLUDED.updated_at RETURNING last_fence`, command.TenantID, command.WorkspaceID, command.Scope.Type, command.Scope.ID, now).Scan(&fence)
	if err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	expires := now.Add(command.Duration)
	if authorityExpiry.Before(expires) {
		expires = authorityExpiry
	}
	if !expires.After(now) {
		return product.ControlLease{}, false, product.ErrControlStale
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.control_leases(tenant_id,lease_id,workspace_id,scope_type,scope_id,controller_actor_type,controller_actor_id,fence,state,issued_at,expires_at,updated_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$9)`, command.TenantID, command.LeaseID, command.WorkspaceID, command.Scope.Type, command.Scope.ID, string(command.Actor.Type), command.Actor.ID, fence, now, expires); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := appendControlEvent(opCtx, tx, command, "control_lease.acquired", fence, now); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "control_lease.acquire", "control_lease", command.LeaseID, "allowed", "authorized", now); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, true)
	}
	return product.ControlLease{ID: command.LeaseID, WorkspaceID: command.WorkspaceID, Scope: command.Scope, Controller: command.Actor, Fence: fence, IssuedAt: now, ExpiresAt: expires}, false, nil
}

func (s *Store) RenewControlLease(ctx context.Context, command product.ControlLeaseCommand) (product.ControlLease, bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return product.ControlLease{}, false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	now, inserted, err := reserveGenericMutation(opCtx, tx, command, "control_lease", command.LeaseID)
	if err != nil {
		return product.ControlLease{}, false, err
	}
	if !inserted {
		lease, err := loadControlLease(opCtx, tx, command.TenantID, command.Actor, command.Path, command.IdempotencyKey, command.RequestDigest)
		return lease, true, err
	}
	lease, workspaceExpiry, err := lockCurrentControlLease(opCtx, tx, command, now)
	if err != nil {
		return product.ControlLease{}, false, err
	}
	expires := now.Add(command.Duration)
	if workspaceExpiry.Before(expires) {
		expires = workspaceExpiry
	}
	if !expires.After(now) {
		return product.ControlLease{}, false, product.ErrControlStale
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.control_leases SET expires_at=$1,updated_at=$2 WHERE tenant_id=$3 AND lease_id=$4`, expires, now, command.TenantID, command.LeaseID); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	lease.ExpiresAt = expires
	command.Scope = lease.Scope
	if err := appendControlEvent(opCtx, tx, command, "control_lease.renewed", command.Fence, now); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "control_lease.renew", "control_lease", command.LeaseID, "allowed", "authorized", now); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.ControlLease{}, false, storeError(ctx, opCtx, err, true)
	}
	return lease, false, nil
}

func (s *Store) ReleaseControlLease(ctx context.Context, command product.ControlLeaseCommand) (bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	now, inserted, err := reserveGenericMutation(opCtx, tx, command, "released_control_lease", command.LeaseID)
	if err != nil {
		return false, err
	}
	if !inserted {
		_, err := loadGenericMutation(opCtx, tx, command.TenantID, command.Actor, command.Path, command.IdempotencyKey, command.RequestDigest)
		return true, err
	}
	lease, _, err := lockCurrentControlLease(opCtx, tx, command, now)
	if err != nil {
		return false, err
	}
	command.Scope = lease.Scope
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.control_leases SET state='released',updated_at=$1 WHERE tenant_id=$2 AND lease_id=$3`, now, command.TenantID, command.LeaseID); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.connection_grants SET state='revoked' WHERE tenant_id=$1 AND control_lease_id=$2 AND state IN ('issued','consumed')`, command.TenantID, command.LeaseID); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if err := appendControlEvent(opCtx, tx, command, "control_lease.released", command.Fence, now); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "control_lease.release", "control_lease", command.LeaseID, "allowed", "authorized", now); err != nil {
		return false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return false, storeError(ctx, opCtx, err, true)
	}
	return false, nil
}

func reserveGenericMutation(ctx context.Context, tx pgx.Tx, command product.ControlLeaseCommand, resultType, resultID string) (time.Time, bool, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, false, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.mutation_idempotency
(tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)
VALUES($1,$2,$3,'POST',$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:], resultType, resultID, now, now.Add(idempotencyRetention))
	if err != nil {
		return time.Time{}, false, err
	}
	return now, tag.RowsAffected() == 1, nil
}

func loadGenericMutation(ctx context.Context, tx pgx.Tx, tenantID string, actor product.ActorRef, path, key string, digest [32]byte) (string, error) {
	var stored []byte
	var resultID string
	err := tx.QueryRow(ctx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='POST' AND normalized_path=$4 AND idempotency_key=$5`, tenantID, string(actor.Type), actor.ID, path, key).Scan(&stored, &resultID)
	if err != nil {
		return "", product.ErrStoreUnavailable
	}
	if len(stored) != 32 || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return "", product.ErrIdempotencyConflict
	}
	return resultID, nil
}
func loadControlLease(ctx context.Context, tx pgx.Tx, tenantID string, actor product.ActorRef, path, key string, digest [32]byte) (product.ControlLease, error) {
	id, err := loadGenericMutation(ctx, tx, tenantID, actor, path, key, digest)
	if err != nil {
		return product.ControlLease{}, err
	}
	return scanControlLease(tx.QueryRow(ctx, `SELECT lease_id,workspace_id,scope_type,scope_id,controller_actor_type,controller_actor_id,fence,issued_at,expires_at FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1 AND lease_id=$2`, tenantID, id))
}
func lockCurrentControlLease(ctx context.Context, tx pgx.Tx, command product.ControlLeaseCommand, now time.Time) (product.ControlLease, time.Time, error) {
	lease, err := scanControlLease(tx.QueryRow(ctx, `SELECT l.lease_id,l.workspace_id,l.scope_type,l.scope_id,l.controller_actor_type,l.controller_actor_id,l.fence,l.issued_at,l.expires_at FROM sandbox_runtime_product.control_leases l WHERE l.tenant_id=$1 AND l.lease_id=$2 FOR UPDATE`, command.TenantID, command.LeaseID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.ControlLease{}, time.Time{}, product.ErrNotFound
	}
	if err != nil {
		return product.ControlLease{}, time.Time{}, err
	}
	if lease.WorkspaceID != command.WorkspaceID || lease.Controller != command.Actor {
		return product.ControlLease{}, time.Time{}, product.ErrNotFound
	}
	if lease.Fence != command.Fence || !lease.ExpiresAt.After(now) {
		return product.ControlLease{}, time.Time{}, product.ErrControlStale
	}
	var state string
	var authorityExpiry time.Time
	if err := tx.QueryRow(ctx, `SELECT state FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1 AND lease_id=$2`, command.TenantID, command.LeaseID).Scan(&state); err != nil {
		return product.ControlLease{}, time.Time{}, err
	}
	if state != "active" {
		return product.ControlLease{}, time.Time{}, product.ErrControlStale
	}
	if err := tx.QueryRow(ctx, `SELECT lease_expires_at FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2`, command.TenantID, command.WorkspaceID).Scan(&authorityExpiry); err != nil {
		return product.ControlLease{}, time.Time{}, err
	}
	if lease.Scope.Type == "session" {
		var sessionWorkspace, sessionState string
		var sessionExpiry time.Time
		if err := tx.QueryRow(ctx, `SELECT workspace_id,state,expires_at FROM sandbox_runtime_product.runtime_sessions WHERE tenant_id=$1 AND session_id=$2`, command.TenantID, lease.Scope.ID).Scan(&sessionWorkspace, &sessionState, &sessionExpiry); err != nil {
			return product.ControlLease{}, time.Time{}, err
		}
		if sessionWorkspace != command.WorkspaceID || (sessionState != "ready" && sessionState != "active") {
			return product.ControlLease{}, time.Time{}, product.ErrControlStale
		}
		if sessionExpiry.Before(authorityExpiry) {
			authorityExpiry = sessionExpiry
		}
	}
	return lease, authorityExpiry, nil
}

type rowScanner interface{ Scan(...any) error }

func scanControlLease(row rowScanner) (product.ControlLease, error) {
	var lease product.ControlLease
	var scopeType, actorType string
	err := row.Scan(&lease.ID, &lease.WorkspaceID, &scopeType, &lease.Scope.ID, &actorType, &lease.Controller.ID, &lease.Fence, &lease.IssuedAt, &lease.ExpiresAt)
	lease.Scope.Type = scopeType
	lease.Controller.Type = product.ActorType(actorType)
	return lease, err
}
func appendControlEvent(ctx context.Context, tx pgx.Tx, command product.ControlLeaseCommand, eventType string, fence int64, now time.Time) error {
	sequence, err := lockWorkspaceAndAdvance(ctx, tx, command.TenantID, command.WorkspaceID, "", now)
	if err != nil {
		return err
	}
	attributes, _ := json.Marshal(map[string]any{"scope_type": command.Scope.Type, "scope_id": command.Scope.ID, "fence": fence})
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,$5,'control_lease',$6,$7,$8,$9,$10)`, command.TenantID, command.WorkspaceID, sequence, command.EventID, eventType, command.LeaseID, string(command.Actor.Type), command.Actor.ID, now, attributes)
	return err
}
func insertAudit(ctx context.Context, tx pgx.Tx, eventID, tenantID string, actor product.ActorRef, action, resourceType, resourceID, outcome, reason string, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO sandbox_runtime_product.security_audit(event_id,tenant_id,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,request_id,occurred_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$1,$10)`, eventID, tenantID, string(actor.Type), actor.ID, action, resourceType, resourceID, outcome, reason, now)
	return err
}
