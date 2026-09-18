package productpostgres

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

type GrantRepository struct {
	store *Store
	aead  cipher.AEAD
	keyID string
}

func NewGrantRepository(store *Store, keyID string, key []byte) (*GrantRepository, error) {
	if store == nil || keyID == "" || len(key) != 32 {
		return nil, product.ErrInvalid
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, product.ErrInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, product.ErrInvalid
	}
	return &GrantRepository{store: store, aead: aead, keyID: keyID}, nil
}

func (r *GrantRepository) MintConnectionGrant(ctx context.Context, command product.ConnectionGrantCommand) (product.ConnectionGrant, bool, error) {
	if r == nil || r.store == nil || ctx == nil {
		return product.ConnectionGrant{}, false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, r.store.operationTimeout)
	defer cancel()
	tx, err := r.store.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, r.store.operationTimeout)
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.connection_grants SET state='expired' WHERE tenant_id=$1 AND state IN ('issued','consumed') AND expires_at<=$2`, command.TenantID, now); err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.connection_grants SET state='revoked' WHERE tenant_id=$1 AND control_lease_id IS NOT NULL AND state IN ('issued','consumed') AND NOT EXISTS(SELECT 1 FROM sandbox_runtime_product.control_leases l WHERE l.tenant_id=connection_grants.tenant_id AND l.lease_id=connection_grants.control_lease_id AND l.state='active' AND l.expires_at>$2)`, command.TenantID, now); err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	tag, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.mutation_idempotency(tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)VALUES($1,$2,$3,'POST',$4,$5,$6,'connection_grant',$7,$8,$9)ON CONFLICT DO NOTHING`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:], command.ConnectionID, now, now.Add(idempotencyRetention))
	if err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() == 0 {
		grant, err := r.loadRetainedGrant(opCtx, tx, command)
		return grant, true, err
	}
	var sessionVersion, slotGeneration, connectionGeneration int64
	var workspaceID, slotKey, kind, profile, state, ownerType, ownerID, providerRevision, sandboxID, handoff string
	var sessionExpiry, handoffExpiry time.Time
	var requiresControl bool
	err = tx.QueryRow(opCtx, `SELECT s.version,s.slot_generation,s.workspace_id,s.slot_key,s.kind,s.protocol_profile,s.state,s.owner_actor_type,s.owner_actor_id,s.expires_at,s.requires_control_lease,COALESCE(s.provider_connection_generation,0),COALESCE(s.provider_handoff_reference,''),s.provider_handoff_expires_at,b.provider_revision_id,b.sandbox_id FROM sandbox_runtime_product.runtime_sessions s JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=s.tenant_id AND b.workspace_id=s.workspace_id AND b.slot_key=s.slot_key AND b.slot_generation=s.slot_generation AND b.current WHERE s.tenant_id=$1 AND s.session_id=$2 FOR UPDATE OF s`, command.TenantID, command.SessionID).Scan(&sessionVersion, &slotGeneration, &workspaceID, &slotKey, &kind, &profile, &state, &ownerType, &ownerID, &sessionExpiry, &requiresControl, &connectionGeneration, &handoff, &handoffExpiry, &providerRevision, &sandboxID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.ConnectionGrant{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	if sessionVersion != command.Request.ExpectedSessionVersion {
		return product.ConnectionGrant{}, false, product.ErrVersionConflict
	}
	if profile != command.Request.ProtocolProfile || state != "ready" || handoff == "" || connectionGeneration < 1 || !handoffExpiry.After(now) {
		return product.ConnectionGrant{}, false, product.ErrControlStale
	}
	browser := kind == product.SessionKindBrowserAutomation || kind == product.SessionKindBrowserLive
	if !browser && command.Request.AccessMode != product.GrantAccessControl {
		return product.ConnectionGrant{}, false, product.ErrCapabilityUnsupported
	}
	if browser {
		if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7346273422))`, command.TenantID); err != nil {
			return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
		}
		var count, limit int
		if command.Request.AccessMode == product.GrantAccessControl {
			var occupied bool
			if err := tx.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.connection_grants WHERE tenant_id=$1 AND session_id=$2 AND access_mode='control' AND state IN ('issued','consumed') AND expires_at>$3)`, command.TenantID, command.SessionID, now).Scan(&occupied); err != nil {
				return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
			}
			if occupied {
				return product.ConnectionGrant{}, false, product.ErrControlConflict
			}
		}
		column := "max_browser_viewers"
		if command.Request.AccessMode == product.GrantAccessControl {
			column = "max_browser_controllers"
		}
		query := `SELECT (SELECT count(*) FROM sandbox_runtime_product.connection_grants g JOIN sandbox_runtime_product.runtime_sessions s ON s.tenant_id=g.tenant_id AND s.session_id=g.session_id WHERE g.tenant_id=$1 AND s.kind IN ('browser_automation','browser_live') AND g.access_mode=$2 AND g.state IN ('issued','consumed') AND g.expires_at>$3),COALESCE((SELECT ` + column + ` FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),16)`
		if err := tx.QueryRow(opCtx, query, command.TenantID, command.Request.AccessMode, now).Scan(&count, &limit); err != nil {
			return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
		}
		if count >= limit {
			return product.ConnectionGrant{}, false, product.ErrQuotaExceeded
		}
	}
	expires := now.Add(command.Lifetime)
	if sessionExpiry.Before(expires) {
		expires = sessionExpiry
	}
	if handoffExpiry.Before(expires) {
		expires = handoffExpiry
	}
	if requiresControl && command.Request.AccessMode == product.GrantAccessControl {
		if command.Request.ControlLeaseID == "" {
			return product.ConnectionGrant{}, false, product.ErrControlStale
		}
		var leaseActorType, leaseActorID, leaseState, scopeType, scopeID string
		var fence int64
		var leaseExpiry time.Time
		err = tx.QueryRow(opCtx, `SELECT controller_actor_type,controller_actor_id,state,scope_type,scope_id,fence,expires_at FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1 AND lease_id=$2 FOR UPDATE`, command.TenantID, command.Request.ControlLeaseID).Scan(&leaseActorType, &leaseActorID, &leaseState, &scopeType, &scopeID, &fence, &leaseExpiry)
		if err != nil || leaseActorType != string(command.Actor.Type) || leaseActorID != command.Actor.ID || leaseState != "active" || scopeType != "session" || scopeID != command.SessionID || fence != command.Request.ControlFence || !leaseExpiry.After(now) {
			return product.ConnectionGrant{}, false, product.ErrControlStale
		}
		if leaseExpiry.Before(expires) {
			expires = leaseExpiry
		}
	}
	if command.Request.AccessMode == product.GrantAccessControl && command.Request.ControlLeaseID == "" {
		return product.ConnectionGrant{}, false, product.ErrControlStale
	}
	if !expires.After(now) {
		return product.ConnectionGrant{}, false, product.ErrControlStale
	}
	digest := sha256.Sum256([]byte(command.Ticket))
	ciphertext, err := r.encrypt(command.TenantID, command.ConnectionID, command.Ticket)
	if err != nil {
		return product.ConnectionGrant{}, false, product.ErrStoreUnavailable
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.connection_grants(tenant_id,connection_id,session_id,workspace_id,slot_key,slot_generation,actor_type,actor_id,protocol_profile,ticket_digest,ticket_ciphertext,ticket_key_id,control_lease_id,control_fence,state,issued_at,expires_at,access_mode)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NULLIF($13,''),NULLIF($14,0),'issued',$15,$16,$17)`, command.TenantID, command.ConnectionID, command.SessionID, workspaceID, slotKey, slotGeneration, string(command.Actor.Type), command.Actor.ID, profile, digest[:], ciphertext, r.keyID, command.Request.ControlLeaseID, command.Request.ControlFence, now, expires, command.Request.AccessMode); err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "connection_grant.issue", "connection_grant", command.ConnectionID, "allowed", "authorized", now); err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.ConnectionGrant{}, false, storeError(ctx, opCtx, err, true)
	}
	return product.ConnectionGrant{ID: command.ConnectionID, SessionID: command.SessionID, ProtocolProfile: profile, AccessMode: command.Request.AccessMode, GatewayURI: command.GatewayURI, Ticket: command.Ticket, ExpiresAt: expires}, false, nil
}

func (r *GrantRepository) ConsumeConnectionGrant(ctx context.Context, ticket string) (product.GatewayBinding, error) {
	if r == nil || r.store == nil || ctx == nil || len(ticket) < 32 {
		return product.GatewayBinding{}, product.ErrNotFound
	}
	digest := sha256.Sum256([]byte(ticket))
	opCtx, cancel := context.WithTimeout(ctx, r.store.operationTimeout)
	defer cancel()
	tx, err := r.store.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.GatewayBinding{}, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, r.store.operationTimeout)
	var binding product.GatewayBinding
	var actorType, state, grantState string
	var controlLeaseID string
	var controlFence int64
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT g.connection_id,g.tenant_id,g.actor_type,g.actor_id,g.workspace_id,g.slot_key,g.slot_generation,g.session_id,g.protocol_profile,g.access_mode,g.expires_at,g.state,COALESCE(g.control_lease_id,''),COALESCE(g.control_fence,0),s.state,b.provider_revision_id,b.sandbox_id,COALESCE(s.provider_handoff_reference,''),COALESCE(s.provider_connection_generation,0),s.provider_handoff_expires_at,clock_timestamp() FROM sandbox_runtime_product.connection_grants g JOIN sandbox_runtime_product.runtime_sessions s ON s.tenant_id=g.tenant_id AND s.session_id=g.session_id JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=g.tenant_id AND b.workspace_id=g.workspace_id AND b.slot_key=g.slot_key AND b.slot_generation=g.slot_generation AND b.current WHERE g.ticket_digest=$1 FOR UPDATE OF g`, digest[:]).Scan(&binding.ConnectionID, &binding.TenantID, &actorType, &binding.Actor.ID, &binding.WorkspaceID, &binding.SlotKey, &binding.SlotGeneration, &binding.SessionID, &binding.ProtocolProfile, &binding.AccessMode, &binding.ExpiresAt, &grantState, &controlLeaseID, &controlFence, &state, &binding.ProviderRevisionID, &binding.SandboxID, &binding.HandoffReference, &binding.ConnectionGeneration, &binding.HandoffExpiresAt, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.GatewayBinding{}, product.ErrNotFound
	}
	if err != nil {
		return product.GatewayBinding{}, storeError(ctx, opCtx, err, false)
	}
	binding.Actor.Type = product.ActorType(actorType)
	binding.ControlLeaseID = controlLeaseID
	binding.ControlFence = controlFence
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.connection_grants SET state='consumed',consumed_at=$1 WHERE connection_id=$2`, now, binding.ConnectionID); err != nil {
		return product.GatewayBinding{}, storeError(ctx, opCtx, err, false)
	}
	valid := grantState == "issued" && binding.ExpiresAt.After(now) && (state == "ready" || state == "active") && binding.HandoffReference != "" && binding.ConnectionGeneration >= 1 && binding.HandoffExpiresAt.After(now)
	if valid && binding.ControlLeaseID != "" {
		var active bool
		err = tx.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1 AND lease_id=$2 AND state='active' AND fence=$3 AND controller_actor_type=$4 AND controller_actor_id=$5 AND expires_at>$6)`, binding.TenantID, binding.ControlLeaseID, binding.ControlFence, string(binding.Actor.Type), binding.Actor.ID, now).Scan(&active)
		valid = err == nil && active
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.GatewayBinding{}, storeError(ctx, opCtx, err, true)
	}
	if !valid {
		return product.GatewayBinding{}, product.ErrControlStale
	}
	return binding, nil
}

func (r *GrantRepository) CheckGatewayAuthority(ctx context.Context, binding product.GatewayBinding) error {
	if r == nil || r.store == nil || ctx == nil {
		return product.ErrStoreUnavailable
	}
	if binding.AccessMode != product.GrantAccessView && binding.AccessMode != product.GrantAccessControl {
		return product.ErrControlStale
	}
	opCtx, cancel := context.WithTimeout(ctx, r.store.operationTimeout)
	defer cancel()
	var valid bool
	err := r.store.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.connection_grants g JOIN sandbox_runtime_product.runtime_sessions s ON s.tenant_id=g.tenant_id AND s.session_id=g.session_id JOIN sandbox_runtime_product.provider_bindings b ON b.tenant_id=g.tenant_id AND b.workspace_id=g.workspace_id AND b.slot_key=g.slot_key AND b.slot_generation=g.slot_generation AND b.current WHERE g.tenant_id=$1 AND g.connection_id=$2 AND g.actor_type=$3 AND g.actor_id=$4 AND g.workspace_id=$5 AND g.slot_key=$6 AND g.slot_generation=$7 AND g.session_id=$8 AND g.protocol_profile=$9 AND g.state='consumed' AND g.expires_at>clock_timestamp() AND s.state IN('ready','active') AND s.provider_connection_generation=$10 AND s.provider_handoff_reference=$11 AND s.provider_handoff_expires_at>clock_timestamp() AND b.provider_revision_id=$12 AND b.sandbox_id=$13 AND g.access_mode=$14 AND COALESCE(g.control_lease_id,'')=$15 AND COALESCE(g.control_fence,0)=$16)`, binding.TenantID, binding.ConnectionID, string(binding.Actor.Type), binding.Actor.ID, binding.WorkspaceID, binding.SlotKey, binding.SlotGeneration, binding.SessionID, binding.ProtocolProfile, binding.ConnectionGeneration, binding.HandoffReference, binding.ProviderRevisionID, binding.SandboxID, binding.AccessMode, binding.ControlLeaseID, binding.ControlFence).Scan(&valid)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if !valid {
		return product.ErrControlStale
	}
	if binding.ControlLeaseID != "" {
		err = r.store.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.control_leases WHERE tenant_id=$1 AND lease_id=$2 AND state='active' AND fence=$3 AND controller_actor_type=$4 AND controller_actor_id=$5 AND expires_at>clock_timestamp())`, binding.TenantID, binding.ControlLeaseID, binding.ControlFence, string(binding.Actor.Type), binding.Actor.ID).Scan(&valid)
		if err != nil {
			return product.ErrStoreUnavailable
		}
		if !valid {
			return product.ErrControlStale
		}
	}
	if binding.AccessMode == product.GrantAccessControl && binding.ControlLeaseID == "" {
		return product.ErrControlStale
	}
	return nil
}

func (r *GrantRepository) loadRetainedGrant(ctx context.Context, tx pgx.Tx, command product.ConnectionGrantCommand) (product.ConnectionGrant, error) {
	var digest []byte
	var connectionID string
	if err := tx.QueryRow(ctx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='POST' AND normalized_path=$4 AND idempotency_key=$5`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey).Scan(&digest, &connectionID); err != nil {
		return product.ConnectionGrant{}, product.ErrStoreUnavailable
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 {
		return product.ConnectionGrant{}, product.ErrIdempotencyConflict
	}
	var grant product.ConnectionGrant
	var ciphertext []byte
	var keyID string
	if err := tx.QueryRow(ctx, `SELECT connection_id,session_id,protocol_profile,access_mode,ticket_ciphertext,ticket_key_id,expires_at FROM sandbox_runtime_product.connection_grants WHERE tenant_id=$1 AND connection_id=$2`, command.TenantID, connectionID).Scan(&grant.ID, &grant.SessionID, &grant.ProtocolProfile, &grant.AccessMode, &ciphertext, &keyID, &grant.ExpiresAt); err != nil {
		return product.ConnectionGrant{}, product.ErrStoreUnavailable
	}
	if keyID != r.keyID {
		return product.ConnectionGrant{}, product.ErrStoreUnavailable
	}
	ticket, err := r.decrypt(command.TenantID, connectionID, ciphertext)
	if err != nil {
		return product.ConnectionGrant{}, product.ErrStoreUnavailable
	}
	grant.GatewayURI = command.GatewayURI
	grant.Ticket = ticket
	return grant, nil
}
func (r *GrantRepository) encrypt(tenantID, connectionID, ticket string) ([]byte, error) {
	nonce := make([]byte, r.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aad := []byte(tenantID + "\x00" + connectionID)
	return append(nonce, r.aead.Seal(nil, nonce, []byte(ticket), aad)...), nil
}
func (r *GrantRepository) decrypt(tenantID, connectionID string, ciphertext []byte) (string, error) {
	if len(ciphertext) < r.aead.NonceSize() {
		return "", errors.New("invalid ticket ciphertext")
	}
	nonce := ciphertext[:r.aead.NonceSize()]
	plaintext, err := r.aead.Open(nil, nonce, ciphertext[r.aead.NonceSize():], []byte(tenantID+"\x00"+connectionID))
	return string(plaintext), err
}
