package productpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) ProvisionGuest(ctx context.Context, command product.GuestBindingCommand) (product.GuestBinding, bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.GuestBinding{}, false, product.ErrStoreUnavailable
	}
	tag, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.mutation_idempotency(tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)VALUES($1,$2,$3,'POST',$4,$5,$6,'guest_binding',$7,$8,$9)ON CONFLICT DO NOTHING`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:], command.GuestID, now, now.Add(idempotencyRetention))
	if err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() == 0 {
		binding, err := loadRetainedGuest(opCtx, tx, command)
		return binding, true, err
	}
	var workspaceVersion, slotGeneration int64
	var ownerType, ownerID, slotState, slotProfileID string
	err = tx.QueryRow(opCtx, `SELECT w.version,w.owner_actor_type,w.owner_actor_id,s.profile_id,s.generation,s.observed_state FROM sandbox_runtime_product.workspaces w JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=w.tenant_id AND s.workspace_id=w.workspace_id WHERE w.tenant_id=$1 AND w.workspace_id=$2 AND s.slot_key=$3 FOR UPDATE OF w,s`, command.TenantID, command.WorkspaceID, command.Request.SlotKey).Scan(&workspaceVersion, &ownerType, &ownerID, &slotProfileID, &slotGeneration, &slotState)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.GuestBinding{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	if workspaceVersion != command.Request.ExpectedWorkspaceVersion {
		return product.GuestBinding{}, false, product.ErrVersionConflict
	}
	if slotState != "ready" {
		return product.GuestBinding{}, false, product.ErrControlStale
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.guest_bindings SET state='revoked',updated_at=$1 WHERE tenant_id=$2 AND workspace_id=$3 AND slot_key=$4 AND state IN('issued','connected','disconnected')`, now, command.TenantID, command.WorkspaceID, command.Request.SlotKey); err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	var generation int64
	if err := tx.QueryRow(opCtx, `SELECT COALESCE(max(binding_generation),0)+1 FROM sandbox_runtime_product.guest_bindings WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3`, command.TenantID, command.WorkspaceID, command.Request.SlotKey).Scan(&generation); err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	capabilities, _ := json.Marshal(command.Request.Capabilities)
	publicKey := append([]byte(nil), command.Request.PublicKey...)
	credentialDigest := sha256.Sum256(publicKey)
	expires := now.Add(time.Duration(command.Request.LifetimeSeconds) * time.Second)
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.guest_bindings(tenant_id,workspace_id,slot_key,slot_profile_id,slot_generation,binding_generation,guest_id,credential_digest,public_key,protocol_version,capabilities,state,expires_at,created_at,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'issued',$12,$13,$13)`, command.TenantID, command.WorkspaceID, command.Request.SlotKey, slotProfileID, slotGeneration, generation, command.GuestID, credentialDigest[:], publicKey, command.Request.ProtocolVersion, capabilities, expires, now); err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, command.WorkspaceID, "", now)
	if err != nil {
		return product.GuestBinding{}, false, err
	}
	attributes, _ := json.Marshal(map[string]any{"slot_key": command.Request.SlotKey, "binding_generation": generation, "protocol_version": command.Request.ProtocolVersion})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,'guest.binding.provisioned','guest_binding',$5,$6,$7,$8,$9)`, command.TenantID, command.WorkspaceID, sequence, command.EventID, command.GuestID, string(command.Actor.Type), command.Actor.ID, now, attributes); err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "guest.provision", "guest_binding", command.GuestID, "allowed", "authorized", now); err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.GuestBinding{}, false, storeError(ctx, opCtx, err, true)
	}
	return product.GuestBinding{TenantID: command.TenantID, WorkspaceID: command.WorkspaceID, SlotKey: command.Request.SlotKey, SlotProfileID: slotProfileID, SlotGeneration: slotGeneration, GuestID: command.GuestID, BindingGeneration: generation, ProtocolVersion: command.Request.ProtocolVersion, Capabilities: append([]string(nil), command.Request.Capabilities...), State: "issued", ExpiresAt: expires}, false, nil
}

func (s *Store) AuthenticateGuest(ctx context.Context, authentication product.GuestAuthentication) (product.GuestBinding, error) {
	binding, _, err := s.authenticateGuest(ctx, authentication, false)
	return binding, err
}

// AuthenticateGuestWithRevocationEvidence is an opt-in private observation
// path. A true result means this very signed attempt matched a revoked row in
// the original locked transaction; it does not grant any additional authority.
func (s *Store) AuthenticateGuestWithRevocationEvidence(ctx context.Context, authentication product.GuestAuthentication) (product.GuestBinding, bool, error) {
	return s.authenticateGuest(ctx, authentication, true)
}

func (s *Store) authenticateGuest(ctx context.Context, authentication product.GuestAuthentication, observeRevoked bool) (product.GuestBinding, bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.GuestBinding{}, false, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var binding product.GuestBinding
	var configuredJSON, publicKey, credentialDigest []byte
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT g.tenant_id,g.workspace_id,g.slot_key,g.slot_profile_id,g.slot_generation,g.binding_generation,g.guest_id,g.credential_digest,g.public_key,g.protocol_version,g.capabilities,g.state,g.expires_at,clock_timestamp() FROM sandbox_runtime_product.guest_bindings g JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=g.tenant_id AND s.workspace_id=g.workspace_id AND s.slot_key=g.slot_key AND s.generation=g.slot_generation AND s.profile_id=g.slot_profile_id WHERE g.guest_id=$1 AND g.binding_generation=$2 AND s.observed_state='ready' FOR UPDATE OF g`, authentication.GuestID, authentication.BindingGeneration).Scan(&binding.TenantID, &binding.WorkspaceID, &binding.SlotKey, &binding.SlotProfileID, &binding.SlotGeneration, &binding.BindingGeneration, &binding.GuestID, &credentialDigest, &publicKey, &binding.ProtocolVersion, &configuredJSON, &binding.State, &binding.ExpiresAt, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.GuestBinding{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.GuestBinding{}, false, product.ErrStoreUnavailable
	}
	publicKeyDigest := sha256.Sum256(publicKey)
	if binding.ProtocolVersion != authentication.ProtocolVersion || (binding.State != "issued" && binding.State != "disconnected") || !binding.ExpiresAt.After(now) || len(publicKey) != ed25519.PublicKeySize || len(credentialDigest) != sha256.Size || subtle.ConstantTimeCompare(credentialDigest, publicKeyDigest[:]) != 1 || !ed25519.Verify(publicKey, authentication.SigningBytes, authentication.Signature) {
		if observeRevoked && binding.State == "revoked" && opCtx.Err() == nil &&
			validObservedGuestSigningBinding(authentication, now) &&
			binding.ProtocolVersion == authentication.ProtocolVersion && binding.ExpiresAt.After(now) &&
			len(publicKey) == ed25519.PublicKeySize && len(credentialDigest) == sha256.Size &&
			subtle.ConstantTimeCompare(credentialDigest, publicKeyDigest[:]) == 1 &&
			ed25519.Verify(publicKey, authentication.SigningBytes, authentication.Signature) &&
			json.Unmarshal(configuredJSON, &binding.Capabilities) == nil &&
			len(capabilityIntersection(binding.Capabilities, authentication.OfferedCapabilities)) > 0 {
			return product.GuestBinding{}, true, product.ErrForbidden
		}
		return product.GuestBinding{}, false, product.ErrForbidden
	}
	if err := json.Unmarshal(configuredJSON, &binding.Capabilities); err != nil {
		return product.GuestBinding{}, false, product.ErrStoreUnavailable
	}
	binding.Capabilities = capabilityIntersection(binding.Capabilities, authentication.OfferedCapabilities)
	if len(binding.Capabilities) == 0 {
		return product.GuestBinding{}, false, product.ErrCapabilityUnsupported
	}
	binding.ClientNonce = authentication.ClientNonce
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.guest_bindings SET state='connected',connection_nonce=$1,last_seen_at=$2,updated_at=$2 WHERE guest_id=$3 AND binding_generation=$4`, authentication.ClientNonce, now, authentication.GuestID, authentication.BindingGeneration); err != nil {
		return product.GuestBinding{}, false, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.GuestBinding{}, false, product.ErrStoreOutcomeUnknown
	}
	binding.State = "connected"
	return binding, false, nil
}

// The signed message must describe the same tuple supplied to this store
// call. This is only consulted for the private positive revoked observation;
// the ordinary authentication path and its historical error mapping remain
// unchanged.
func validObservedGuestSigningBinding(authentication product.GuestAuthentication, now time.Time) bool {
	if len(authentication.SigningBytes) < 1 || len(authentication.SigningBytes) > 4096 ||
		len(authentication.Signature) != ed25519.SignatureSize ||
		len(authentication.OfferedCapabilities) < 1 || len(authentication.OfferedCapabilities) > 32 {
		return false
	}
	fields := bytes.Split(authentication.SigningBytes, []byte{'\n'})
	if len(fields) != 8 || string(fields[0]) != "sandbox-runtime-guest-auth-v1" ||
		string(fields[3]) != authentication.ClientNonce || string(fields[4]) != authentication.GuestID ||
		string(fields[5]) != strconv.FormatInt(authentication.BindingGeneration, 10) ||
		string(fields[6]) != authentication.ProtocolVersion ||
		!validObservedGuestNonce(string(fields[1])) || !validObservedGuestNonce(authentication.ClientNonce) {
		return false
	}
	challengeExpiresAt, err := time.Parse(time.RFC3339Nano, string(fields[2]))
	if err != nil || !challengeExpiresAt.After(now) || challengeExpiresAt.After(now.Add(30*time.Second)) {
		return false
	}
	capabilities := append([]string(nil), authentication.OfferedCapabilities...)
	sort.Strings(capabilities)
	for i, capability := range capabilities {
		if capability == "" || len(capability) > 200 || strings.ContainsAny(capability, ",\r\n") ||
			i > 0 && capability == capabilities[i-1] {
			return false
		}
	}
	return string(fields[7]) == strings.Join(capabilities, ",")
}

func validObservedGuestNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func (s *Store) CheckGuestAuthority(ctx context.Context, binding product.GuestBinding) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var valid bool
	err := s.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.guest_bindings g JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=g.tenant_id AND s.workspace_id=g.workspace_id AND s.slot_key=g.slot_key WHERE g.guest_id=$1 AND g.binding_generation=$2 AND g.connection_nonce=$3 AND g.state='connected' AND g.expires_at>clock_timestamp() AND s.generation=g.slot_generation AND s.observed_state='ready')`, binding.GuestID, binding.BindingGeneration, binding.ClientNonce).Scan(&valid)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if !valid {
		return product.ErrControlStale
	}
	return nil
}

func (s *Store) DisconnectGuest(ctx context.Context, binding product.GuestBinding) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	_, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.guest_bindings SET state='disconnected',connection_nonce=NULL,last_seen_at=clock_timestamp(),updated_at=clock_timestamp() WHERE guest_id=$1 AND binding_generation=$2 AND connection_nonce=$3 AND state='connected'`, binding.GuestID, binding.BindingGeneration, binding.ClientNonce)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (s *Store) RevokeGuest(ctx context.Context, tenantID, guestID, reason string) error {
	if reason == "" {
		return product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tag, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.guest_bindings SET state='revoked',connection_nonce=NULL,updated_at=clock_timestamp() WHERE tenant_id=$1 AND guest_id=$2 AND state IN('issued','connected','disconnected')`, tenantID, guestID)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if tag.RowsAffected() == 0 {
		return product.ErrNotFound
	}
	return nil
}

func loadRetainedGuest(ctx context.Context, tx pgx.Tx, command product.GuestBindingCommand) (product.GuestBinding, error) {
	var digest []byte
	var guestID string
	if err := tx.QueryRow(ctx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='POST' AND normalized_path=$4 AND idempotency_key=$5`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey).Scan(&digest, &guestID); err != nil {
		return product.GuestBinding{}, product.ErrStoreUnavailable
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 {
		return product.GuestBinding{}, product.ErrIdempotencyConflict
	}
	var binding product.GuestBinding
	var capabilities []byte
	if err := tx.QueryRow(ctx, `SELECT tenant_id,workspace_id,slot_key,slot_profile_id,slot_generation,binding_generation,guest_id,protocol_version,capabilities,state,expires_at FROM sandbox_runtime_product.guest_bindings WHERE tenant_id=$1 AND guest_id=$2`, command.TenantID, guestID).Scan(&binding.TenantID, &binding.WorkspaceID, &binding.SlotKey, &binding.SlotProfileID, &binding.SlotGeneration, &binding.BindingGeneration, &binding.GuestID, &binding.ProtocolVersion, &capabilities, &binding.State, &binding.ExpiresAt); err != nil {
		return product.GuestBinding{}, product.ErrStoreUnavailable
	}
	if err := json.Unmarshal(capabilities, &binding.Capabilities); err != nil {
		return product.GuestBinding{}, product.ErrStoreUnavailable
	}
	return binding, nil
}

func capabilityIntersection(configured, offered []string) []string {
	set := make(map[string]struct{}, len(offered))
	for _, value := range offered {
		set[value] = struct{}{}
	}
	selected := make([]string, 0, len(configured))
	for _, value := range configured {
		if _, ok := set[value]; ok {
			selected = append(selected, value)
		}
	}
	sort.Strings(selected)
	return selected
}
