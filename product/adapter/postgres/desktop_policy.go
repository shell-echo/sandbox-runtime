package productpostgres

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) PutDesktopPolicy(ctx context.Context, command product.DesktopPolicyCommand) (product.DesktopPolicy, bool, error) {
	if s == nil || s.pool == nil || ctx == nil || command.Actor.Validate() != nil || command.ExpectedRevision < 0 || command.Policy.Revision != command.ExpectedRevision+1 || command.Policy.Validate() != nil {
		return product.DesktopPolicy{}, false, product.ErrInvalid
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
	}
	resultID := command.WorkspaceID + ":" + strconv.FormatInt(command.Policy.Revision, 10)
	tag, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.mutation_idempotency
    (tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)
VALUES($1,$2,$3,'PUT',$4,$5,$6,'desktop_policy',$7,$8,$9) ON CONFLICT DO NOTHING`,
		command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey,
		command.RequestDigest[:], resultID, now, now.Add(idempotencyRetention))
	if err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() == 0 {
		var digest []byte
		var retainedResult string
		err := tx.QueryRow(opCtx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency
WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='PUT' AND normalized_path=$4 AND idempotency_key=$5`,
			command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey).Scan(&digest, &retainedResult)
		if err != nil {
			return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
		}
		if len(digest) != len(command.RequestDigest) || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 || retainedResult != resultID {
			return product.DesktopPolicy{}, false, product.ErrIdempotencyConflict
		}
		policy, err := loadDesktopPolicyRevision(opCtx, tx, command.TenantID, command.WorkspaceID, command.Policy.Revision)
		if err != nil {
			return product.DesktopPolicy{}, false, err
		}
		return policy, true, nil
	}

	var ownerType, ownerID string
	if err := tx.QueryRow(opCtx, `SELECT owner_actor_type,owner_actor_id FROM sandbox_runtime_product.workspaces
WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE`, command.TenantID, command.WorkspaceID).Scan(&ownerType, &ownerID); errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.DesktopPolicy{}, false, product.ErrNotFound
	} else if err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
	}
	var current int64
	if err := tx.QueryRow(opCtx, `SELECT COALESCE(max(revision),0) FROM sandbox_runtime_product.desktop_policy_revisions
WHERE tenant_id=$1 AND workspace_id=$2`, command.TenantID, command.WorkspaceID).Scan(&current); err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
	}
	if current != command.ExpectedRevision {
		return product.DesktopPolicy{}, false, product.ErrVersionConflict
	}
	document, err := json.Marshal(command.Policy)
	if err != nil {
		return product.DesktopPolicy{}, false, product.ErrInvalid
	}
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.desktop_policy_revisions
    (tenant_id,workspace_id,revision,policy,updated_by_actor_type,updated_by_actor_id,created_at)
VALUES($1,$2,$3,$4,$5,$6,$7)`, command.TenantID, command.WorkspaceID, command.Policy.Revision,
		document, string(command.Actor.Type), command.Actor.ID, now); err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "desktop_policy.update", "workspace", command.WorkspaceID, "allowed", "authorized", now); err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.DesktopPolicy{}, false, storeError(ctx, opCtx, err, true)
	}
	return command.Policy, false, nil
}

func (s *Store) CurrentDesktopPolicy(ctx context.Context, binding product.GatewayBinding) (product.DesktopPolicy, error) {
	if s == nil || s.pool == nil || ctx == nil || binding.ProtocolProfile != product.SessionProfileDesktop {
		return product.DesktopPolicy{}, product.ErrForbidden
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var document []byte
	err := s.pool.QueryRow(opCtx, `SELECT p.policy FROM sandbox_runtime_product.desktop_policy_revisions p
JOIN sandbox_runtime_product.runtime_sessions s ON s.tenant_id=p.tenant_id AND s.workspace_id=p.workspace_id
JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=p.tenant_id AND w.workspace_id=p.workspace_id
WHERE p.tenant_id=$1 AND p.workspace_id=$2 AND s.session_id=$3 AND s.slot_key=$4 AND s.slot_generation=$5
  AND s.kind='desktop' AND s.protocol_profile='product-desktop.v1'
  AND w.owner_actor_type=$6 AND w.owner_actor_id=$7
ORDER BY p.revision DESC LIMIT 1`, binding.TenantID, binding.WorkspaceID, binding.SessionID, binding.SlotKey, binding.SlotGeneration, string(binding.Actor.Type), binding.Actor.ID).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.DesktopPolicy{}, product.ErrForbidden
	}
	if err != nil {
		return product.DesktopPolicy{}, storeError(ctx, opCtx, err, false)
	}
	policy, err := decodeDesktopPolicy(document)
	if err != nil || policy.Validate() != nil {
		return product.DesktopPolicy{}, product.ErrStoreUnavailable
	}
	return policy, nil
}

func loadDesktopPolicyRevision(ctx context.Context, tx pgx.Tx, tenantID, workspaceID string, revision int64) (product.DesktopPolicy, error) {
	var document []byte
	if err := tx.QueryRow(ctx, `SELECT policy FROM sandbox_runtime_product.desktop_policy_revisions
WHERE tenant_id=$1 AND workspace_id=$2 AND revision=$3`, tenantID, workspaceID, revision).Scan(&document); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return product.DesktopPolicy{}, product.ErrStoreUnavailable
		}
		return product.DesktopPolicy{}, err
	}
	policy, err := decodeDesktopPolicy(document)
	if err != nil {
		return product.DesktopPolicy{}, product.ErrStoreUnavailable
	}
	return policy, nil
}

func decodeDesktopPolicy(document []byte) (product.DesktopPolicy, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var policy product.DesktopPolicy
	if err := decoder.Decode(&policy); err != nil {
		return product.DesktopPolicy{}, fmt.Errorf("decode Desktop policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return product.DesktopPolicy{}, errors.New("decode Desktop policy: trailing data")
	}
	return policy, nil
}

var _ product.DesktopPolicyStore = (*Store)(nil)
