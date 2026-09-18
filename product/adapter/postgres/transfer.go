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

func (s *Store) BeginUpload(ctx context.Context, command product.BeginTransferCommand) (product.TransferRecord, bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	tag, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.mutation_idempotency(tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)VALUES($1,$2,$3,'POST',$4,$5,$6,'blob_transfer',$7,$8,$9)ON CONFLICT DO NOTHING`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:], command.TransferID, now, now.Add(idempotencyRetention))
	if err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	if tag.RowsAffected() == 0 {
		record, err := loadRetainedTransfer(opCtx, tx, command)
		return record, true, err
	}
	var workspaceVersion int64
	var ownerType, ownerID string
	err = tx.QueryRow(opCtx, `SELECT version,owner_actor_type,owner_actor_id FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE`, command.TenantID, command.WorkspaceID).Scan(&workspaceVersion, &ownerType, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.TransferRecord{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	if workspaceVersion != command.Request.ExpectedWorkspaceVersion {
		return product.TransferRecord{}, false, product.ErrVersionConflict
	}
	if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7346273421))`, command.TenantID); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	var maxTransfers int
	if err := tx.QueryRow(opCtx, `SELECT COALESCE((SELECT max_active_transfers FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),10)`, command.TenantID).Scan(&maxTransfers); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	var active int
	if err := tx.QueryRow(opCtx, `SELECT count(*) FROM sandbox_runtime_product.blob_transfers WHERE tenant_id=$1 AND state IN('pending','transferring','cleanup_pending')`, command.TenantID).Scan(&active); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	if active >= maxTransfers {
		return product.TransferRecord{}, false, product.ErrQuotaExceeded
	}
	expires := now.Add(time.Duration(command.Request.ExpiresInSeconds) * time.Second)
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.blob_transfers(tenant_id,transfer_id,workspace_id,actor_type,actor_id,direction,digest,size_bytes,committed_bytes,state,version,object_reference,expires_at,created_at,updated_at)VALUES($1,$2,$3,$4,$5,'upload',$6,$7,0,'pending',1,$8,$9,$10,$10)`, command.TenantID, command.TransferID, command.WorkspaceID, string(command.Actor.Type), command.Actor.ID, command.Request.Digest, command.Request.SizeBytes, command.ObjectReference, expires, now); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, command.WorkspaceID, "", now)
	if err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	attributes, _ := json.Marshal(map[string]any{"direction": "upload", "digest": command.Request.Digest, "size_bytes": command.Request.SizeBytes})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,'transfer.started','transfer',$5,$6,$7,$8,$9)`, command.TenantID, command.WorkspaceID, sequence, command.EventID, command.TransferID, string(command.Actor.Type), command.Actor.ID, now, attributes); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "transfer.begin", "transfer", command.TransferID, "allowed", "authorized", now); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.TransferRecord{}, false, product.ErrStoreOutcomeUnknown
	}
	return product.TransferRecord{TenantID: command.TenantID, ObjectReference: command.ObjectReference, Actor: command.Actor, BlobTransfer: product.BlobTransfer{ID: command.TransferID, WorkspaceID: command.WorkspaceID, Direction: "upload", Digest: command.Request.Digest, SizeBytes: command.Request.SizeBytes, State: "pending", Version: 1, ExpiresAt: expires, CreatedAt: now, UpdatedAt: now}}, false, nil
}

func (s *Store) GetTransfer(ctx context.Context, tenantID string, actor product.ActorRef, transferID string) (product.TransferRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	record, err := scanTransfer(s.pool.QueryRow(opCtx, `SELECT tenant_id,transfer_id,workspace_id,actor_type,actor_id,direction,digest,size_bytes,committed_bytes,state,version,object_reference,expires_at,created_at,updated_at FROM sandbox_runtime_product.blob_transfers WHERE tenant_id=$1 AND transfer_id=$2 AND actor_type=$3 AND actor_id=$4`, tenantID, transferID, string(actor.Type), actor.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.TransferRecord{}, product.ErrNotFound
	}
	if err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	return record, nil
}

func (s *Store) RecordTransferProgress(ctx context.Context, tenantID, transferID string, committed int64) (product.TransferRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	row := s.pool.QueryRow(opCtx, `UPDATE sandbox_runtime_product.blob_transfers SET committed_bytes=$1,state=CASE WHEN $1=0 THEN 'pending' ELSE 'transferring' END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$2 AND transfer_id=$3 AND state IN('pending','transferring') AND committed_bytes<=$1 AND size_bytes>=$1 AND expires_at>clock_timestamp() RETURNING tenant_id,transfer_id,workspace_id,actor_type,actor_id,direction,digest,size_bytes,committed_bytes,state,version,object_reference,expires_at,created_at,updated_at`, committed, tenantID, transferID)
	record, err := scanTransfer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.TransferRecord{}, product.ErrControlStale
	}
	if err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	return record, nil
}

func (s *Store) CompleteTransfer(ctx context.Context, tenantID, transferID, objectReference string, committed int64) (product.TransferRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	record, err := scanTransfer(s.pool.QueryRow(opCtx, `UPDATE sandbox_runtime_product.blob_transfers SET committed_bytes=$1,state='complete',version=version+1,object_reference=$2,completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE tenant_id=$3 AND transfer_id=$4 AND direction='upload' AND state IN('pending','transferring') AND size_bytes=$1 RETURNING tenant_id,transfer_id,workspace_id,actor_type,actor_id,direction,digest,size_bytes,committed_bytes,state,version,object_reference,expires_at,created_at,updated_at`, committed, objectReference, tenantID, transferID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.TransferRecord{}, product.ErrControlStale
	}
	if err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	return record, nil
}

func (s *Store) FailTransfer(ctx context.Context, tenantID, transferID, code string) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	_, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.blob_transfers SET state='failed',error_code=$1,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$2 AND transfer_id=$3 AND state IN('pending','transferring')`, code, tenantID, transferID)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (s *Store) CancelTransfer(ctx context.Context, tenantID string, actor product.ActorRef, transferID string) (product.TransferRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	record, err := scanTransfer(s.pool.QueryRow(opCtx, `UPDATE sandbox_runtime_product.blob_transfers SET state='cleanup_pending',error_code='cancelled',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND transfer_id=$2 AND actor_type=$3 AND actor_id=$4 AND direction='upload' AND state IN('pending','transferring','failed') RETURNING tenant_id,transfer_id,workspace_id,actor_type,actor_id,direction,digest,size_bytes,committed_bytes,state,version,object_reference,expires_at,created_at,updated_at`, tenantID, transferID, string(actor.Type), actor.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.TransferRecord{}, product.ErrControlStale
	}
	if err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	return record, nil
}

func (s *Store) MarkTransferClean(ctx context.Context, tenantID, transferID string) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tag, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.blob_transfers SET state=CASE WHEN error_code='expired' THEN 'expired' ELSE 'cancelled' END,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND transfer_id=$2 AND state='cleanup_pending'`, tenantID, transferID)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if tag.RowsAffected() == 0 {
		return product.ErrControlStale
	}
	return nil
}

func (s *Store) LeaseTransferCleanup(ctx context.Context, limit int) ([]product.TransferCleanup, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	rows, err := tx.Query(opCtx, `WITH candidates AS (
SELECT tenant_id,transfer_id FROM sandbox_runtime_product.blob_transfers
WHERE direction='upload' AND (state='cleanup_pending' OR (expires_at<=clock_timestamp() AND state IN('pending','transferring','failed')))
ORDER BY expires_at,transfer_id FOR UPDATE SKIP LOCKED LIMIT $1
), marked AS (
UPDATE sandbox_runtime_product.blob_transfers t SET state='cleanup_pending',error_code=CASE WHEN t.state='cleanup_pending' THEN t.error_code ELSE 'expired' END,version=t.version+1,updated_at=clock_timestamp()
FROM candidates c WHERE t.tenant_id=c.tenant_id AND t.transfer_id=c.transfer_id
RETURNING t.tenant_id,t.transfer_id,t.object_reference)
SELECT tenant_id,transfer_id,object_reference FROM marked`, limit)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	defer rows.Close()
	work := make([]product.TransferCleanup, 0)
	for rows.Next() {
		var item product.TransferCleanup
		if err := rows.Scan(&item.TenantID, &item.TransferID, &item.ObjectReference); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		work = append(work, item)
	}
	if rows.Err() != nil {
		return nil, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return nil, product.ErrStoreOutcomeUnknown
	}
	return work, nil
}

func (s *Store) CommitRevision(ctx context.Context, command product.CommitRevisionCommand) (product.WorkspaceRevision, bool, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	tag, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.mutation_idempotency(tenant_id,actor_type,actor_id,method,normalized_path,idempotency_key,request_digest,result_type,result_id,created_at,expires_at)VALUES($1,$2,$3,'POST',$4,$5,$6,'workspace_revision',$7,$8,$9)ON CONFLICT DO NOTHING`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey, command.RequestDigest[:], command.RevisionID, now, now.Add(idempotencyRetention))
	if err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	if tag.RowsAffected() == 0 {
		revision, err := loadRetainedRevision(opCtx, tx, command)
		return revision, true, err
	}
	var workspaceVersion int64
	var ownerType, ownerID string
	err = tx.QueryRow(opCtx, `SELECT version,owner_actor_type,owner_actor_id FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2 FOR UPDATE`, command.TenantID, command.WorkspaceID).Scan(&workspaceVersion, &ownerType, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(command.Actor.Type) || ownerID != command.Actor.ID) {
		return product.WorkspaceRevision{}, false, product.ErrNotFound
	}
	if err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	if workspaceVersion != command.Request.ExpectedWorkspaceVersion {
		return product.WorkspaceRevision{}, false, product.ErrVersionConflict
	}
	var currentHead string
	err = tx.QueryRow(opCtx, `SELECT revision_id FROM sandbox_runtime_product.workspace_heads WHERE tenant_id=$1 AND workspace_id=$2 AND branch_id='main' FOR UPDATE`, command.TenantID, command.WorkspaceID).Scan(&currentHead)
	if errors.Is(err, pgx.ErrNoRows) {
		currentHead = ""
	} else if err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	if currentHead != command.Request.ExpectedHeadRevisionID {
		return product.WorkspaceRevision{}, false, product.ErrVersionConflict
	}
	var manifestDigest, objectReference string
	var manifestSize int64
	err = tx.QueryRow(opCtx, `SELECT digest,object_reference,size_bytes FROM sandbox_runtime_product.blob_transfers WHERE tenant_id=$1 AND transfer_id=$2 AND workspace_id=$3 AND actor_type=$4 AND actor_id=$5 AND direction='upload' AND state='complete' FOR UPDATE`, command.TenantID, command.Request.UploadTransferID, command.WorkspaceID, string(command.Actor.Type), command.Actor.ID).Scan(&manifestDigest, &objectReference, &manifestSize)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.WorkspaceRevision{}, false, product.ErrControlStale
	}
	if err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	fileCount, contentSize := productManifestStats(command.Manifest)
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_revisions(tenant_id,revision_id,workspace_id,parent_revision_id,manifest_digest,manifest_size_bytes,object_reference,file_count,size_bytes,created_actor_type,created_actor_id,created_at)VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,$9,$10,$11,$12)`, command.TenantID, command.RevisionID, command.WorkspaceID, currentHead, manifestDigest, manifestSize, objectReference, fileCount, contentSize, string(command.Actor.Type), command.Actor.ID, now); err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	if currentHead == "" {
		_, err = tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_heads(tenant_id,workspace_id,branch_id,revision_id,version,updated_at)VALUES($1,$2,'main',$3,1,$4)`, command.TenantID, command.WorkspaceID, command.RevisionID, now)
	} else {
		_, err = tx.Exec(opCtx, `UPDATE sandbox_runtime_product.workspace_heads SET revision_id=$1,version=version+1,updated_at=$2 WHERE tenant_id=$3 AND workspace_id=$4 AND branch_id='main'`, command.RevisionID, now, command.TenantID, command.WorkspaceID)
	}
	if err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	sequence, err := lockWorkspaceAndAdvance(opCtx, tx, command.TenantID, command.WorkspaceID, "", now)
	if err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	attributes, _ := json.Marshal(map[string]any{"branch_id": "main", "parent_revision_id": currentHead, "manifest_digest": manifestDigest})
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.workspace_events(tenant_id,workspace_id,sequence,event_id,event_type,subject_type,subject_id,actor_type,actor_id,occurred_at,attributes)VALUES($1,$2,$3,$4,'revision.committed','revision',$5,$6,$7,$8,$9)`, command.TenantID, command.WorkspaceID, sequence, command.EventID, command.RevisionID, string(command.Actor.Type), command.Actor.ID, now, attributes); err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "revision.commit", "revision", command.RevisionID, "allowed", "authorized", now); err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.WorkspaceRevision{}, false, product.ErrStoreOutcomeUnknown
	}
	return product.WorkspaceRevision{ID: command.RevisionID, WorkspaceID: command.WorkspaceID, ParentRevisionID: currentHead, ManifestDigest: manifestDigest, FileCount: fileCount, SizeBytes: contentSize, CreatedBy: command.Actor, CreatedAt: now}, false, nil
}

func (s *Store) BeginRevisionDownload(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID, revisionID, transferID string) (product.TransferRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var digest, objectReference, ownerType, ownerID string
	var size int64
	err = tx.QueryRow(opCtx, `SELECT r.manifest_digest,r.manifest_size_bytes,r.object_reference,w.owner_actor_type,w.owner_actor_id FROM sandbox_runtime_product.workspace_revisions r JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=r.tenant_id AND w.workspace_id=r.workspace_id WHERE r.tenant_id=$1 AND r.workspace_id=$2 AND r.revision_id=$3`, tenantID, workspaceID, revisionID).Scan(&digest, &size, &objectReference, &ownerType, &ownerID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (ownerType != string(actor.Type) || ownerID != actor.ID) {
		return product.TransferRecord{}, product.ErrNotFound
	}
	if err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	expires := now.Add(5 * time.Minute)
	if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.blob_transfers(tenant_id,transfer_id,workspace_id,actor_type,actor_id,direction,digest,size_bytes,committed_bytes,state,version,object_reference,expires_at,created_at,updated_at,completed_at)VALUES($1,$2,$3,$4,$5,'download',$6,$7,$7,'complete',1,$8,$9,$10,$10,$10)`, tenantID, transferID, workspaceID, string(actor.Type), actor.ID, digest, size, objectReference, expires, now); err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.TransferRecord{}, product.ErrStoreOutcomeUnknown
	}
	return product.TransferRecord{TenantID: tenantID, ObjectReference: objectReference, Actor: actor, BlobTransfer: product.BlobTransfer{ID: transferID, WorkspaceID: workspaceID, Direction: "download", Digest: digest, SizeBytes: size, CommittedBytes: size, State: "complete", Version: 1, ExpiresAt: expires, CreatedAt: now, UpdatedAt: now}}, nil
}

func loadRetainedTransfer(ctx context.Context, tx pgx.Tx, command product.BeginTransferCommand) (product.TransferRecord, error) {
	var digest []byte
	var transferID string
	if err := tx.QueryRow(ctx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='POST' AND normalized_path=$4 AND idempotency_key=$5`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey).Scan(&digest, &transferID); err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 {
		return product.TransferRecord{}, product.ErrIdempotencyConflict
	}
	record, err := scanTransfer(tx.QueryRow(ctx, `SELECT tenant_id,transfer_id,workspace_id,actor_type,actor_id,direction,digest,size_bytes,committed_bytes,state,version,object_reference,expires_at,created_at,updated_at FROM sandbox_runtime_product.blob_transfers WHERE tenant_id=$1 AND transfer_id=$2`, command.TenantID, transferID))
	if err != nil {
		return product.TransferRecord{}, product.ErrStoreUnavailable
	}
	return record, nil
}

func loadRetainedRevision(ctx context.Context, tx pgx.Tx, command product.CommitRevisionCommand) (product.WorkspaceRevision, error) {
	var digest []byte
	var revisionID string
	if err := tx.QueryRow(ctx, `SELECT request_digest,result_id FROM sandbox_runtime_product.mutation_idempotency WHERE tenant_id=$1 AND actor_type=$2 AND actor_id=$3 AND method='POST' AND normalized_path=$4 AND idempotency_key=$5`, command.TenantID, string(command.Actor.Type), command.Actor.ID, command.Path, command.IdempotencyKey).Scan(&digest, &revisionID); err != nil {
		return product.WorkspaceRevision{}, product.ErrStoreUnavailable
	}
	if len(digest) != 32 || subtle.ConstantTimeCompare(digest, command.RequestDigest[:]) != 1 {
		return product.WorkspaceRevision{}, product.ErrIdempotencyConflict
	}
	return scanRevision(tx.QueryRow(ctx, `SELECT revision_id,workspace_id,COALESCE(parent_revision_id,''),manifest_digest,file_count,size_bytes,created_actor_type,created_actor_id,created_at FROM sandbox_runtime_product.workspace_revisions WHERE tenant_id=$1 AND revision_id=$2`, command.TenantID, revisionID))
}

type transferScanner interface{ Scan(...any) error }

func scanTransfer(row transferScanner) (product.TransferRecord, error) {
	var record product.TransferRecord
	var actorType string
	err := row.Scan(&record.TenantID, &record.ID, &record.WorkspaceID, &actorType, &record.Actor.ID, &record.Direction, &record.Digest, &record.SizeBytes, &record.CommittedBytes, &record.State, &record.Version, &record.ObjectReference, &record.ExpiresAt, &record.CreatedAt, &record.UpdatedAt)
	record.Actor.Type = product.ActorType(actorType)
	return record, err
}

func scanRevision(row transferScanner) (product.WorkspaceRevision, error) {
	var revision product.WorkspaceRevision
	var actorType string
	err := row.Scan(&revision.ID, &revision.WorkspaceID, &revision.ParentRevisionID, &revision.ManifestDigest, &revision.FileCount, &revision.SizeBytes, &actorType, &revision.CreatedBy.ID, &revision.CreatedAt)
	revision.CreatedBy.Type = product.ActorType(actorType)
	return revision, err
}

func productManifestStats(manifest product.RevisionManifest) (int, int64) {
	count := 0
	var size int64
	for _, entry := range manifest.Entries {
		if entry.Type == "file" {
			count++
			size += entry.SizeBytes
		}
	}
	return count, size
}

var _ product.TransferStore = (*Store)(nil)
