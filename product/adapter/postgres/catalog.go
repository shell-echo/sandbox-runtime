package productpostgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/shell-echo/sandbox-runtime/product"
)

func (s *Store) PublishArtifact(ctx context.Context, command product.PublishArtifactCommand) (product.Artifact, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.Artifact{}, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	var artifact product.Artifact
	var workspaceVersion int64
	var objectReference string
	err = tx.QueryRow(opCtx, `SELECT w.version,t.digest,t.size_bytes,t.object_reference,clock_timestamp()
FROM sandbox_runtime_product.workspaces w JOIN sandbox_runtime_product.blob_transfers t ON t.tenant_id=w.tenant_id AND t.workspace_id=w.workspace_id
WHERE w.tenant_id=$1 AND w.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4 AND t.transfer_id=$5 AND t.actor_type=$3 AND t.actor_id=$4 AND t.direction='upload' AND t.state='complete'
FOR UPDATE OF w,t`, command.TenantID, command.WorkspaceID, string(command.Actor.Type), command.Actor.ID, command.Request.UploadTransferID).Scan(&workspaceVersion, &artifact.Digest, &artifact.SizeBytes, &objectReference, &artifact.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.Artifact{}, product.ErrNotFound
	}
	if err != nil {
		return product.Artifact{}, storeError(ctx, opCtx, err, false)
	}
	if workspaceVersion != command.Request.ExpectedWorkspaceVersion {
		return product.Artifact{}, product.ErrVersionConflict
	}
	artifact.ID, artifact.WorkspaceID, artifact.SlotKey = command.ArtifactID, command.WorkspaceID, command.Request.SlotKey
	artifact.Name, artifact.MediaType, artifact.State, artifact.CreatedBy = command.Request.Name, command.Request.MediaType, "available", command.Actor
	_, err = tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.artifacts(tenant_id,artifact_id,workspace_id,slot_key,name,media_type,size_bytes,digest,state,object_reference,created_actor_type,created_actor_id,created_at)
VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,$8,'available',$9,$10,$11,$12)`, command.TenantID, artifact.ID, artifact.WorkspaceID, artifact.SlotKey, artifact.Name, artifact.MediaType, artifact.SizeBytes, artifact.Digest, objectReference, string(command.Actor.Type), command.Actor.ID, artifact.CreatedAt)
	if err != nil {
		return product.Artifact{}, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "artifact.publish", "artifact", artifact.ID, "allowed", "authorized", artifact.CreatedAt); err != nil {
		return product.Artifact{}, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.Artifact{}, storeError(ctx, opCtx, err, true)
	}
	return artifact, nil
}

func (s *Store) ListArtifacts(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID, cursor string, limit int) (product.ArtifactPage, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	if err := s.authorizeCatalogWorkspace(opCtx, tenantID, actor, workspaceID); err != nil {
		return product.ArtifactPage{}, err
	}
	query := `SELECT a.artifact_id,a.workspace_id,COALESCE(a.slot_key,''),a.name,a.media_type,a.size_bytes,a.digest,a.state,a.created_actor_type,a.created_actor_id,a.created_at
FROM sandbox_runtime_product.artifacts a JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=a.tenant_id AND w.workspace_id=a.workspace_id
WHERE a.tenant_id=$1 AND a.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4
ORDER BY a.created_at DESC,a.artifact_id DESC LIMIT $5`
	args := []any{tenantID, workspaceID, string(actor.Type), actor.ID, limit + 1}
	if cursor != "" {
		query = `SELECT a.artifact_id,a.workspace_id,COALESCE(a.slot_key,''),a.name,a.media_type,a.size_bytes,a.digest,a.state,a.created_actor_type,a.created_actor_id,a.created_at
FROM sandbox_runtime_product.artifacts a JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=a.tenant_id AND w.workspace_id=a.workspace_id
WHERE a.tenant_id=$1 AND a.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4 AND (a.created_at,a.artifact_id)<(SELECT created_at,artifact_id FROM sandbox_runtime_product.artifacts WHERE tenant_id=$1 AND workspace_id=$2 AND artifact_id=$5)
ORDER BY a.created_at DESC,a.artifact_id DESC LIMIT $6`
		args = []any{tenantID, workspaceID, string(actor.Type), actor.ID, cursor, limit + 1}
	}
	rows, err := s.pool.Query(opCtx, query, args...)
	if err != nil {
		return product.ArtifactPage{}, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	page := product.ArtifactPage{}
	for rows.Next() {
		item, err := scanArtifact(rows)
		if err != nil {
			return product.ArtifactPage{}, storeError(ctx, opCtx, err, false)
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return product.ArtifactPage{}, storeError(ctx, opCtx, err, false)
	}
	if len(page.Items) > limit {
		page.NextCursor = page.Items[limit-1].ID
		page.Items = page.Items[:limit]
	}
	return page, nil
}

func (s *Store) GetArtifact(ctx context.Context, tenantID string, actor product.ActorRef, artifactID string) (product.Artifact, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	item, err := scanArtifact(s.pool.QueryRow(opCtx, `SELECT a.artifact_id,a.workspace_id,COALESCE(a.slot_key,''),a.name,a.media_type,a.size_bytes,a.digest,a.state,a.created_actor_type,a.created_actor_id,a.created_at
FROM sandbox_runtime_product.artifacts a JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=a.tenant_id AND w.workspace_id=a.workspace_id
WHERE a.tenant_id=$1 AND a.artifact_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4`, tenantID, artifactID, string(actor.Type), actor.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.Artifact{}, product.ErrNotFound
	}
	if err != nil {
		return product.Artifact{}, storeError(ctx, opCtx, err, false)
	}
	return item, nil
}

func (s *Store) StartRecording(ctx context.Context, command product.StartRecordingCommand) (product.RecordingRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7346273419))`, command.TenantID+":"+command.Request.SessionID); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7346273423))`, command.TenantID); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	var policy, kind string
	var now time.Time
	err = tx.QueryRow(opCtx, `SELECT s.recording_policy,s.kind,clock_timestamp() FROM sandbox_runtime_product.runtime_sessions s JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=s.tenant_id AND w.workspace_id=s.workspace_id
WHERE s.tenant_id=$1 AND s.workspace_id=$2 AND s.session_id=$3 AND w.owner_actor_type=$4 AND w.owner_actor_id=$5 FOR UPDATE OF s,w`, command.TenantID, command.WorkspaceID, command.Request.SessionID, string(command.Actor.Type), command.Actor.ID).Scan(&policy, &kind, &now)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.RecordingRecord{}, product.ErrNotFound
	}
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if policy != "required" {
		return product.RecordingRecord{}, product.ErrForbidden
	}
	if (command.Request.RecordingType == "media") != (kind == product.SessionKindBrowserLive) || command.Request.RecordingType == "terminal" && kind != product.SessionKindTerminal {
		return product.RecordingRecord{}, product.ErrCapabilityUnsupported
	}
	var activeCount, activeLimit int
	var retainedBytes, byteLimit int64
	if err := tx.QueryRow(opCtx, `SELECT
    (SELECT count(*) FROM sandbox_runtime_product.recordings WHERE tenant_id=$1 AND state IN('recording','finalizing')),
    COALESCE((SELECT max_active_recordings FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),16),
    COALESCE((SELECT sum(COALESCE(size_bytes,0)) FROM sandbox_runtime_product.recordings WHERE tenant_id=$1 AND state IN('recording','finalizing','available')),0),
    COALESCE((SELECT max_recording_bytes FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),1073741824)`, command.TenantID).Scan(&activeCount, &activeLimit, &retainedBytes, &byteLimit); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if activeCount >= activeLimit || retainedBytes >= byteLimit {
		return product.RecordingRecord{}, product.ErrQuotaExceeded
	}
	var active bool
	if err := tx.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.recordings WHERE tenant_id=$1 AND session_id=$2 AND state IN('recording','finalizing','available'))`, command.TenantID, command.Request.SessionID).Scan(&active); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if active {
		return product.RecordingRecord{}, product.ErrControlConflict
	}
	record := product.RecordingRecord{Recording: product.Recording{ID: command.RecordingID, WorkspaceID: command.WorkspaceID, SessionID: command.Request.SessionID, Type: command.Request.RecordingType, State: "recording", StartedAt: now, RetentionExpiresAt: now.Add(time.Duration(command.Request.RetentionSeconds) * time.Second)}, TenantID: command.TenantID, KeyReference: command.KeyReference, ConsentReference: command.Request.ConsentReference}
	_, err = tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.recordings(tenant_id,recording_id,workspace_id,session_id,recording_type,state,encryption_key_reference,consent_reference,started_at,retention_expires_at) VALUES($1,$2,$3,$4,$5,'recording',$6,$7,$8,$9)`, record.TenantID, record.ID, record.WorkspaceID, record.SessionID, record.Type, record.KeyReference, record.ConsentReference, record.StartedAt, record.RetentionExpiresAt)
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if err := insertAudit(opCtx, tx, command.AuditID, command.TenantID, command.Actor, "recording.start", "recording", record.ID, "allowed", "consent_verified", now); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, true)
	}
	return record, nil
}

func (s *Store) GetRecording(ctx context.Context, tenantID string, actor product.ActorRef, recordingID string) (product.RecordingRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	record, err := scanRecording(s.pool.QueryRow(opCtx, recordingSelect+` WHERE r.tenant_id=$1 AND r.recording_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4`, tenantID, recordingID, string(actor.Type), actor.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return product.RecordingRecord{}, product.ErrNotFound
	}
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	record.Segments, err = s.loadRecordingSegments(opCtx, tenantID, recordingID)
	return record, err
}

func (s *Store) ListRecordings(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID, cursor string, limit int) (product.RecordingPage, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	if err := s.authorizeCatalogWorkspace(opCtx, tenantID, actor, workspaceID); err != nil {
		return product.RecordingPage{}, err
	}
	query := recordingSelect + ` WHERE r.tenant_id=$1 AND r.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4 ORDER BY r.started_at DESC,r.recording_id DESC LIMIT $5`
	args := []any{tenantID, workspaceID, string(actor.Type), actor.ID, limit + 1}
	if cursor != "" {
		query = recordingSelect + ` WHERE r.tenant_id=$1 AND r.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4 AND (r.started_at,r.recording_id)<(SELECT started_at,recording_id FROM sandbox_runtime_product.recordings WHERE tenant_id=$1 AND workspace_id=$2 AND recording_id=$5) ORDER BY r.started_at DESC,r.recording_id DESC LIMIT $6`
		args = []any{tenantID, workspaceID, string(actor.Type), actor.ID, cursor, limit + 1}
	}
	rows, err := s.pool.Query(opCtx, query, args...)
	if err != nil {
		return product.RecordingPage{}, storeError(ctx, opCtx, err, false)
	}
	defer rows.Close()
	page := product.RecordingPage{}
	for rows.Next() {
		record, err := scanRecording(rows)
		if err != nil {
			return product.RecordingPage{}, storeError(ctx, opCtx, err, false)
		}
		page.Items = append(page.Items, record.Recording)
	}
	if err := rows.Err(); err != nil {
		return product.RecordingPage{}, storeError(ctx, opCtx, err, false)
	}
	if len(page.Items) > limit {
		page.NextCursor = page.Items[limit-1].ID
		page.Items = page.Items[:limit]
	}
	return page, nil
}

func (s *Store) AppendRecordingSegment(ctx context.Context, tenantID, recordingID string, sequence int64, reference, digest, previous string, size int64, startedAt, completedAt time.Time) (product.RecordingRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	if _, err := tx.Exec(opCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7346273423))`, tenantID); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	var state string
	var count int64
	var retainedPrevious string
	var retainedSize int64
	if err := tx.QueryRow(opCtx, `SELECT state FROM sandbox_runtime_product.recordings WHERE tenant_id=$1 AND recording_id=$2 FOR UPDATE`, tenantID, recordingID).Scan(&state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return product.RecordingRecord{}, product.ErrNotFound
		}
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if err := tx.QueryRow(opCtx, `SELECT COUNT(sequence),COALESCE((SELECT digest FROM sandbox_runtime_product.recording_segments WHERE tenant_id=$1 AND recording_id=$2 ORDER BY sequence DESC LIMIT 1),''),COALESCE(SUM(size_bytes),0) FROM sandbox_runtime_product.recording_segments WHERE tenant_id=$1 AND recording_id=$2`, tenantID, recordingID).Scan(&count, &retainedPrevious, &retainedSize); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if state != "recording" || sequence != count+1 || previous != retainedPrevious || retainedSize+size > product.MaxRecordingBytes {
		return product.RecordingRecord{}, product.ErrVersionConflict
	}
	var tenantBytes, tenantLimit int64
	if err := tx.QueryRow(opCtx, `SELECT
    COALESCE((SELECT sum(COALESCE(size_bytes,0)) FROM sandbox_runtime_product.recordings WHERE tenant_id=$1 AND state IN('recording','finalizing','available')),0),
    COALESCE((SELECT max_recording_bytes FROM sandbox_runtime_product.tenant_quotas WHERE tenant_id=$1),1073741824)`, tenantID).Scan(&tenantBytes, &tenantLimit); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if tenantBytes+size > tenantLimit {
		return product.RecordingRecord{}, product.ErrQuotaExceeded
	}
	_, err = tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.recording_segments(tenant_id,recording_id,sequence,object_reference,digest,previous_digest,size_bytes,started_at,completed_at) VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9)`, tenantID, recordingID, sequence, reference, digest, previous, size, startedAt, completedAt)
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if _, err := tx.Exec(opCtx, `UPDATE sandbox_runtime_product.recordings SET size_bytes=$3 WHERE tenant_id=$1 AND recording_id=$2`, tenantID, recordingID, retainedSize+size); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if err := tx.Commit(opCtx); err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, true)
	}
	return s.getRecordingInternal(ctx, tenantID, recordingID)
}

func (s *Store) FinalizeRecording(ctx context.Context, tenantID, recordingID, digest string, size int64, completedAt time.Time) (product.RecordingRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tag, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.recordings r SET state='available',digest=$3,size_bytes=$4,completed_at=$5,integrity_manifest_reference='hash-chain:'||$3 WHERE tenant_id=$1 AND recording_id=$2 AND state='recording' AND size_bytes=$4 AND EXISTS(SELECT 1 FROM sandbox_runtime_product.recording_segments s WHERE s.tenant_id=r.tenant_id AND s.recording_id=r.recording_id AND s.digest=$3 AND s.sequence=(SELECT MAX(sequence) FROM sandbox_runtime_product.recording_segments WHERE tenant_id=$1 AND recording_id=$2))`, tenantID, recordingID, digest, size, completedAt)
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() != 1 {
		return product.RecordingRecord{}, product.ErrControlStale
	}
	return s.getRecordingInternal(ctx, tenantID, recordingID)
}

func (s *Store) FailRecording(ctx context.Context, tenantID string, actor product.ActorRef, recordingID string, completedAt time.Time) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tag, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.recordings r SET state='failed',completed_at=$5
FROM sandbox_runtime_product.workspaces w
WHERE r.tenant_id=$1 AND r.recording_id=$2 AND r.state IN('recording','finalizing')
AND w.tenant_id=r.tenant_id AND w.workspace_id=r.workspace_id AND w.owner_actor_type=$3 AND w.owner_actor_id=$4`, tenantID, recordingID, string(actor.Type), actor.ID, completedAt)
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() != 1 {
		return product.ErrNotFound
	}
	return nil
}

func (s *Store) LeaseExpiredRecordings(ctx context.Context, limit int) ([]product.RecordingCleanup, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	defer rollbackBounded(tx, s.operationTimeout)
	rows, err := tx.Query(opCtx, `WITH selected AS (SELECT tenant_id,recording_id FROM sandbox_runtime_product.recordings WHERE state IN('recording','available','failed','expired') AND retention_expires_at<=clock_timestamp() ORDER BY retention_expires_at FOR UPDATE SKIP LOCKED LIMIT $1) UPDATE sandbox_runtime_product.recordings r SET state='expired' FROM selected s WHERE r.tenant_id=s.tenant_id AND r.recording_id=s.recording_id RETURNING r.tenant_id,r.recording_id,r.encryption_key_reference`, limit)
	if err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	var items []product.RecordingCleanup
	for rows.Next() {
		var item product.RecordingCleanup
		if err := rows.Scan(&item.TenantID, &item.RecordingID, &item.KeyReference); err != nil {
			return nil, storeError(ctx, opCtx, err, false)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, storeError(ctx, opCtx, err, false)
	}
	rows.Close()
	for index := range items {
		refs, err := loadSegmentReferences(opCtx, tx, items[index].TenantID, items[index].RecordingID)
		if err != nil {
			return nil, err
		}
		items[index].ObjectReferences = refs
	}
	if err := tx.Commit(opCtx); err != nil {
		return nil, storeError(ctx, opCtx, err, true)
	}
	return items, nil
}

func (s *Store) MarkRecordingDeleted(ctx context.Context, tenantID, recordingID string, deletedAt time.Time) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tag, err := s.pool.Exec(opCtx, `UPDATE sandbox_runtime_product.recordings SET state='deleted',deleted_at=$3 WHERE tenant_id=$1 AND recording_id=$2 AND state='expired'`, tenantID, recordingID, deletedAt)
	if err != nil {
		return storeError(ctx, opCtx, err, false)
	}
	if tag.RowsAffected() != 1 {
		return product.ErrControlStale
	}
	return nil
}

const recordingSelect = `SELECT r.recording_id,r.workspace_id,COALESCE(r.session_id,''),COALESCE(r.agent_run_id,''),r.recording_type,r.state,COALESCE(r.digest,''),COALESCE(r.size_bytes,0),r.started_at,COALESCE(r.completed_at,'epoch'::timestamptz),r.retention_expires_at,r.tenant_id,r.encryption_key_reference,r.consent_reference FROM sandbox_runtime_product.recordings r JOIN sandbox_runtime_product.workspaces w ON w.tenant_id=r.tenant_id AND w.workspace_id=r.workspace_id`

type catalogScanner interface{ Scan(...any) error }

func scanArtifact(row catalogScanner) (product.Artifact, error) {
	var item product.Artifact
	var actorType string
	err := row.Scan(&item.ID, &item.WorkspaceID, &item.SlotKey, &item.Name, &item.MediaType, &item.SizeBytes, &item.Digest, &item.State, &actorType, &item.CreatedBy.ID, &item.CreatedAt)
	item.CreatedBy.Type = product.ActorType(actorType)
	return item, err
}
func scanRecording(row catalogScanner) (product.RecordingRecord, error) {
	var item product.RecordingRecord
	err := row.Scan(&item.ID, &item.WorkspaceID, &item.SessionID, &item.AgentRunID, &item.Type, &item.State, &item.Digest, &item.SizeBytes, &item.StartedAt, &item.CompletedAt, &item.RetentionExpiresAt, &item.TenantID, &item.KeyReference, &item.ConsentReference)
	return item, err
}

func (s *Store) getRecordingInternal(ctx context.Context, tenantID, recordingID string) (product.RecordingRecord, error) {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	record, err := scanRecording(s.pool.QueryRow(opCtx, recordingSelect+` WHERE r.tenant_id=$1 AND r.recording_id=$2`, tenantID, recordingID))
	if err != nil {
		return product.RecordingRecord{}, storeError(ctx, opCtx, err, false)
	}
	record.Segments, err = s.loadRecordingSegments(opCtx, tenantID, recordingID)
	return record, err
}
func (s *Store) loadRecordingSegments(ctx context.Context, tenantID, recordingID string) ([]product.RecordingSegment, error) {
	rows, err := s.pool.Query(ctx, `SELECT sequence,object_reference,digest,COALESCE(previous_digest,''),size_bytes,started_at,completed_at FROM sandbox_runtime_product.recording_segments WHERE tenant_id=$1 AND recording_id=$2 ORDER BY sequence`, tenantID, recordingID)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	defer rows.Close()
	var result []product.RecordingSegment
	for rows.Next() {
		var item product.RecordingSegment
		if err := rows.Scan(&item.Sequence, &item.ObjectReference, &item.Digest, &item.PreviousDigest, &item.SizeBytes, &item.StartedAt, &item.CompletedAt); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
func loadSegmentReferences(ctx context.Context, tx pgx.Tx, tenantID, recordingID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT object_reference FROM sandbox_runtime_product.recording_segments WHERE tenant_id=$1 AND recording_id=$2 ORDER BY sequence`, tenantID, recordingID)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		result = append(result, ref)
	}
	return result, rows.Err()
}

func (s *Store) authorizeCatalogWorkspace(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID string) error {
	var authorized bool
	err := s.pool.QueryRow(ctx, `SELECT true FROM sandbox_runtime_product.workspaces WHERE tenant_id=$1 AND workspace_id=$2 AND owner_actor_type=$3 AND owner_actor_id=$4`, tenantID, workspaceID, string(actor.Type), actor.ID).Scan(&authorized)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.ErrNotFound
	}
	if err != nil {
		return product.ErrStoreUnavailable
	}
	return nil
}

var _ product.CatalogStore = (*Store)(nil)
