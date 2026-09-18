package product

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	MaxTransferBytes = int64(1 << 30)
	MaxChunkBytes    = 1 << 20
	MaxManifestBytes = int64(16 << 20)
)

type BlobTransfer struct {
	ID, WorkspaceID, Direction, Digest, State string
	SizeBytes, CommittedBytes                 int64
	Version                                   int64
	ExpiresAt, CreatedAt, UpdatedAt           time.Time
}

type TransferRecord struct {
	BlobTransfer
	TenantID, ObjectReference string
	Actor                     ActorRef
}

type TransferCleanup struct {
	TenantID, TransferID, ObjectReference string
}

type BeginUploadRequest struct {
	ExpectedWorkspaceVersion int64
	Digest                   string
	SizeBytes                int64
	ExpiresInSeconds         int64
}

type BeginTransferCommand struct {
	TenantID, WorkspaceID, TransferID, ObjectReference string
	Actor                                              ActorRef
	EventID, AuditID, IdempotencyKey, Path             string
	RequestDigest                                      [32]byte
	Request                                            BeginUploadRequest
}

type RevisionManifest struct {
	Entries []RevisionManifestEntry `json:"entries"`
}
type RevisionManifestEntry struct {
	Path      string `json:"path"`
	Type      string `json:"type"`
	Mode      uint32 `json:"mode"`
	SizeBytes int64  `json:"size_bytes"`
	Digest    string `json:"digest,omitempty"`
}

type CommitRevisionRequest struct {
	ExpectedWorkspaceVersion int64
	ExpectedHeadRevisionID   string
	UploadTransferID         string
}
type WorkspaceRevision struct {
	ID, WorkspaceID, ParentRevisionID, ManifestDigest string
	FileCount                                         int
	SizeBytes                                         int64
	CreatedBy                                         ActorRef
	CreatedAt                                         time.Time
}
type CommitRevisionCommand struct {
	TenantID, WorkspaceID, RevisionID, IdempotencyKey, Path string
	Actor                                                   ActorRef
	EventID, AuditID                                        string
	RequestDigest                                           [32]byte
	Request                                                 CommitRevisionRequest
	Manifest                                                RevisionManifest
}

type TransferStore interface {
	BeginUpload(context.Context, BeginTransferCommand) (TransferRecord, bool, error)
	GetTransfer(context.Context, string, ActorRef, string) (TransferRecord, error)
	RecordTransferProgress(context.Context, string, string, int64) (TransferRecord, error)
	CompleteTransfer(context.Context, string, string, string, int64) (TransferRecord, error)
	FailTransfer(context.Context, string, string, string) error
	CancelTransfer(context.Context, string, ActorRef, string) (TransferRecord, error)
	MarkTransferClean(context.Context, string, string) error
	LeaseTransferCleanup(context.Context, int) ([]TransferCleanup, error)
	CommitRevision(context.Context, CommitRevisionCommand) (WorkspaceRevision, bool, error)
	BeginRevisionDownload(context.Context, string, ActorRef, string, string, string) (TransferRecord, error)
}

type BlobStore interface {
	EnsureStaging(context.Context, string) error
	Append(context.Context, string, int64, []byte) (int64, error)
	Inspect(context.Context, string) (int64, string, error)
	Commit(context.Context, string, string, int64) (string, error)
	Read(context.Context, string, int64, int) ([]byte, bool, error)
	Delete(context.Context, string) error
}

type TransferService struct {
	store TransferStore
	blobs BlobStore
	ids   IDGenerator
}

func NewTransferService(store TransferStore, blobs BlobStore, ids IDGenerator) (*TransferService, error) {
	if nilInterface(store) || nilInterface(blobs) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &TransferService{store: store, blobs: blobs, ids: ids}, nil
}

func (s *TransferService) BeginUpload(ctx context.Context, tenantID string, actor ActorRef, workspaceID, key string, request BeginUploadRequest) (BlobTransfer, bool, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdempotencyKey(key) || request.ExpectedWorkspaceVersion < 1 || !validDigest(request.Digest) || request.SizeBytes < 0 || request.SizeBytes > MaxTransferBytes || request.ExpiresInSeconds < 60 || request.ExpiresInSeconds > 3600 {
		return BlobTransfer{}, false, ErrInvalid
	}
	transferID, err := s.ids.NewID("xfer")
	if err != nil {
		return BlobTransfer{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return BlobTransfer{}, false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return BlobTransfer{}, false, ErrStoreUnavailable
	}
	encoded, _ := json.Marshal(request)
	digest := sha256.Sum256(encoded)
	record, replay, err := s.store.BeginUpload(ctx, BeginTransferCommand{TenantID: tenantID, WorkspaceID: workspaceID, TransferID: transferID, ObjectReference: "staging:" + transferID, Actor: actor, EventID: eventID, AuditID: auditID, IdempotencyKey: key, Path: "/internal/v1/workspaces/" + workspaceID + "/transfers", RequestDigest: digest, Request: request})
	if err != nil {
		return BlobTransfer{}, false, err
	}
	if record.State == "pending" || record.State == "transferring" {
		if err := s.blobs.EnsureStaging(ctx, record.ObjectReference); err != nil {
			return record.BlobTransfer, replay, ErrStoreUnavailable
		}
	}
	return record.BlobTransfer, replay, nil
}

func (s *TransferService) Resume(ctx context.Context, tenantID string, actor ActorRef, transferID string) (BlobTransfer, error) {
	record, err := s.store.GetTransfer(ctx, tenantID, actor, transferID)
	if err != nil {
		return BlobTransfer{}, err
	}
	if record.Direction == "upload" && record.State == "complete" {
		return record.BlobTransfer, nil
	}
	if record.Direction != "upload" || (record.State != "pending" && record.State != "transferring") {
		return BlobTransfer{}, ErrControlStale
	}
	size, _, err := s.blobs.Inspect(ctx, record.ObjectReference)
	if err != nil || size > record.SizeBytes {
		return BlobTransfer{}, ErrStoreUnavailable
	}
	if size != record.CommittedBytes {
		record, err = s.store.RecordTransferProgress(ctx, tenantID, transferID, size)
	}
	return record.BlobTransfer, err
}

func (s *TransferService) Append(ctx context.Context, tenantID string, actor ActorRef, transferID string, offset int64, chunk []byte) (BlobTransfer, error) {
	if len(chunk) < 1 || len(chunk) > MaxChunkBytes || offset < 0 {
		return BlobTransfer{}, ErrInvalid
	}
	record, err := s.store.GetTransfer(ctx, tenantID, actor, transferID)
	if err != nil {
		return BlobTransfer{}, err
	}
	if record.Direction != "upload" || (record.State != "pending" && record.State != "transferring") || offset != record.CommittedBytes || offset+int64(len(chunk)) > record.SizeBytes {
		return BlobTransfer{}, ErrVersionConflict
	}
	committed, err := s.blobs.Append(ctx, record.ObjectReference, offset, append([]byte(nil), chunk...))
	if err != nil {
		return BlobTransfer{}, ErrStoreUnavailable
	}
	updated, err := s.store.RecordTransferProgress(ctx, tenantID, transferID, committed)
	return updated.BlobTransfer, err
}

func (s *TransferService) Complete(ctx context.Context, tenantID string, actor ActorRef, transferID string) (BlobTransfer, error) {
	record, err := s.store.GetTransfer(ctx, tenantID, actor, transferID)
	if err != nil {
		return BlobTransfer{}, err
	}
	if record.Direction == "upload" && record.State == "complete" {
		return record.BlobTransfer, nil
	}
	if record.Direction != "upload" || (record.State != "pending" && record.State != "transferring") {
		return BlobTransfer{}, ErrControlStale
	}
	size, digest, err := s.blobs.Inspect(ctx, record.ObjectReference)
	if err != nil {
		return BlobTransfer{}, ErrStoreUnavailable
	}
	if size != record.SizeBytes || digest != record.Digest {
		_ = s.store.FailTransfer(ctx, tenantID, transferID, "digest_mismatch")
		return BlobTransfer{}, ErrInvalid
	}
	finalReference, err := s.blobs.Commit(ctx, record.ObjectReference, digest, size)
	if err != nil {
		return BlobTransfer{}, ErrStoreUnavailable
	}
	completed, err := s.store.CompleteTransfer(ctx, tenantID, transferID, finalReference, size)
	if errors.Is(err, ErrControlStale) {
		retained, readErr := s.store.GetTransfer(ctx, tenantID, actor, transferID)
		if readErr == nil && retained.Direction == "upload" && retained.State == "complete" && retained.Digest == record.Digest {
			return retained.BlobTransfer, nil
		}
	}
	return completed.BlobTransfer, err
}

func (s *TransferService) Cancel(ctx context.Context, tenantID string, actor ActorRef, transferID string) error {
	record, err := s.store.CancelTransfer(ctx, tenantID, actor, transferID)
	if err != nil {
		return err
	}
	if err := s.blobs.Delete(ctx, record.ObjectReference); err != nil {
		return ErrStoreUnavailable
	}
	return s.store.MarkTransferClean(ctx, tenantID, transferID)
}

func (s *TransferService) CleanupExpired(ctx context.Context, limit int) (int, error) {
	if s == nil || ctx == nil || limit < 1 || limit > 100 {
		return 0, ErrInvalid
	}
	work, err := s.store.LeaseTransferCleanup(ctx, limit)
	if err != nil {
		return 0, err
	}
	cleaned := 0
	for _, item := range work {
		if err := s.blobs.Delete(ctx, item.ObjectReference); err != nil {
			return cleaned, ErrStoreUnavailable
		}
		if err := s.store.MarkTransferClean(ctx, item.TenantID, item.TransferID); err != nil && !errors.Is(err, ErrControlStale) {
			return cleaned, err
		}
		cleaned++
	}
	return cleaned, nil
}

func (s *TransferService) CommitRevision(ctx context.Context, tenantID string, actor ActorRef, workspaceID, key string, request CommitRevisionRequest) (WorkspaceRevision, bool, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdempotencyKey(key) || request.ExpectedWorkspaceVersion < 1 || !validIdentifier(request.UploadTransferID) || (request.ExpectedHeadRevisionID != "" && !validIdentifier(request.ExpectedHeadRevisionID)) {
		return WorkspaceRevision{}, false, ErrInvalid
	}
	upload, err := s.store.GetTransfer(ctx, tenantID, actor, request.UploadTransferID)
	if err != nil || upload.Direction != "upload" || upload.State != "complete" {
		return WorkspaceRevision{}, false, ErrControlStale
	}
	if upload.SizeBytes > MaxManifestBytes {
		return WorkspaceRevision{}, false, ErrInvalid
	}
	document, err := readCompleteBlob(ctx, s.blobs, upload.ObjectReference, upload.SizeBytes)
	if err != nil {
		return WorkspaceRevision{}, false, ErrStoreUnavailable
	}
	manifest, err := validateManifest(document)
	if err != nil {
		return WorkspaceRevision{}, false, err
	}
	revisionID, err := s.ids.NewID("rev")
	if err != nil {
		return WorkspaceRevision{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return WorkspaceRevision{}, false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return WorkspaceRevision{}, false, ErrStoreUnavailable
	}
	encoded, _ := json.Marshal(request)
	digest := sha256.Sum256(encoded)
	return s.store.CommitRevision(ctx, CommitRevisionCommand{TenantID: tenantID, WorkspaceID: workspaceID, RevisionID: revisionID, Actor: actor, EventID: eventID, AuditID: auditID, IdempotencyKey: key, Path: "/internal/v1/workspaces/" + workspaceID + "/revisions", RequestDigest: digest, Request: request, Manifest: manifest})
}

func readCompleteBlob(ctx context.Context, blobs BlobStore, reference string, expectedSize int64) ([]byte, error) {
	document := make([]byte, 0, int(expectedSize))
	for {
		chunk, eof, err := blobs.Read(ctx, reference, int64(len(document)), MaxChunkBytes)
		if err != nil {
			return nil, err
		}
		document = append(document, chunk...)
		if int64(len(document)) > expectedSize {
			return nil, ErrInvalid
		}
		if eof {
			break
		}
		if len(chunk) == 0 {
			return nil, ErrStoreUnavailable
		}
	}
	if int64(len(document)) != expectedSize {
		return nil, ErrInvalid
	}
	return document, nil
}

func (s *TransferService) BeginRevisionDownload(ctx context.Context, tenantID string, actor ActorRef, workspaceID, revisionID string) (BlobTransfer, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdentifier(revisionID) {
		return BlobTransfer{}, ErrInvalid
	}
	transferID, err := s.ids.NewID("xfer")
	if err != nil {
		return BlobTransfer{}, ErrStoreUnavailable
	}
	record, err := s.store.BeginRevisionDownload(ctx, tenantID, actor, workspaceID, revisionID, transferID)
	return record.BlobTransfer, err
}

func (s *TransferService) ReadDownload(ctx context.Context, tenantID string, actor ActorRef, transferID string, offset int64, limit int) ([]byte, bool, error) {
	if offset < 0 || limit < 1 || limit > MaxChunkBytes {
		return nil, false, ErrInvalid
	}
	record, err := s.store.GetTransfer(ctx, tenantID, actor, transferID)
	if err != nil {
		return nil, false, err
	}
	if record.Direction != "download" || record.State != "complete" {
		return nil, false, ErrControlStale
	}
	return s.blobs.Read(ctx, record.ObjectReference, offset, limit)
}

func validateManifest(document []byte) (RevisionManifest, error) {
	if len(document) < 2 || int64(len(document)) > MaxManifestBytes {
		return RevisionManifest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest RevisionManifest
	if err := decoder.Decode(&manifest); err != nil || len(manifest.Entries) > 100000 {
		return RevisionManifest{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return RevisionManifest{}, ErrInvalid
	}
	previous := ""
	var total int64
	for _, entry := range manifest.Entries {
		if !validGuestPath(entry.Path) || entry.Path == "" || entry.Path <= previous || (entry.Type != "file" && entry.Type != "directory") || entry.Mode > 4095 || entry.SizeBytes < 0 || (entry.Type == "file" && !validDigest(entry.Digest)) || (entry.Type == "directory" && (entry.Digest != "" || entry.SizeBytes != 0)) {
			return RevisionManifest{}, ErrInvalid
		}
		previous = entry.Path
		total += entry.SizeBytes
		if total < 0 || total > MaxTransferBytes {
			return RevisionManifest{}, ErrInvalid
		}
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, document) {
		return RevisionManifest{}, ErrInvalid
	}
	return manifest, nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func manifestStats(manifest RevisionManifest) (int, int64) {
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
