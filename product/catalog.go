package product

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

const (
	MaxCatalogPageSize       = 200
	MaxRecordingSegmentBytes = 64 << 10
	MaxRecordingSegments     = 10000
	MaxRecordingBytes        = int64(256 << 20)
)

type Artifact struct {
	ID, WorkspaceID, SlotKey, Name, MediaType, Digest, State string
	SizeBytes                                                int64
	CreatedBy                                                ActorRef
	CreatedAt                                                time.Time
}

type Recording struct {
	ID, WorkspaceID, SessionID, AgentRunID, Type, State, Digest string
	SizeBytes                                                   int64
	StartedAt, CompletedAt, RetentionExpiresAt                  time.Time
}

type ArtifactPage struct {
	Items      []Artifact
	NextCursor string
}

type RecordingPage struct {
	Items      []Recording
	NextCursor string
}

type PublishArtifactRequest struct {
	ExpectedWorkspaceVersion int64
	UploadTransferID         string
	SlotKey                  string
	Name                     string
	MediaType                string
}

type PublishArtifactCommand struct {
	TenantID, ArtifactID, WorkspaceID string
	Actor                             ActorRef
	AuditID                           string
	Request                           PublishArtifactRequest
}

type StartRecordingRequest struct {
	SessionID        string
	RecordingType    string
	ConsentReference string
	RetentionSeconds int64
}

type StartRecordingCommand struct {
	TenantID, RecordingID, WorkspaceID, KeyReference string
	Actor                                            ActorRef
	AuditID                                          string
	Request                                          StartRecordingRequest
}

type RecordingRecord struct {
	Recording
	TenantID, KeyReference, ConsentReference string
	Segments                                 []RecordingSegment
}

type RecordingSegment struct {
	Sequence                                int64
	ObjectReference, Digest, PreviousDigest string
	SizeBytes                               int64
	StartedAt, CompletedAt                  time.Time
}

type RecordingCleanup struct {
	TenantID, RecordingID, KeyReference string
	ObjectReferences                    []string
}

type CatalogStore interface {
	PublishArtifact(context.Context, PublishArtifactCommand) (Artifact, error)
	ListArtifacts(context.Context, string, ActorRef, string, string, int) (ArtifactPage, error)
	GetArtifact(context.Context, string, ActorRef, string) (Artifact, error)
	StartRecording(context.Context, StartRecordingCommand) (RecordingRecord, error)
	GetRecording(context.Context, string, ActorRef, string) (RecordingRecord, error)
	ListRecordings(context.Context, string, ActorRef, string, string, int) (RecordingPage, error)
	AppendRecordingSegment(context.Context, string, string, int64, string, string, string, int64, time.Time, time.Time) (RecordingRecord, error)
	FinalizeRecording(context.Context, string, string, string, int64, time.Time) (RecordingRecord, error)
	FailRecording(context.Context, string, ActorRef, string, time.Time) error
	LeaseExpiredRecordings(context.Context, int) ([]RecordingCleanup, error)
	MarkRecordingDeleted(context.Context, string, string, time.Time) error
}

type RecordingContentStore interface {
	CreateKeyReference(context.Context, string, string) (string, error)
	PutSegment(context.Context, string, string, string, int64, []byte) (string, error)
	ReadSegment(context.Context, string, string, string, int64, string) ([]byte, error)
	DeleteSegments(context.Context, string, string, string, []string) error
	DeleteRecording(context.Context, string, string, string) error
}

type Redactor interface {
	Redact(context.Context, []byte) ([]byte, error)
}

type CatalogService struct {
	store CatalogStore
	ids   IDGenerator
}

func NewCatalogService(store CatalogStore, ids IDGenerator) (*CatalogService, error) {
	if nilInterface(store) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &CatalogService{store: store, ids: ids}, nil
}

func (s *CatalogService) PublishArtifact(ctx context.Context, tenantID string, actor ActorRef, workspaceID string, request PublishArtifactRequest) (Artifact, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || request.ExpectedWorkspaceVersion < 1 || !validIdentifier(request.UploadTransferID) || (request.SlotKey != "" && !validIdentifier(request.SlotKey)) || !validCatalogText(request.Name, 256) || !validCatalogText(request.MediaType, 256) {
		return Artifact{}, ErrInvalid
	}
	id, err := s.ids.NewID("art")
	if err != nil {
		return Artifact{}, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return Artifact{}, ErrStoreUnavailable
	}
	return s.store.PublishArtifact(ctx, PublishArtifactCommand{TenantID: tenantID, ArtifactID: id, WorkspaceID: workspaceID, Actor: actor, AuditID: auditID, Request: request})
}

func (s *CatalogService) ListArtifacts(ctx context.Context, tenantID string, actor ActorRef, workspaceID, cursor string, limit int) (ArtifactPage, error) {
	if !validCatalogRead(ctx, tenantID, actor, workspaceID, cursor, limit) {
		return ArtifactPage{}, ErrInvalid
	}
	return s.store.ListArtifacts(ctx, tenantID, actor, workspaceID, cursor, limit)
}

func (s *CatalogService) GetArtifact(ctx context.Context, tenantID string, actor ActorRef, artifactID string) (Artifact, error) {
	if ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(artifactID) {
		return Artifact{}, ErrInvalid
	}
	return s.store.GetArtifact(ctx, tenantID, actor, artifactID)
}

func (s *CatalogService) ListRecordings(ctx context.Context, tenantID string, actor ActorRef, workspaceID, cursor string, limit int) (RecordingPage, error) {
	if !validCatalogRead(ctx, tenantID, actor, workspaceID, cursor, limit) {
		return RecordingPage{}, ErrInvalid
	}
	return s.store.ListRecordings(ctx, tenantID, actor, workspaceID, cursor, limit)
}

func (s *CatalogService) GetRecording(ctx context.Context, tenantID string, actor ActorRef, recordingID string) (Recording, error) {
	if ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(recordingID) {
		return Recording{}, ErrInvalid
	}
	record, err := s.store.GetRecording(ctx, tenantID, actor, recordingID)
	return record.Recording, err
}

type RecordingService struct {
	store    CatalogStore
	content  RecordingContentStore
	redactor Redactor
	ids      IDGenerator
	clock    func() time.Time
}

func NewRecordingService(store CatalogStore, content RecordingContentStore, redactor Redactor, ids IDGenerator, clock func() time.Time) (*RecordingService, error) {
	if nilInterface(store) || nilInterface(content) || nilInterface(redactor) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	if clock == nil {
		clock = time.Now
	}
	return &RecordingService{store: store, content: content, redactor: redactor, ids: ids, clock: clock}, nil
}

func (s *RecordingService) Start(ctx context.Context, tenantID string, actor ActorRef, workspaceID string, request StartRecordingRequest) (Recording, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdentifier(request.SessionID) || (request.RecordingType != "terminal" && request.RecordingType != "media") || !validIdentifier(request.ConsentReference) || request.RetentionSeconds < 60 || request.RetentionSeconds > 30*24*3600 {
		return Recording{}, ErrInvalid
	}
	recordingID, err := s.ids.NewID("rec")
	if err != nil {
		return Recording{}, ErrStoreUnavailable
	}
	keyReference, err := s.content.CreateKeyReference(ctx, tenantID, recordingID)
	if err != nil {
		return Recording{}, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return Recording{}, ErrStoreUnavailable
	}
	record, err := s.store.StartRecording(ctx, StartRecordingCommand{TenantID: tenantID, RecordingID: recordingID, WorkspaceID: workspaceID, KeyReference: keyReference, Actor: actor, AuditID: auditID, Request: request})
	return record.Recording, err
}

func (s *RecordingService) Append(ctx context.Context, tenantID string, actor ActorRef, recordingID string, payload []byte) (Recording, error) {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(recordingID) || len(payload) < 1 || len(payload) > MaxRecordingSegmentBytes {
		return Recording{}, ErrInvalid
	}
	record, err := s.store.GetRecording(ctx, tenantID, actor, recordingID)
	if err != nil {
		return Recording{}, err
	}
	if record.State != "recording" || len(record.Segments) >= MaxRecordingSegments || record.SizeBytes+int64(len(payload)) > MaxRecordingBytes {
		return Recording{}, ErrControlStale
	}
	redacted, err := s.redactor.Redact(ctx, append([]byte(nil), payload...))
	if err != nil || len(redacted) < 1 || len(redacted) > MaxRecordingSegmentBytes {
		return Recording{}, ErrStoreUnavailable
	}
	sequence := int64(len(record.Segments) + 1)
	previous := ""
	if len(record.Segments) > 0 {
		previous = record.Segments[len(record.Segments)-1].Digest
	}
	digest := chainedRecordingDigest(previous, redacted)
	reference, err := s.content.PutSegment(ctx, tenantID, recordingID, record.KeyReference, sequence, redacted)
	if err != nil {
		return Recording{}, ErrStoreUnavailable
	}
	now := s.clock().UTC()
	updated, err := s.store.AppendRecordingSegment(ctx, tenantID, recordingID, sequence, reference, digest, previous, int64(len(redacted)), now, now)
	return updated.Recording, err
}

func (s *RecordingService) Finalize(ctx context.Context, tenantID string, actor ActorRef, recordingID string) (Recording, error) {
	record, err := s.store.GetRecording(ctx, tenantID, actor, recordingID)
	if err != nil {
		return Recording{}, err
	}
	if record.State == "available" {
		return record.Recording, nil
	}
	if record.State != "recording" || len(record.Segments) == 0 {
		return Recording{}, ErrControlStale
	}
	last := record.Segments[len(record.Segments)-1]
	updated, err := s.store.FinalizeRecording(ctx, tenantID, recordingID, last.Digest, record.SizeBytes, s.clock().UTC())
	return updated.Recording, err
}

func (s *RecordingService) Fail(ctx context.Context, tenantID string, actor ActorRef, recordingID string) error {
	if s == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(recordingID) {
		return ErrInvalid
	}
	return s.store.FailRecording(ctx, tenantID, actor, recordingID, s.clock().UTC())
}

func (s *RecordingService) Replay(ctx context.Context, tenantID string, actor ActorRef, recordingID string) ([][]byte, error) {
	record, err := s.store.GetRecording(ctx, tenantID, actor, recordingID)
	if err != nil {
		return nil, err
	}
	if record.State != "available" || len(record.Segments) == 0 {
		return nil, ErrControlStale
	}
	result := make([][]byte, 0, len(record.Segments))
	previous := ""
	var total int64
	for _, segment := range record.Segments {
		payload, err := s.content.ReadSegment(ctx, tenantID, recordingID, record.KeyReference, segment.Sequence, segment.ObjectReference)
		if err != nil || int64(len(payload)) != segment.SizeBytes || segment.PreviousDigest != previous || chainedRecordingDigest(previous, payload) != segment.Digest {
			return nil, ErrStoreUnavailable
		}
		total += int64(len(payload))
		if total > MaxRecordingBytes {
			return nil, ErrStoreUnavailable
		}
		result = append(result, payload)
		previous = segment.Digest
	}
	if previous != record.Digest || total != record.SizeBytes {
		return nil, ErrStoreUnavailable
	}
	return result, nil
}

func (s *RecordingService) CleanupExpired(ctx context.Context, limit int) (int, error) {
	if s == nil || ctx == nil || limit < 1 || limit > 100 {
		return 0, ErrInvalid
	}
	items, err := s.store.LeaseExpiredRecordings(ctx, limit)
	if err != nil {
		return 0, err
	}
	cleaned := 0
	for _, item := range items {
		if err := s.content.DeleteRecording(ctx, item.TenantID, item.RecordingID, item.KeyReference); err != nil {
			return cleaned, ErrStoreUnavailable
		}
		if err := s.store.MarkRecordingDeleted(ctx, item.TenantID, item.RecordingID, s.clock().UTC()); err != nil && !errors.Is(err, ErrControlStale) {
			return cleaned, err
		}
		cleaned++
	}
	return cleaned, nil
}

type PatternRedactor struct{ patterns [][]byte }

func NewPatternRedactor(patterns []string) (*PatternRedactor, error) {
	if len(patterns) < 1 || len(patterns) > 32 {
		return nil, ErrInvalid
	}
	redactor := &PatternRedactor{patterns: make([][]byte, 0, len(patterns))}
	for _, pattern := range patterns {
		if len(pattern) < 4 || len(pattern) > 512 {
			return nil, ErrInvalid
		}
		redactor.patterns = append(redactor.patterns, []byte(pattern))
	}
	return redactor, nil
}

func (r *PatternRedactor) Redact(ctx context.Context, payload []byte) ([]byte, error) {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalid
	}
	result := append([]byte(nil), payload...)
	for _, pattern := range r.patterns {
		result = bytes.ReplaceAll(result, pattern, []byte("[REDACTED]"))
	}
	return result, nil
}

func chainedRecordingDigest(previous string, payload []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(previous))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(payload)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func validCatalogRead(ctx context.Context, tenantID string, actor ActorRef, workspaceID, cursor string, limit int) bool {
	return ctx != nil && ctx.Err() == nil && validIdentifier(tenantID) && actor.Validate() == nil && validIdentifier(workspaceID) && len(cursor) <= 1024 && limit >= 1 && limit <= MaxCatalogPageSize
}

func validCatalogText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}
