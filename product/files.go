package product

import (
	"context"
	"path"
	"strings"
	"time"
)

const MaxFilePageSize = 200

type FileEntry struct {
	Path, Name, Type, Revision string
	Mode                       uint32
	SizeBytes                  int64
	ModifiedAt                 time.Time
}
type FilePage struct {
	Items     []FileEntry
	NextAfter string
}
type FileChange struct {
	Sequence                 int64
	Path, PreviousPath, Type string
	Revision                 string
	OccurredAt               time.Time
}
type FileAuthority struct {
	TenantID, WorkspaceID, SlotKey, GuestID string
	SlotGeneration, BindingGeneration       int64
}
type FileSnapshot struct {
	Authority FileAuthority
	Entries   []FileEntry
}
type FileSnapshotCommand struct {
	TenantID, WorkspaceID, SlotKey string
	Actor                          ActorRef
	Snapshot                       FileSnapshot
}

type FileGuest interface {
	List(context.Context, string, string, string, string, string, int) (FilePage, FileAuthority, error)
	Stat(context.Context, string, string, string, string) (FileEntry, FileAuthority, error)
	Snapshot(context.Context, string, string, string, string) (FileSnapshot, error)
}
type FileStore interface {
	AuthorizeFileAccess(context.Context, string, ActorRef, string, string, string) error
	CheckFileAuthority(context.Context, FileAuthority) error
	ApplyFileSnapshot(context.Context, FileSnapshotCommand) ([]FileChange, error)
	ListFileChanges(context.Context, string, ActorRef, string, string, int64, int) ([]FileChange, error)
}

type FileService struct {
	store FileStore
	guest FileGuest
}

func NewFileService(store FileStore, guest FileGuest) (*FileService, error) {
	if nilInterface(store) || nilInterface(guest) {
		return nil, ErrInvalid
	}
	return &FileService{store: store, guest: guest}, nil
}

func (s *FileService) List(ctx context.Context, tenantID string, actor ActorRef, workspaceID, slotKey, guestPath, after string, limit int) (FilePage, error) {
	if err := validateFileRequest(ctx, s, tenantID, actor, workspaceID, slotKey, guestPath); err != nil {
		return FilePage{}, err
	}
	if limit < 1 || limit > MaxFilePageSize {
		return FilePage{}, ErrInvalid
	}
	if err := s.store.AuthorizeFileAccess(ctx, tenantID, actor, workspaceID, slotKey, "files.list"); err != nil {
		return FilePage{}, err
	}
	page, authority, err := s.guest.List(ctx, tenantID, workspaceID, slotKey, guestPath, after, limit)
	if err != nil {
		return FilePage{}, err
	}
	if err := s.store.CheckFileAuthority(ctx, authority); err != nil {
		return FilePage{}, err
	}
	return page, nil
}

func (s *FileService) Stat(ctx context.Context, tenantID string, actor ActorRef, workspaceID, slotKey, guestPath string) (FileEntry, error) {
	if err := validateFileRequest(ctx, s, tenantID, actor, workspaceID, slotKey, guestPath); err != nil {
		return FileEntry{}, err
	}
	if guestPath == "" {
		return FileEntry{}, ErrInvalid
	}
	if err := s.store.AuthorizeFileAccess(ctx, tenantID, actor, workspaceID, slotKey, "files.stat"); err != nil {
		return FileEntry{}, err
	}
	entry, authority, err := s.guest.Stat(ctx, tenantID, workspaceID, slotKey, guestPath)
	if err != nil {
		return FileEntry{}, err
	}
	if err := s.store.CheckFileAuthority(ctx, authority); err != nil {
		return FileEntry{}, err
	}
	return entry, nil
}

func (s *FileService) Refresh(ctx context.Context, tenantID string, actor ActorRef, workspaceID, slotKey, guestPath string) ([]FileChange, error) {
	if err := validateFileRequest(ctx, s, tenantID, actor, workspaceID, slotKey, guestPath); err != nil {
		return nil, ErrInvalid
	}
	if err := s.store.AuthorizeFileAccess(ctx, tenantID, actor, workspaceID, slotKey, "files.snapshot"); err != nil {
		return nil, err
	}
	snapshot, err := s.guest.Snapshot(ctx, tenantID, workspaceID, slotKey, guestPath)
	if err != nil {
		return nil, err
	}
	return s.store.ApplyFileSnapshot(ctx, FileSnapshotCommand{TenantID: tenantID, WorkspaceID: workspaceID, SlotKey: slotKey, Actor: actor, Snapshot: snapshot})
}

func (s *FileService) Changes(ctx context.Context, tenantID string, actor ActorRef, workspaceID, slotKey string, after int64, limit int) ([]FileChange, error) {
	if err := validateFileRequest(ctx, s, tenantID, actor, workspaceID, slotKey, ""); err != nil {
		return nil, err
	}
	if after < 0 || limit < 1 || limit > MaxFilePageSize {
		return nil, ErrInvalid
	}
	return s.store.ListFileChanges(ctx, tenantID, actor, workspaceID, slotKey, after, limit)
}

func validateFileRequest(ctx context.Context, service *FileService, tenantID string, actor ActorRef, workspaceID, slotKey, guestPath string) error {
	if service == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdentifier(slotKey) || !validGuestPath(guestPath) {
		return ErrInvalid
	}
	return ctx.Err()
}

func validGuestPath(value string) bool {
	if len(value) > 4096 || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\\") {
		return false
	}
	if value == "" {
		return true
	}
	return path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
}
