package productpostgres

import (
	"context"
	"encoding/hex"
	"errors"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shell-echo/sandbox-runtime/product"
)

const retainedFileChanges = 1000

func (s *Store) AuthorizeFileAccess(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID, slotKey, capability string) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var authorized bool
	if err := s.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.workspaces w JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=w.tenant_id AND s.workspace_id=w.workspace_id WHERE w.tenant_id=$1 AND w.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4 AND s.slot_key=$5 AND s.observed_state='ready')`, tenantID, workspaceID, string(actor.Type), actor.ID, slotKey).Scan(&authorized); err != nil {
		return product.ErrStoreUnavailable
	}
	if !authorized {
		return product.ErrNotFound
	}
	if err := s.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.guest_bindings g JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=g.tenant_id AND s.workspace_id=g.workspace_id AND s.slot_key=g.slot_key WHERE g.tenant_id=$1 AND g.workspace_id=$2 AND g.slot_key=$3 AND g.state='connected' AND g.expires_at>clock_timestamp() AND g.slot_generation=s.generation AND g.capabilities ? $4)`, tenantID, workspaceID, slotKey, capability).Scan(&authorized); err != nil {
		return product.ErrStoreUnavailable
	}
	if !authorized {
		return product.ErrCapabilityUnsupported
	}
	return nil
}

func (s *Store) CheckFileAuthority(ctx context.Context, authority product.FileAuthority) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var valid bool
	err := s.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.guest_bindings g JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=g.tenant_id AND s.workspace_id=g.workspace_id AND s.slot_key=g.slot_key WHERE g.tenant_id=$1 AND g.workspace_id=$2 AND g.slot_key=$3 AND g.guest_id=$4 AND g.binding_generation=$5 AND g.slot_generation=$6 AND g.state='connected' AND g.expires_at>clock_timestamp() AND s.generation=g.slot_generation AND s.observed_state='ready')`, authority.TenantID, authority.WorkspaceID, authority.SlotKey, authority.GuestID, authority.BindingGeneration, authority.SlotGeneration).Scan(&valid)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	if !valid {
		return product.ErrControlStale
	}
	return nil
}

func (s *Store) ApplyFileSnapshot(ctx context.Context, command product.FileSnapshotCommand) ([]product.FileChange, error) {
	if command.Snapshot.Authority.TenantID != command.TenantID || command.Snapshot.Authority.WorkspaceID != command.WorkspaceID || command.Snapshot.Authority.SlotKey != command.SlotKey || len(command.Snapshot.Entries) > 10000 {
		return nil, product.ErrInvalid
	}
	entries := make(map[string]product.FileEntry, len(command.Snapshot.Entries))
	for _, entry := range command.Snapshot.Entries {
		if !validSnapshotEntry(entry) {
			return nil, product.ErrInvalid
		}
		if _, duplicate := entries[entry.Path]; duplicate {
			return nil, product.ErrInvalid
		}
		entries[entry.Path] = entry
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	tx, err := s.pool.BeginTx(opCtx, pgx.TxOptions{})
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	defer rollbackBounded(tx, s.operationTimeout)
	if err := authorizeSnapshot(opCtx, tx, command); err != nil {
		return nil, err
	}
	current, err := loadFileEntries(opCtx, tx, command.TenantID, command.WorkspaceID, command.SlotKey)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	changes := diffFileEntries(current, entries)
	var now time.Time
	if err := tx.QueryRow(opCtx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, product.ErrStoreUnavailable
	}
	var sequence int64
	if err := tx.QueryRow(opCtx, `SELECT COALESCE(max(sequence),0) FROM sandbox_runtime_product.file_changes WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3`, command.TenantID, command.WorkspaceID, command.SlotKey).Scan(&sequence); err != nil {
		return nil, product.ErrStoreUnavailable
	}
	for index := range changes {
		sequence++
		changes[index].Sequence = sequence
		changes[index].OccurredAt = now
		if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.file_changes(tenant_id,workspace_id,slot_key,sequence,path,previous_path,change_type,revision,occurred_at)VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9)`, command.TenantID, command.WorkspaceID, command.SlotKey, sequence, changes[index].Path, changes[index].PreviousPath, changes[index].Type, changes[index].Revision, now); err != nil {
			return nil, product.ErrStoreUnavailable
		}
	}
	if _, err := tx.Exec(opCtx, `DELETE FROM sandbox_runtime_product.file_entries WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3`, command.TenantID, command.WorkspaceID, command.SlotKey); err != nil {
		return nil, product.ErrStoreUnavailable
	}
	paths := make([]string, 0, len(entries))
	for entryPath := range entries {
		paths = append(paths, entryPath)
	}
	sort.Strings(paths)
	for _, entryPath := range paths {
		entry := entries[entryPath]
		if _, err := tx.Exec(opCtx, `INSERT INTO sandbox_runtime_product.file_entries(tenant_id,workspace_id,slot_key,path,entry_type,mode,size_bytes,modified_at,revision,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, command.TenantID, command.WorkspaceID, command.SlotKey, entry.Path, entry.Type, int(entry.Mode), entry.SizeBytes, entry.ModifiedAt, entry.Revision, now); err != nil {
			return nil, product.ErrStoreUnavailable
		}
	}
	if sequence > retainedFileChanges {
		if _, err := tx.Exec(opCtx, `DELETE FROM sandbox_runtime_product.file_changes WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3 AND sequence <= $4`, command.TenantID, command.WorkspaceID, command.SlotKey, sequence-retainedFileChanges); err != nil {
			return nil, product.ErrStoreUnavailable
		}
	}
	if err := tx.Commit(opCtx); err != nil {
		return nil, product.ErrStoreOutcomeUnknown
	}
	return changes, nil
}

func (s *Store) ListFileChanges(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID, slotKey string, after int64, limit int) ([]product.FileChange, error) {
	if err := s.authorizeFileOwner(ctx, tenantID, actor, workspaceID, slotKey); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var minimum, maximum int64
	if err := s.pool.QueryRow(opCtx, `SELECT COALESCE(min(sequence),0),COALESCE(max(sequence),0) FROM sandbox_runtime_product.file_changes WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3`, tenantID, workspaceID, slotKey).Scan(&minimum, &maximum); err != nil {
		return nil, product.ErrStoreUnavailable
	}
	if after > maximum {
		return nil, product.ErrInvalid
	}
	if after > 0 && minimum > after+1 {
		return nil, product.ErrCursorExpired
	}
	rows, err := s.pool.Query(opCtx, `SELECT sequence,path,COALESCE(previous_path,''),change_type,revision,occurred_at FROM sandbox_runtime_product.file_changes WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3 AND sequence>$4 ORDER BY sequence LIMIT $5`, tenantID, workspaceID, slotKey, after, limit)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	defer rows.Close()
	changes := make([]product.FileChange, 0)
	for rows.Next() {
		var change product.FileChange
		if err := rows.Scan(&change.Sequence, &change.Path, &change.PreviousPath, &change.Type, &change.Revision, &change.OccurredAt); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		changes = append(changes, change)
	}
	if err := rows.Err(); err != nil {
		return nil, product.ErrStoreUnavailable
	}
	return changes, nil
}

func (s *Store) authorizeFileOwner(ctx context.Context, tenantID string, actor product.ActorRef, workspaceID, slotKey string) error {
	opCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	var valid bool
	if err := s.pool.QueryRow(opCtx, `SELECT EXISTS(SELECT 1 FROM sandbox_runtime_product.workspaces w JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=w.tenant_id AND s.workspace_id=w.workspace_id WHERE w.tenant_id=$1 AND w.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4 AND s.slot_key=$5)`, tenantID, workspaceID, string(actor.Type), actor.ID, slotKey).Scan(&valid); err != nil {
		return product.ErrStoreUnavailable
	}
	if !valid {
		return product.ErrNotFound
	}
	return nil
}

func authorizeSnapshot(ctx context.Context, tx pgx.Tx, command product.FileSnapshotCommand) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT true FROM sandbox_runtime_product.workspaces w JOIN sandbox_runtime_product.workspace_slots s ON s.tenant_id=w.tenant_id AND s.workspace_id=w.workspace_id JOIN sandbox_runtime_product.guest_bindings g ON g.tenant_id=s.tenant_id AND g.workspace_id=s.workspace_id AND g.slot_key=s.slot_key WHERE w.tenant_id=$1 AND w.workspace_id=$2 AND w.owner_actor_type=$3 AND w.owner_actor_id=$4 AND s.slot_key=$5 AND s.observed_state='ready' AND g.guest_id=$6 AND g.binding_generation=$7 AND g.slot_generation=$8 AND g.state='connected' AND g.expires_at>clock_timestamp() AND g.capabilities ? 'files.snapshot' FOR UPDATE OF w,s,g`, command.TenantID, command.WorkspaceID, string(command.Actor.Type), command.Actor.ID, command.SlotKey, command.Snapshot.Authority.GuestID, command.Snapshot.Authority.BindingGeneration, command.Snapshot.Authority.SlotGeneration).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return product.ErrControlStale
	}
	if err != nil {
		return product.ErrStoreUnavailable
	}
	return nil
}

func loadFileEntries(ctx context.Context, tx pgx.Tx, tenantID, workspaceID, slotKey string) (map[string]product.FileEntry, error) {
	rows, err := tx.Query(ctx, `SELECT path,entry_type,mode,size_bytes,modified_at,revision FROM sandbox_runtime_product.file_entries WHERE tenant_id=$1 AND workspace_id=$2 AND slot_key=$3 ORDER BY path FOR UPDATE`, tenantID, workspaceID, slotKey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make(map[string]product.FileEntry)
	for rows.Next() {
		var entry product.FileEntry
		var mode int
		if err := rows.Scan(&entry.Path, &entry.Type, &mode, &entry.SizeBytes, &entry.ModifiedAt, &entry.Revision); err != nil {
			return nil, err
		}
		entry.Mode = uint32(mode)
		entry.Name = path.Base(entry.Path)
		entries[entry.Path] = entry
	}
	return entries, rows.Err()
}

func diffFileEntries(current, next map[string]product.FileEntry) []product.FileChange {
	removed := make(map[string]product.FileEntry)
	created := make(map[string]product.FileEntry)
	changes := make([]product.FileChange, 0)
	for entryPath, old := range current {
		fresh, exists := next[entryPath]
		if !exists {
			removed[entryPath] = old
		} else if old.Revision != fresh.Revision || old.Mode != fresh.Mode || old.SizeBytes != fresh.SizeBytes || old.Type != fresh.Type {
			changes = append(changes, product.FileChange{Path: entryPath, Type: "modify", Revision: fresh.Revision})
		}
	}
	for entryPath, fresh := range next {
		if _, exists := current[entryPath]; !exists {
			created[entryPath] = fresh
		}
	}
	removedByRevision := make(map[string][]string)
	for entryPath, entry := range removed {
		removedByRevision[entry.Type+"\x00"+entry.Revision] = append(removedByRevision[entry.Type+"\x00"+entry.Revision], entryPath)
	}
	createdPaths := make([]string, 0, len(created))
	for entryPath := range created {
		createdPaths = append(createdPaths, entryPath)
	}
	sort.Strings(createdPaths)
	for _, entryPath := range createdPaths {
		entry := created[entryPath]
		matches := removedByRevision[entry.Type+"\x00"+entry.Revision]
		if len(matches) == 1 {
			changes = append(changes, product.FileChange{Path: entryPath, PreviousPath: matches[0], Type: "rename", Revision: entry.Revision})
			delete(removed, matches[0])
			delete(removedByRevision, entry.Type+"\x00"+entry.Revision)
		} else {
			changes = append(changes, product.FileChange{Path: entryPath, Type: "create", Revision: entry.Revision})
		}
	}
	for entryPath, entry := range removed {
		changes = append(changes, product.FileChange{Path: entryPath, Type: "remove", Revision: entry.Revision})
	}
	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Path == changes[j].Path {
			return changes[i].Type < changes[j].Type
		}
		return changes[i].Path < changes[j].Path
	})
	return changes
}

func validSnapshotEntry(entry product.FileEntry) bool {
	if len(entry.Path) < 1 || len(entry.Path) > 4096 || strings.HasPrefix(entry.Path, "/") || strings.ContainsAny(entry.Path, "\x00\\") || path.Clean(entry.Path) != entry.Path || entry.Path == ".." || strings.HasPrefix(entry.Path, "../") || (entry.Type != "file" && entry.Type != "directory") || entry.Mode > 4095 || entry.SizeBytes < 0 || entry.ModifiedAt.IsZero() || !strings.HasPrefix(entry.Revision, "sha256:") || len(entry.Revision) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(entry.Revision, "sha256:"))
	return err == nil
}

var _ product.FileStore = (*Store)(nil)
