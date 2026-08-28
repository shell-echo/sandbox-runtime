// Package file provides versioned, atomically replaced usage evidence storage
// for one controller process. It is not an accounting or billing ledger.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/usage"
)

const (
	snapshotVersion = 1
	maxFileSize     = 32 << 20
)

var (
	ErrConflict   = errors.New("usage evidence repository conflict")
	ErrClosed     = errors.New("usage evidence repository is closed")
	ErrCorrupt    = errors.New("usage evidence repository is corrupt")
	ErrDurability = errors.New("usage evidence repository durability failure")
)

type Clock interface{ Now() time.Time }
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type snapshot struct {
	Version  int              `json:"version"`
	Evidence []usage.Evidence `json:"evidence"`
}

type Repository struct {
	mu             sync.RWMutex
	path           string
	lockFile       *os.File
	clock          Clock
	values         map[string]usage.Evidence
	operationIndex map[string]string
	closed         bool
}

func NewRepository(path string, clock Clock) (*Repository, error) {
	if strings.TrimSpace(path) == "" || clock == nil {
		return nil, errors.New("usage evidence repository path and clock are required")
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create usage evidence repository directory: %w", err)
	}
	lockFile, err := acquireLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock usage evidence repository: %w", err)
	}
	r := &Repository{
		path: cleanPath, lockFile: lockFile, clock: clock,
		values: make(map[string]usage.Evidence), operationIndex: make(map[string]string),
	}
	if err := r.load(); err != nil {
		_ = releaseLock(lockFile)
		return nil, err
	}
	return r, nil
}

func (r *Repository) Put(ctx context.Context, evidence usage.Evidence) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if err := evidence.Validate(r.clock.Now().UTC()); err != nil {
		return err
	}
	if previous, ok := r.values[evidence.EvidenceID]; ok {
		if reflect.DeepEqual(previous, evidence) {
			return nil
		}
		return ErrConflict
	}
	if evidenceID, ok := r.operationIndex[evidence.OperationID]; ok {
		previous, exists := r.values[evidenceID]
		if exists && reflect.DeepEqual(previous, evidence) {
			return nil
		}
		return ErrConflict
	}
	r.values[evidence.EvidenceID] = evidence.Clone()
	r.operationIndex[evidence.OperationID] = evidence.EvidenceID
	committed, err := r.persist(ctx)
	if err != nil {
		if !committed {
			delete(r.values, evidence.EvidenceID)
			delete(r.operationIndex, evidence.OperationID)
		}
		return err
	}
	return nil
}

func (r *Repository) GetEvidence(ctx context.Context, operationID string, now time.Time) (usage.Evidence, error) {
	if err := contextError(ctx); err != nil {
		return usage.Evidence{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return usage.Evidence{}, ErrClosed
	}
	evidenceID, ok := r.operationIndex[operationID]
	if !ok {
		return usage.Evidence{}, usage.ErrEvidenceNotFound
	}
	evidence, ok := r.values[evidenceID]
	if !ok || evidence.OperationID != operationID {
		return usage.Evidence{}, ErrCorrupt
	}
	if now.IsZero() || !now.UTC().Before(evidence.RetainedUntil) {
		return usage.Evidence{}, usage.ErrEvidenceExpired
	}
	return evidence.Clone(), nil
}

func (r *Repository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	err := releaseLock(r.lockFile)
	r.lockFile = nil
	return err
}

func (r *Repository) load() error {
	file, err := os.Open(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open usage evidence repository: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return ErrCorrupt
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var state snapshot
	if err := decoder.Decode(&state); err != nil || state.Version != snapshotVersion {
		return fmt.Errorf("%w: decode snapshot", ErrCorrupt)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing snapshot data", ErrCorrupt)
	}
	for _, evidence := range state.Evidence {
		if err := evidence.Validate(evidence.ObservedAt); err != nil {
			return fmt.Errorf("%w: invalid evidence", ErrCorrupt)
		}
		if _, exists := r.values[evidence.EvidenceID]; exists {
			return fmt.Errorf("%w: duplicate evidence", ErrCorrupt)
		}
		if _, exists := r.operationIndex[evidence.OperationID]; exists {
			return fmt.Errorf("%w: duplicate operation", ErrCorrupt)
		}
		r.values[evidence.EvidenceID] = evidence.Clone()
		r.operationIndex[evidence.OperationID] = evidence.EvidenceID
	}
	return nil
}

func (r *Repository) persist(ctx context.Context) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	state := snapshot{Version: snapshotVersion, Evidence: make([]usage.Evidence, 0, len(r.values))}
	for _, evidence := range r.values {
		state.Evidence = append(state.Evidence, evidence.Clone())
	}
	sort.Slice(state.Evidence, func(i, j int) bool { return state.Evidence[i].OperationID < state.Evidence[j].OperationID })
	directory := filepath.Dir(r.path)
	temporary, err := os.CreateTemp(directory, ".usage-evidence-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create temporary file", ErrDurability)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: secure temporary file", ErrDurability)
	}
	if err := json.NewEncoder(temporary).Encode(state); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: encode snapshot", ErrDurability)
	}
	info, err := temporary.Stat()
	if err != nil || info.Size() > maxFileSize {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: snapshot size", ErrDurability)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: sync snapshot", ErrDurability)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("%w: close snapshot", ErrDurability)
	}
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return false, fmt.Errorf("%w: replace snapshot", ErrDurability)
	}
	committed := true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return committed, fmt.Errorf("%w: open repository directory", ErrDurability)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return committed, fmt.Errorf("%w: sync repository directory: %v", ErrDurability, errors.Join(syncErr, closeErr))
	}
	return committed, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ usage.Store = (*Repository)(nil)
