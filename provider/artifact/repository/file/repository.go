// Package file provides a versioned, atomically replaced artifact staging
// authority for one controller process. It is not multi-controller storage.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
	"github.com/shell-echo/sandbox-runtime/provider/artifact/repository"
)

const maxFileSize = 32 << 20

type Repository struct {
	mu       sync.RWMutex
	path     string
	lockFile *os.File
	state    repository.State
	closed   bool
}

func NewRepository(path string) (*Repository, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("artifact staging repository path is required")
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create artifact staging repository directory: %w", err)
	}
	lockFile, err := acquireLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock artifact staging repository: %w", err)
	}
	r := &Repository{path: cleanPath, lockFile: lockFile, state: repository.NewState()}
	if err := r.load(); err != nil {
		_ = releaseLock(lockFile)
		return nil, err
	}
	return r, nil
}

func (r *Repository) ReserveStage(ctx context.Context, request artifact.Request, acceptedAt time.Time) (artifact.Reservation, error) {
	var result artifact.Reservation
	err := r.mutate(ctx, func() error {
		var err error
		result, err = r.state.ReserveStageAt(request, acceptedAt)
		return err
	})
	return result, err
}

func (r *Repository) GetStage(ctx context.Context, operationID string) (artifact.Operation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return artifact.Operation{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return artifact.Operation{}, repository.ErrClosed
	}
	return r.state.GetStage(operationID)
}

func (r *Repository) ListStages(ctx context.Context) ([]artifact.Operation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListStages()
}

func (r *Repository) UpdateStage(ctx context.Context, operation artifact.Operation, expected artifact.OperationStatus) error {
	return r.mutate(ctx, func() error { return r.state.UpdateStage(operation, expected) })
}

func (r *Repository) GetEvidence(ctx context.Context, operationID string, now time.Time) (artifact.Evidence, error) {
	if err := repository.ContextError(ctx); err != nil {
		return artifact.Evidence{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return artifact.Evidence{}, repository.ErrClosed
	}
	previous := r.state.Export()
	evidence, readErr, changed := r.state.ReadEvidenceAt(operationID, now)
	if !changed {
		return evidence, readErr
	}
	committed, persistErr := r.persist(ctx)
	if persistErr != nil {
		if !committed {
			_ = r.state.Import(previous)
		}
		return artifact.Evidence{}, persistErr
	}
	return evidence, readErr
}

func (r *Repository) PutSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority) error {
	return r.mutate(ctx, func() error { return r.state.PutSandboxAuthority(authority) })
}

func (r *Repository) ReplaceSandboxAuthority(ctx context.Context, authority artifact.SandboxAuthority, expectedGeneration, fencingToken int64) error {
	return r.mutate(ctx, func() error { return r.state.ReplaceSandboxAuthority(authority, expectedGeneration, fencingToken) })
}

func (r *Repository) GetSandboxAuthority(ctx context.Context, sandboxID string) (artifact.SandboxAuthority, error) {
	if err := repository.ContextError(ctx); err != nil {
		return artifact.SandboxAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return artifact.SandboxAuthority{}, repository.ErrClosed
	}
	return r.state.GetSandboxAuthority(sandboxID)
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
		return fmt.Errorf("open artifact staging repository: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat artifact staging repository: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return fmt.Errorf("%w: invalid artifact staging repository file", repository.ErrCorrupt)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var snapshot repository.PersistedState
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: decode artifact staging repository: %v", repository.ErrCorrupt, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if err := r.state.Import(snapshot); err != nil {
		return err
	}
	return nil
}

func (r *Repository) mutate(ctx context.Context, mutation func() error) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return repository.ErrClosed
	}
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	previous := r.state.Export()
	if err := mutation(); err != nil {
		return err
	}
	committed, err := r.persist(ctx)
	if err != nil && !committed {
		_ = r.state.Import(previous)
	}
	return err
}

func (r *Repository) persist(ctx context.Context) (bool, error) {
	if err := repository.ContextError(ctx); err != nil {
		return false, err
	}
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("%w: create repository directory: %v", repository.ErrDurability, err)
	}
	temporary, err := os.CreateTemp(directory, ".artifact-stage-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create temporary file: %v", repository.ErrDurability, err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: secure temporary file: %v", repository.ErrDurability, err)
	}
	if err := json.NewEncoder(temporary).Encode(r.state.Export()); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: encode repository: %v", repository.ErrDurability, err)
	}
	info, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: stat temporary file: %v", repository.ErrDurability, err)
	}
	if info.Size() > maxFileSize {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: repository exceeds %d bytes", repository.ErrDurability, maxFileSize)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: sync repository: %v", repository.ErrDurability, err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("%w: close repository: %v", repository.ErrDurability, err)
	}
	if err := repository.ContextError(ctx); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return false, fmt.Errorf("%w: replace repository: %v", repository.ErrDurability, err)
	}
	committed := true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return committed, fmt.Errorf("%w: open repository directory: %v", repository.ErrDurability, err)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return committed, fmt.Errorf("%w: sync repository directory: %v", repository.ErrDurability, errors.Join(syncErr, closeErr))
	}
	return committed, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%w: decode repository trailer: %v", repository.ErrCorrupt, err)
	}
	return fmt.Errorf("%w: repository contains multiple JSON values", repository.ErrCorrupt)
}

var _ repository.Repository = (*Repository)(nil)
