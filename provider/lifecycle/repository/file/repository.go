// Package file provides a versioned, atomically replaced lifecycle repository
// for one controller process. It is not a multi-controller implementation.
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

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository"
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
		return nil, errors.New("lifecycle repository path is required")
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create lifecycle repository directory: %w", err)
	}
	lockFile, err := acquireLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock lifecycle repository: %w", err)
	}
	r := &Repository{path: cleanPath, lockFile: lockFile, state: repository.NewState()}
	if err := r.load(); err != nil {
		_ = releaseLock(lockFile)
		return nil, err
	}
	return r, nil
}

func (r *Repository) ReserveCreate(ctx context.Context, key, digest string, sandbox lifecycle.Sandbox, operation lifecycle.Operation) (repository.CreateResult, error) {
	if err := contextError(ctx); err != nil {
		return repository.CreateResult{}, err
	}
	var result repository.CreateResult
	err := r.mutate(ctx, func() error {
		var err error
		result, err = r.state.ReserveCreate(key, digest, sandbox, operation)
		return err
	})
	return result, err
}

func (r *Repository) GetSandbox(ctx context.Context, id string) (lifecycle.Sandbox, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Sandbox{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return lifecycle.Sandbox{}, repository.ErrClosed
	}
	return r.state.GetSandbox(id)
}

func (r *Repository) UpdateSandbox(ctx context.Context, sandbox lifecycle.Sandbox, expectedGeneration, fencingToken uint64) error {
	return r.mutate(ctx, func() error { return r.state.UpdateSandbox(sandbox, expectedGeneration, fencingToken) })
}

func (r *Repository) ListSandboxes(ctx context.Context) ([]lifecycle.Sandbox, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListSandboxes(), nil
}

func (r *Repository) GetOperation(ctx context.Context, id string) (lifecycle.Operation, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Operation{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return lifecycle.Operation{}, repository.ErrClosed
	}
	return r.state.GetOperation(id)
}

func (r *Repository) UpdateOperation(ctx context.Context, operation lifecycle.Operation) error {
	return r.mutate(ctx, func() error { return r.state.UpdateOperation(operation) })
}

func (r *Repository) ListOperations(ctx context.Context) ([]lifecycle.Operation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListOperations(), nil
}

func (r *Repository) GetLease(ctx context.Context, id string) (lifecycle.Lease, error) {
	if err := contextError(ctx); err != nil {
		return lifecycle.Lease{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return lifecycle.Lease{}, repository.ErrClosed
	}
	return r.state.GetLease(id)
}

func (r *Repository) ReplaceLease(ctx context.Context, lease lifecycle.Lease, fencingToken uint64) error {
	return r.mutate(ctx, func() error { return r.state.ReplaceLease(lease, fencingToken) })
}

func (r *Repository) AppendEvent(ctx context.Context, event lifecycle.Event) (lifecycle.Event, error) {
	var result lifecycle.Event
	err := r.mutate(ctx, func() error {
		var err error
		result, err = r.state.AppendEvent(event)
		return err
	})
	return result, err
}

func (r *Repository) ListEvents(ctx context.Context, sandboxID string, after uint64, limit int) ([]lifecycle.Event, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListEvents(sandboxID, after, limit)
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
		return fmt.Errorf("open lifecycle repository: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat lifecycle repository: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return fmt.Errorf("%w: invalid lifecycle repository file", repository.ErrCorrupt)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var snapshot repository.PersistedState
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: decode lifecycle repository: %v", repository.ErrCorrupt, err)
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
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return repository.ErrClosed
	}
	if err := contextError(ctx); err != nil {
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
	if err := contextError(ctx); err != nil {
		return false, err
	}
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("%w: create lifecycle repository directory: %v", repository.ErrDurability, err)
	}
	temporary, err := os.CreateTemp(directory, ".lifecycle-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create lifecycle repository temporary file: %v", repository.ErrDurability, err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	defer cleanup()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: secure lifecycle repository temporary file: %v", repository.ErrDurability, err)
	}
	encoder := json.NewEncoder(temporary)
	if err := encoder.Encode(r.state.Export()); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: encode lifecycle repository: %v", repository.ErrDurability, err)
	}
	info, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: stat lifecycle repository temporary file: %v", repository.ErrDurability, err)
	}
	if info.Size() > maxFileSize {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: lifecycle repository exceeds %d bytes", repository.ErrDurability, maxFileSize)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: sync lifecycle repository: %v", repository.ErrDurability, err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("%w: close lifecycle repository: %v", repository.ErrDurability, err)
	}
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return false, fmt.Errorf("%w: replace lifecycle repository: %v", repository.ErrDurability, err)
	}
	committed := true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return committed, fmt.Errorf("%w: open lifecycle repository directory: %v", repository.ErrDurability, err)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return committed, fmt.Errorf("%w: sync lifecycle repository directory: %v", repository.ErrDurability, errors.Join(syncErr, closeErr))
	}
	return committed, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%w: decode lifecycle repository trailer: %v", repository.ErrCorrupt, err)
	}
	return fmt.Errorf("%w: lifecycle repository contains multiple JSON values", repository.ErrCorrupt)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ repository.Repository = (*Repository)(nil)
