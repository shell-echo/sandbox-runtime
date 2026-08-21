// Package file provides a versioned, atomically replaced exec repository for
// one controller process. It is deliberately not multi-controller storage.
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

	providerexec "github.com/shell-echo/sandbox-runtime/provider/exec"
	"github.com/shell-echo/sandbox-runtime/provider/exec/repository"
)

const maxFileSize = 16 << 20

type Repository struct {
	mu       sync.RWMutex
	path     string
	lockFile *os.File
	state    repository.State
	closed   bool
}

func NewRepository(path string) (*Repository, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("exec repository path is required")
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create exec repository directory: %w", err)
	}
	lockFile, err := acquireLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock exec repository: %w", err)
	}
	r := &Repository{path: cleanPath, lockFile: lockFile, state: repository.NewState()}
	if err := r.load(); err != nil {
		_ = releaseLock(lockFile)
		return nil, err
	}
	return r, nil
}

func (r *Repository) ReserveExecution(ctx context.Context, request providerexec.Request, dispatch providerexec.Dispatch) (providerexec.ExecutionReservation, error) {
	var reservation providerexec.ExecutionReservation
	err := r.mutate(ctx, func() error {
		var err error
		reservation, err = r.state.ReserveExecution(request, dispatch)
		return err
	})
	return reservation, err
}

func (r *Repository) GetExecution(ctx context.Context, operationID string) (providerexec.ExecutionRecord, error) {
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.ExecutionRecord{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return providerexec.ExecutionRecord{}, repository.ErrClosed
	}
	return r.state.GetExecution(operationID)
}

func (r *Repository) ReserveCancellation(ctx context.Context, intent providerexec.CancellationIntent) (providerexec.CancellationReservation, error) {
	var reservation providerexec.CancellationReservation
	err := r.mutate(ctx, func() error {
		var err error
		reservation, err = r.state.ReserveCancellation(intent, time.Now().UTC())
		return err
	})
	return reservation, err
}

func (r *Repository) StoreResult(ctx context.Context, result providerexec.Result) error {
	return r.mutate(ctx, func() error { return r.state.StoreResult(result) })
}

func (r *Repository) GetResult(ctx context.Context, operationID string, now time.Time) (providerexec.Result, error) {
	if err := repository.ContextError(ctx); err != nil {
		return providerexec.Result{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return providerexec.Result{}, repository.ErrClosed
	}
	previous := r.state.Export()
	result, readErr, changed := r.state.ReadResult(operationID, now.UTC())
	if !changed {
		return result, readErr
	}
	committed, persistErr := r.persist(ctx)
	if persistErr != nil {
		if !committed {
			_ = r.state.Import(previous)
		}
		return providerexec.Result{}, persistErr
	}
	return result, readErr
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
		return fmt.Errorf("open exec repository: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat exec repository: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return fmt.Errorf("%w: invalid exec repository file", repository.ErrCorrupt)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var snapshot repository.PersistedState
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: decode exec repository: %v", repository.ErrCorrupt, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if err := r.state.Import(snapshot); err != nil {
		return fmt.Errorf("%w: import exec repository: %v", repository.ErrCorrupt, err)
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
	temporary, err := os.CreateTemp(directory, ".exec-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create temporary file: %v", repository.ErrDurability, err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	defer cleanup()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: secure temporary file: %v", repository.ErrDurability, err)
	}
	if err := json.NewEncoder(temporary).Encode(r.state.Export()); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: encode snapshot: %v", repository.ErrDurability, err)
	}
	info, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: stat temporary file: %v", repository.ErrDurability, err)
	}
	if info.Size() > maxFileSize {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: snapshot exceeds %d bytes", repository.ErrDurability, maxFileSize)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: sync temporary file: %v", repository.ErrDurability, err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("%w: close temporary file: %v", repository.ErrDurability, err)
	}
	if err := repository.ContextError(ctx); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return false, fmt.Errorf("%w: replace snapshot: %v", repository.ErrDurability, err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("%w: open repository directory: %v", repository.ErrDurability, err)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return true, fmt.Errorf("%w: sync repository directory: %v", repository.ErrDurability, errors.Join(syncErr, closeErr))
	}
	return true, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%w: decode snapshot trailer: %v", repository.ErrCorrupt, err)
	}
	return fmt.Errorf("%w: snapshot contains multiple JSON values", repository.ErrCorrupt)
}

var _ repository.Repository = (*Repository)(nil)
