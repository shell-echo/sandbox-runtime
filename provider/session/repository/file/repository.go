// Package file provides a versioned, atomically replaced terminal-session
// repository for one controller process. It is not a multi-controller
// implementation.
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

	"github.com/shell-echo/sandbox-runtime/provider/session"
	"github.com/shell-echo/sandbox-runtime/provider/session/repository"
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
		return nil, errors.New("terminal session repository path is required")
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create terminal session repository directory: %w", err)
	}
	lockFile, err := acquireLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock terminal session repository: %w", err)
	}
	r := &Repository{path: cleanPath, lockFile: lockFile, state: repository.NewState()}
	if err := r.load(); err != nil {
		_ = releaseLock(lockFile)
		return nil, err
	}
	return r, nil
}

func (r *Repository) ReserveOpen(ctx context.Context, request session.OpenRequest, acceptedAt time.Time) (session.Reservation, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.Reservation{}, err
	}
	var result session.Reservation
	err := r.mutate(ctx, func() error {
		var err error
		result, err = r.state.ReserveOpenAt(request, acceptedAt)
		return err
	})
	return result, err
}

func (r *Repository) GetOpen(ctx context.Context, operationID string) (session.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return session.Record{}, repository.ErrClosed
	}
	return r.state.GetOpen(operationID)
}

func (r *Repository) GetOpenAt(ctx context.Context, operationID string, now time.Time) (session.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return session.Record{}, repository.ErrClosed
	}
	return r.state.GetOpenAt(operationID, now)
}

func (r *Repository) UpdateOpen(ctx context.Context, record session.Record, expectedStatus session.Status) error {
	return r.UpdateOpenAt(ctx, record, expectedStatus, time.Now().UTC())
}

func (r *Repository) UpdateOpenAt(ctx context.Context, record session.Record, expectedStatus session.Status, now time.Time) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	return r.mutate(ctx, func() error { return r.state.UpdateOpenAt(record, expectedStatus, now) })
}

func (r *Repository) PutSandboxAuthority(ctx context.Context, authority session.SandboxAuthority) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	return r.mutate(ctx, func() error { return r.state.PutSandboxAuthority(authority) })
}

func (r *Repository) ReplaceSandboxAuthority(ctx context.Context, authority session.SandboxAuthority, expectedGeneration, fencingToken int64) error {
	if err := repository.ContextError(ctx); err != nil {
		return err
	}
	return r.mutate(ctx, func() error {
		return r.state.ReplaceSandboxAuthority(authority, expectedGeneration, fencingToken)
	})
}

func (r *Repository) GetSandboxAuthority(ctx context.Context, sandboxID string) (session.SandboxAuthority, error) {
	if err := repository.ContextError(ctx); err != nil {
		return session.SandboxAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return session.SandboxAuthority{}, repository.ErrClosed
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
		return fmt.Errorf("open terminal session repository: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat terminal session repository: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return fmt.Errorf("%w: invalid terminal session repository file", repository.ErrCorrupt)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var snapshot repository.PersistedState
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: decode terminal session repository: %v", repository.ErrCorrupt, err)
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
	temporary, err := os.CreateTemp(directory, ".terminal-session-*.tmp")
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
