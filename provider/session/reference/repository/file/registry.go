// Package file provides a versioned, atomically replaced opaque-reference
// registry for one controller process. It is not a multi-controller adapter.
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

	"github.com/shell-echo/sandbox-runtime/provider/session/reference"
	"github.com/shell-echo/sandbox-runtime/provider/session/reference/repository"
)

const maxFileSize = 32 << 20

type Registry struct {
	mu       sync.RWMutex
	path     string
	lockFile *os.File
	state    repository.State
	closed   bool
}

func NewRegistry(path string) (*Registry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("terminal reference registry path is required")
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create terminal reference registry directory: %w", err)
	}
	lockFile, err := acquireLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock terminal reference registry: %w", err)
	}
	r := &Registry{path: cleanPath, lockFile: lockFile, state: repository.NewState()}
	if err := r.load(); err != nil {
		_ = releaseLock(lockFile)
		return nil, err
	}
	return r, nil
}

func (r *Registry) Create(ctx context.Context, record reference.Record) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return r.mutate(ctx, func() error { return r.state.Create(record) })
}

func (r *Registry) Get(ctx context.Context, value string) (reference.Record, error) {
	if err := contextError(ctx); err != nil {
		return reference.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return reference.Record{}, reference.ErrClosed
	}
	return r.state.Get(value)
}

func (r *Registry) Revoke(ctx context.Context, value string, revokedAt time.Time) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return r.mutate(ctx, func() error { return r.state.Revoke(value, revokedAt) })
}

func (r *Registry) Close() error {
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

func (r *Registry) load() error {
	file, err := os.Open(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open terminal reference registry: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat terminal reference registry: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return fmt.Errorf("%w: invalid terminal reference registry file", reference.ErrUnavailable)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var snapshot repository.PersistedState
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: decode terminal reference registry: %v", reference.ErrUnavailable, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	return r.state.Import(snapshot)
}

func (r *Registry) mutate(ctx context.Context, mutation func() error) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return reference.ErrClosed
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

func (r *Registry) persist(ctx context.Context) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("%w: create registry directory: %v", reference.ErrDurability, err)
	}
	temporary, err := os.CreateTemp(directory, ".terminal-reference-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create temporary file: %v", reference.ErrDurability, err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: secure temporary file: %v", reference.ErrDurability, err)
	}
	if err := json.NewEncoder(temporary).Encode(r.state.Export()); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: encode registry: %v", reference.ErrDurability, err)
	}
	info, err := temporary.Stat()
	if err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: stat temporary file: %v", reference.ErrDurability, err)
	}
	if info.Size() > maxFileSize {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: registry exceeds %d bytes", reference.ErrDurability, maxFileSize)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: sync registry: %v", reference.ErrDurability, err)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("%w: close registry: %v", reference.ErrDurability, err)
	}
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return false, fmt.Errorf("%w: replace registry: %v", reference.ErrDurability, err)
	}
	committed := true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return committed, fmt.Errorf("%w: open registry directory: %v", reference.ErrDurability, err)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return committed, fmt.Errorf("%w: sync registry directory: %v", reference.ErrDurability, errors.Join(syncErr, closeErr))
	}
	return committed, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%w: decode registry trailer: %v", reference.ErrUnavailable, err)
	}
	return fmt.Errorf("%w: registry contains multiple JSON values", reference.ErrUnavailable)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ reference.Store = (*Registry)(nil)
