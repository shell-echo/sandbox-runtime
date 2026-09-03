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

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	"github.com/shell-echo/sandbox-runtime/provider/browser/reference/repository"
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
		return nil, errors.New("browser reference registry path is required")
	}
	clean := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		return nil, err
	}
	lock, err := acquireLock(clean + ".lock")
	if err != nil {
		return nil, err
	}
	r := &Registry{path: clean, lockFile: lock, state: repository.NewState()}
	if err := r.load(); err != nil {
		_ = releaseLock(lock)
		return nil, err
	}
	return r, nil
}
func (r *Registry) Create(ctx context.Context, record reference.Record) error {
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
func (r *Registry) FindRunning(ctx context.Context, source browser.Record) (reference.Record, error) {
	if err := contextError(ctx); err != nil {
		return reference.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return reference.Record{}, reference.ErrClosed
	}
	return r.state.FindRunning(source)
}
func (r *Registry) Revoke(ctx context.Context, value string, revokedAt time.Time) error {
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
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return reference.ErrUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var state repository.PersistedState
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("%w: decode registry", reference.ErrUnavailable)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return reference.ErrUnavailable
	}
	return r.state.Import(state)
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
	file, err := os.CreateTemp(directory, ".browser-reference-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create temp", reference.ErrDurability)
	}
	name := file.Name()
	defer os.Remove(name)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, reference.ErrDurability
	}
	if err := json.NewEncoder(file).Encode(r.state.Export()); err != nil {
		_ = file.Close()
		return false, reference.ErrDurability
	}
	info, err := file.Stat()
	if err != nil || info.Size() > maxFileSize {
		_ = file.Close()
		return false, reference.ErrDurability
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, reference.ErrDurability
	}
	if err := file.Close(); err != nil {
		return false, reference.ErrDurability
	}
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if err := os.Rename(name, r.path); err != nil {
		return false, reference.ErrDurability
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("%w: open directory", reference.ErrDurability)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return true, fmt.Errorf("%w: sync directory: %v", reference.ErrDurability, errors.Join(syncErr, closeErr))
	}
	return true, nil
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ reference.Store = (*Registry)(nil)
