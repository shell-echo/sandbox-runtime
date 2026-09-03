// Package file provides versioned, atomically replaced browser-session state
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
	"time"

	"github.com/shell-echo/sandbox-runtime/provider/browser"
	"github.com/shell-echo/sandbox-runtime/provider/browser/repository"
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
		return nil, errors.New("browser session repository path is required")
	}
	cleanPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o700); err != nil {
		return nil, fmt.Errorf("create browser session repository directory: %w", err)
	}
	lockFile, err := acquireLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock browser session repository: %w", err)
	}
	r := &Repository{path: cleanPath, lockFile: lockFile, state: repository.NewState()}
	if err := r.load(); err != nil {
		_ = releaseLock(lockFile)
		return nil, err
	}
	return r, nil
}

func (r *Repository) ReserveOpen(ctx context.Context, request browser.OpenRequest, acceptedAt time.Time) (browser.Reservation, error) {
	var result browser.Reservation
	err := r.mutate(ctx, func() error { var err error; result, err = r.state.ReserveOpenAt(request, acceptedAt); return err })
	return result, err
}
func (r *Repository) GetOpen(ctx context.Context, operationID string) (browser.Record, error) {
	return r.GetOpenAt(ctx, operationID, time.Now().UTC())
}
func (r *Repository) GetOpenAt(ctx context.Context, operationID string, now time.Time) (browser.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return browser.Record{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return browser.Record{}, repository.ErrClosed
	}
	return r.state.GetOpenAt(operationID, now)
}
func (r *Repository) ListOpen(ctx context.Context) ([]browser.Record, error) {
	if err := repository.ContextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, repository.ErrClosed
	}
	return r.state.ListOpen(), nil
}
func (r *Repository) AttachAllocation(ctx context.Context, receipt browser.AllocationReceipt) (browser.Reservation, error) {
	var result browser.Reservation
	err := r.mutate(ctx, func() error { var err error; result, err = r.state.AttachAllocation(receipt); return err })
	return result, err
}
func (r *Repository) ObserveAllocation(ctx context.Context, operationID string, observation browser.AllocationEvidence) (browser.Record, error) {
	var result browser.Record
	err := r.mutate(ctx, func() error {
		var err error
		result, err = r.state.ObserveAllocation(operationID, observation)
		return err
	})
	return result, err
}
func (r *Repository) UpdateOpen(ctx context.Context, record browser.Record, expectedStatus browser.Status) error {
	return r.UpdateOpenAt(ctx, record, expectedStatus, time.Now().UTC())
}
func (r *Repository) UpdateOpenAt(ctx context.Context, record browser.Record, expectedStatus browser.Status, now time.Time) error {
	return r.mutate(ctx, func() error { return r.state.UpdateOpenAt(record, expectedStatus, now) })
}
func (r *Repository) SynchronizeSandboxAuthority(ctx context.Context, authority browser.SandboxAuthority) error {
	return r.mutate(ctx, func() error { return r.state.SynchronizeSandboxAuthority(authority) })
}
func (r *Repository) GetSandboxAuthority(ctx context.Context, sandboxID string) (browser.SandboxAuthority, error) {
	if err := repository.ContextError(ctx); err != nil {
		return browser.SandboxAuthority{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return browser.SandboxAuthority{}, repository.ErrClosed
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
		return fmt.Errorf("open browser session repository: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return fmt.Errorf("%w: invalid repository file", repository.ErrCorrupt)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var snapshot repository.PersistedState
	if err := decoder.Decode(&snapshot); err != nil {
		return fmt.Errorf("%w: decode repository: %v", repository.ErrCorrupt, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing repository data", repository.ErrCorrupt)
	}
	return r.state.Import(snapshot)
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
		return false, fmt.Errorf("%w: create directory", repository.ErrDurability)
	}
	temporary, err := os.CreateTemp(directory, ".browser-session-*.tmp")
	if err != nil {
		return false, fmt.Errorf("%w: create temporary file", repository.ErrDurability)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: chmod", repository.ErrDurability)
	}
	if err := json.NewEncoder(temporary).Encode(r.state.Export()); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: encode", repository.ErrDurability)
	}
	info, err := temporary.Stat()
	if err != nil || info.Size() > maxFileSize {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: size", repository.ErrDurability)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return false, fmt.Errorf("%w: sync", repository.ErrDurability)
	}
	if err := temporary.Close(); err != nil {
		return false, fmt.Errorf("%w: close", repository.ErrDurability)
	}
	if err := repository.ContextError(ctx); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return false, fmt.Errorf("%w: replace", repository.ErrDurability)
	}
	committed := true
	directoryFile, err := os.Open(directory)
	if err != nil {
		return committed, fmt.Errorf("%w: open directory", repository.ErrDurability)
	}
	syncErr := directoryFile.Sync()
	closeErr := directoryFile.Close()
	if syncErr != nil || closeErr != nil {
		return committed, fmt.Errorf("%w: sync directory: %v", repository.ErrDurability, errors.Join(syncErr, closeErr))
	}
	return committed, nil
}

var _ browser.CoordinationAuthority = (*Repository)(nil)
