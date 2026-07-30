// Package file provides a durable instance repository with exclusive process ownership.
package file

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/shell-echo/sandbox-runtime/instance"
)

const (
	formatVersion = 1
	maxFileSize   = 16 << 20
)

type snapshot struct {
	Version   int                  `json:"version"`
	Instances []*instance.Instance `json:"instances"`
}

// Repository persists a complete, versioned snapshot with atomic replacement.
// It is safe for concurrent use and holds an advisory lock for its lifetime so
// a second process cannot open and overwrite the same snapshot.
type Repository struct {
	mu        sync.RWMutex
	path      string
	instances map[string]*instance.Instance
	lockFile  *os.File
}

// NewRepository loads path or creates an empty in-memory snapshot when the
// file does not exist. The first mutation creates the parent directory and
// durable state file.
func NewRepository(path string) (*Repository, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("instance repository path is required")
	}
	cleanPath := filepath.Clean(path)
	lockFile, err := acquireFileLock(cleanPath + ".lock")
	if err != nil {
		return nil, fmt.Errorf("lock instance repository: %w", err)
	}
	r := &Repository{path: cleanPath, instances: make(map[string]*instance.Instance), lockFile: lockFile}
	if err := r.load(); err != nil {
		_ = releaseFileLock(lockFile)
		return nil, err
	}
	return r, nil
}

// Close releases the process-level repository lock.
func (r *Repository) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lockFile == nil {
		return nil
	}
	err := releaseFileLock(r.lockFile)
	r.lockFile = nil
	return err
}

func (r *Repository) Create(ctx context.Context, inst *instance.Instance) error {
	if err := validateContextAndInstance(ctx, inst); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.instances[inst.ID]; exists {
		return fmt.Errorf("%w: %s", instance.ErrAlreadyExists, inst.ID)
	}
	r.instances[inst.ID] = clone(inst)
	if committed, err := r.persist(ctx); err != nil {
		if !committed {
			delete(r.instances, inst.ID)
		}
		return err
	}
	return nil
}

func (r *Repository) Get(ctx context.Context, id string) (*instance.Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	inst, exists := r.instances[id]
	if !exists {
		return nil, fmt.Errorf("%w: %s", instance.ErrNotFound, id)
	}
	return clone(inst), nil
}

func (r *Repository) List(ctx context.Context) ([]*instance.Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	instances := make([]*instance.Instance, 0, len(r.instances))
	for _, inst := range r.instances {
		instances = append(instances, clone(inst))
	}
	slices.SortFunc(instances, func(a, b *instance.Instance) int { return strings.Compare(a.ID, b.ID) })
	return instances, nil
}

func (r *Repository) Count(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.instances), nil
}

func (r *Repository) Update(ctx context.Context, inst *instance.Instance) error {
	if err := validateContextAndInstance(ctx, inst); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previous, exists := r.instances[inst.ID]
	if !exists {
		return fmt.Errorf("%w: %s", instance.ErrNotFound, inst.ID)
	}
	r.instances[inst.ID] = clone(inst)
	if committed, err := r.persist(ctx); err != nil {
		if !committed {
			r.instances[inst.ID] = previous
		}
		return err
	}
	return nil
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previous, exists := r.instances[id]
	if !exists {
		return fmt.Errorf("%w: %s", instance.ErrNotFound, id)
	}
	delete(r.instances, id)
	if committed, err := r.persist(ctx); err != nil {
		if !committed {
			r.instances[id] = previous
		}
		return err
	}
	return nil
}

func (r *Repository) load() error {
	file, err := os.Open(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open instance repository: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat instance repository: %w", err)
	}
	if info.Size() > maxFileSize {
		return fmt.Errorf("instance repository exceeds %d bytes", maxFileSize)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxFileSize+1))
	decoder.DisallowUnknownFields()
	var data snapshot
	if err := decoder.Decode(&data); err != nil {
		return fmt.Errorf("decode instance repository: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	if data.Version != formatVersion {
		return fmt.Errorf("unsupported instance repository version %d", data.Version)
	}
	for _, inst := range data.Instances {
		if err := validateInstance(inst); err != nil {
			return fmt.Errorf("invalid persisted instance: %w", err)
		}
		if _, exists := r.instances[inst.ID]; exists {
			return fmt.Errorf("duplicate persisted instance %q", inst.ID)
		}
		r.instances[inst.ID] = clone(inst)
	}
	return nil
}

// persist reports committed once the atomic rename has made the new snapshot
// visible. Callers must not roll back memory after that point, even if syncing
// the directory subsequently reports a durability error.
func (r *Repository) persist(ctx context.Context) (committed bool, result error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	directory := filepath.Dir(r.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("create repository directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".instances-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create repository temporary file: %w", err)
	}
	temporaryPath := file.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	defer cleanup()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("secure repository temporary file: %w", err)
	}
	instances := make([]*instance.Instance, 0, len(r.instances))
	for _, inst := range r.instances {
		instances = append(instances, clone(inst))
	}
	slices.SortFunc(instances, func(a, b *instance.Instance) int { return strings.Compare(a.ID, b.ID) })
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(snapshot{Version: formatVersion, Instances: instances}); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("encode instance repository: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return false, fmt.Errorf("stat instance repository temporary file: %w", err)
	}
	if info.Size() > maxFileSize {
		_ = file.Close()
		return false, fmt.Errorf("instance repository exceeds %d bytes", maxFileSize)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("sync instance repository: %w", err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("close instance repository: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := os.Rename(temporaryPath, r.path); err != nil {
		return false, fmt.Errorf("replace instance repository: %w", err)
	}
	committed = true
	dir, err := os.Open(directory)
	if err != nil {
		return true, fmt.Errorf("open repository directory: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil || closeErr != nil {
		return true, fmt.Errorf("sync repository directory: %w", errors.Join(syncErr, closeErr))
	}
	return true, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode instance repository trailer: %w", err)
	}
	return errors.New("instance repository contains multiple JSON values")
}

func validateContextAndInstance(ctx context.Context, inst *instance.Instance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return validateInstance(inst)
}

func validateInstance(inst *instance.Instance) error {
	if inst == nil {
		return errors.New("instance is required")
	}
	if err := instance.ValidateID(inst.ID); err != nil {
		return err
	}
	if err := (instance.Spec{Name: inst.Name, Workload: inst.Workload}).Validate(); err != nil {
		return err
	}
	switch inst.State {
	case instance.StateCreating, instance.StateStopped, instance.StateStarting,
		instance.StateRunning, instance.StateStopping, instance.StateRemoving, instance.StateFailed:
	default:
		return fmt.Errorf("invalid state %q", inst.State)
	}
	if inst.CreatedAt.IsZero() || inst.UpdatedAt.IsZero() || inst.UpdatedAt.Before(inst.CreatedAt) {
		return errors.New("instance timestamps are invalid")
	}
	if len(inst.Failure) > instance.MaxFailureLength {
		return fmt.Errorf("instance failure must not exceed %d bytes", instance.MaxFailureLength)
	}
	return nil
}

func clone(inst *instance.Instance) *instance.Instance {
	copy := *inst
	return &copy
}

var _ instance.Repository = (*Repository)(nil)
