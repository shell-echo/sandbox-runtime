// Package memory provides an in-memory instance repository.
package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/shell-echo/sandbox-runtime/instance"
)

// Repository stores instance snapshots in memory. It is concurrency-safe and
// intended for development, tests, and single-process prototypes.
type Repository struct {
	mu        sync.RWMutex
	instances map[string]*instance.Instance
}

func NewRepository() *Repository {
	return &Repository{instances: make(map[string]*instance.Instance)}
}

func (r *Repository) Create(ctx context.Context, inst *instance.Instance) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, exists := r.instances[inst.ID]; exists {
		return fmt.Errorf("%w: %s", instance.ErrAlreadyExists, inst.ID)
	}
	r.instances[inst.ID] = clone(inst)
	return nil
}

func (r *Repository) Get(ctx context.Context, id string) (*instance.Instance, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	inst, exists := r.instances[id]
	if !exists {
		return nil, fmt.Errorf("%w: %s", instance.ErrNotFound, id)
	}
	return clone(inst), nil
}

func (r *Repository) List(ctx context.Context) ([]*instance.Instance, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	instances := make([]*instance.Instance, 0, len(r.instances))
	for _, inst := range r.instances {
		instances = append(instances, clone(inst))
	}
	slices.SortFunc(instances, func(a, b *instance.Instance) int {
		return strings.Compare(a.ID, b.ID)
	})
	return instances, nil
}

func (r *Repository) Count(ctx context.Context) (int, error) {
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := contextError(ctx); err != nil {
		return 0, err
	}
	return len(r.instances), nil
}

func (r *Repository) Update(ctx context.Context, inst *instance.Instance) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, exists := r.instances[inst.ID]; !exists {
		return fmt.Errorf("%w: %s", instance.ErrNotFound, inst.ID)
	}
	r.instances[inst.ID] = clone(inst)
	return nil
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, exists := r.instances[id]; !exists {
		return fmt.Errorf("%w: %s", instance.ErrNotFound, id)
	}
	delete(r.instances, id)
	return nil
}

func clone(inst *instance.Instance) *instance.Instance {
	copy := *inst
	return &copy
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

var _ instance.Repository = (*Repository)(nil)
