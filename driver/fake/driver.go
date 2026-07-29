// Package fake provides an in-memory runtime driver for lifecycle validation.
package fake

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/instance"
)

// Driver simulates only backend runtime resources. Instance metadata and
// control-plane state are owned by instance.Service and its Repository.
type Driver struct {
	mu      sync.Mutex
	states  map[string]runtimeState
	specs   map[string]instance.Spec
	created map[string]time.Time
}

type runtimeState uint8

const (
	runtimeStopped runtimeState = iota
	runtimeRunning
)

func NewDriver() *Driver {
	return &Driver{
		states: make(map[string]runtimeState), specs: make(map[string]instance.Spec),
		created: make(map[string]time.Time),
	}
}

func (d *Driver) Create(ctx context.Context, id string, spec instance.Spec) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, exists := d.states[id]; exists {
		return fmt.Errorf("%w: %s", instance.ErrAlreadyExists, id)
	}
	d.states[id] = runtimeStopped
	d.specs[id] = spec
	d.created[id] = time.Now()
	return nil
}

func (d *Driver) List(ctx context.Context) ([]instance.RuntimeResource, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	resources := make([]instance.RuntimeResource, 0, len(d.states))
	for id := range d.states {
		resources = append(resources, instance.RuntimeResource{ID: id, Spec: d.specs[id], CreatedAt: d.created[id]})
	}
	slices.SortFunc(resources, func(a, b instance.RuntimeResource) int { return strings.Compare(a.ID, b.ID) })
	return resources, nil
}

func (d *Driver) Start(ctx context.Context, id string) error {
	return d.changeState(ctx, id, runtimeStopped, runtimeRunning)
}

func (d *Driver) Inspect(ctx context.Context, id string) (instance.RuntimeObservation, error) {
	if err := contextError(ctx); err != nil {
		return instance.RuntimeObservation{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return instance.RuntimeObservation{}, err
	}
	state, exists := d.states[id]
	if !exists {
		return instance.RuntimeObservation{}, fmt.Errorf("%w: %s", instance.ErrNotFound, id)
	}
	if state == runtimeRunning {
		return instance.RuntimeObservation{State: instance.RuntimeRunning}, nil
	}
	return instance.RuntimeObservation{State: instance.RuntimeStopped}, nil
}

func (d *Driver) Stop(ctx context.Context, id string) error {
	return d.changeState(ctx, id, runtimeRunning, runtimeStopped)
}

func (d *Driver) Remove(ctx context.Context, id string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, exists := d.states[id]; !exists {
		return nil // backend removal is idempotent
	}
	delete(d.states, id)
	delete(d.specs, id)
	delete(d.created, id)
	return nil
}

func (d *Driver) changeState(ctx context.Context, id string, from, to runtimeState) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	state, exists := d.states[id]
	if !exists {
		return fmt.Errorf("%w: %s", instance.ErrNotFound, id)
	}
	if state != from {
		return fmt.Errorf("%w: unexpected runtime state", instance.ErrInvalidTransition)
	}
	d.states[id] = to
	return nil
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

var _ instance.Driver = (*Driver)(nil)
