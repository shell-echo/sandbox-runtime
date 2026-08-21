// Package fake provides a Provider-specific lifecycle driver for development
// composition and deterministic application tests.
package fake

import (
	"context"
	"errors"
	"sync"

	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

var ErrInvalidDriver = errors.New("invalid Provider lifecycle fake driver")

// Driver stores only bounded Provider runtime observations. It deliberately
// does not import or adapt the local instance runtime model.
type Driver struct {
	mu     sync.Mutex
	states map[string]coordinator.RuntimeState
}

func New() *Driver { return &Driver{states: make(map[string]coordinator.RuntimeState)} }

func (d *Driver) Create(ctx context.Context, sandbox lifecycle.Sandbox) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || sandbox.ID == "" {
		return ErrInvalidDriver
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return err
	}
	d.states[sandbox.ID] = coordinator.RuntimeReady
	return nil
}

func (d *Driver) Inspect(ctx context.Context, id string) (coordinator.RuntimeObservation, error) {
	if err := contextError(ctx); err != nil {
		return coordinator.RuntimeObservation{}, err
	}
	if d == nil || id == "" {
		return coordinator.RuntimeObservation{}, ErrInvalidDriver
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := contextError(ctx); err != nil {
		return coordinator.RuntimeObservation{}, err
	}
	state, ok := d.states[id]
	if !ok {
		return coordinator.RuntimeObservation{State: coordinator.RuntimeAbsent}, nil
	}
	return coordinator.RuntimeObservation{State: state}, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

var _ coordinator.Driver = (*Driver)(nil)
