// Package lifecycle provides the Browser profile's Provider-local sandbox
// readiness adapter. A Browser sandbox is a durable control-plane authority;
// the concrete Chromium allocation is created by the separate Browser session
// vertical after an admitted session request.
package lifecycle

import (
	"context"
	"errors"
	"reflect"

	providerlifecycle "github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/coordinator"
)

var (
	ErrInvalidDriver = errors.New("invalid Provider Browser lifecycle driver")
	ErrUnavailable   = errors.New("Provider Browser lifecycle readiness is unavailable")
)

type RuntimeReadiness interface {
	Ready(context.Context) error
}

type Driver struct {
	runtime                RuntimeReadiness
	networkPolicyReference string
}

func New(runtime RuntimeReadiness, networkPolicyReference string) (*Driver, error) {
	if nilDependency(runtime) || providerlifecycle.ValidateIdentifier(networkPolicyReference) != nil {
		return nil, ErrInvalidDriver
	}
	return &Driver{runtime: runtime, networkPolicyReference: networkPolicyReference}, nil
}

func (d *Driver) Create(ctx context.Context, sandbox providerlifecycle.Sandbox) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if d == nil || nilDependency(d.runtime) || sandbox.Validate() != nil ||
		sandbox.RuntimeProfile != providerlifecycle.BrowserRuntimeProfile ||
		sandbox.Network.Mode != providerlifecycle.NetworkRestricted ||
		!sandbox.Network.EgressGatewayRequired ||
		sandbox.Network.PolicyReference != d.networkPolicyReference {
		return ErrInvalidDriver
	}
	if err := d.runtime.Ready(ctx); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return errors.Join(ErrUnavailable, coordinator.ErrUnknownRuntime)
	}
	return nil
}

func (d *Driver) Inspect(ctx context.Context, sandboxID string) (coordinator.RuntimeObservation, error) {
	if err := contextError(ctx); err != nil {
		return coordinator.RuntimeObservation{}, err
	}
	if d == nil || nilDependency(d.runtime) || providerlifecycle.ValidateIdentifier(sandboxID) != nil {
		return coordinator.RuntimeObservation{}, ErrInvalidDriver
	}
	if err := d.runtime.Ready(ctx); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return coordinator.RuntimeObservation{}, contextErr
		}
		return coordinator.RuntimeObservation{}, ErrUnavailable
	}
	return coordinator.RuntimeObservation{State: coordinator.RuntimeReady}, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Pointer || kind == reflect.Interface || kind == reflect.Func) && reflect.ValueOf(value).IsNil()
}

var _ coordinator.Driver = (*Driver)(nil)
