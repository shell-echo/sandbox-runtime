package instance

import "context"

// Repository persists the control plane's view of instances independently of
// the runtime backend. Implementations must return snapshots safe for callers
// to mutate.
type Repository interface {
	Create(context.Context, *Instance) error
	Get(context.Context, string) (*Instance, error)
	List(context.Context) ([]*Instance, error)
	Count(context.Context) (int, error)
	Update(context.Context, *Instance) error
	Delete(context.Context, string) error
}
