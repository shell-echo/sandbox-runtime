package artifact

import "context"

// Stager is a provider-local staging adapter. It may read the stable output
// mount, but it must return bounded evidence and never publish an artifact.
type Stager interface {
	Stage(context.Context, Request) (Evidence, error)
}
