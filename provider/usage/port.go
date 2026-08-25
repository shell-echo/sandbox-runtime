package usage

import "context"

// Collector supplies provider-local usage observations for one admitted
// operation. The calling platform remains responsible for accounting.
type Collector interface {
	Collect(context.Context, string, string, string, int64) (Evidence, error)
}
