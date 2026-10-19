//go:build !linux

package phase6process

import "context"

func ObserveProbe(context.Context, string, bool) (ProbeObservation, error) {
	return ProbeObservation{}, ErrIdentity
}
