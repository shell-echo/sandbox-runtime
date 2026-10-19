//go:build !linux

package phase6process

import "context"

func ObservePID1(context.Context) (Observation, error) { return Observation{}, ErrIdentity }
