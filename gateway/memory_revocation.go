package gateway

import (
	"context"
	"sync"
)

// MemoryRevocations is a concurrency-safe development adapter for revocation
// tests and single-process composition. It is not a distributed or durable
// multi-controller revocation source.
type MemoryRevocations struct {
	mu       sync.Mutex
	revoked  map[string]bool
	watchers map[string]map[*memoryWatcher]struct{}
}

type memoryWatcher struct {
	signal     chan struct{}
	stop       chan struct{}
	signalOnce sync.Once
	stopOnce   sync.Once
}

func NewMemoryRevocations() *MemoryRevocations {
	return &MemoryRevocations{revoked: make(map[string]bool), watchers: make(map[string]map[*memoryWatcher]struct{})}
}

func (r *MemoryRevocations) IsRevoked(ctx context.Context, grantID string) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked[grantID], nil
}

func (r *MemoryRevocations) Watch(ctx context.Context, grantID string) (<-chan struct{}, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	watch := &memoryWatcher{signal: make(chan struct{}), stop: make(chan struct{})}
	r.mu.Lock()
	if r.revoked[grantID] {
		watch.signalOnce.Do(func() { close(watch.signal) })
		watch.stopOnce.Do(func() { close(watch.stop) })
		r.mu.Unlock()
		return watch.signal, nil
	}
	if r.watchers[grantID] == nil {
		r.watchers[grantID] = make(map[*memoryWatcher]struct{})
	}
	r.watchers[grantID][watch] = struct{}{}
	r.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
		case <-watch.stop:
			return
		}
		r.mu.Lock()
		if watchers := r.watchers[grantID]; watchers != nil {
			delete(watchers, watch)
			if len(watchers) == 0 {
				delete(r.watchers, grantID)
			}
		}
		r.mu.Unlock()
		watch.stopOnce.Do(func() { close(watch.stop) })
	}()
	return watch.signal, nil
}

func (r *MemoryRevocations) Revoke(ctx context.Context, grantID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked[grantID] {
		return nil
	}
	r.revoked[grantID] = true
	for watch := range r.watchers[grantID] {
		watch.signalOnce.Do(func() { close(watch.signal) })
		watch.stopOnce.Do(func() { close(watch.stop) })
	}
	delete(r.watchers, grantID)
	return nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

var _ RevocationSource = (*MemoryRevocations)(nil)
