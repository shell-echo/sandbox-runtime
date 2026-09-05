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
	watchers map[string]map[*memoryRevocationWatch]struct{}
}

type memoryRevocationWatch struct {
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func NewMemoryRevocations() *MemoryRevocations {
	return &MemoryRevocations{revoked: make(map[string]bool), watchers: make(map[string]map[*memoryRevocationWatch]struct{})}
}

func (w *memoryRevocationWatch) Done() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.done
}

func (w *memoryRevocationWatch) Err() error {
	if w == nil {
		return ErrRevocationUnavailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *memoryRevocationWatch) finish(err error) {
	w.once.Do(func() {
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		close(w.done)
	})
}

func (r *MemoryRevocations) Watch(ctx context.Context, subject RevocationSubject) (RevocationWatch, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if r == nil || subject.Validate() != nil {
		return nil, ErrRevocationUnavailable
	}
	watch := &memoryRevocationWatch{done: make(chan struct{})}
	r.mu.Lock()
	if r.revoked[subject.GrantID] {
		watch.finish(ErrRevoked)
		r.mu.Unlock()
		return watch, nil
	}
	if r.watchers[subject.GrantID] == nil {
		r.watchers[subject.GrantID] = make(map[*memoryRevocationWatch]struct{})
	}
	r.watchers[subject.GrantID][watch] = struct{}{}
	r.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
		case <-watch.done:
			return
		}
		r.mu.Lock()
		if watchers := r.watchers[subject.GrantID]; watchers != nil {
			delete(watchers, watch)
			if len(watchers) == 0 {
				delete(r.watchers, subject.GrantID)
			}
		}
		r.mu.Unlock()
		watch.finish(ctx.Err())
	}()
	return watch, nil
}

func (r *MemoryRevocations) Revoke(ctx context.Context, subject RevocationSubject) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if r == nil || subject.Validate() != nil {
		return ErrRevocationUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked[subject.GrantID] {
		return nil
	}
	r.revoked[subject.GrantID] = true
	for watch := range r.watchers[subject.GrantID] {
		watch.finish(ErrRevoked)
	}
	delete(r.watchers, subject.GrantID)
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
var _ RevocationWriter = (*MemoryRevocations)(nil)
var _ RevocationWatch = (*memoryRevocationWatch)(nil)
