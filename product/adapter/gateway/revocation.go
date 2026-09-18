package productgateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/product"
)

type authoritySource struct {
	store        product.ConnectionGrantStore
	binding      product.GatewayBinding
	pollInterval time.Duration
}

func (s *authoritySource) Watch(ctx context.Context, subject gateway.RevocationSubject) (gateway.RevocationWatch, error) {
	watch := &authorityWatch{done: make(chan struct{})}
	if subject.GrantID != s.binding.ConnectionID || !subject.ExpiresAt.Equal(minTime(s.binding.ExpiresAt, s.binding.HandoffExpiresAt)) {
		watch.finish(gateway.ErrRevoked)
		return watch, nil
	}
	if err := s.store.CheckGatewayAuthority(ctx, s.binding); err != nil {
		watch.finish(authorityError(err))
		return watch, nil
	}
	go s.poll(ctx, watch)
	return watch, nil
}

func (s *authoritySource) poll(ctx context.Context, watch *authorityWatch) {
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			watch.finish(ctx.Err())
			return
		case <-ticker.C:
			if err := s.store.CheckGatewayAuthority(ctx, s.binding); err != nil {
				watch.finish(authorityError(err))
				return
			}
		}
	}
}

func authorityError(err error) error {
	if errors.Is(err, product.ErrControlStale) || errors.Is(err, product.ErrNotFound) || errors.Is(err, product.ErrForbidden) {
		return gateway.ErrRevoked
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return gateway.ErrRevocationUnavailable
}

type authorityWatch struct {
	once sync.Once
	mu   sync.RWMutex
	done chan struct{}
	err  error
}

func (w *authorityWatch) Done() <-chan struct{} { return w.done }

func (w *authorityWatch) Err() error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.err
}

func (w *authorityWatch) finish(err error) {
	w.once.Do(func() {
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		close(w.done)
	})
}

func minTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

var _ gateway.RevocationSource = (*authoritySource)(nil)
var _ gateway.RevocationWatch = (*authorityWatch)(nil)
