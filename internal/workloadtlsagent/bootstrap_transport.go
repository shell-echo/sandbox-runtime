package workloadtlsagent

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// BootstrapTrackingTransport counts requests that could have selected a
// bootstrap client leaf. Use it with a non-reusing HTTP transport; after
// Switch, wait for every pre-switch body to finish before destroying the
// bootstrap private key.
type BootstrapTrackingTransport struct {
	base     http.RoundTripper
	mu       sync.Mutex
	switched bool
	active   int
}

func NewBootstrapTrackingTransport(base http.RoundTripper) *BootstrapTrackingTransport {
	if base == nil {
		return nil
	}
	return &BootstrapTrackingTransport{base: base}
}

func (t *BootstrapTrackingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.mu.Lock()
	bootstrap := !t.switched
	if bootstrap {
		t.active++
	}
	t.mu.Unlock()
	response, err := t.base.RoundTrip(request)
	if !bootstrap {
		return response, err
	}
	if err != nil || response == nil || response.Body == nil {
		t.finished()
		return response, err
	}
	response.Body = &trackedBootstrapBody{ReadCloser: response.Body, finished: t.finished}
	return response, nil
}

func (t *BootstrapTrackingTransport) finished() {
	t.mu.Lock()
	t.active--
	t.mu.Unlock()
}

func (t *BootstrapTrackingTransport) Switch() {
	t.mu.Lock()
	t.switched = true
	t.mu.Unlock()
}

func (t *BootstrapTrackingTransport) WaitBootstrapDrain(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		t.mu.Lock()
		finished := t.switched && t.active == 0
		t.mu.Unlock()
		if finished {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type trackedBootstrapBody struct {
	io.ReadCloser
	once     sync.Once
	finished func()
}

func (body *trackedBootstrapBody) Read(buffer []byte) (int, error) {
	count, err := body.ReadCloser.Read(buffer)
	if err == io.EOF {
		body.once.Do(body.finished)
	}
	return count, err
}

func (body *trackedBootstrapBody) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(body.finished)
	return err
}
