// Package connectiondrain bounds the lifetime of accepted transport sockets,
// including connections that net/http no longer owns after a hijack.
package connectiondrain

import (
	"errors"
	"net"
	"sync"
	"time"
)

type Registry struct {
	mu      sync.Mutex
	active  map[*trackedConn]struct{}
	maxAge  time.Duration
	drained bool
	onClose func(net.Conn)
}

// OnClose installs a cleanup hook before the listener is wrapped. The hook
// runs once for each socket, including hijacked sockets closed by max age or
// shutdown drain.
func (r *Registry) OnClose(hook func(net.Conn)) error {
	if r == nil || hook == nil {
		return errors.New("connection close hook is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.drained || len(r.active) != 0 || r.onClose != nil {
		return errors.New("connection close hook must be installed before accepts")
	}
	r.onClose = hook
	return nil
}

func New(maxAge time.Duration) (*Registry, error) {
	if maxAge < time.Second || maxAge > time.Hour {
		return nil, errors.New("connection lifetime must be between one second and one hour")
	}
	return &Registry{active: make(map[*trackedConn]struct{}), maxAge: maxAge}, nil
}

// Wrap registers each accepted socket before the TLS handshake. Closing the
// HTTP listener alone does not discard accepted or hijacked sockets.
func (r *Registry) Wrap(listener net.Listener) (net.Listener, error) {
	if r == nil || listener == nil {
		return nil, errors.New("connection registry and listener are required")
	}
	return &trackedListener{Listener: listener, registry: r}, nil
}

// Drain closes every accepted socket and rejects racing future accepts. It is
// idempotent and does not require net/http to report a hijacked connection.
func (r *Registry) Drain() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	r.drained = true
	connections := make([]*trackedConn, 0, len(r.active))
	for connection := range r.active {
		connections = append(connections, connection)
	}
	r.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return len(connections)
}

func (r *Registry) Active() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}

type trackedListener struct {
	net.Listener
	registry *Registry
}

func (l *trackedListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	r := l.registry
	r.mu.Lock()
	if r.drained {
		r.mu.Unlock()
		_ = connection.Close()
		return nil, net.ErrClosed
	}
	tracked := &trackedConn{Conn: connection, registry: r}
	r.active[tracked] = struct{}{}
	tracked.timer = time.AfterFunc(r.maxAge, func() { _ = tracked.Close() })
	r.mu.Unlock()
	return tracked, nil
}

type trackedConn struct {
	net.Conn
	registry *Registry
	once     sync.Once
	timer    *time.Timer
	err      error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.registry.mu.Lock()
		c.timer.Stop()
		delete(c.registry.active, c)
		hook := c.registry.onClose
		c.registry.mu.Unlock()
		if hook != nil {
			hook(c)
		}
	})
	return c.err
}
