package controloperator

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/controldelivery"
)

// The SDK's ordinary HTTP transport represents its Unix URL as tcp/path:80,
// while its hijack path passes unix/path directly. Normalize only these two
// exact local representations; never resolve a hostname or dial TCP.
func dockerUnixDial(ceremony context.Context, socket string) func(context.Context, string, string) (net.Conn, error) {
	dial := boundedUnixDial(ceremony, socket)
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network == "tcp" && address == net.JoinHostPort(socket, "80") {
			network, address = "unix", socket
		}
		return dial(ctx, network, address)
	}
}

// boundedUnixDial covers the SDK's HTTP upgrade handshake, which happens
// before ContainerAttach/ExecAttach return a connection to the caller. The
// endpoint is operator-controlled; checking its path is not authentication.
func boundedUnixDial(ceremony context.Context, socket string) func(context.Context, string, string) (net.Conn, error) {
	return func(request context.Context, network, address string) (net.Conn, error) {
		fail := controldelivery.ErrUnavailable
		if ceremony == nil || request == nil || ceremony.Err() != nil || request.Err() != nil || network != "unix" || !filepath.IsAbs(socket) || address != socket {
			return nil, fail
		}
		deadline, ok := ceremony.Deadline()
		if !ok {
			return nil, fail
		}
		if d, ok := request.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		// HTTP transports may detach their dial context from request cancellation.
		// The complete ceremony still bounds both connecting and pooled sockets.
		dialCtx, cancel := context.WithDeadline(request, deadline)
		stop := context.AfterFunc(ceremony, cancel)
		raw, err := (&net.Dialer{}).DialContext(dialCtx, network, address)
		stop()
		cancel()
		if err != nil {
			return nil, fail
		}
		unix, ok := raw.(*net.UnixConn)
		if !ok {
			raw.Close()
			return nil, fail
		}
		conn := &boundedUnixConn{UnixConn: unix, deadline: deadline}
		if conn.SetDeadline(deadline) != nil {
			conn.Close()
			return nil, fail
		}
		// Registration and Close share a lock: even an already-canceled context
		// cannot leave a late callback retained after the connection is closed.
		conn.mu.Lock()
		conn.stops = []func() bool{
			context.AfterFunc(ceremony, func() { conn.Close() }),
			context.AfterFunc(request, func() { conn.Close() }),
		}
		conn.mu.Unlock()
		if ceremony.Err() != nil || request.Err() != nil {
			conn.Close()
			return nil, fail
		}
		return conn, nil
	}
}

// Embedding UnixConn preserves CloseWrite for the SDK's hijacked stream.
type boundedUnixConn struct {
	*net.UnixConn
	deadline time.Time
	mu       sync.Mutex
	closed   bool
	stops    []func() bool
}

func (c *boundedUnixConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	stops := c.stops
	c.stops = nil
	c.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
	return c.UnixConn.Close()
}

func (c *boundedUnixConn) limit(t time.Time) time.Time {
	if t.IsZero() || t.After(c.deadline) {
		return c.deadline
	}
	return t
}
func (c *boundedUnixConn) SetDeadline(t time.Time) error {
	return c.UnixConn.SetDeadline(c.limit(t))
}
func (c *boundedUnixConn) SetReadDeadline(t time.Time) error {
	return c.UnixConn.SetReadDeadline(c.limit(t))
}
func (c *boundedUnixConn) SetWriteDeadline(t time.Time) error {
	return c.UnixConn.SetWriteDeadline(c.limit(t))
}
