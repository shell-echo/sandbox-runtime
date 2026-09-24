package phase6tls

import (
	"net"
	"sync"
	"time"
)

// boundedClientConn closes upgraded WebSockets at the profile's maximum TLS
// connection age; net/http idle limits do not cover hijacked connections.
type boundedClientConn struct {
	net.Conn
	once  sync.Once
	timer *time.Timer
	done  chan struct{}
	err   error
}

func newBoundedClientConn(connection net.Conn, maxAge time.Duration) *boundedClientConn {
	bounded := &boundedClientConn{Conn: connection, timer: time.NewTimer(maxAge), done: make(chan struct{})}
	go func() {
		select {
		case <-bounded.timer.C:
			_ = bounded.Close()
		case <-bounded.done:
		}
	}()
	return bounded
}

func (c *boundedClientConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.timer.Stop()
		c.err = c.Conn.Close()
	})
	return c.err
}
