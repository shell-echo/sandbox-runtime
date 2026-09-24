package phase6tls

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type countedClientConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *countedClientConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

func TestBoundedClientConnClosesUpgradedConnectionExactlyOnce(t *testing.T) {
	first, second := net.Pipe()
	defer second.Close()
	underlying := &countedClientConn{Conn: first}
	bounded := newBoundedClientConn(underlying, 25*time.Millisecond)
	deadline := time.Now().Add(time.Second)
	for underlying.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if underlying.closed.Load() != 1 {
		t.Fatal("bounded client connection did not expire exactly once")
	}
	if err := bounded.Close(); err != nil {
		t.Fatal(err)
	}
	if underlying.closed.Load() != 1 {
		t.Fatal("explicit close duplicated expired connection cleanup")
	}
}
