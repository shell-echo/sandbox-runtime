package restrictedunix

import (
	"net"
	"sync"
)

// Tracker closes admitted sockets before waiting for handlers, including
// peers stalled on the first frame. Add and Stop are serialized.
type Tracker struct {
	mu          sync.Mutex
	connections map[*net.UnixConn]struct{}
	handlers    sync.WaitGroup
	closed      bool
}

func NewTracker() *Tracker {
	return &Tracker{connections: make(map[*net.UnixConn]struct{})}
}

func (t *Tracker) Add(connection *net.UnixConn) bool {
	if t == nil || connection == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.connections[connection] = struct{}{}
	t.handlers.Add(1)
	return true
}

func (t *Tracker) Done(connection *net.UnixConn) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.connections, connection)
	t.mu.Unlock()
	t.handlers.Done()
}

func (t *Tracker) Stop() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.closed = true
	for connection := range t.connections {
		_ = connection.Close()
	}
	t.mu.Unlock()
}

func (t *Tracker) Wait() {
	if t != nil {
		t.handlers.Wait()
	}
}
