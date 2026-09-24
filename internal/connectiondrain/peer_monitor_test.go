package connectiondrain

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type pollMonitorFixture struct {
	interval time.Duration
	calls    atomic.Int32
}

func (*pollMonitorFixture) Track(net.Conn, tls.ConnectionState) error { return nil }
func (*pollMonitorFixture) Forget(net.Conn)                           {}
func (p *pollMonitorFixture) Poll(context.Context) error {
	p.calls.Add(1)
	return nil
}
func (p *pollMonitorFixture) PollInterval() time.Duration { return p.interval }
func (*pollMonitorFixture) Ready() bool                   { return true }
func (*pollMonitorFixture) Close()                        {}

func TestStartPeerPollUsesOneBoundedScheduleAndStops(t *testing.T) {
	monitor := &pollMonitorFixture{interval: 100 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	stop := StartPeerPoll(ctx, monitor)
	deadline := time.Now().Add(500 * time.Millisecond)
	for monitor.calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if monitor.calls.Load() < 2 {
		t.Fatal("peer monitor did not poll at its declared interval")
	}
	cancel()
	stop()
	calls := monitor.calls.Load()
	time.Sleep(120 * time.Millisecond)
	if monitor.calls.Load() != calls {
		t.Fatal("peer monitor continued polling after stop")
	}
	invalid := &pollMonitorFixture{interval: 0}
	StartPeerPoll(context.Background(), invalid)()
	if invalid.calls.Load() != 0 {
		t.Fatal("invalid interval started a poller")
	}
}
