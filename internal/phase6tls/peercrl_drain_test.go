package phase6tls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
)

type controlledPeerClose struct {
	net.Conn
	err      error
	started  chan struct{}
	release  <-chan struct{}
	once     sync.Once
	calls    atomic.Int32
	onStart  func()
	onFinish func()
}

func (c *controlledPeerClose) Close() error {
	c.calls.Add(1)
	if c.onStart != nil {
		c.onStart()
	}
	if c.onFinish != nil {
		defer c.onFinish()
	}
	c.once.Do(func() {
		if c.started != nil {
			close(c.started)
		}
	})
	if c.release != nil {
		<-c.release
	}
	if c.err != nil {
		return c.err
	}
	return c.Conn.Close()
}

func waitPeerDrainCleanup(t *testing.T, guard *PeerCRLGuard) {
	t.Helper()
	guard.mu.Lock()
	batch := guard.draining
	guard.mu.Unlock()
	if batch != nil {
		select {
		case <-batch.done:
		case <-time.After(time.Second):
			t.Error("released owned close workers did not finish")
		}
	}
}

func TestPeerCRLSuccessfulSelectiveDrainPreservesOtherPeer(t *testing.T) {
	f := readyPeerCloseFixture(t)
	revoked, revokedPeer := peerClosePipe(t)
	good, goodPeer := peerClosePipe(t)
	if err := f.guard.Track(revoked, f.state); err != nil {
		t.Fatal(err)
	}
	if err := f.guard.Track(good, anotherPeerCloseState(t, f)); err != nil {
		t.Fatal(err)
	}
	f.client.response = f.response(t, 2, true, "fixed-source")
	if err := f.guard.Poll(t.Context()); err != nil || !f.guard.Ready() {
		t.Fatalf("successful selective closure lost readiness: %v", err)
	}
	requirePeerCloseEOF(t, revokedPeer)
	wrote := make(chan error, 1)
	go func() { _, err := goodPeer.Write([]byte{7}); wrote <- err }()
	_ = good.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	var one [1]byte
	if _, err := io.ReadFull(good, one[:]); err != nil || one[0] != 7 {
		t.Fatalf("unrevoked peer stopped forwarding: %v", err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
}

type onePeerCloseListener struct{ connection net.Conn }

func (l *onePeerCloseListener) Accept() (net.Conn, error) {
	if l.connection == nil {
		return nil, net.ErrClosed
	}
	c := l.connection
	l.connection = nil
	return c, nil
}

func (*onePeerCloseListener) Close() error   { return nil }
func (*onePeerCloseListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestPeerCRLDrainRetainsCloseErrorAcrossRegistryForget(t *testing.T) {
	f := readyPeerCloseFixture(t)
	local, _ := peerClosePipe(t)
	bad := &controlledPeerClose{Conn: local, err: errors.New("injected uncertain registry close")}
	registry, err := connectiondrain.New(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var forgot atomic.Int32
	if err := registry.OnClose(func(c net.Conn) { forgot.Add(1); f.guard.Forget(c) }); err != nil {
		t.Fatal(err)
	}
	listener, err := registry.Wrap(&onePeerCloseListener{connection: bad})
	if err != nil {
		t.Fatal(err)
	}
	tracked, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.guard.Track(tracked, f.state); err != nil {
		t.Fatal(err)
	}
	f.client.response = f.response(t, 2, true, "fixed-source")
	if err := f.guard.Poll(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Errorf("registry Close error was accepted: %v", err)
	}
	f.guard.mu.Lock()
	_, retained := f.guard.closing[tracked]
	failed := f.guard.failed
	f.guard.mu.Unlock()
	if !retained || !failed || registry.Active() != 0 || forgot.Load() != 1 || bad.calls.Load() != 1 {
		t.Fatalf("Forget erased uncertainty: retained=%v failed=%v registry=%d hooks=%d attempts=%d", retained, failed, registry.Active(), forgot.Load(), bad.calls.Load())
	}
	f.guard.Close()
	if bad.calls.Load() != 1 {
		t.Fatal("failed claimed identity was retried")
	}
}

func TestPeerCRLDrainScopeDoesNotRenewBudget(t *testing.T) {
	first, firstPeer := peerClosePipe(t)
	second, _ := peerClosePipe(t)
	releaseFirst, releaseSecond := make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	a := &controlledPeerClose{Conn: first, release: releaseFirst}
	b := &controlledPeerClose{Conn: second, release: releaseSecond}
	guard := &PeerCRLGuard{active: map[net.Conn]tls.ConnectionState{a: {}, b: {}}, closeBudget: 400 * time.Millisecond}
	t.Cleanup(func() {
		firstOnce.Do(func() { close(releaseFirst) })
		secondOnce.Do(func() { close(releaseSecond) })
		guard.Close()
		waitPeerDrainCleanup(t, guard)
	})
	scope := &peerCRLCloseScope{}
	guard.mu.Lock()
	one := guard.beginPeerDrainLocked(scope, []net.Conn{a}, false)
	deadline := one.deadline
	guard.mu.Unlock()
	timer := time.AfterFunc(80*time.Millisecond, func() { firstOnce.Do(func() { close(releaseFirst) }) })
	defer timer.Stop()
	if !guard.awaitPeerDrain(one) {
		t.Fatal("first selective phase did not finish within its budget")
	}
	requirePeerCloseEOF(t, firstPeer)
	guard.mu.Lock()
	two := guard.beginPeerDrainLocked(scope, []net.Conn{b}, false)
	unchanged := two.deadline.Equal(deadline) && scope.deadline.Equal(deadline)
	guard.mu.Unlock()
	if !unchanged || guard.awaitPeerDrain(two) {
		t.Fatal("second blocked phase renewed the same-call deadline or reported success")
	}
}

func TestPeerCRLDrainRejectsNonpositiveBudget(t *testing.T) {
	for _, budget := range []time.Duration{0, -time.Millisecond} {
		t.Run(budget.String(), func(t *testing.T) {
			local, peer := peerClosePipe(t)
			guard := &PeerCRLGuard{active: map[net.Conn]tls.ConnectionState{local: {}}, closeBudget: budget}
			t.Cleanup(func() { guard.Close(); waitPeerDrainCleanup(t, guard) })
			guard.mu.Lock()
			batch := guard.beginPeerDrainLocked(&peerCRLCloseScope{}, nil, true)
			guard.mu.Unlock()
			if guard.awaitPeerDrain(batch) {
				t.Error("nonpositive C was silently enlarged or accepted")
			}
			waitPeerDrainCleanup(t, guard)
			requirePeerCloseEOF(t, peer)
			guard.mu.Lock()
			failed := guard.failed
			guard.mu.Unlock()
			if !failed {
				t.Error("late cleanup cleared invalid-budget failure")
			}
		})
	}
}

func TestPeerCRLDrainTimeoutSharesOneBoundedPool(t *testing.T) {
	f := readyPeerCloseFixture(t)
	f.guard.closeBudget = 100 * time.Millisecond
	release := make(chan struct{})
	var once sync.Once
	started := make(chan struct{}, 17)
	var concurrent, peak atomic.Int32
	connections := make([]*controlledPeerClose, 0, 17)
	for range 17 {
		local, _ := peerClosePipe(t)
		connection := &controlledPeerClose{Conn: local, release: release, onFinish: func() { concurrent.Add(-1) }, onStart: func() {
			count := concurrent.Add(1)
			for old := peak.Load(); count > old; old = peak.Load() {
				if peak.CompareAndSwap(old, count) {
					break
				}
			}
			started <- struct{}{}
		}}
		connections = append(connections, connection)
		if err := f.guard.Track(connection, f.state); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { once.Do(func() { close(release) }); waitPeerDrainCleanup(t, f.guard) })
	done := make(chan struct{})
	go func() { f.guard.Close(); close(done) }()
	for range 16 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("initial bounded workers did not start")
		}
	}
	<-done
	f.guard.mu.Lock()
	batch := f.guard.draining
	if batch == nil {
		f.guard.mu.Unlock()
		t.Fatal("pending closes disappeared after the deadline")
	}
	deadline := batch.deadline
	valid := batch.timedOut && batch.workers == 16 && batch.next == 16 && len(batch.queue) == 17 && len(f.guard.closing) == 17 && len(f.guard.active) == 0
	newerScope := &peerCRLCloseScope{deadline: deadline.Add(time.Second)}
	joined := f.guard.beginPeerDrainLocked(newerScope, nil, false)
	valid = valid && joined == batch && newerScope.deadline.Equal(deadline)
	f.guard.mu.Unlock()
	if !valid || f.guard.Ready() {
		t.Fatal("timed-out queued peers were lost or claimed closed")
	}
	for range 3 {
		f.guard.Close()
	}
	if err := f.guard.Bootstrap(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Fatal("timeout was recoverable")
	}
	f.guard.mu.Lock()
	unchanged := f.guard.draining == batch && batch.deadline.Equal(deadline) && batch.workers == 16
	f.guard.mu.Unlock()
	if !unchanged || peak.Load() != 16 {
		t.Fatal("reentry renewed C or started another pool")
	}
	once.Do(func() { close(release) })
	waitPeerDrainCleanup(t, f.guard)
	for _, connection := range connections {
		if connection.calls.Load() != 1 {
			t.Fatalf("queued identity attempts=%d", connection.calls.Load())
		}
	}
	if peak.Load() > 16 || concurrent.Load() != 0 {
		t.Fatalf("Close concurrency peak=%d remaining=%d", peak.Load(), concurrent.Load())
	}
	if f.guard.Ready() {
		t.Fatal("late cleanup turned a failed deadline into success")
	}
}

func TestPeerCRLExpiryJoinsSelectiveDrain(t *testing.T) {
	f := readyPeerCloseFixture(t)
	f.guard.maxStaleness = 100 * time.Millisecond
	f.guard.closeBudget = 500 * time.Millisecond
	local, peer := peerClosePipe(t)
	good, goodPeer := peerClosePipe(t)
	release := make(chan struct{})
	var once sync.Once
	blocked := &controlledPeerClose{Conn: local, started: make(chan struct{}), release: release}
	if err := f.guard.Track(blocked, f.state); err != nil {
		t.Fatal(err)
	}
	if err := f.guard.Track(good, anotherPeerCloseState(t, f)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { once.Do(func() { close(release) }); waitPeerDrainCleanup(t, f.guard) })
	f.client.response = f.response(t, 2, true, "fixed-source")
	done := make(chan error, 1)
	go func() { done <- f.guard.Poll(t.Context()) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("selective Close did not start")
	}
	f.guard.mu.Lock()
	batch, deadline := f.guard.draining, f.guard.draining.deadline
	f.guard.mu.Unlock()
	requirePeerCloseEOF(t, goodPeer) // The expiry timer must claim this previously valid peer.
	f.guard.mu.Lock()
	joined := f.guard.draining == batch && batch.deadline.Equal(deadline) && f.guard.unavailable
	f.guard.mu.Unlock()
	if !joined || f.guard.Ready() {
		t.Error("expiry did not join the original pending batch/deadline")
	}
	once.Do(func() { close(release) })
	if err := <-done; !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Errorf("expired source poll = %v", err)
	}
	requirePeerCloseEOF(t, peer)
	f.guard.mu.Lock()
	failed := f.guard.failed
	f.guard.mu.Unlock()
	if failed {
		t.Error("successful expiry closure became permanently failed")
	}
	f.client.response = f.response(t, 3, true, "fixed-source")
	if err := f.guard.Bootstrap(t.Context()); err != nil || !f.guard.Ready() {
		t.Errorf("completed expiry could not recover fresh authority: %v", err)
	}
}

func peerClosePipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = peer.Close() })
	return local, peer
}

func readyPeerCloseFixture(t *testing.T) guardFixture {
	t.Helper()
	f := newGuardFixture(t)
	f.client.response = f.response(t, 1, false, "fixed-source")
	if err := f.guard.CheckHandshake(t.Context(), f.state); err != nil || !f.guard.Ready() {
		t.Fatalf("initial peer authority unavailable: %v", err)
	}
	return f
}

func anotherPeerCloseState(t *testing.T, f guardFixture) tls.ConnectionState {
	t.Helper()
	template := *f.leaf
	template.SerialNumber = big.NewInt(43)
	der, err := x509.CreateCertificate(rand.Reader, &template, f.issuer, &f.leafKey.PublicKey, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf, f.issuer},
		VerifiedChains: [][]*x509.Certificate{{leaf, f.issuer}}}
}

func requirePeerCloseEOF(t *testing.T, peer net.Conn) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	var one [1]byte
	if _, err := peer.Read(one[:]); !errors.Is(err, io.EOF) {
		t.Errorf("peer was not actually closed: %v", err)
	}
}

func TestPeerCRLCloseErrorRejectsReadiness(t *testing.T) {
	f := readyPeerCloseFixture(t)
	local, _ := peerClosePipe(t)
	bad := &controlledPeerClose{Conn: local, err: errors.New("injected uncertain close")}
	if err := f.guard.Track(bad, f.state); err != nil {
		t.Fatal(err)
	}
	f.client.response = f.response(t, 2, true, "fixed-source")
	if err := f.guard.Poll(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Errorf("failed close reported a successful poll: %v", err)
	}
	if f.guard.Ready() {
		t.Error("failed close retained readiness")
	}
	if bad.calls.Load() != 1 {
		t.Errorf("close attempts = %d, want exactly one", bad.calls.Load())
	}
	// Fresh signed evidence cannot prove that an uncertain socket closed.
	f.client.response = f.response(t, 3, true, "fixed-source")
	if err := f.guard.Bootstrap(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
		t.Errorf("fresh CRL recovered an uncertain close: %v", err)
	}
}

func TestPeerCRLPartialCloseErrorDrainsRemainingPeer(t *testing.T) {
	f := readyPeerCloseFixture(t)
	badLocal, _ := peerClosePipe(t)
	bad := &controlledPeerClose{Conn: badLocal, err: errors.New("injected uncertain close")}
	good, goodPeer := peerClosePipe(t)
	if err := f.guard.Track(bad, f.state); err != nil {
		t.Fatal(err)
	}
	if err := f.guard.Track(good, anotherPeerCloseState(t, f)); err != nil {
		t.Fatal(err)
	}
	f.client.response = f.response(t, 2, true, "fixed-source")
	if err := f.guard.Poll(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Errorf("partial close error did not fail the poll: %v", err)
	}
	requirePeerCloseEOF(t, goodPeer)
	if f.guard.Ready() || bad.calls.Load() != 1 {
		t.Errorf("partial failure retained authority or retried: ready=%v attempts=%d", f.guard.Ready(), bad.calls.Load())
	}
}

func TestPeerCRLPendingDrainCannotRestoreReadiness(t *testing.T) {
	f := readyPeerCloseFixture(t)
	f.guard.closeBudget = 500 * time.Millisecond
	local, peer := peerClosePipe(t)
	release := make(chan struct{})
	var once sync.Once
	blocked := &controlledPeerClose{Conn: local, started: make(chan struct{}), release: release}
	if err := f.guard.Track(blocked, f.state); err != nil {
		t.Fatal(err)
	}
	f.client.err = errors.New("injected authority loss")
	done := make(chan error, 1)
	go func() { done <- f.guard.Poll(t.Context()) }()
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("owned close did not start")
	}
	f.client.err = nil // The failed authority call has returned and is now closing.
	f.client.response = f.response(t, 2, false, "fixed-source")
	if err := f.guard.Bootstrap(t.Context()); !errors.Is(err, ErrPeerCRLUnavailable) {
		t.Errorf("fresh pull admitted while the old socket was still closing: %v", err)
	}
	late, _ := peerClosePipe(t)
	if err := f.guard.Track(late, f.state); !errors.Is(err, ErrPeerCRLUnavailable) || f.guard.Ready() {
		t.Errorf("pending closure restored admission/readiness: %v", err)
	}
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		if !errors.Is(err, ErrPeerCRLUnavailable) {
			t.Errorf("original source-loss poll = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("owned poll did not finish after release")
	}
	requirePeerCloseEOF(t, peer)
	f.client.response = f.response(t, 3, false, "fixed-source")
	if err := f.guard.Bootstrap(t.Context()); err != nil || !f.guard.Ready() {
		t.Errorf("successful completed source-loss drain could not recover: %v", err)
	}
}
