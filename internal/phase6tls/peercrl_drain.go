package phase6tls

import (
	"net"
	"time"
)

// This scope is local control flow, never cached evidence or authority. Its
// monotonic deadline begins at the first Close, after any authority pull.
type peerCRLCloseScope struct {
	deadline       time.Time
	failureHandled bool
}

type peerCRLDrain struct {
	deadline   time.Time
	queue      []net.Conn
	next       int
	workers    int
	done       chan struct{}
	expired    chan struct{}
	timer      *time.Timer
	failed     bool
	timedOut   bool
	finishedAt time.Time
}

// All batch/identity fields are protected by g.mu. Claim before unlocking:
// neither a transport Forget nor a fresh pull can erase pending closure.
func (g *PeerCRLGuard) beginPeerDrainLocked(scope *peerCRLCloseScope, selected []net.Conn, all bool) *peerCRLDrain {
	batch := g.draining
	if batch == nil && len(selected) == 0 && (!all || len(g.active) == 0) {
		return nil
	}
	if batch == nil {
		if scope.deadline.IsZero() {
			scope.deadline = time.Now().Add(g.closeBudget)
		}
		batch = &peerCRLDrain{deadline: scope.deadline, done: make(chan struct{}), expired: make(chan struct{})}
		g.draining = batch
		if g.closing == nil {
			g.closing = make(map[net.Conn]struct{})
		}
		batch.timer = time.AfterFunc(time.Until(batch.deadline), func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.draining == batch {
				g.failPeerDrainLocked(batch, true)
				g.startPeerDrainWorkersLocked(batch)
			}
		})
	} else {
		if scope.deadline.IsZero() || batch.deadline.Before(scope.deadline) {
			scope.deadline = batch.deadline
		}
		if scope.deadline.Before(batch.deadline) {
			batch.deadline = scope.deadline
			batch.timer.Reset(time.Until(batch.deadline))
		}
	}
	if all {
		g.claimRemainingPeersLocked(batch)
	} else {
		for _, connection := range selected {
			g.claimPeerLocked(batch, connection)
		}
	}
	if !time.Now().Before(batch.deadline) {
		g.failPeerDrainLocked(batch, true)
	}
	g.startPeerDrainWorkersLocked(batch)
	if batch.workers == 0 {
		g.finishPeerDrainLocked(batch)
	}
	return batch
}

func (g *PeerCRLGuard) claimPeerLocked(batch *peerCRLDrain, connection net.Conn) {
	if _, active := g.active[connection]; !active {
		return
	}
	delete(g.active, connection)
	if _, claimed := g.closing[connection]; claimed {
		return
	}
	g.closing[connection] = struct{}{}
	batch.queue = append(batch.queue, connection)
}

func (g *PeerCRLGuard) claimRemainingPeersLocked(batch *peerCRLDrain) {
	for connection := range g.active {
		g.claimPeerLocked(batch, connection)
	}
}

func (g *PeerCRLGuard) failPeerDrainLocked(batch *peerCRLDrain, expired bool) {
	if !batch.failed {
		batch.failed = true
		g.failed = true
		g.unavailable = true
		g.failureSequence++
		g.expirySequence++
		if g.expiryTimer != nil {
			g.expiryTimer.Stop()
		}
	}
	// Escalate within this batch and its original pool/deadline. Every retained
	// peer is claimed, even when blocked workers cannot yet start its Close.
	g.claimRemainingPeersLocked(batch)
	if expired && !batch.timedOut {
		batch.timedOut = true
		close(batch.expired)
	}
}

func (g *PeerCRLGuard) startPeerDrainWorkersLocked(batch *peerCRLDrain) {
	count := min(len(batch.queue)-batch.next, 16-batch.workers)
	batch.workers += count
	for range count {
		go g.closePeerDrainWorker(batch)
	}
}

func (g *PeerCRLGuard) closePeerDrainWorker(batch *peerCRLDrain) {
	for {
		g.mu.Lock()
		if batch.next == len(batch.queue) {
			batch.workers--
			if batch.workers == 0 {
				g.finishPeerDrainLocked(batch)
			}
			g.mu.Unlock()
			return
		}
		connection := batch.queue[batch.next]
		batch.next++
		g.mu.Unlock()

		// trackedConn.Close synchronously invokes Forget; never hold g.mu here.
		err := connection.Close()
		g.mu.Lock()
		if err != nil {
			g.failPeerDrainLocked(batch, false)
		} else {
			delete(g.closing, connection)
		}
		if !time.Now().Before(batch.deadline) {
			g.failPeerDrainLocked(batch, true)
		}
		g.startPeerDrainWorkersLocked(batch)
		g.mu.Unlock()
	}
}

func (g *PeerCRLGuard) finishPeerDrainLocked(batch *peerCRLDrain) {
	now := time.Now()
	if !now.Before(batch.deadline) {
		g.failPeerDrainLocked(batch, true)
		g.startPeerDrainWorkersLocked(batch)
		if batch.workers != 0 {
			return
		}
	}
	batch.finishedAt = now
	batch.timer.Stop()
	g.draining = nil
	close(batch.done)
}

func (g *PeerCRLGuard) awaitPeerDrain(batch *peerCRLDrain) bool {
	if batch == nil {
		return true
	}
	select {
	case <-batch.done:
	case <-batch.expired:
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return !batch.failed && !batch.finishedAt.IsZero() && batch.finishedAt.Before(batch.deadline)
}

func (g *PeerCRLGuard) invalidateAndDrain(scope *peerCRLCloseScope) {
	g.mu.Lock()
	batch := g.invalidatePeerEvidenceLocked(scope)
	g.mu.Unlock()
	g.awaitPeerDrain(batch)
}

func (g *PeerCRLGuard) invalidatePeerEvidenceLocked(scope *peerCRLCloseScope) *peerCRLDrain {
	scope.failureHandled = true
	g.unavailable = true
	g.failureSequence++
	g.expirySequence++
	if g.expiryTimer != nil {
		g.expiryTimer.Stop()
	}
	return g.beginPeerDrainLocked(scope, nil, true)
}
