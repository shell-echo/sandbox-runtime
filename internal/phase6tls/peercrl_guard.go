package phase6tls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

var ErrPeerCRLUnavailable = errors.New("peer revocation evidence unavailable")

const maxObservedRevokedPeers = 8192

type PeerCRLClient interface {
	PeerCRL(context.Context, workloadtlsagent.PeerCRLBinding, []byte) (workloadtlsagent.PeerCRLResponse, error)
	BootstrapPeerCRL(context.Context, workloadtlsagent.PeerCRLBinding, string) (workloadtlsagent.PeerCRLResponse, error)
}

type PeerCRLGuard struct {
	binding              workloadtlsagent.PeerCRLBinding
	expectedIssuerDigest string
	client               PeerCRLClient
	pullPermit           chan struct{}
	maxStaleness         time.Duration
	timeout              time.Duration
	pollInterval         time.Duration
	closeBudget          time.Duration
	now                  func() time.Time

	mu              sync.Mutex
	failed          bool
	unavailable     bool
	failureSequence uint64
	lastNow         time.Time
	sourceID        string
	issuerDigest    string
	number          *big.Int
	thisUpdate      time.Time
	crlDigest       string
	collectedAt     time.Time
	nextUpdate      time.Time
	current         workloadpki.VerifiedCRL
	observedRevoked map[string]revokedPeerObservation
	active          map[net.Conn]tls.ConnectionState
	expiryTimer     *time.Timer
	expirySequence  uint64
}

type revokedPeerObservation struct {
	serial   *big.Int
	notAfter time.Time
}

// NewPeerCRLGuard binds one local role's exact mTLS edge to its role-owned
// agent. The caller cannot provide a Vault source, issuer reference or URL.
func NewPeerCRLGuard(profile phase6security.Profile, roleDocument phase6security.PeerCRLRoleDocument,
	edgeID, localPrincipalDigest, direction string,
	client PeerCRLClient, timeout time.Duration, now func() time.Time) (*PeerCRLGuard, error) {
	roleBinding, bindingErr := roleDocument.Binding(edgeID, direction)
	if profile.Validate() != nil || client == nil || now == nil || now().IsZero() ||
		timeout < time.Second || timeout > 30*time.Second ||
		roleDocument.ValidateForPrincipal(profile, roleDocument.SourceMappingDigest, localPrincipalDigest) != nil ||
		bindingErr != nil ||
		!validPeerCRLDigest(roleBinding.IssuerDigest) {
		return nil, ErrPeerCRLUnavailable
	}
	for _, edge := range profile.TrustEdges {
		if edge.ID != edgeID || edge.Authentication != "mtls" || edge.ClientAnchorID == "" {
			continue
		}
		localName, anchorID, principalDigest := "", "", ""
		switch direction {
		case "outbound":
			localName, anchorID, principalDigest = edge.From, edge.ServerAnchorID, edge.FromPrincipalDigest
		case "inbound":
			localName, anchorID, principalDigest = edge.To, edge.ClientAnchorID, edge.ToPrincipalDigest
		default:
			return nil, ErrPeerCRLUnavailable
		}
		if principalDigest != localPrincipalDigest || anchorID == "" || roleBinding.PeerAnchorID != anchorID {
			return nil, ErrPeerCRLUnavailable
		}
		for _, principal := range profile.Principals {
			if principal.Name != localName || principal.PrincipalDigest != localPrincipalDigest || principal.TLS == nil {
				continue
			}
			staleness := time.Duration(principal.TLS.RevocationMaxStalenessSeconds) * time.Second
			drain := time.Duration(principal.TLS.ConnectionDrainSeconds) * time.Second
			budget, budgetErr := derivePeerCRLBudget(staleness, drain, timeout)
			if budgetErr != nil {
				return nil, ErrPeerCRLUnavailable
			}
			return &PeerCRLGuard{binding: workloadtlsagent.PeerCRLBinding{
				ProfileDigest: profile.ProfileDigest, SourceMappingDigest: roleDocument.SourceMappingDigest,
				EdgeID: edgeID, LocalPrincipalDigest: localPrincipalDigest,
				Direction: direction, PeerAnchorID: anchorID}, expectedIssuerDigest: roleBinding.IssuerDigest,
				client: client, pullPermit: make(chan struct{}, 1), timeout: budget.timeout,
				pollInterval: budget.interval, closeBudget: budget.close,
				maxStaleness: staleness, now: now, observedRevoked: make(map[string]revokedPeerObservation),
				active: make(map[net.Conn]tls.ConnectionState)}, nil
		}
	}
	return nil, ErrPeerCRLUnavailable
}

type peerCRLBudget struct {
	timeout  time.Duration
	interval time.Duration
	close    time.Duration
}

// D is the exact local role's declared drain bound, S is evidence freshness,
// T includes permit queueing and the entire pull, P is poll wait, C is total
// close time. The real gate must additionally verify U+J <= D/5 and leave
// >=D/10 margin: U + 2*T + P + C + J < D. This configuration calculation is
// not a substitute for measuring Vault publication and scheduler behavior.
func derivePeerCRLBudget(staleness, drain, operationTimeout time.Duration) (peerCRLBudget, error) {
	if staleness < time.Second || staleness > 5*time.Minute ||
		drain < time.Second || drain > 5*time.Minute ||
		operationTimeout < time.Second || operationTimeout > 30*time.Second {
		return peerCRLBudget{}, ErrPeerCRLUnavailable
	}
	budget := peerCRLBudget{timeout: min(operationTimeout, drain/5),
		interval: min(staleness/2, drain/5, 30*time.Second), close: drain / 10}
	if budget.timeout < 100*time.Millisecond || budget.interval < 100*time.Millisecond ||
		budget.close < 100*time.Millisecond ||
		2*budget.timeout+budget.interval+budget.close+drain/5 > drain-drain/10 {
		return peerCRLBudget{}, ErrPeerCRLUnavailable
	}
	return budget, nil
}

// CheckHandshake runs only after standard TLS chain and identity verification.
// The actual verified leaf and its immediate issuer, not a claimed serial or
// header, select the CRL. Every call makes a fresh nonce-bound agent pull.
func (g *PeerCRLGuard) CheckHandshake(ctx context.Context, state tls.ConnectionState) error {
	if g == nil || ctx == nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) != 1 ||
		len(state.VerifiedChains[0]) < 2 || len(state.PeerCertificates) < 1 ||
		!bytes.Equal(state.PeerCertificates[0].Raw, state.VerifiedChains[0][0].Raw) {
		return ErrPeerCRLUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	leaf, issuer := state.VerifiedChains[0][0], state.VerifiedChains[0][1]
	if leaf == nil || issuer == nil || len(leaf.Raw) == 0 || len(issuer.Raw) == 0 {
		return ErrPeerCRLUnavailable
	}
	return g.refresh(ctx, issuer.Raw, leaf.Raw, false)
}

// Bootstrap reads the same fixed source before any peer exists. It validates
// the returned full issuer DER against the operator-pinned digest, but does
// not identify a peer or add the issuer to TLS trust roots.
func (g *PeerCRLGuard) Bootstrap(ctx context.Context) error {
	if g == nil || ctx == nil {
		return ErrPeerCRLUnavailable
	}
	return g.refresh(ctx, nil, nil, true)
}

func (g *PeerCRLGuard) refresh(ctx context.Context, issuerDER, leafDER []byte, bootstrap bool) (result error) {
	if g == nil || ctx == nil {
		return ErrPeerCRLUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !bootstrap && (len(issuerDER) == 0 || len(leafDER) == 0) {
		return ErrPeerCRLUnavailable
	}
	if !bootstrap && peerCRLIssuerDigest(issuerDER) != g.expectedIssuerDigest {
		return ErrPeerCRLUnavailable
	}
	g.mu.Lock()
	startedFailureSequence := g.failureSequence
	g.mu.Unlock()
	defer func() {
		if result != nil && !errors.Is(result, workloadpki.ErrPeerRevoked) {
			g.mu.Lock()
			g.unavailable = true
			g.failureSequence++
			g.expirySequence++
			if g.expiryTimer != nil {
				g.expiryTimer.Stop()
			}
			g.mu.Unlock()
			g.drainAll()
		}
	}()
	operationContext, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	if g.pullPermit == nil {
		return ErrPeerCRLUnavailable
	}
	select {
	case g.pullPermit <- struct{}{}:
		defer func() { <-g.pullPermit }()
	case <-operationContext.Done():
		return ErrPeerCRLUnavailable
	}
	g.mu.Lock()
	start := g.now().UTC()
	if g.failed || (!g.lastNow.IsZero() && start.Before(g.lastNow)) {
		g.failed = true
		g.mu.Unlock()
		return ErrPeerCRLUnavailable
	}
	g.lastNow = start
	g.mu.Unlock()
	var response workloadtlsagent.PeerCRLResponse
	var err error
	if bootstrap {
		response, err = g.client.BootstrapPeerCRL(operationContext, g.binding, g.expectedIssuerDigest)
		issuerDER = response.IssuerDER
	} else {
		response, err = g.client.PeerCRL(operationContext, g.binding, issuerDER)
	}
	defer clear(response.CRLDER)
	if err != nil || operationContext.Err() != nil {
		return ErrPeerCRLUnavailable
	}
	verifiedAt := g.now().UTC()
	issuerDigest := peerCRLIssuerDigest(issuerDER)
	if response.SourceID == "" || response.ProfileDigest != g.binding.ProfileDigest ||
		response.SourceMappingDigest != g.binding.SourceMappingDigest ||
		response.EdgeID != g.binding.EdgeID || response.Direction != g.binding.Direction ||
		response.PeerAnchorID != g.binding.PeerAnchorID || response.IssuerDigest != issuerDigest ||
		issuerDigest != g.expectedIssuerDigest || !bytes.Equal(response.IssuerDER, issuerDER) {
		return ErrPeerCRLUnavailable
	}
	thisUpdate, firstErr := parsePeerCRLTime(response.ThisUpdate)
	nextUpdate, secondErr := parsePeerCRLTime(response.NextUpdate)
	collectedAt, thirdErr := parsePeerCRLTime(response.CollectedAt)
	if firstErr != nil || secondErr != nil || thirdErr != nil ||
		collectedAt.Before(verifiedAt.Add(-g.maxStaleness)) || collectedAt.After(verifiedAt.Add(5*time.Second)) ||
		collectedAt.Before(thisUpdate) || !collectedAt.Before(nextUpdate) {
		return ErrPeerCRLUnavailable
	}
	verified, err := workloadpki.VerifyCRLForIssuer(workloadpki.RevocationSnapshot{DER: response.CRLDER,
		ThisUpdate: thisUpdate, NextUpdate: nextUpdate}, issuerDER, verifiedAt)
	if err != nil || verified.IssuerDigest() != issuerDigest || verified.CRLDigest() != response.CRLDigest ||
		verified.Number().String() != response.CRLNumber {
		return ErrPeerCRLUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	observedAt := g.now().UTC()
	if g.failed || observedAt.Before(g.lastNow) {
		g.failed = true
		return ErrPeerCRLUnavailable
	}
	if g.failureSequence != startedFailureSequence {
		return ErrPeerCRLUnavailable
	}
	g.lastNow = observedAt
	if collectedAt.Before(observedAt.Add(-g.maxStaleness)) || collectedAt.After(observedAt.Add(5*time.Second)) ||
		observedAt.Before(verified.ThisUpdate()) || !observedAt.Before(verified.NextUpdate()) {
		return ErrPeerCRLUnavailable
	}
	if g.sourceID != "" && (g.sourceID != response.SourceID || g.issuerDigest != issuerDigest) {
		g.failed = true
		return ErrPeerCRLUnavailable
	}
	if g.number != nil {
		comparison := verified.Number().Cmp(g.number)
		if comparison < 0 || verified.ThisUpdate().Before(g.thisUpdate) ||
			(comparison == 0 && (verified.CRLDigest() != g.crlDigest || !verified.ThisUpdate().Equal(g.thisUpdate))) {
			g.failed = true
			return ErrPeerCRLUnavailable
		}
	}
	for key, prior := range g.observedRevoked {
		if !observedAt.Before(prior.notAfter) {
			delete(g.observedRevoked, key)
			continue
		}
		if !verified.RevokesSerial(prior.serial) {
			g.failed = true
			return ErrPeerCRLUnavailable
		}
	}
	g.sourceID, g.issuerDigest = response.SourceID, issuerDigest
	g.number, g.thisUpdate, g.crlDigest = verified.Number(), verified.ThisUpdate(), verified.CRLDigest()
	g.collectedAt, g.nextUpdate = collectedAt, verified.NextUpdate()
	g.current = verified
	g.unavailable = false
	g.scheduleEvidenceExpiryLocked(observedAt)
	if bootstrap {
		return nil
	}
	checkErr := verified.CheckPeer(leafDER, issuerDER, observedAt)
	if errors.Is(checkErr, workloadpki.ErrPeerRevoked) {
		if len(g.observedRevoked) >= maxObservedRevokedPeers {
			g.failed = true
			return ErrPeerCRLUnavailable
		}
		leaf, parseErr := x509.ParseCertificate(leafDER)
		if parseErr != nil {
			return ErrPeerCRLUnavailable
		}
		g.observedRevoked[leaf.SerialNumber.String()] = revokedPeerObservation{
			serial: new(big.Int).Set(leaf.SerialNumber), notAfter: leaf.NotAfter}
	}
	return checkErr
}

// scheduleEvidenceExpiryLocked closes active sockets at the earlier of source
// freshness expiry and CRL nextUpdate, even if the next poll has not run yet.
// The sequence prevents an old timer from draining a newer valid snapshot.
func (g *PeerCRLGuard) scheduleEvidenceExpiryLocked(observedAt time.Time) {
	g.expirySequence++
	sequence := g.expirySequence
	if g.expiryTimer != nil {
		g.expiryTimer.Stop()
	}
	deadline := g.collectedAt.Add(g.maxStaleness)
	if g.nextUpdate.Before(deadline) {
		deadline = g.nextUpdate
	}
	delay := deadline.Sub(observedAt)
	if delay < 0 {
		delay = 0
	}
	g.expiryTimer = time.AfterFunc(delay, func() {
		g.mu.Lock()
		if sequence != g.expirySequence || g.failed || g.unavailable {
			g.mu.Unlock()
			return
		}
		g.unavailable = true
		g.mu.Unlock()
		g.drainAll()
	})
}

// Track adds a connection only after its actual TLS handshake passed the
// configured VerifyConnection callback. It rechecks the current complete CRL
// before admitting the connection to the bounded drain registry.
func (g *PeerCRLGuard) Track(connection net.Conn, state tls.ConnectionState) error {
	if g == nil || connection == nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) != 1 ||
		len(state.VerifiedChains[0]) < 2 || len(state.PeerCertificates) < 1 ||
		!bytes.Equal(state.PeerCertificates[0].Raw, state.VerifiedChains[0][0].Raw) {
		return ErrPeerCRLUnavailable
	}
	leaf, issuer := state.VerifiedChains[0][0], state.VerifiedChains[0][1]
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().UTC()
	_, alreadyTracked := g.active[connection]
	if g.failed || g.current.Number() == nil || now.Before(g.lastNow) ||
		!now.Before(g.collectedAt.Add(g.maxStaleness)) || !now.Before(g.nextUpdate) ||
		(len(g.active) >= maxObservedRevokedPeers && !alreadyTracked) ||
		g.current.CheckPeer(leaf.Raw, issuer.Raw, now) != nil {
		return ErrPeerCRLUnavailable
	}
	g.lastNow = now
	g.active[connection] = state
	return nil
}

func (g *PeerCRLGuard) Forget(connection net.Conn) {
	if g == nil || connection == nil {
		return
	}
	g.mu.Lock()
	delete(g.active, connection)
	g.mu.Unlock()
}

// Poll performs one fresh authority pull for the exact issuer observed in a
// real TLS handshake, then rechecks every active peer. A failed pull or a
// rollback closes all tracked connections immediately; it never retains a
// last-good response as an authorization to keep them alive.
func (g *PeerCRLGuard) Poll(ctx context.Context) error {
	if g == nil || ctx == nil {
		return ErrPeerCRLUnavailable
	}
	g.mu.Lock()
	var representative tls.ConnectionState
	for _, state := range g.active {
		representative = state
		break
	}
	g.mu.Unlock()
	var err error
	if len(representative.VerifiedChains) == 0 {
		err = g.Bootstrap(ctx)
	} else {
		err = g.CheckHandshake(ctx, representative)
	}
	if err != nil && !errors.Is(err, workloadpki.ErrPeerRevoked) {
		g.drainAll()
		return ErrPeerCRLUnavailable
	}
	g.mu.Lock()
	now := g.now().UTC()
	toClose := make([]net.Conn, 0)
	for connection, state := range g.active {
		leaf, issuer := state.VerifiedChains[0][0], state.VerifiedChains[0][1]
		checkErr := g.current.CheckPeer(leaf.Raw, issuer.Raw, now)
		if checkErr == nil {
			continue
		}
		if errors.Is(checkErr, workloadpki.ErrPeerRevoked) {
			if len(g.observedRevoked) >= maxObservedRevokedPeers {
				g.failed = true
			} else {
				g.observedRevoked[leaf.SerialNumber.String()] = revokedPeerObservation{
					serial: new(big.Int).Set(leaf.SerialNumber), notAfter: leaf.NotAfter}
			}
		}
		delete(g.active, connection)
		toClose = append(toClose, connection)
	}
	failed := g.failed
	g.mu.Unlock()
	if !closeTrackedConnections(toClose, g.closeBudget) {
		g.mu.Lock()
		g.failed = true
		g.mu.Unlock()
	}
	if failed {
		g.drainAll()
		return ErrPeerCRLUnavailable
	}
	if !g.Ready() {
		return ErrPeerCRLUnavailable
	}
	return nil
}

func (g *PeerCRLGuard) drainAll() {
	g.mu.Lock()
	connections := make([]net.Conn, 0, len(g.active))
	for connection := range g.active {
		connections = append(connections, connection)
		delete(g.active, connection)
	}
	g.mu.Unlock()
	if !closeTrackedConnections(connections, g.closeBudget) {
		g.mu.Lock()
		g.failed = true
		g.mu.Unlock()
	}
}

// A fixed worker set closes all underlying sockets without allowing one slow
// Close to hold every other peer. This is a total collection budget, not a
// per-connection timeout; a gate must fail if actual closure exceeds it.
func closeTrackedConnections(connections []net.Conn, totalBudget time.Duration) bool {
	if len(connections) == 0 {
		return true
	}
	if totalBudget < 100*time.Millisecond {
		totalBudget = 100 * time.Millisecond
	}
	jobs := make(chan net.Conn, len(connections))
	for _, connection := range connections {
		jobs <- connection
	}
	close(jobs)
	var workers sync.WaitGroup
	for range min(len(connections), 16) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for connection := range jobs {
				_ = connection.Close()
			}
		}()
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	timer := time.NewTimer(totalBudget)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func (g *PeerCRLGuard) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.failed = true
	g.expirySequence++
	if g.expiryTimer != nil {
		g.expiryTimer.Stop()
	}
	g.mu.Unlock()
	g.drainAll()
}

func parsePeerCRLTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, ErrPeerCRLUnavailable
	}
	return parsed, nil
}

func validPeerCRLDigest(value string) bool {
	if len(value) != len("sha256:")+64 || value[:len("sha256:")] != "sha256:" {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256.Size && "sha256:"+hex.EncodeToString(decoded) == value
}

func peerCRLIssuerDigest(issuerDER []byte) string {
	digest := sha256.Sum256(issuerDER)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// Ready reports only observed, unexpired evidence. A new process has no
// last-good state. A fresh pull must succeed before this becomes true.
func (g *PeerCRLGuard) Ready() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().UTC()
	if g.failed || g.unavailable || g.collectedAt.IsZero() || now.Before(g.lastNow) {
		g.failed = g.failed || now.Before(g.lastNow)
		return false
	}
	ready := now.Before(g.collectedAt.Add(g.maxStaleness)) && now.Before(g.nextUpdate)
	if ready {
		g.lastNow = now
	}
	return ready
}

func (g *PeerCRLGuard) PollInterval() time.Duration {
	if g == nil {
		return 0
	}
	return g.pollInterval
}

// StartPolling keeps both zero-peer readiness and active connections bounded
// to fresh authority evidence. The returned stop function waits for a pull in
// flight to observe cancellation before role shutdown completes.
func (g *PeerCRLGuard) StartPolling(parent context.Context) (func(), error) {
	if g == nil || parent == nil || g.PollInterval() == 0 {
		return nil, ErrPeerCRLUnavailable
	}
	return connectiondrain.StartPeerPoll(parent, g), nil
}
