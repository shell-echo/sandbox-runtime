package phase6egress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/trustanchor"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
)

const maxOwnPostgresConnections = 64

type postgresSnapshotSource interface {
	Snapshot(context.Context) (workloadtlsagent.Snapshot, error)
}

// PostgresOwnGuard is deliberately conservative: every signer leaf change
// closes all connections made with the previous leaf. It never treats the
// current signer snapshot as evidence that a prior leaf remains unrevoked.
type PostgresOwnGuard struct {
	source           postgresSnapshotSource
	identity         workloadpki.PostgresClientIdentity
	issuerDER        []byte
	maximumStaleness time.Duration
	timeout          time.Duration
	interval         time.Duration
	closeBudget      time.Duration
	now              func() time.Time
	pull             sync.Mutex
	mu               sync.Mutex
	failed           bool
	unavailable      bool
	lastNow          time.Time
	leafDigest       string
	issuerDigest     string
	serial           string
	safeTo           time.Time
	notAfter         time.Time
	active           map[net.Conn]postgresOwnSelection
	timer            *time.Timer
	timerSequence    uint64
}

type postgresOwnSelection struct {
	leafDigest   string
	issuerDigest string
	serial       string
}

func NewPostgresOwnGuard(profile phase6security.Profile, owner string, source postgresSnapshotSource,
	timeout time.Duration, now func() time.Time) (*PostgresOwnGuard, error) {
	if source == nil || now == nil || now().IsZero() || timeout < time.Second || timeout > 30*time.Second {
		return nil, ErrUnavailable
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority(owner)
	if err != nil {
		return nil, ErrUnavailable
	}
	binding, target, _, principal, anchor, err := profile.PostgresClientSignerForOwner(owner)
	if err != nil || principal.TLS == nil || binding.SocketPath != authority.Signer.SocketPath ||
		target.DatabaseName != authority.Database || target.SQLRole != authority.SQLRole {
		return nil, ErrUnavailable
	}
	staleness := time.Duration(principal.TLS.RevocationMaxStalenessSeconds) * time.Second
	drain := time.Duration(principal.TLS.ConnectionDrainSeconds) * time.Second
	boundedTimeout := min(timeout, drain/5)
	interval := min(staleness/2, drain/5, 30*time.Second)
	closeBudget := drain / 10
	if staleness < time.Second || staleness > 5*time.Minute || drain < time.Second || drain > 5*time.Minute ||
		boundedTimeout < 100*time.Millisecond || interval < 100*time.Millisecond || closeBudget < 100*time.Millisecond ||
		2*boundedTimeout+interval+closeBudget+drain/5 > drain-drain/10 {
		return nil, ErrUnavailable
	}
	bundle, err := trustanchor.Load(anchor, now().UTC())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(bundle)
	block, rest := pem.Decode(bundle)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrUnavailable
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, ErrUnavailable
	}
	return &PostgresOwnGuard{source: source, issuerDER: bytes.Clone(block.Bytes),
		identity: workloadpki.PostgresClientIdentity{OwnerDeployment: owner, DatabaseName: authority.Database,
			RuntimeRole: authority.SQLRole, ServiceName: "postgres", URI: principal.TLS.URI,
			CommonName: binding.CommonName, MaxTTL: time.Duration(principal.TLS.TTLSeconds) * time.Second},
		maximumStaleness: staleness, timeout: boundedTimeout, interval: interval, closeBudget: closeBudget,
		now: now, active: make(map[net.Conn]postgresOwnSelection)}, nil
}

func (g *PostgresOwnGuard) validateSnapshot(snapshot workloadtlsagent.Snapshot, now time.Time) (postgresOwnSelection, error) {
	if g == nil || len(snapshot.CertificateDER) != 2 || len(snapshot.PublicKeyDER) == 0 ||
		snapshot.Generation < 1 || snapshot.IssuerRevision == "" ||
		!bytes.Equal(snapshot.CertificateDER[1], g.issuerDER) || now.IsZero() ||
		!snapshot.RevocationSafeTo.After(now) || snapshot.RevocationSafeTo.After(now.Add(g.maximumStaleness)) ||
		!snapshot.NotBefore.Before(snapshot.NotAfter) || now.Before(snapshot.NotBefore) || !now.Before(snapshot.NotAfter) {
		return postgresOwnSelection{}, ErrUnavailable
	}
	leaf, err := x509.ParseCertificate(snapshot.CertificateDER[0])
	if err != nil || workloadpki.ValidatePostgresClientLeaf(leaf, g.identity, now) != nil ||
		!leaf.NotBefore.Equal(snapshot.NotBefore) || !leaf.NotAfter.Equal(snapshot.NotAfter) ||
		postgresOwnSerial(leaf) != snapshot.Serial {
		return postgresOwnSelection{}, ErrUnavailable
	}
	publicDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(publicDER, snapshot.PublicKeyDER) {
		return postgresOwnSelection{}, ErrUnavailable
	}
	issuer, err := x509.ParseCertificate(g.issuerDER)
	if err != nil || !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) || leaf.CheckSignatureFrom(issuer) != nil {
		return postgresOwnSelection{}, ErrUnavailable
	}
	return postgresOwnSelection{leafDigest: postgresOwnDigest(leaf.Raw),
		issuerDigest: postgresOwnDigest(issuer.Raw), serial: snapshot.Serial}, nil
}

func postgresOwnDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func postgresOwnSerial(leaf *x509.Certificate) string {
	if leaf == nil || leaf.SerialNumber == nil || leaf.SerialNumber.Sign() < 1 {
		return ""
	}
	raw := leaf.SerialNumber.Bytes()
	encoded := make([]byte, 0, len(raw)*3-1)
	for index, item := range raw {
		if index > 0 {
			encoded = append(encoded, ':')
		}
		var pair [2]byte
		hex.Encode(pair[:], []byte{item})
		encoded = append(encoded, pair[:]...)
	}
	return string(encoded)
}

// Refresh serializes all pulls and publishes only a snapshot observed after
// the prior publication. Active connections using a different actual leaf are
// closed before the new identity becomes ready for acquisition.
func (g *PostgresOwnGuard) Refresh(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	g.pull.Lock()
	defer g.pull.Unlock()
	operationContext, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	snapshot, err := g.source.Snapshot(operationContext)
	if err != nil || operationContext.Err() != nil {
		g.failAndDrain()
		return ErrUnavailable
	}
	defer snapshot.Destroy()
	now := g.now().UTC()
	selected, err := g.validateSnapshot(snapshot, now)
	if err != nil {
		g.failAndDrain()
		return ErrUnavailable
	}
	g.mu.Lock()
	if g.failed || (!g.lastNow.IsZero() && now.Before(g.lastNow)) {
		g.failed = true
		g.mu.Unlock()
		g.failAndDrain()
		return ErrUnavailable
	}
	g.lastNow = now
	toClose := make([]net.Conn, 0)
	g.unavailable = true
	for connection, prior := range g.active {
		if prior != selected {
			delete(g.active, connection)
			toClose = append(toClose, connection)
		}
	}
	g.leafDigest, g.issuerDigest, g.serial = selected.leafDigest, selected.issuerDigest, selected.serial
	g.safeTo, g.notAfter = snapshot.RevocationSafeTo, snapshot.NotAfter
	g.timerSequence++
	if g.timer != nil {
		g.timer.Stop()
	}
	g.mu.Unlock()
	if !drainPostgresOwnConnections(toClose, g.closeBudget) {
		g.failAndDrain()
		return ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	finished := g.now().UTC()
	if g.failed || finished.Before(g.lastNow) || !finished.Before(g.safeTo) || !finished.Before(g.notAfter) {
		g.unavailable = true
		return ErrUnavailable
	}
	g.lastNow = finished
	g.unavailable = false
	g.scheduleExpiryLocked(finished)
	return nil
}

func (g *PostgresOwnGuard) scheduleExpiryLocked(now time.Time) {
	g.timerSequence++
	sequence := g.timerSequence
	if g.timer != nil {
		g.timer.Stop()
	}
	deadline := g.safeTo
	if g.notAfter.Before(deadline) {
		deadline = g.notAfter
	}
	delay := deadline.Sub(now)
	if delay < 0 {
		delay = 0
	}
	g.timer = time.AfterFunc(delay, func() {
		g.mu.Lock()
		if g.timerSequence != sequence || g.failed || g.unavailable {
			g.mu.Unlock()
			return
		}
		g.unavailable = true
		g.mu.Unlock()
		g.drainAll()
	})
}

func (g *PostgresOwnGuard) failAndDrain() {
	g.mu.Lock()
	g.unavailable = true
	g.timerSequence++
	if g.timer != nil {
		g.timer.Stop()
	}
	g.mu.Unlock()
	g.drainAll()
}

func (g *PostgresOwnGuard) drainAll() {
	g.mu.Lock()
	connections := make([]net.Conn, 0, len(g.active))
	for connection := range g.active {
		connections = append(connections, connection)
		delete(g.active, connection)
	}
	g.mu.Unlock()
	if !drainPostgresOwnConnections(connections, g.closeBudget) {
		g.mu.Lock()
		g.failed = true
		g.mu.Unlock()
	}
}

func drainPostgresOwnConnections(connections []net.Conn, budget time.Duration) bool {
	if len(connections) == 0 {
		return true
	}
	if budget < 100*time.Millisecond {
		return false
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
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func (g *PostgresOwnGuard) Ready() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	now := g.now().UTC()
	if now.Before(g.lastNow) {
		g.failed = true
		g.mu.Unlock()
		g.drainAll()
		return false
	}
	ready := !g.failed && !g.unavailable && g.leafDigest != "" && now.Before(g.safeTo) && now.Before(g.notAfter)
	g.mu.Unlock()
	return ready
}

func (g *PostgresOwnGuard) track(connection net.Conn, selected postgresOwnSelection) error {
	if g == nil || connection == nil || selected.leafDigest == "" || selected.issuerDigest == "" || selected.serial == "" {
		return ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now().UTC()
	if g.failed || g.unavailable || now.Before(g.lastNow) || !now.Before(g.safeTo) || !now.Before(g.notAfter) ||
		len(g.active) >= maxOwnPostgresConnections ||
		selected != (postgresOwnSelection{leafDigest: g.leafDigest, issuerDigest: g.issuerDigest, serial: g.serial}) {
		return ErrUnavailable
	}
	g.lastNow = now
	g.active[connection] = selected
	return nil
}

func (g *PostgresOwnGuard) forget(connection net.Conn) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.active, connection)
	g.mu.Unlock()
}

func (g *PostgresOwnGuard) Poll(ctx context.Context) error { return g.Refresh(ctx) }
func (g *PostgresOwnGuard) PollInterval() time.Duration {
	if g == nil {
		return 0
	}
	return g.interval
}

func (g *PostgresOwnGuard) StartPolling(parent context.Context) (func(), error) {
	if g == nil || parent == nil || g.interval < 100*time.Millisecond {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(g.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = g.Poll(ctx)
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}

func (g *PostgresOwnGuard) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.failed = true
	g.timerSequence++
	if g.timer != nil {
		g.timer.Stop()
	}
	g.mu.Unlock()
	g.drainAll()
}

type ownTrackedPostgresConn struct {
	net.Conn
	guard *PostgresOwnGuard
	once  sync.Once
}

func (c *ownTrackedPostgresConn) Close() error {
	if c == nil {
		return nil
	}
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.guard.forget(c.Conn) })
	return err
}

// BindPostgresOwnGuard must run after the peer guard and before pool creation.
// Its per-connection callback captures the exact client leaf selected for the
// successful TLS handshake; no shared mutable serial or resumed session is
// accepted. The earlier peer guard remains on the same connection.
func BindPostgresOwnGuard(config *pgxpool.Config, guard *PostgresOwnGuard) error {
	if config == nil || config.ConnConfig == nil || guard == nil || !guard.Ready() ||
		config.BeforeConnect == nil || config.ConnConfig.AfterNetConnect == nil ||
		config.ConnConfig.TLSConfig == nil || config.ConnConfig.TLSConfig.GetClientCertificate == nil {
		return ErrUnavailable
	}
	priorBefore := config.BeforeConnect
	config.BeforeConnect = func(ctx context.Context, connectionConfig *pgx.ConnConfig) error {
		if ctx == nil || ctx.Err() != nil || connectionConfig == nil || !guard.Ready() ||
			priorBefore(ctx, connectionConfig) != nil || connectionConfig.TLSConfig == nil ||
			connectionConfig.AfterNetConnect == nil {
			return ErrUnavailable
		}
		remote := connectionConfig.TLSConfig.Clone()
		remote.ClientSessionCache = nil
		remote.SessionTicketsDisabled = true
		priorCertificate := remote.GetClientCertificate
		if priorCertificate == nil {
			return ErrUnavailable
		}
		priorAfter := connectionConfig.AfterNetConnect
		var selected postgresOwnSelection
		remote.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if request == nil || request.Context().Err() != nil || selected.leafDigest != "" {
				return nil, ErrUnavailable
			}
			certificate, err := priorCertificate(request)
			if err != nil || certificate == nil || len(certificate.Certificate) != 2 ||
				!bytes.Equal(certificate.Certificate[1], guard.issuerDER) {
				return nil, ErrUnavailable
			}
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil || workloadpki.ValidatePostgresClientLeaf(leaf, guard.identity, guard.now()) != nil {
				return nil, ErrUnavailable
			}
			selected = postgresOwnSelection{leafDigest: postgresOwnDigest(leaf.Raw),
				issuerDigest: postgresOwnDigest(certificate.Certificate[1]), serial: postgresOwnSerial(leaf)}
			return certificate, nil
		}
		connectionConfig.TLSConfig = remote
		connectionConfig.AfterNetConnect = func(afterContext context.Context, pgConfig *pgconn.Config, connection net.Conn) (net.Conn, error) {
			peer, ok := connection.(*tls.Conn)
			if !ok || afterContext == nil || afterContext.Err() != nil || peer.HandshakeContext(afterContext) != nil ||
				!peer.ConnectionState().HandshakeComplete || peer.ConnectionState().Version != tls.VersionTLS13 ||
				peer.ConnectionState().DidResume || selected.leafDigest == "" {
				return connection, ErrUnavailable
			}
			wrapped, err := priorAfter(afterContext, pgConfig, connection)
			if err != nil {
				return wrapped, err
			}
			if guard.track(wrapped, selected) != nil {
				return wrapped, ErrUnavailable
			}
			return &ownTrackedPostgresConn{Conn: wrapped, guard: guard}, nil
		}
		return nil
	}
	beforeAcquire := config.BeforeAcquire
	config.BeforeAcquire = func(ctx context.Context, connection *pgx.Conn) bool {
		return ctx != nil && ctx.Err() == nil && guard.Ready() &&
			(beforeAcquire == nil || beforeAcquire(ctx, connection))
	}
	return nil
}
