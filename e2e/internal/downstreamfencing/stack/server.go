package stack

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/netutil"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
)

const (
	maxCertificateBytes = 128 << 10
	maxPrivateKeyBytes  = 64 << 10
	maxCABundleBytes    = 128 << 10
	maxCACertificates   = 8
)

type privateServer struct {
	http           *http.Server
	tlsConfig      *tls.Config
	maxConnections int
	listen         func(context.Context, string, string) (net.Listener, error)
	tracker        *privateConnectionTracker
}

func newPrivateServer(config IngressConfig, capacity CapacityPolicy, handler http.Handler) (*privateServer, error) {
	if handler == nil {
		return nil, errors.New("private ingress handler is required")
	}
	if err := validateIngress(config, capacity); err != nil {
		return nil, err
	}
	tlsConfig, err := loadPrivateServerTLSConfig(config)
	if err != nil {
		return nil, err
	}
	return newPrivateServerWithTLS(config, capacity, handler, tlsConfig)
}

func loadPrivateServerTLSConfig(config IngressConfig) (*tls.Config, error) {
	certificatePEM, err := readTLSFile(config.ServerCertificateFile, maxCertificateBytes, false)
	if err != nil {
		return nil, errors.New("read private ingress certificate")
	}
	privateKeyPEM, err := readTLSFile(config.ServerPrivateKeyFile, maxPrivateKeyBytes, true)
	if err != nil {
		return nil, errors.New("read private ingress key")
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("load private ingress key pair")
	}
	if err := validateCertificateValidity(certificate, time.Now()); err != nil {
		return nil, err
	}
	caPEM, err := readTLSFile(config.ClientCAFile, maxCABundleBytes, false)
	if err != nil {
		return nil, errors.New("read private ingress client CA")
	}
	roots, err := parseStrictCABundle(caPEM, time.Now())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := transport.NewServerTLSConfig(certificate, roots, config.AllowedGatewayURIs...)
	if err != nil {
		return nil, errors.New("construct private ingress TLS policy")
	}
	return tlsConfig, nil
}

func newPrivateServerWithTLS(config IngressConfig, capacity CapacityPolicy, handler http.Handler, tlsConfig *tls.Config) (*privateServer, error) {
	if handler == nil || tlsConfig == nil {
		return nil, errors.New("private ingress dependencies are required")
	}
	if err := validateIngress(config, capacity); err != nil {
		return nil, err
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	listenConfig := &net.ListenConfig{}
	tracker := newPrivateConnectionTracker()
	return &privateServer{
		http: &http.Server{
			Addr:              config.Address,
			Handler:           &trackedPrivateHandler{next: handler, tracker: tracker},
			ReadHeaderTimeout: durationMillis(config.ReadHeaderTimeoutMillis),
			ReadTimeout:       durationMillis(config.ReadTimeoutMillis),
			WriteTimeout:      durationMillis(config.WriteTimeoutMillis),
			IdleTimeout:       durationMillis(config.IdleTimeoutMillis),
			MaxHeaderBytes:    config.MaxHeaderBytes,
			Protocols:         protocols,
		},
		tlsConfig: tlsConfig, maxConnections: config.MaxConnections,
		listen: listenConfig.Listen, tracker: tracker,
	}, nil
}

func (s *privateServer) Startup(ctx context.Context) error {
	if s == nil || s.http == nil || s.tlsConfig == nil || s.listen == nil || s.maxConnections < 1 {
		return errors.New("private ingress server is unavailable")
	}
	if ctx == nil {
		return errors.New("private ingress startup context is nil")
	}
	listener, err := s.listen(ctx, "tcp", s.http.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("bind private ingress: %w", err)
	}
	limited := netutil.LimitListener(listener, s.maxConnections)
	secured := tls.NewListener(limited, s.tlsConfig)
	stopClosing := context.AfterFunc(ctx, func() { _ = secured.Close() })
	defer stopClosing()
	if err := s.http.Serve(secured); err != nil && !errors.Is(err, http.ErrServerClosed) &&
		!(ctx.Err() != nil && errors.Is(err, net.ErrClosed)) {
		return fmt.Errorf("serve private ingress: %w", err)
	}
	return nil
}

func (s *privateServer) Shutdown(ctx context.Context) error {
	if s == nil || s.http == nil || s.tracker == nil {
		return errors.New("private ingress server is unavailable")
	}
	if ctx == nil {
		return errors.New("private ingress shutdown context is nil")
	}
	httpResult := make(chan error, 1)
	go func() { httpResult <- s.http.Shutdown(ctx) }()
	trackerErr := s.tracker.closeAndWait(ctx)
	httpErr := <-httpResult
	if errors.Is(httpErr, net.ErrClosed) {
		httpErr = nil
	}
	var forceCloseErr error
	if httpErr != nil {
		forceCloseErr = s.http.Close()
		if errors.Is(forceCloseErr, net.ErrClosed) {
			forceCloseErr = nil
		}
	}
	return errors.Join(httpErr, trackerErr, forceCloseErr)
}

type privateConnectionTracker struct {
	mu          sync.Mutex
	connections map[*trackedPrivateConn]struct{}
	handlers    int
	closing     bool
	done        chan struct{}
	doneOnce    sync.Once
}

func newPrivateConnectionTracker() *privateConnectionTracker {
	return &privateConnectionTracker{connections: make(map[*trackedPrivateConn]struct{}), done: make(chan struct{})}
}

func (t *privateConnectionTracker) beginHandler() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing {
		return false
	}
	t.handlers++
	return true
}

func (t *privateConnectionTracker) endHandler() {
	t.mu.Lock()
	t.handlers--
	ready := t.closing && t.handlers == 0
	t.mu.Unlock()
	if ready {
		t.doneOnce.Do(func() { close(t.done) })
	}
}

func (t *privateConnectionTracker) track(connection net.Conn) net.Conn {
	tracked := &trackedPrivateConn{Conn: connection, tracker: t}
	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		_ = connection.Close()
		return tracked
	}
	t.connections[tracked] = struct{}{}
	t.mu.Unlock()
	return tracked
}

func (t *privateConnectionTracker) untrack(connection *trackedPrivateConn) {
	t.mu.Lock()
	delete(t.connections, connection)
	t.mu.Unlock()
}

func (t *privateConnectionTracker) closeAndWait(ctx context.Context) error {
	t.mu.Lock()
	t.closing = true
	connections := make([]*trackedPrivateConn, 0, len(t.connections))
	for connection := range t.connections {
		connections = append(connections, connection)
	}
	ready := t.handlers == 0
	t.mu.Unlock()
	if ready {
		t.doneOnce.Do(func() { close(t.done) })
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type trackedPrivateConn struct {
	net.Conn
	tracker *privateConnectionTracker
	once    sync.Once
}

func (c *trackedPrivateConn) Close() error {
	if c == nil || c.Conn == nil {
		return nil
	}
	var result error
	c.once.Do(func() {
		result = c.Conn.Close()
		if c.tracker != nil {
			c.tracker.untrack(c)
		}
	})
	return result
}

type trackedPrivateHandler struct {
	next    http.Handler
	tracker *privateConnectionTracker
}

func (h *trackedPrivateHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if h == nil || h.next == nil || h.tracker == nil || !h.tracker.beginHandler() {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer h.tracker.endHandler()
	h.next.ServeHTTP(&trackedPrivateResponseWriter{ResponseWriter: response, tracker: h.tracker}, request)
}

type trackedPrivateResponseWriter struct {
	http.ResponseWriter
	tracker *privateConnectionTracker
}

func (w *trackedPrivateResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok || w.tracker == nil {
		return nil, nil, errors.New("private ingress connection cannot be hijacked")
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, err
	}
	return w.tracker.track(connection), buffered, nil
}

func (w *trackedPrivateResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *trackedPrivateResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func readTLSFile(path string, maximum int64, private bool) ([]byte, error) {
	contents, err := readBoundedRegularFile(path, maximum, private)
	if err != nil {
		return nil, errors.New("TLS material is not a bounded regular file")
	}
	return contents, nil
}

func validateCertificateValidity(certificate tls.Certificate, now time.Time) error {
	if len(certificate.Certificate) == 0 {
		return errors.New("private ingress certificate chain is empty")
	}
	for index, raw := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(raw)
		if err != nil || now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
			return fmt.Errorf("private ingress certificate %d is invalid or outside its validity period", index)
		}
		if index == 0 {
			certificate.Leaf = parsed
		}
	}
	return nil
}

func parseStrictCABundle(contents []byte, now time.Time) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	remaining := contents
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("private ingress client CA bundle is invalid")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
			return nil, errors.New("private ingress client CA is invalid or outside its validity period")
		}
		count++
		if count > maxCACertificates {
			return nil, errors.New("private ingress client CA bundle contains too many certificates")
		}
		roots.AddCert(certificate)
		remaining = rest
	}
	if count == 0 {
		return nil, errors.New("private ingress client CA bundle is empty")
	}
	return roots, nil
}
