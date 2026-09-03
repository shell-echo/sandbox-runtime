package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DNSPort             = 53
	HTTPPort            = 80
	TLSPort             = 443
	maxClientHelloBytes = 64 << 10
	proxyHeaderTimeout  = 5 * time.Second
	upstreamDialTimeout = 10 * time.Second
)

var errClientHelloCaptured = errors.New("TLS ClientHello captured")

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Server struct {
	config   Config
	resolver Resolver
	dialer   Dialer
}

func New(config Config, resolver Resolver, dialer Dialer) (*Server, error) {
	normalized, err := normalizeConfig(config)
	if err != nil || resolver == nil || dialer == nil {
		return nil, ErrInvalidConfig
	}
	return &Server{config: normalized, resolver: resolver, dialer: dialer}, nil
}

func NewSystem(config Config) (*Server, error) {
	dialer := &net.Dialer{Timeout: upstreamDialTimeout, KeepAlive: 15 * time.Second}
	return New(config, net.DefaultResolver, dialer)
}

func Healthcheck(ctx context.Context, config Config) error {
	normalized, err := normalizeConfig(config)
	if err != nil || ctx == nil {
		return ErrInvalidConfig
	}
	dialer := &net.Dialer{Timeout: time.Second}
	for _, port := range []int{DNSPort, HTTPPort, TLSPort} {
		connection, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(normalized.GatewayAddress, strconv.Itoa(port)))
		if err != nil {
			return ErrPolicyDenied
		}
		_ = connection.Close()
	}
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ip := s.config.GatewayAddress
	dnsAddress := net.JoinHostPort(ip, strconv.Itoa(DNSPort))
	httpAddress := net.JoinHostPort(ip, strconv.Itoa(HTTPPort))
	tlsAddress := net.JoinHostPort(ip, strconv.Itoa(TLSPort))
	udp, err := net.ListenPacket("udp4", dnsAddress)
	if err != nil {
		return fmt.Errorf("listen DNS UDP: %w", err)
	}
	dnsTCP, err := net.Listen("tcp4", dnsAddress)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("listen DNS TCP: %w", err)
	}
	httpListener, err := net.Listen("tcp4", httpAddress)
	if err != nil {
		_ = udp.Close()
		_ = dnsTCP.Close()
		return fmt.Errorf("listen HTTP: %w", err)
	}
	tlsListener, err := net.Listen("tcp4", tlsAddress)
	if err != nil {
		_ = udp.Close()
		_ = dnsTCP.Close()
		_ = httpListener.Close()
		return fmt.Errorf("listen TLS: %w", err)
	}
	return s.serve(ctx, udp, dnsTCP, httpListener, tlsListener)
}

func (s *Server) serve(ctx context.Context, udp net.PacketConn, dnsTCP, httpListener, tlsListener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	httpServer := &http.Server{
		Handler:           http.HandlerFunc(s.serveHTTP),
		ReadHeaderTimeout: proxyHeaderTimeout,
		IdleTimeout:       proxyHeaderTimeout,
		MaxHeaderBytes:    32 << 10,
	}
	closers := []io.Closer{udp, dnsTCP, httpListener, tlsListener}
	defer func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}()
	results := make(chan error, 4)
	go func() { results <- s.serveDNSUDP(ctx, udp) }()
	go func() { results <- s.serveDNSTCP(ctx, dnsTCP) }()
	go func() { results <- httpServer.Serve(httpListener) }()
	go func() { results <- s.serveTLS(ctx, tlsListener) }()
	select {
	case <-ctx.Done():
		_ = httpServer.Close()
		return ctx.Err()
	case err := <-results:
		_ = httpServer.Close()
		if errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) serveHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil || request.Context() == nil || request.URL == nil || request.URL.IsAbs() || request.Method == http.MethodConnect {
		http.Error(response, "egress denied", http.StatusForbidden)
		return
	}
	host, err := destinationHost(request.Host, HTTPPort)
	if err != nil || !s.config.Policy.Allows(host) {
		http.Error(response, "egress denied", http.StatusForbidden)
		return
	}
	address, err := s.resolvePublic(request.Context(), host)
	if err != nil {
		http.Error(response, "egress denied", http.StatusForbidden)
		return
	}
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.URL.Scheme = "http"
	outbound.URL.Host = host
	outbound.Host = host
	outbound.Close = true
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return s.dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), strconv.Itoa(HTTPPort)))
		},
	}
	defer transport.CloseIdleConnections()
	upstream, err := transport.RoundTrip(outbound)
	if err != nil {
		http.Error(response, "egress unavailable", http.StatusBadGateway)
		return
	}
	defer upstream.Body.Close()
	copyResponseHeaders(response.Header(), upstream.Header)
	response.WriteHeader(upstream.StatusCode)
	_, _ = io.Copy(response, upstream.Body)
}

func (s *Server) serveTLS(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handleTLS(ctx, connection)
	}
}

func (s *Server) handleTLS(parent context.Context, client net.Conn) {
	defer client.Close()
	ctx, cancel := context.WithTimeout(parent, upstreamDialTimeout)
	defer cancel()
	_ = client.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
	recorded := &recordingConn{Conn: client, maximum: maxClientHelloBytes}
	host := ""
	parser := tls.Server(recorded, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			host = hello.ServerName
			return nil, errClientHelloCaptured
		},
	})
	if err := parser.HandshakeContext(ctx); !errors.Is(err, errClientHelloCaptured) || !s.config.Policy.Allows(host) {
		return
	}
	address, err := s.resolvePublic(ctx, host)
	if err != nil {
		return
	}
	upstream, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(TLSPort)))
	if err != nil {
		return
	}
	defer upstream.Close()
	if err := writeFull(upstream, recorded.Bytes()); err != nil {
		return
	}
	_ = client.SetReadDeadline(time.Time{})
	proxyContext(parent, client, upstream)
}

func (s *Server) resolvePublic(ctx context.Context, host string) (netip.Addr, error) {
	if !s.config.Policy.Allows(host) {
		return netip.Addr{}, ErrPolicyDenied
	}
	addresses, err := s.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > 32 {
		return netip.Addr{}, ErrPolicyDenied
	}
	var selected netip.Addr
	for _, address := range addresses {
		address = address.Unmap()
		if !PublicUpstreamAddress(address) {
			return netip.Addr{}, ErrPolicyDenied
		}
		if !selected.IsValid() || address.String() < selected.String() {
			selected = address
		}
	}
	return selected, nil
}

func destinationHost(value string, port int) (string, error) {
	host := value
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		if parsedPort != strconv.Itoa(port) {
			return "", ErrPolicyDenied
		}
		host = parsedHost
	} else if strings.Contains(value, ":") {
		return "", ErrPolicyDenied
	}
	return normalizeDestinationHost(host)
}

func copyResponseHeaders(destination, source http.Header) {
	for key, values := range source {
		switch strings.ToLower(key) {
		case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

type recordingConn struct {
	net.Conn
	maximum int
	read    []byte
}

func (c *recordingConn) Read(value []byte) (int, error) {
	if len(c.read) >= c.maximum {
		return 0, ErrPolicyDenied
	}
	if len(value) > c.maximum-len(c.read) {
		value = value[:c.maximum-len(c.read)]
	}
	n, err := c.Conn.Read(value)
	c.read = append(c.read, value[:n]...)
	return n, err
}

// TLS may try to write an alert after the callback deliberately stops the
// handshake. The client must receive no bytes until its original ClientHello
// has been forwarded to the selected upstream.
func (c *recordingConn) Write(value []byte) (int, error) { return len(value), nil }
func (c *recordingConn) Bytes() []byte                   { return append([]byte(nil), c.read...) }

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}

func proxyContext(ctx context.Context, left, right net.Conn) {
	var once sync.Once
	closeBoth := func() { _ = left.Close(); _ = right.Close() }
	done := make(chan struct{}, 2)
	copySide := func(destination, source net.Conn) {
		_, _ = io.Copy(destination, source)
		if tcp, ok := destination.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}
	go copySide(left, right)
	go copySide(right, left)
	select {
	case <-ctx.Done():
		once.Do(closeBoth)
	case <-done:
		select {
		case <-done:
		case <-ctx.Done():
			once.Do(closeBoth)
		}
	}
}
