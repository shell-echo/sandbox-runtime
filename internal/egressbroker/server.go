package egressbroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/netpolicy"
)

type ServerConfig struct {
	Address           string
	TLSConfig         *tls.Config
	Policy            Policy
	PrincipalURI      string
	PrincipalDNSNames []string
	PrincipalUsages   []string
	Resolver          netpolicy.IPResolver
	Dialer            netpolicy.ContextDialer
	MaxConnections    int
	ReplayCapacity    int
	Now               func() time.Time
	PeerRevocation    PeerRevocationMonitor
}

// PeerRevocationMonitor is owned by the caller's exact mTLS edge. A nil
// monitor is retained only for component fixtures; the production broker
// command supplies a profile-bound guard before accepting any request frame.
type PeerRevocationMonitor interface {
	Ready() bool
	CheckHandshake(context.Context, tls.ConnectionState) error
	Track(net.Conn, tls.ConnectionState) error
	Forget(net.Conn)
}

type Server struct {
	listener          net.Listener
	policy            Policy
	principalURI      string
	principalDNSNames []string
	principalUsages   []x509.ExtKeyUsage
	resolver          netpolicy.IPResolver
	dialer            netpolicy.ContextDialer
	capacity          chan struct{}
	replayCapacity    int
	now               func() time.Time
	peerRevocation    PeerRevocationMonitor
	replayMu          sync.Mutex
	replay            map[string]time.Time
	sessionsMu        sync.Mutex
	sessions          map[net.Conn]net.Conn
	connections       map[net.Conn]struct{}
	revoked           bool
	handlers          sync.WaitGroup
	closeOnce         sync.Once
}

func Listen(config ServerConfig) (*Server, error) {
	if config.Policy.Validate() != nil || config.TLSConfig == nil || config.Resolver == nil || config.Dialer == nil ||
		config.MaxConnections < 1 || config.MaxConnections > 1024 || config.ReplayCapacity < 16 || config.ReplayCapacity > 65536 ||
		config.Now == nil || config.Now().IsZero() || config.PrincipalURI == "" || config.Address == "" ||
		validateServerTLS(config.TLSConfig) != nil {
		return nil, ErrInvalid
	}
	listener, err := tls.Listen("tcp", config.Address, config.TLSConfig.Clone())
	if err != nil {
		return nil, ErrUnavailable
	}
	principalUsages, err := parseUsages(config.PrincipalUsages)
	if err != nil || !slices.Contains(principalUsages, x509.ExtKeyUsageClientAuth) {
		_ = listener.Close()
		return nil, ErrInvalid
	}
	return &Server{listener: listener, policy: config.Policy, principalURI: config.PrincipalURI,
		principalDNSNames: append([]string(nil), config.PrincipalDNSNames...), principalUsages: principalUsages,
		resolver: config.Resolver, dialer: config.Dialer,
		capacity: make(chan struct{}, config.MaxConnections), replayCapacity: config.ReplayCapacity, now: config.Now,
		peerRevocation: config.PeerRevocation,
		replay:         make(map[string]time.Time, config.ReplayCapacity), sessions: make(map[net.Conn]net.Conn),
		connections: make(map[net.Conn]struct{})}, nil
}

func (s *Server) Addr() net.Addr {
	if s == nil || s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) Serve(ctx context.Context) error {
	if s == nil || s.listener == nil || ctx == nil {
		return ErrUnavailable
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			s.handlers.Wait()
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return ErrUnavailable
		}
		select {
		case s.capacity <- struct{}{}:
			s.trackConnection(connection)
			s.handlers.Add(1)
			go func() {
				defer s.handlers.Done()
				defer func() { <-s.capacity }()
				s.handle(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) RevokePolicy(revision string) error {
	if s == nil || revision != s.policy.Revision {
		return ErrDenied
	}
	s.sessionsMu.Lock()
	s.revoked = true
	for client, upstream := range s.sessions {
		_ = client.Close()
		_ = upstream.Close()
	}
	for connection := range s.connections {
		_ = connection.Close()
	}
	s.sessionsMu.Unlock()
	return nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var result error
	s.closeOnce.Do(func() {
		result = s.listener.Close()
		s.sessionsMu.Lock()
		for client, upstream := range s.sessions {
			_ = client.Close()
			_ = upstream.Close()
		}
		for connection := range s.connections {
			_ = connection.Close()
		}
		s.sessionsMu.Unlock()
	})
	s.handlers.Wait()
	if errors.Is(result, net.ErrClosed) {
		return nil
	}
	return result
}

func (s *Server) handle(parent context.Context, raw net.Conn) {
	defer raw.Close()
	defer s.untrackConnection(raw)
	connection, ok := raw.(*tls.Conn)
	if !ok {
		return
	}
	handshakeContext, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	if err := connection.HandshakeContext(handshakeContext); err != nil || validatePeerIdentity(connection.ConnectionState(),
		s.principalURI, s.principalDNSNames, s.principalUsages) != nil {
		return
	}
	if monitor := s.peerRevocation; monitor != nil {
		state := connection.ConnectionState()
		if !monitor.Ready() || monitor.CheckHandshake(handshakeContext, state) != nil ||
			monitor.Track(connection, state) != nil {
			return
		}
		defer monitor.Forget(connection)
	}
	document, err := readFrame(connection, maxRequestBytes)
	if err != nil {
		return
	}
	defer clear(document)
	now := s.now().UTC()
	request, err := decodeOpen(document, s.policy, now)
	if err != nil {
		return
	}
	deadline, _ := parseTime(request.Deadline)
	if !s.reserve(request.Nonce, deadline, now) || s.isRevoked() {
		s.writeDenied(connection, request, now)
		return
	}
	operationContext, operationCancel := context.WithDeadline(parent, deadline)
	defer operationCancel()
	target, _ := s.policy.target(request.TargetAlias)
	upstream, err := s.policy.network.DialContext(operationContext, s.resolver, s.dialer, target.Host, target.Port)
	if err != nil {
		s.writeDenied(connection, request, s.now().UTC())
		return
	}
	defer upstream.Close()
	leaseExpiry := s.now().UTC().Add(time.Duration(request.LeaseSeconds) * time.Second)
	if s.register(connection, upstream) != nil {
		s.writeDenied(connection, request, s.now().UTC())
		return
	}
	defer s.unregister(connection)
	response := acceptedFor(request, s.policy, leaseExpiry)
	responseDocument, err := encodeAccepted(response, request, s.policy, s.now().UTC())
	if err != nil || writeFrame(connection, responseDocument, maxResponseBytes) != nil {
		clear(responseDocument)
		return
	}
	clear(responseDocument)
	_ = connection.SetDeadline(leaseExpiry)
	_ = upstream.SetDeadline(leaseExpiry)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, connection); done <- struct{}{} }()
	go func() { _, _ = io.Copy(connection, upstream); done <- struct{}{} }()
	select {
	case <-parent.Done():
	case <-time.After(time.Until(leaseExpiry)):
	case <-done:
	}
}

func (s *Server) writeDenied(connection net.Conn, request Open, now time.Time) {
	document, err := encodeAccepted(deniedFor(request, s.policy), request, s.policy, now)
	if err != nil {
		return
	}
	defer clear(document)
	_ = writeFrame(connection, document, maxResponseBytes)
}

func (s *Server) reserve(nonce string, deadline, now time.Time) bool {
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	for known, expiry := range s.replay {
		if !expiry.After(now) {
			delete(s.replay, known)
		}
	}
	if _, duplicate := s.replay[nonce]; duplicate || len(s.replay) >= s.replayCapacity {
		return false
	}
	s.replay[nonce] = deadline
	return true
}

func (s *Server) register(client, upstream net.Conn) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.revoked {
		return ErrDenied
	}
	s.sessions[client] = upstream
	return nil
}

func (s *Server) unregister(client net.Conn) {
	s.sessionsMu.Lock()
	delete(s.sessions, client)
	s.sessionsMu.Unlock()
}

func (s *Server) trackConnection(connection net.Conn) {
	s.sessionsMu.Lock()
	s.connections[connection] = struct{}{}
	s.sessionsMu.Unlock()
}

func (s *Server) untrackConnection(connection net.Conn) {
	s.sessionsMu.Lock()
	delete(s.connections, connection)
	s.sessionsMu.Unlock()
}

func (s *Server) isRevoked() bool {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return s.revoked
}

func readFrame(reader io.Reader, maximum int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, ErrUnavailable
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length < 1 || length > maximum {
		return nil, ErrUnavailable
	}
	document := make([]byte, length)
	if _, err := io.ReadFull(reader, document); err != nil {
		clear(document)
		return nil, ErrUnavailable
	}
	return document, nil
}

func writeFrame(writer io.Writer, document []byte, maximum int) error {
	if len(document) < 1 || len(document) > maximum {
		return ErrUnavailable
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(document)))
	if err := writeBytes(writer, header[:]); err != nil {
		return err
	}
	return writeBytes(writer, document)
}

func writeBytes(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil || count < 1 {
			return ErrUnavailable
		}
		value = value[count:]
	}
	return nil
}

func ValidateTLSIdentity(state tls.ConnectionState, uri string, dnsNames, usages []string) error {
	parsed, err := parseUsages(usages)
	if err != nil {
		return ErrDenied
	}
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.PeerCertificates) < 1 || len(state.VerifiedChains) != 1 {
		return ErrDenied
	}
	return validateCertificateIdentity(state.PeerCertificates[0], uri, dnsNames, parsed)
}

// ValidateTLSIdentityInVerifyConnection is for tls.Config.VerifyConnection
// only. Go invokes that callback after standard chain verification but before
// HandshakeComplete is set. Post-handshake callers must use ValidateTLSIdentity.
func ValidateTLSIdentityInVerifyConnection(state tls.ConnectionState, uri string, dnsNames, usages []string) error {
	parsed, err := parseUsages(usages)
	if err != nil {
		return ErrDenied
	}
	if state.HandshakeComplete || state.DidResume || state.Version != tls.VersionTLS13 ||
		len(state.PeerCertificates) < 1 || state.PeerCertificates[0] == nil ||
		len(state.PeerCertificates[0].Raw) == 0 || len(state.VerifiedChains) != 1 ||
		len(state.VerifiedChains[0]) < 2 || state.VerifiedChains[0][0] == nil ||
		state.VerifiedChains[0][1] == nil || len(state.VerifiedChains[0][1].Raw) == 0 ||
		!bytes.Equal(state.PeerCertificates[0].Raw, state.VerifiedChains[0][0].Raw) {
		return ErrDenied
	}
	return validateCertificateIdentity(state.PeerCertificates[0], uri, dnsNames, parsed)
}

func validatePeerIdentity(state tls.ConnectionState, uri string, dnsNames []string, usages []x509.ExtKeyUsage) error {
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != ProtocolID ||
		len(state.PeerCertificates) < 1 || len(state.VerifiedChains) != 1 {
		return ErrDenied
	}
	return validateCertificateIdentity(state.PeerCertificates[0], uri, dnsNames, usages)
}

func validateCertificateIdentity(leaf *x509.Certificate, uri string, dnsNames []string, usages []x509.ExtKeyUsage) error {
	if leaf.Subject.String() != "" || len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri ||
		!slices.Equal(leaf.DNSNames, dnsNames) || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 ||
		!slices.Equal(leaf.ExtKeyUsage, usages) || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		return ErrDenied
	}
	return nil
}

func parseUsages(values []string) ([]x509.ExtKeyUsage, error) {
	if len(values) < 1 || len(values) > 2 || !sort.StringsAreSorted(values) {
		return nil, ErrInvalid
	}
	result := make([]x509.ExtKeyUsage, 0, len(values))
	for _, value := range values {
		switch value {
		case "client_auth":
			result = append(result, x509.ExtKeyUsageClientAuth)
		case "server_auth":
			result = append(result, x509.ExtKeyUsageServerAuth)
		default:
			return nil, ErrInvalid
		}
	}
	return result, nil
}

func validateServerTLS(config *tls.Config) error {
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ClientAuth != tls.RequireAndVerifyClientCert || config.ClientCAs == nil ||
		(len(config.Certificates) == 0 && config.GetCertificate == nil) || !slices.Equal(config.NextProtos, []string{ProtocolID}) {
		return ErrInvalid
	}
	return nil
}
