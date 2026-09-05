package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/composition"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

const defaultClientTimeout = 5 * time.Second

type ResolverOptions struct {
	Address         string
	TLSConfig       *tls.Config
	ResolveTimeout  time.Duration
	ConnectTimeout  time.Duration
	MaxMessageBytes int64
}

// Resolver projects the two-step private protocol as the narrow fenced
// resolver consumed by Browser Gateway composition. Resolve is read-only;
// endpoint Dial performs activation over the fixed WSS connect path.
type Resolver struct {
	address         string
	tlsConfig       *tls.Config
	client          *http.Client
	resolveTimeout  time.Duration
	connectTimeout  time.Duration
	maxMessageBytes int64
}

// CloseIdleConnections releases resolved HTTPS connections owned by this
// process. Active private WebSocket streams remain owned by their Gateway
// connection and are closed through the Stream contract.
func (r *Resolver) CloseIdleConnections() {
	if r == nil || r.client == nil {
		return
	}
	r.client.CloseIdleConnections()
}

func NewResolver(options ResolverOptions) (*Resolver, error) {
	if !validPrivateAddress(options.Address) || !validClientTLSPolicy(options.TLSConfig) {
		return nil, ErrInvalidConfiguration
	}
	resolveTimeout, err := clientTimeout(options.ResolveTimeout)
	if err != nil {
		return nil, err
	}
	connectTimeout, err := clientTimeout(options.ConnectTimeout)
	if err != nil {
		return nil, err
	}
	maximum := options.MaxMessageBytes
	if maximum == 0 {
		maximum = wire.MaxMessageBytes
	}
	if maximum < 1 || maximum > wire.MaxMessageBytes {
		return nil, ErrInvalidConfiguration
	}
	frozenCertificate, _, _ := freezeCertificate(options.TLSConfig.Certificates[0])
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"}, RootCAs: options.TLSConfig.RootCAs.Clone(),
		ServerName: options.TLSConfig.ServerName, Certificates: []tls.Certificate{frozenCertificate},
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		_, err := verifyPeerRole(state, x509.ExtKeyUsageServerAuth, map[string]struct{}{wire.IngressRoleURI: {}})
		return err
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig.Clone(), ForceAttemptHTTP2: false,
		DisableCompression: true, MaxIdleConns: 2, MaxIdleConnsPerHost: 2,
		IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: connectTimeout,
	}
	return &Resolver{
		address: options.Address, tlsConfig: tlsConfig,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}, resolveTimeout: resolveTimeout,
		connectTimeout: connectTimeout, maxMessageBytes: maximum,
	}, nil
}

func (r *Resolver) ResolveFenced(ctx context.Context, reference string, subject gateway.DownstreamFenceSubject, fence gateway.DownstreamFence) (browserreference.Endpoint, error) {
	if r == nil || r.client == nil || ctx == nil {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	if err := ctx.Err(); err != nil {
		return browserreference.Endpoint{}, err
	}
	activation, err := wire.NewActivation(reference, subject, fence)
	if err != nil {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	resolutionRequest, err := wire.NewResolutionRequest(reference)
	if err != nil {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	encoded, err := wire.EncodeResolutionRequest(resolutionRequest)
	if err != nil {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	operationCtx, cancel := context.WithTimeout(ctx, r.resolveTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(operationCtx, http.MethodPost, r.privateURL("https", wire.ResolvePath), bytes.NewReader(encoded))
	if err != nil {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return browserreference.Endpoint{}, clientBoundaryError(ctx, err)
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, wire.MaxResolutionBytes+1))
	if readErr != nil || len(payload) > wire.MaxResolutionBytes || response.StatusCode != http.StatusOK ||
		response.Header.Get("Content-Type") != "application/json" {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	resolution, err := wire.DecodeResolution(payload)
	if err != nil || resolution.Status != wire.StatusReady || resolution.Endpoint == nil {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	metadata := *resolution.Endpoint
	expiresAt, err := time.Parse(time.RFC3339Nano, metadata.ExpiresAt)
	if err != nil {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	endpoint := browserreference.Endpoint{
		Reference: metadata.Reference, SandboxID: metadata.SandboxID,
		BrowserSessionID: metadata.BrowserSessionID, CapabilityProfileID: metadata.CapabilityProfileID,
		ConnectionGeneration: metadata.ConnectionGeneration, ExpiresAt: expiresAt.UTC(),
	}
	endpoint.Dial = func(dialCtx context.Context) (providerbrowser.Stream, error) {
		return r.connect(dialCtx, activation)
	}
	if !endpointMatches(endpoint, reference, subject) {
		return browserreference.Endpoint{}, gateway.ErrDownstreamUnavailable
	}
	return endpoint, nil
}

func (r *Resolver) connect(ctx context.Context, activation wire.Activation) (providerbrowser.Stream, error) {
	if ctx == nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encoded, err := wire.EncodeActivation(activation)
	if err != nil {
		return nil, gateway.ErrDownstreamUnavailable
	}
	operationCtx, cancel := context.WithTimeout(ctx, r.connectTimeout)
	defer cancel()
	dialer := ws.Dialer{
		TLSConfig: r.tlsConfig.Clone(), Protocols: []string{wire.ProtocolName},
		Timeout: r.connectTimeout,
	}
	connection, buffered, handshake, err := dialer.Dial(operationCtx, r.privateURL("wss", wire.ConnectPath))
	if err != nil || connection == nil || handshake.Protocol != wire.ProtocolName {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, clientBoundaryError(ctx, err)
	}
	reader := io.Reader(connection)
	if buffered != nil {
		reader = buffered
	}
	writes := &sync.Mutex{}
	if err := writeClientMessage(operationCtx, connection, writes, ws.OpText, encoded); err != nil {
		_ = connection.Close()
		return nil, clientBoundaryError(ctx, err)
	}
	responsePayload, operation, err := readServerMessage(operationCtx, connection, reader, writes, wire.MaxActivationBytes, nil)
	if err != nil {
		_ = connection.Close()
		return nil, clientBoundaryError(ctx, err)
	}
	if operation != ws.OpText {
		_ = connection.Close()
		return nil, gateway.ErrDownstreamUnavailable
	}
	response, err := wire.DecodeResponse(responsePayload)
	if err == nil && response.Status == wire.StatusRejected && response.ErrorCode == wire.ErrorFenceLost {
		_ = connection.Close()
		return nil, gateway.ErrDownstreamFenceLost
	}
	if err != nil || response.Status != wire.StatusReady {
		_ = connection.Close()
		return nil, gateway.ErrDownstreamUnavailable
	}
	stream := newClientStream(connection, reader, writes, r.maxMessageBytes, r.connectTimeout)
	go stream.receive()
	return stream, nil
}

func (r *Resolver) privateURL(scheme, path string) string {
	return (&url.URL{Scheme: scheme, Host: r.address, Path: path}).String()
}

type clientStream struct {
	connection net.Conn
	reader     io.Reader
	wireWrites *sync.Mutex
	maximum    int64
	timeout    time.Duration

	writeMu sync.Mutex
	raw     []byte

	ackMu   sync.Mutex
	pending chan error

	readMu    sync.Mutex
	remaining []byte
	responses chan []byte

	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error
}

func newClientStream(connection net.Conn, reader io.Reader, writes *sync.Mutex, maximum int64, timeout time.Duration) *clientStream {
	return &clientStream{
		connection: connection, reader: reader, wireWrites: writes, maximum: maximum, timeout: timeout,
		responses: make(chan []byte, 32), done: make(chan struct{}),
	}
}

func (s *clientStream) Write(ctx context.Context, value []byte) (int, error) {
	if s == nil || s.connection == nil || ctx == nil {
		return 0, gateway.ErrDownstreamUnavailable
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(value) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.done:
		return 0, s.terminalError()
	default:
	}
	if len(s.raw)+len(value) > int(s.maximum)+ws.MaxHeaderSize {
		s.fail(gateway.ErrDownstreamUnavailable)
		return 0, gateway.ErrDownstreamUnavailable
	}
	s.raw = append(s.raw, value...)
	for len(s.raw) > 0 {
		operation, payload, consumed, complete, err := decodeRawClientFrame(s.raw, s.maximum)
		if err != nil {
			s.fail(gateway.ErrDownstreamUnavailable)
			return 0, gateway.ErrDownstreamUnavailable
		}
		if !complete {
			break
		}
		s.raw = append(s.raw[:0], s.raw[consumed:]...)
		if err := s.sendAction(ctx, operation, payload); err != nil {
			return 0, err
		}
	}
	return len(value), nil
}

func (s *clientStream) sendAction(ctx context.Context, operation ws.OpCode, payload []byte) error {
	operationCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	ack := make(chan error, 1)
	s.ackMu.Lock()
	if s.pending != nil {
		s.ackMu.Unlock()
		return gateway.ErrDownstreamUnavailable
	}
	s.pending = ack
	s.ackMu.Unlock()
	defer func() {
		s.ackMu.Lock()
		if s.pending == ack {
			s.pending = nil
		}
		s.ackMu.Unlock()
	}()
	if err := writeClientMessage(operationCtx, s.connection, s.wireWrites, operation, payload); err != nil {
		s.fail(gateway.ErrDownstreamUnavailable)
		return clientBoundaryError(ctx, err)
	}
	select {
	case err := <-ack:
		return err
	case <-operationCtx.Done():
		if ctx.Err() != nil {
			s.fail(ctx.Err())
			return ctx.Err()
		}
		s.fail(gateway.ErrDownstreamUnavailable)
		return gateway.ErrDownstreamUnavailable
	case <-s.done:
		return s.terminalError()
	}
}

func (s *clientStream) Read(ctx context.Context, target []byte) (int, error) {
	if s == nil || ctx == nil {
		return 0, gateway.ErrDownstreamUnavailable
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(target) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.remaining) == 0 {
		select {
		case value := <-s.responses:
			s.remaining = value
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			select {
			case value := <-s.responses:
				s.remaining = value
			default:
				return 0, s.terminalError()
			}
		}
	}
	count := copy(target, s.remaining)
	s.remaining = s.remaining[count:]
	return count, nil
}

func (s *clientStream) Close() error {
	if s == nil {
		return nil
	}
	s.fail(io.EOF)
	return nil
}

func (s *clientStream) receive() {
	for {
		payload, operation, err := readServerMessage(context.Background(), s.connection, s.reader, s.wireWrites, s.maximum, s.handleControl)
		if err != nil {
			s.fail(err)
			return
		}
		if operation != ws.OpText && operation != ws.OpBinary {
			s.fail(gateway.ErrDownstreamUnavailable)
			return
		}
		var encoded bytes.Buffer
		if err := wsutil.WriteServerMessage(&encoded, operation, payload); err != nil {
			s.fail(gateway.ErrDownstreamUnavailable)
			return
		}
		select {
		case s.responses <- encoded.Bytes():
		default:
			s.fail(gateway.ErrDownstreamUnavailable)
			return
		}
	}
}

func (s *clientStream) handleControl(operation ws.OpCode, payload []byte) error {
	switch operation {
	case ws.OpPong:
		if !bytes.Equal(payload, []byte(wire.ActionACKPayload)) {
			return nil
		}
		s.ackMu.Lock()
		pending := s.pending
		s.ackMu.Unlock()
		if pending == nil {
			return gateway.ErrDownstreamUnavailable
		}
		select {
		case pending <- nil:
			return nil
		default:
			return gateway.ErrDownstreamUnavailable
		}
	case ws.OpPing:
		writeCtx, cancel := context.WithTimeout(context.Background(), s.timeout)
		defer cancel()
		return writeClientMessage(writeCtx, s.connection, s.wireWrites, ws.OpPong, payload)
	case ws.OpClose:
		_, reason := ws.ParseCloseFrameData(payload)
		if reason == "downstream fence lost" {
			return gateway.ErrDownstreamFenceLost
		}
		if reason == "downstream unavailable" {
			return gateway.ErrDownstreamUnavailable
		}
		return io.EOF
	default:
		return gateway.ErrDownstreamUnavailable
	}
}

func (s *clientStream) fail(err error) {
	if err == nil {
		err = gateway.ErrDownstreamUnavailable
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, gateway.ErrDownstreamFenceLost) &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		err = gateway.ErrDownstreamUnavailable
	}
	s.closeOnce.Do(func() {
		s.errMu.Lock()
		s.err = err
		s.errMu.Unlock()
		_ = s.connection.Close()
		s.ackMu.Lock()
		if s.pending != nil {
			select {
			case s.pending <- err:
			default:
			}
		}
		s.ackMu.Unlock()
		close(s.done)
	})
}

func (s *clientStream) terminalError() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		return gateway.ErrDownstreamUnavailable
	}
	return s.err
}

func decodeRawClientFrame(value []byte, maximum int64) (ws.OpCode, []byte, int, bool, error) {
	if len(value) < 2 {
		return 0, nil, 0, false, nil
	}
	if value[0]&0x80 == 0 || value[0]&0x70 != 0 {
		return 0, nil, 0, false, gateway.ErrDownstreamUnavailable
	}
	operation := ws.OpCode(value[0] & 0x0f)
	if operation != ws.OpText && operation != ws.OpBinary || value[1]&0x80 == 0 {
		return 0, nil, 0, false, gateway.ErrDownstreamUnavailable
	}
	headerLength := 2
	payloadLength := uint64(value[1] & 0x7f)
	switch payloadLength {
	case 126:
		headerLength += 2
		if len(value) < headerLength {
			return 0, nil, 0, false, nil
		}
		payloadLength = uint64(binary.BigEndian.Uint16(value[2:4]))
	case 127:
		headerLength += 8
		if len(value) < headerLength {
			return 0, nil, 0, false, nil
		}
		payloadLength = binary.BigEndian.Uint64(value[2:10])
	}
	headerLength += 4
	if payloadLength > uint64(maximum) || payloadLength > uint64(^uint(0)>>1) {
		return 0, nil, 0, false, gateway.ErrDownstreamUnavailable
	}
	total := headerLength + int(payloadLength)
	if len(value) < total {
		return 0, nil, 0, false, nil
	}
	frame, err := ws.ReadFrame(bytes.NewReader(value[:total]))
	if err != nil || ws.CheckHeader(frame.Header, ws.StateServerSide) != nil {
		return 0, nil, 0, false, gateway.ErrDownstreamUnavailable
	}
	ws.Cipher(frame.Payload, frame.Header.Mask, 0)
	if operation == ws.OpText && !utf8.Valid(frame.Payload) {
		return 0, nil, 0, false, gateway.ErrDownstreamUnavailable
	}
	return operation, append([]byte(nil), frame.Payload...), total, true, nil
}

type controlHandler func(ws.OpCode, []byte) error

func readServerMessage(ctx context.Context, connection net.Conn, source io.Reader, writes *sync.Mutex, maximum int64, control controlHandler) ([]byte, ws.OpCode, error) {
	clear := applyReadContext(ctx, connection)
	defer clear()
	reader := wsutil.Reader{Source: source, State: ws.StateClientSide, CheckUTF8: true, MaxFrameSize: maximum}
	handle := func(header ws.Header, payload io.Reader) error {
		value, err := io.ReadAll(io.LimitReader(payload, ws.MaxControlFramePayloadSize+1))
		if err != nil || len(value) > ws.MaxControlFramePayloadSize {
			return gateway.ErrDownstreamUnavailable
		}
		if control == nil {
			if header.OpCode == ws.OpClose {
				return io.EOF
			}
			if header.OpCode == ws.OpPing {
				return writeClientMessage(ctx, connection, writes, ws.OpPong, value)
			}
			return nil
		}
		return control(header.OpCode, value)
	}
	reader.OnIntermediate = handle
	for {
		header, err := reader.NextFrame()
		if err != nil {
			return nil, 0, boundedIOError(ctx, err)
		}
		if header.OpCode.IsControl() {
			if err := handle(header, &reader); err != nil {
				return nil, 0, err
			}
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(&reader, maximum+1))
		if err != nil || int64(len(payload)) > maximum {
			return nil, 0, gateway.ErrDownstreamUnavailable
		}
		return payload, header.OpCode, nil
	}
}

func writeClientMessage(ctx context.Context, connection net.Conn, writes *sync.Mutex, operation ws.OpCode, payload []byte) error {
	if ctx == nil || connection == nil || writes == nil {
		return gateway.ErrDownstreamUnavailable
	}
	writes.Lock()
	defer writes.Unlock()
	clear := applyWriteContext(ctx, connection)
	defer clear()
	if err := wsutil.WriteClientMessage(connection, operation, append([]byte(nil), payload...)); err != nil {
		return clientBoundaryError(ctx, err)
	}
	return nil
}

func validPrivateAddress(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "/?#@") {
		return false
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
}

func validClientTLSPolicy(config *tls.Config) bool {
	if config == nil || config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.InsecureSkipVerify || len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" ||
		config.RootCAs == nil || config.ServerName == "" || len(config.Certificates) != 1 {
		return false
	}
	_, leaf, err := freezeCertificate(config.Certificates[0])
	return err == nil && (certificateHasExactUsageAndRole(leaf, x509.ExtKeyUsageClientAuth, wire.GatewayARoleURI) ||
		certificateHasExactUsageAndRole(leaf, x509.ExtKeyUsageClientAuth, wire.GatewayBRoleURI))
}

func clientTimeout(value time.Duration) (time.Duration, error) {
	if value == 0 {
		value = defaultClientTimeout
	}
	if value < gateway.MinDownstreamActionWindow || value > gateway.MaxDownstreamActionWindow {
		return 0, ErrInvalidConfiguration
	}
	return value, nil
}

func clientBoundaryError(ctx context.Context, _ error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return gateway.ErrDownstreamUnavailable
}

var _ composition.BrowserFencedProviderResolver = (*Resolver)(nil)
var _ providerbrowser.Stream = (*clientStream)(nil)
