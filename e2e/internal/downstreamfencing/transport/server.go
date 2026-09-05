package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

const defaultActivationTimeout = 5 * time.Second

type ProviderResolver interface {
	Resolve(context.Context, string) (browserreference.Endpoint, error)
}

type HandlerOptions struct {
	Ingress           *cdpfence.Ingress
	Resolver          ProviderResolver
	GatewayRoles      []string
	ResolveTimeout    time.Duration
	ActivationTimeout time.Duration
	MaxMessageBytes   int64
}

// Handler owns only the private resolve/connect transport. Its resolve path is
// read-only; only the WSS connect path may call Ingress.Open.
type Handler struct {
	ingress           *cdpfence.Ingress
	resolver          ProviderResolver
	gatewayRoles      []string
	resolveTimeout    time.Duration
	activationTimeout time.Duration
	maxMessageBytes   int64
	upgrader          ws.HTTPUpgrader
}

func NewHandler(options HandlerOptions) (*Handler, error) {
	if options.Ingress == nil || nilDependency(options.Resolver) {
		return nil, ErrInvalidConfiguration
	}
	if _, err := exactGatewayRoles(options.GatewayRoles); err != nil {
		return nil, err
	}
	resolveTimeout := options.ResolveTimeout
	if resolveTimeout == 0 {
		resolveTimeout = defaultActivationTimeout
	}
	activationTimeout := options.ActivationTimeout
	if activationTimeout == 0 {
		activationTimeout = defaultActivationTimeout
	}
	if resolveTimeout < gateway.MinDownstreamActionWindow || resolveTimeout > gateway.MaxDownstreamActionWindow ||
		activationTimeout < gateway.MinDownstreamActionWindow || activationTimeout > gateway.MaxDownstreamActionWindow {
		return nil, ErrInvalidConfiguration
	}
	maximum := options.MaxMessageBytes
	if maximum == 0 {
		maximum = wire.MaxMessageBytes
	}
	if maximum < 1 || maximum > wire.MaxMessageBytes {
		return nil, ErrInvalidConfiguration
	}
	return &Handler{
		ingress: options.Ingress, resolver: options.Resolver,
		gatewayRoles:   append([]string(nil), options.GatewayRoles...),
		resolveTimeout: resolveTimeout, activationTimeout: activationTimeout, maxMessageBytes: maximum,
		upgrader: ws.HTTPUpgrader{
			Protocol: func(value string) bool { return value == wire.ProtocolName },
		},
	}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if h == nil || request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.URL.User != nil || request.URL.Fragment != "" || request.URL.Opaque != "" || request.URL.RawPath != "" ||
		request.RequestURI != request.URL.Path {
		http.Error(response, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if _, err := GatewayPeerRole(request.TLS, h.gatewayRoles...); err != nil {
		http.Error(response, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	switch request.URL.Path {
	case wire.ResolvePath:
		h.serveResolve(response, request)
	case wire.ConnectPath:
		h.serveConnect(response, request)
	default:
		http.Error(response, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

func (h *Handler) serveResolve(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	resolveCtx, cancel := context.WithTimeout(request.Context(), h.resolveTimeout)
	defer cancel()
	deadline, _ := resolveCtx.Deadline()
	responseController := http.NewResponseController(response)
	if err := responseController.SetReadDeadline(deadline); err != nil {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = responseController.SetReadDeadline(time.Time{}) }()
	encoded, err := io.ReadAll(io.LimitReader(request.Body, wire.MaxResolutionBytes+1))
	if err != nil || len(encoded) > wire.MaxResolutionBytes {
		h.writeResolution(response, http.StatusBadRequest, wire.ResolutionResponse{Version: wire.ProtocolVersion, Status: wire.StatusRejected, ErrorCode: wire.ErrorInvalidActivation})
		return
	}
	resolutionRequest, err := wire.DecodeResolutionRequest(encoded)
	if err != nil {
		h.writeResolution(response, http.StatusBadRequest, wire.ResolutionResponse{Version: wire.ProtocolVersion, Status: wire.StatusRejected, ErrorCode: wire.ErrorInvalidActivation})
		return
	}
	reference, _ := resolutionRequest.Values()
	endpoint, err := h.resolver.Resolve(resolveCtx, reference)
	if err != nil || !validResolvedEndpoint(endpoint, reference) {
		h.writeResolution(response, http.StatusServiceUnavailable, wire.ResolutionResponse{Version: wire.ProtocolVersion, Status: wire.StatusRejected, ErrorCode: wire.ErrorUnavailable})
		return
	}
	h.writeResolution(response, http.StatusOK, wire.ResolutionResponse{
		Version: wire.ProtocolVersion, Status: wire.StatusReady,
		Endpoint: &wire.EndpointMetadata{
			Reference: endpoint.Reference, SandboxID: endpoint.SandboxID,
			BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
			ConnectionGeneration: endpoint.ConnectionGeneration,
			ExpiresAt:            endpoint.ExpiresAt.UTC().Format(time.RFC3339Nano),
		},
	})
}

func (h *Handler) writeResolution(response http.ResponseWriter, status int, value wire.ResolutionResponse) {
	encoded, err := wire.EncodeResolution(value)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_, _ = response.Write(encoded)
}

func (h *Handler) serveConnect(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !offersExactProtocol(request.Header.Values("Sec-WebSocket-Protocol")) {
		http.Error(response, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	connection, buffered, handshake, err := h.upgrader.Upgrade(request, response)
	if err != nil {
		return
	}
	if handshake.Protocol != wire.ProtocolName {
		_ = connection.Close()
		return
	}
	reader := io.Reader(connection)
	if buffered != nil {
		reader = buffered.Reader
	}
	h.handleConnection(request.Context(), connection, reader)
}

func (h *Handler) handleConnection(parent context.Context, connection net.Conn, reader io.Reader) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	defer connection.Close()
	writes := &sync.Mutex{}
	activationCtx, activationCancel := context.WithTimeout(ctx, h.activationTimeout)
	defer activationCancel()
	encoded, operation, err := readCompleteMessage(activationCtx, connection, reader, writes, wire.MaxActivationBytes, h.activationTimeout)
	if err != nil || operation != ws.OpText {
		writeClose(connection, writes, ws.StatusPolicyViolation, "invalid private activation")
		return
	}
	activation, err := wire.DecodeActivation(encoded)
	if err != nil {
		writeRejected(connection, writes, wire.ErrorInvalidActivation)
		return
	}
	reference, subject, fence, _ := activation.Values()
	endpoint, err := h.resolver.Resolve(activationCtx, reference)
	if err != nil || !endpointMatches(endpoint, reference, subject) {
		writeRejected(connection, writes, wire.ErrorUnavailable)
		return
	}
	stream, err := h.ingress.Open(activationCtx, subject, fence, func(dialCtx context.Context) (gateway.Stream, error) {
		downstream, err := endpoint.Dial(dialCtx)
		if err != nil || nilDependency(downstream) {
			return nil, gateway.ErrDownstreamUnavailable
		}
		return adaptBrowserDownstream(downstream, h.maxMessageBytes)
	})
	if err != nil {
		if errors.Is(err, gateway.ErrDownstreamFenceLost) {
			writeRejected(connection, writes, wire.ErrorFenceLost)
		} else {
			writeRejected(connection, writes, wire.ErrorUnavailable)
		}
		return
	}
	ready, _ := wire.EncodeResponse(wire.ActivationResponse{Version: wire.ProtocolVersion, Status: wire.StatusReady})
	if err := writeServerMessage(activationCtx, connection, writes, ws.OpText, ready); err != nil {
		_ = stream.Close(context.Background())
		return
	}

	results := make(chan error, 2)
	go func() { results <- h.forwardActions(ctx, connection, reader, writes, stream) }()
	go func() { results <- h.forwardResponses(ctx, connection, writes, stream) }()
	result := <-results
	cancel()
	_ = stream.Close(context.Background())
	if errors.Is(result, gateway.ErrDownstreamFenceLost) {
		writeClose(connection, writes, ws.StatusPolicyViolation, "downstream fence lost")
	} else if result != nil && !errors.Is(result, io.EOF) && !errors.Is(result, context.Canceled) {
		writeClose(connection, writes, ws.StatusInternalServerError, "downstream unavailable")
	}
}

func (h *Handler) forwardActions(ctx context.Context, connection net.Conn, reader io.Reader, writes *sync.Mutex, stream gateway.Stream) error {
	for {
		payload, operation, err := readCompleteMessage(ctx, connection, reader, writes, h.maxMessageBytes, h.activationTimeout)
		if err != nil {
			return err
		}
		var frameType gateway.FrameType
		switch operation {
		case ws.OpText:
			frameType = gateway.TextFrame
		case ws.OpBinary:
			frameType = gateway.BinaryFrame
		default:
			return gateway.ErrDownstreamUnavailable
		}
		if err := stream.Send(ctx, gateway.Frame{Type: frameType, Payload: payload}); err != nil {
			return err
		}
		writeCtx, cancel := context.WithTimeout(ctx, h.activationTimeout)
		err = writeServerMessage(writeCtx, connection, writes, ws.OpPong, []byte(wire.ActionACKPayload))
		cancel()
		if err != nil {
			return gateway.ErrDownstreamUnavailable
		}
	}
}

func (h *Handler) forwardResponses(ctx context.Context, connection net.Conn, writes *sync.Mutex, stream gateway.Stream) error {
	for {
		frame, err := stream.Receive(ctx)
		if err != nil {
			return err
		}
		var operation ws.OpCode
		switch frame.Type {
		case gateway.TextFrame:
			operation = ws.OpText
		case gateway.BinaryFrame:
			operation = ws.OpBinary
		default:
			return gateway.ErrDownstreamUnavailable
		}
		if int64(len(frame.Payload)) > h.maxMessageBytes {
			return gateway.ErrDownstreamUnavailable
		}
		writeCtx, cancel := context.WithTimeout(ctx, h.activationTimeout)
		writeErr := writeServerMessage(writeCtx, connection, writes, operation, frame.Payload)
		cancel()
		if writeErr != nil {
			return gateway.ErrDownstreamUnavailable
		}
	}
}

func endpointMatches(endpoint browserreference.Endpoint, reference string, subject gateway.DownstreamFenceSubject) bool {
	return endpoint.Reference == reference && endpoint.SandboxID == subject.SandboxID &&
		endpoint.BrowserSessionID == subject.BrowserSessionID && endpoint.CapabilityProfileID == subject.CapabilityProfileID &&
		endpoint.ConnectionGeneration == subject.ConnectionGeneration && endpoint.Dial != nil &&
		!endpoint.ExpiresAt.IsZero() && !endpoint.ExpiresAt.Before(subject.ExpiresAt)
}

func validResolvedEndpoint(endpoint browserreference.Endpoint, reference string) bool {
	return endpoint.Reference == reference && endpoint.SandboxID != "" && endpoint.BrowserSessionID != "" &&
		endpoint.CapabilityProfileID != "" && endpoint.ConnectionGeneration > 0 && endpoint.Dial != nil &&
		!endpoint.ExpiresAt.IsZero()
}

func adaptBrowserDownstream(downstream providerbrowser.Stream, maximum int64) (gateway.Stream, error) {
	if nilDependency(downstream) {
		return nil, gateway.ErrDownstreamUnavailable
	}
	adapted, err := adapter.NewBrowserStream(downstream, adapter.BrowserOptions{MaxFrameBytes: maximum})
	if err != nil {
		_ = downstream.Close()
		return nil, gateway.ErrDownstreamUnavailable
	}
	return adapted, nil
}

func offersExactProtocol(values []string) bool {
	if len(values) != 1 {
		return false
	}
	parts := strings.Split(values[0], ",")
	return len(parts) == 1 && strings.TrimSpace(parts[0]) == wire.ProtocolName
}

func writeRejected(connection net.Conn, writes *sync.Mutex, code string) {
	encoded, _ := wire.EncodeResponse(wire.ActivationResponse{Version: wire.ProtocolVersion, Status: wire.StatusRejected, ErrorCode: code})
	ctx, cancel := context.WithTimeout(context.Background(), defaultActivationTimeout)
	defer cancel()
	_ = writeServerMessage(ctx, connection, writes, ws.OpText, encoded)
	writeClose(connection, writes, ws.StatusPolicyViolation, "private activation rejected")
}

func writeClose(connection net.Conn, writes *sync.Mutex, code ws.StatusCode, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultActivationTimeout)
	defer cancel()
	_ = writeServerMessage(ctx, connection, writes, ws.OpClose, ws.NewCloseFrameBody(code, reason))
}

func writeServerMessage(ctx context.Context, connection net.Conn, writes *sync.Mutex, operation ws.OpCode, payload []byte) error {
	if ctx == nil || connection == nil || writes == nil {
		return gateway.ErrDownstreamUnavailable
	}
	writes.Lock()
	defer writes.Unlock()
	clear := applyWriteContext(ctx, connection)
	defer clear()
	if err := wsutil.WriteServerMessage(connection, operation, append([]byte(nil), payload...)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return gateway.ErrDownstreamUnavailable
	}
	return nil
}

func readCompleteMessage(ctx context.Context, connection net.Conn, source io.Reader, writes *sync.Mutex, maximum int64, controlTimeout time.Duration) ([]byte, ws.OpCode, error) {
	if ctx == nil || connection == nil || source == nil || maximum < 1 || controlTimeout < gateway.MinDownstreamActionWindow || controlTimeout > gateway.MaxDownstreamActionWindow {
		return nil, 0, gateway.ErrDownstreamUnavailable
	}
	clear := applyReadContext(ctx, connection)
	defer clear()
	reader := wsutil.Reader{Source: source, State: ws.StateServerSide, CheckUTF8: true, MaxFrameSize: maximum}
	reader.OnIntermediate = func(header ws.Header, payload io.Reader) error {
		return handleClientControl(ctx, connection, writes, header, payload, controlTimeout)
	}
	for {
		header, err := reader.NextFrame()
		if err != nil {
			return nil, 0, boundedIOError(ctx, err)
		}
		if header.OpCode.IsControl() {
			if err := handleClientControl(ctx, connection, writes, header, &reader, controlTimeout); err != nil {
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

func handleClientControl(ctx context.Context, connection net.Conn, writes *sync.Mutex, header ws.Header, source io.Reader, writeTimeout time.Duration) error {
	payload, err := io.ReadAll(io.LimitReader(source, ws.MaxControlFramePayloadSize+1))
	if err != nil || len(payload) > ws.MaxControlFramePayloadSize {
		return gateway.ErrDownstreamUnavailable
	}
	switch header.OpCode {
	case ws.OpPing:
		writeCtx, cancel := context.WithTimeout(ctx, writeTimeout)
		defer cancel()
		return writeServerMessage(writeCtx, connection, writes, ws.OpPong, payload)
	case ws.OpPong:
		return nil
	case ws.OpClose:
		return io.EOF
	default:
		return gateway.ErrDownstreamUnavailable
	}
}

func applyReadContext(ctx context.Context, connection net.Conn) func() {
	return applyDeadlineContext(ctx, connection.SetReadDeadline)
}

func applyWriteContext(ctx context.Context, connection net.Conn) func() {
	return applyDeadlineContext(ctx, connection.SetWriteDeadline)
}

func applyDeadlineContext(ctx context.Context, setDeadline func(time.Time) error) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = setDeadline(deadline)
	} else {
		_ = setDeadline(time.Time{})
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = setDeadline(time.Now())
		close(callbackDone)
	})
	return func() {
		if !stop() {
			<-callbackDone
		}
		_ = setDeadline(time.Time{})
	}
}

func boundedIOError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	return gateway.ErrDownstreamUnavailable
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ http.Handler = (*Handler)(nil)
