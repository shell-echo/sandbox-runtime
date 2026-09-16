package providerapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/provider"
	"github.com/shell-echo/sandbox-runtime/provider/admission"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	"github.com/shell-echo/sandbox-runtime/provider/session"
	sessionapplication "github.com/shell-echo/sandbox-runtime/provider/session/application"
	"github.com/shell-echo/sandbox-runtime/provider/terminal"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	runtimeSessionHandoffHeader             = "X-Sandbox-Runtime-Session-Handoff"
	runtimeSessionWebSocketProtocol         = "sandbox-runtime-terminal.v1"
	maxRuntimeSessionConnectCarrierBytes    = 5462
	maxRuntimeSessionConnectDescriptorBytes = 4096
	maxRuntimeSessionWebSocketMessageBytes  = 64 << 10
)

var (
	// These errors are the transport-neutral result vocabulary for a concrete
	// RuntimeSessionConnector. They intentionally carry no repository or
	// backend detail into the HTTP response.
	ErrRuntimeSessionConnectUnknown     = errors.New("runtime session connection is unknown")
	ErrRuntimeSessionConnectConflict    = errors.New("runtime session connection is stale or conflicting")
	ErrRuntimeSessionConnectGone        = errors.New("runtime session connection is expired or revoked")
	ErrRuntimeSessionConnectUnsupported = errors.New("runtime session connection is unsupported")
	ErrRuntimeSessionConnectCapacity    = errors.New("runtime session connection capacity is exhausted")
	ErrRuntimeSessionConnectUnavailable = errors.New("runtime session connection is unavailable")
)

func runtimeSessionConnectDocument(request *http.Request) ([]byte, int) {
	if request == nil || request.URL == nil {
		return nil, http.StatusBadRequest
	}
	protocolValues := request.Header.Values("Sec-WebSocket-Protocol")
	if request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.ContentLength != 0 || len(request.TransferEncoding) != 0 || !readBodyIsEmpty(request.Body) ||
		len(request.Header.Values("Origin")) != 0 || len(protocolValues) != 1 || protocolValues[0] != runtimeSessionWebSocketProtocol {
		return nil, http.StatusBadRequest
	}
	values := request.Header.Values(runtimeSessionHandoffHeader)
	if len(values) != 1 {
		return nil, http.StatusBadRequest
	}
	carrier := values[0]
	if len(carrier) == 0 || len(carrier) > maxRuntimeSessionConnectCarrierBytes ||
		strings.ContainsAny(carrier, "= \t\r\n,") || !utf8.ValidString(carrier) {
		return nil, http.StatusBadRequest
	}
	document, err := base64.RawURLEncoding.Strict().DecodeString(carrier)
	if err != nil || len(document) == 0 || len(document) > maxRuntimeSessionConnectDescriptorBytes || !utf8.Valid(document) {
		return nil, http.StatusBadRequest
	}
	return document, 0
}

func (h *protectedHandler) serveRuntimeSessionConnect(response http.ResponseWriter, request *http.Request, admitted admission.AdmissionContext, document []byte) {
	now := h.now().UTC()
	descriptor, err := decodeRuntimeSessionConnectDescriptor(document, admitted, now)
	if err != nil {
		writeStandardError(response, http.StatusBadRequest, "SANDBOX_INVALID_REQUEST", false, "terminal session connection descriptor is invalid")
		return
	}
	deadlineAt, _ := time.Parse(time.RFC3339Nano, admitted.DeadlineAt)
	connectContext, cancelConnect := context.WithDeadline(request.Context(), deadlineAt)
	stream, err := h.sessionConnector.ConnectRuntimeSession(connectContext, descriptor)
	cancelConnect()
	if err != nil {
		status, code, retryable := mapRuntimeSessionConnectError(err)
		writeStandardError(response, status, code, retryable, "terminal session connection is not available")
		return
	}
	if stream == nil {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "terminal session connection is not available")
		return
	}
	var closeStreamOnce sync.Once
	closeStream := func() { closeStreamOnce.Do(func() { _ = stream.Close() }) }
	defer closeStream()
	if observed := h.now().UTC(); !observed.Before(descriptor.ExpiresAt) || !observed.Before(deadlineAt) {
		writeStandardError(response, http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true, "terminal session connection authority expired during resolution")
		return
	}

	connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols:    []string{runtimeSessionWebSocketProtocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	connection.SetReadLimit(maxRuntimeSessionWebSocketMessageBytes)
	defer connection.CloseNow()

	authorityContext, cancel := context.WithDeadline(request.Context(), descriptor.ExpiresAt)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- copyWebSocketToTerminal(authorityContext, connection, stream) }()
	go func() { results <- copyTerminalToWebSocket(authorityContext, stream, connection) }()
	<-results
	cancel()
	closeStream()
	connection.CloseNow()
	<-results
}

func terminalConnectAdvertised(snapshot provider.CapabilitySnapshot) bool {
	terminal := false
	connect := false
	for _, capability := range snapshot.Capabilities {
		switch capability.ID {
		case "sandbox.terminal":
			terminal = len(capability.Versions) == 1 && capability.Versions[0] == "1.0.0" && len(capability.Profiles) == 1 && capability.Profiles[0] == "terminal-v1"
		case "sandbox.terminal-connect":
			connect = len(capability.Versions) == 1 && capability.Versions[0] == "1.0.0" && len(capability.Profiles) == 1 && capability.Profiles[0] == "terminal-connect-v1"
		}
	}
	if !terminal || !connect {
		return false
	}
	for _, runtimeProfile := range snapshot.RuntimeProfiles {
		hasTerminal := false
		hasConnect := false
		for _, profileID := range runtimeProfile.CapabilityProfileIDs {
			hasTerminal = hasTerminal || profileID == "terminal-v1"
			hasConnect = hasConnect || profileID == "terminal-connect-v1"
		}
		if hasTerminal && hasConnect {
			return true
		}
	}
	return false
}

func decodeRuntimeSessionConnectDescriptor(document []byte, admitted admission.AdmissionContext, now time.Time) (sessionapplication.Handoff, error) {
	var descriptor providerv1.RuntimeSessionHandoff
	if err := providerv1.DecodeStrict(bytes.NewReader(document), maxRuntimeSessionConnectDescriptorBytes, &descriptor); err != nil {
		return sessionapplication.Handoff{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, descriptor.ExpiresAt)
	if err != nil || now.IsZero() || !now.Before(expiresAt) {
		return sessionapplication.Handoff{}, errors.New("terminal session connection expiry is invalid")
	}
	deadlineAt, err := time.Parse(time.RFC3339Nano, admitted.DeadlineAt)
	if err != nil || deadlineAt.After(expiresAt) || !now.Before(deadlineAt) {
		return sessionapplication.Handoff{}, errors.New("terminal session connection deadline is invalid")
	}
	for _, value := range []string{descriptor.OperationID, descriptor.AttemptID, descriptor.SandboxID, descriptor.RuntimeSessionID, descriptor.CapabilityProfileID} {
		if lifecycle.ValidateIdentifier(value) != nil {
			return sessionapplication.Handoff{}, errors.New("terminal session connection identity is invalid")
		}
	}
	if descriptor.OperationID != admitted.OperationID || descriptor.AttemptID != admitted.AttemptID ||
		descriptor.FencingToken != admitted.FencingToken || descriptor.SandboxID != admitted.SandboxID ||
		descriptor.FencingToken < 1 || descriptor.ConnectionGeneration < 1 ||
		descriptor.RuntimeType != providerv1.TerminalRuntimeTerminal || descriptor.Protocol != providerv1.TerminalProtocolWebSocket ||
		descriptor.CapabilityProfileID != "terminal-v1" || !runtimeSessionEndpointPattern.MatchString(descriptor.InternalEndpointReference) {
		return sessionapplication.Handoff{}, errors.New("terminal session connection descriptor does not match admission")
	}
	return sessionapplication.Handoff{
		OperationID: descriptor.OperationID, AttemptID: descriptor.AttemptID,
		FencingToken: descriptor.FencingToken, SandboxID: descriptor.SandboxID,
		RuntimeSessionID: descriptor.RuntimeSessionID, RuntimeType: session.RuntimeTerminal,
		CapabilityProfileID: descriptor.CapabilityProfileID, Protocol: session.ProtocolWebSocket,
		InternalEndpointReference: descriptor.InternalEndpointReference,
		ConnectionGeneration:      descriptor.ConnectionGeneration, ExpiresAt: expiresAt.UTC(),
	}, nil
}

func copyWebSocketToTerminal(ctx context.Context, connection *websocket.Conn, stream terminal.Stream) error {
	for {
		messageType, payload, err := connection.Read(ctx)
		if err != nil {
			return err
		}
		if messageType != websocket.MessageBinary || len(payload) > maxRuntimeSessionWebSocketMessageBytes {
			return errors.New("terminal WebSocket message is invalid")
		}
		for len(payload) != 0 {
			written, writeErr := stream.Write(ctx, payload)
			if written < 0 || written > len(payload) {
				return io.ErrShortWrite
			}
			payload = payload[written:]
			if writeErr != nil {
				return writeErr
			}
			if written == 0 {
				return io.ErrShortWrite
			}
		}
	}
}

func copyTerminalToWebSocket(ctx context.Context, stream terminal.Stream, connection *websocket.Conn) error {
	payload := make([]byte, maxRuntimeSessionWebSocketMessageBytes)
	for {
		read, err := stream.Read(ctx, payload)
		if read < 0 || read > len(payload) {
			return errors.New("terminal stream returned an invalid read count")
		}
		if read != 0 {
			if writeErr := connection.Write(ctx, websocket.MessageBinary, append([]byte(nil), payload[:read]...)); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			return err
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
}

func mapRuntimeSessionConnectError(err error) (int, string, bool) {
	switch {
	case errors.Is(err, ErrRuntimeSessionConnectUnknown):
		return http.StatusNotFound, "SANDBOX_RUNTIME_SESSION_UNAVAILABLE", false
	case errors.Is(err, ErrRuntimeSessionConnectConflict):
		return http.StatusConflict, "SANDBOX_CONFLICT", false
	case errors.Is(err, ErrRuntimeSessionConnectGone):
		return http.StatusGone, "SANDBOX_RUNTIME_SESSION_EXPIRED", false
	case errors.Is(err, ErrRuntimeSessionConnectUnsupported):
		return http.StatusUnprocessableEntity, "SANDBOX_CAPABILITY_UNSUPPORTED", false
	case errors.Is(err, ErrRuntimeSessionConnectCapacity):
		return http.StatusTooManyRequests, "SANDBOX_CAPACITY_EXHAUSTED", true
	default:
		return http.StatusServiceUnavailable, "SANDBOX_PROVIDER_UNAVAILABLE", true
	}
}
