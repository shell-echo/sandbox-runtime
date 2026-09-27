package cdpfence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/internal/browserhandoffv2"
	"github.com/shell-echo/sandbox-runtime/internal/browseringress"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

const BrowserActionV2Path = "/browser/action"

const (
	BrowserActionFenceLostCloseCode   websocket.StatusCode = 4001
	BrowserActionUnavailableCloseCode websocket.StatusCode = 4002
)

var v2AudiencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

// BrowserProviderDialer is the only ingress-to-Provider private Browser edge.
// Its implementation must use the inventory-owned ingress principal, TLS/CRL
// and exact Provider audience; it must not accept a direct Gateway peer.
type BrowserProviderDialer interface {
	Open(context.Context, browserhandoffv2.OpenRequest) (gateway.Stream, error)
}

type V2NetworkOptions struct {
	Ingress                   *Ingress
	Provider                  BrowserProviderDialer
	PeerAuthorizer            PeerAuthorizer
	ExpectedHost              string
	ExpectedProviderAudience  string
	OperationTimeout          time.Duration
	MaxMessageBytes           int64
	AllowInsecureHTTPForTests bool
	Now                       func() time.Time
}

// V2NetworkHandler admits a canonical Gateway projection only after exact
// mTLS peer validation. Redis+witness action admission occurs inside Ingress
// before this handler derives a Provider v2 Open or starts the upstream dial.
type V2NetworkHandler struct {
	ingress      *Ingress
	provider     BrowserProviderDialer
	authorizer   PeerAuthorizer
	host         string
	audience     string
	operation    time.Duration
	messageLimit int64
	slots        chan struct{}
	insecureTest bool
	now          func() time.Time
}

func NewV2NetworkHandler(options V2NetworkOptions) (*V2NetworkHandler, error) {
	limit := options.MaxMessageBytes
	if limit == 0 {
		limit = defaultNetworkMessageBytes
	}
	operation := options.OperationTimeout
	if operation == 0 {
		operation = DefaultActionTimeout
	}
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if options.Ingress == nil || nilDependency(options.Provider) ||
		(!options.AllowInsecureHTTPForTests && nilDependency(options.PeerAuthorizer)) ||
		!validV2PrivateHost(options.ExpectedHost) ||
		!v2AudiencePattern.MatchString(options.ExpectedProviderAudience) ||
		operation < MinOperationTimeout || operation > MaxOperationTimeout ||
		limit < 1 || limit > maxNetworkMessageBytes {
		return nil, gateway.ErrDownstreamUnavailable
	}
	return &V2NetworkHandler{ingress: options.Ingress, provider: options.Provider,
		authorizer: options.PeerAuthorizer, host: options.ExpectedHost,
		audience: options.ExpectedProviderAudience, operation: operation,
		messageLimit: limit, slots: make(chan struct{}, options.Ingress.maxSessions),
		insecureTest: options.AllowInsecureHTTPForTests, now: now}, nil
}

func validV2PrivateHost(value string) bool {
	return value != "" && len(value) <= 255 && !strings.ContainsAny(value, "/@?# \r\n\t")
}

func (h *V2NetworkHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if h == nil || request == nil || request.Method != http.MethodGet || request.URL == nil ||
		request.URL.Path != BrowserActionV2Path || request.URL.EscapedPath() != BrowserActionV2Path ||
		request.URL.RawQuery != "" || request.URL.ForceQuery || request.Host != h.host ||
		len(request.Header.Values("Origin")) != 0 || len(request.Header.Values("Authorization")) != 0 ||
		len(request.Header.Values("Sec-WebSocket-Protocol")) != 1 ||
		request.Header.Get("Sec-WebSocket-Protocol") != browseringress.ProtocolID ||
		(!h.insecureTest && (request.TLS == nil || h.authorizer.AuthorizePeer(request.Context(), *request.TLS) != nil)) {
		http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{browseringress.ProtocolID}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(handoff.MaxDocumentBytes)
	readCtx, cancelRead := context.WithTimeout(request.Context(), h.operation)
	kind, document, readErr := connection.Read(readCtx)
	cancelRead()
	if readErr != nil || kind != websocket.MessageText {
		h.reject(request.Context(), connection, "invalid")
		return
	}
	open, err := browseringress.DecodeOpen(document, h.now().UTC())
	if err != nil || open.ProviderAudience != h.audience {
		h.reject(request.Context(), connection, "invalid")
		return
	}
	subject, fence, err := open.Subject(h.now().UTC())
	if err != nil {
		h.reject(request.Context(), connection, open.RequestID)
		return
	}
	downstream, err := h.ingress.Open(request.Context(), subject, fence, func(ctx context.Context) (gateway.Stream, error) {
		// This callback runs only after the exact Redis+witness admission and
		// after the previous actual upstream has confirmed closure.
		private, buildErr := admittedProviderOpen(open, h.now().UTC())
		if buildErr != nil {
			return nil, gateway.ErrDownstreamUnavailable
		}
		return h.provider.Open(ctx, private)
	})
	if err != nil {
		h.reject(request.Context(), connection, open.RequestID)
		return
	}
	accepted, _ := handoff.Encode(browseringress.AcceptedResponse(open.RequestID))
	if connection.Write(request.Context(), websocket.MessageText, accepted) != nil {
		_ = downstream.Close(context.Background())
		return
	}
	connection.SetReadLimit(h.messageLimit)
	client := &networkWebSocketStream{connection: connection, maxMessageBytes: h.messageLimit}
	proxyV2Streams(request.Context(), connection, client, downstream)
}

func proxyV2Streams(parent context.Context, connection *websocket.Conn, client, downstream gateway.Stream) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	type result struct {
		fromClient bool
		err        error
	}
	results := make(chan result, 2)
	copyStream := func(fromClient bool, source, destination gateway.Stream) {
		for {
			frame, err := source.Receive(ctx)
			if err != nil {
				results <- result{fromClient: fromClient, err: err}
				return
			}
			if err := destination.Send(ctx, frame); err != nil {
				results <- result{fromClient: fromClient, err: err}
				return
			}
		}
	}
	go copyStream(true, client, downstream)
	go copyStream(false, downstream, client)
	first := <-results
	cancel()
	_ = downstream.Close(context.Background())
	if errors.Is(first.err, gateway.ErrDownstreamFenceLost) {
		_ = connection.Close(BrowserActionFenceLostCloseCode, "fence_lost")
	} else if errors.Is(first.err, gateway.ErrDownstreamUnavailable) {
		_ = connection.Close(BrowserActionUnavailableCloseCode, "unavailable")
	} else if !first.fromClient {
		_ = connection.Close(websocket.StatusNormalClosure, "upstream_closed")
	} else {
		_ = connection.CloseNow()
	}
	<-results
}

func (h *V2NetworkHandler) reject(ctx context.Context, connection *websocket.Conn, requestID string) {
	document, _ := handoff.Encode(browseringress.RejectedResponse(requestID))
	writeCtx, cancel := context.WithTimeout(ctx, h.operation)
	defer cancel()
	_ = connection.Write(writeCtx, websocket.MessageText, document)
}

// admittedProviderOpen is deterministic per Gateway attach attempt. An exact
// replay has the same Provider epoch/request ID and cannot mint a new attach;
// a bounded internal reconnect receives a fresh Gateway request ID. Neither
// the raw capacity claim nor Product's raw control lease reaches Provider.
func admittedProviderOpen(open browseringress.Open, now time.Time) (browserhandoffv2.OpenRequest, error) {
	if open.Validate(now) != nil {
		return browserhandoffv2.OpenRequest{}, gateway.ErrDownstreamUnavailable
	}
	identity := struct {
		Domain, Grant, Request, Binding, Reference string
	}{"sandbox-runtime/browser-ingress-attempt/v2", open.GrantConnectionID, open.RequestID,
		open.TenantBindingDigest, open.HandoffReference}
	document, _ := json.Marshal(identity)
	sum := sha256.Sum256(append([]byte("sandbox-runtime/browser-ingress-attempt/v2\x00"), document...))
	attempt := hex.EncodeToString(sum[:])
	private := browserhandoffv2.OpenRequest{
		BindingVersion: browserhandoffv2.BindingVersion, BindingIssuer: browserhandoffv2.BindingIssuer,
		Protocol: browserhandoffv2.ProtocolID, RequestID: "open-" + attempt,
		Resource: browserhandoffv2.ResourceBrowser, TenantBindingDigest: open.TenantBindingDigest,
		ProviderRevisionID: open.ProviderRevisionID, SandboxID: open.SandboxID,
		BrowserSessionID: open.BrowserSessionID, CapabilityProfileID: open.CapabilityProfileID,
		MediaProfileID: browserhandoffv2.MediaProfileID, ControlProfileID: browserhandoffv2.ControlProfileID,
		HandoffReference: open.HandoffReference, HandoffDigest: browserhandoffv2.ReferenceDigest(open.HandoffReference),
		ConnectionGeneration: open.ConnectionGeneration, ConnectionEpoch: "epoch-" + attempt,
		ControlLeaseDigest: open.ControlLeaseDigest, ControlFence: open.ControlFence,
		AuthorityExpiresAt: open.AuthorityExpiresAt, HandoffExpiresAt: open.HandoffExpiresAt,
	}
	private.AuthorityDigest = browserhandoffv2.AuthorityDigest(private)
	private.RequestDigest = browserhandoffv2.RequestDigest(private)
	if private.Validate(now) != nil {
		return browserhandoffv2.OpenRequest{}, gateway.ErrDownstreamUnavailable
	}
	return private, nil
}

var _ http.Handler = (*V2NetworkHandler)(nil)
