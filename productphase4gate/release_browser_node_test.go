//go:build phase4browsergate

package productphase4gate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/rtp"
	"github.com/shell-echo/sandbox-runtime/gateway"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
)

func runReleaseBrowserNode(config nodeConfig) error {
	ctx := context.Background()
	redisClient := releaseRedisClient(config.RedisAddress)
	defer redisClient.Close()
	capacity, err := releaseCapacity(redisClient)
	if err != nil {
		return err
	}
	if err := capacity.Provision(ctx); err != nil {
		return err
	}
	actionFencer, err := rediscapacity.NewActionFencer(capacity)
	if err != nil {
		return err
	}
	if err := actionFencer.Provision(ctx); err != nil {
		return err
	}
	ingress, err := cdpfence.New(cdpfence.Options{Authority: actionFencer, ActionTimeout: 200 * time.Millisecond, CloseTimeout: 500 * time.Millisecond, MaxActionBytes: 32 << 10})
	if err != nil {
		return err
	}
	automation, err := cdpfence.NewNetworkHandler(cdpfence.NetworkOptions{
		Ingress: ingress, Resolver: &releaseBrowserResolver{expiresAt: config.ExpiresAt},
		PeerAuthorizer: cdpfence.PeerAuthorizerFunc(releasePeerAuthorizer), MaxMessageBytes: 32 << 10,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/private/browser", automation)
	mux.HandleFunc("/private/live", releaseLiveBrowserHandler)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	tlsConfig, err := serverTLSConfig(config.ProviderCert, config.ProviderKey, config.CACertificate, true)
	if err != nil {
		return err
	}
	return serveUntilSignal(config.ProviderAddress, mux, tlsConfig)
}

type releaseBrowserResolver struct {
	expiresAt time.Time
}

func (r *releaseBrowserResolver) Resolve(_ context.Context, reference string) (gateway.Endpoint, error) {
	parts := strings.Split(strings.TrimPrefix(reference, "ref:browser-session:"), ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(reference, " \r\n\t") {
		return gateway.Endpoint{}, gateway.ErrReferenceUnavailable
	}
	return gateway.Endpoint{
		Reference: reference, SandboxID: parts[0], BrowserSessionID: parts[1],
		CapabilityProfileID: productgateway.BrowserAutomationSubprotocol, ConnectionGeneration: 1, ExpiresAt: r.expiresAt,
		Dial: func(context.Context) (gateway.Stream, error) {
			return newReleaseCDPStream(), nil
		},
	}, nil
}

type releaseCDPStream struct {
	frames chan gateway.Frame
	done   chan struct{}
	once   sync.Once
}

func newReleaseCDPStream() *releaseCDPStream {
	return &releaseCDPStream{frames: make(chan gateway.Frame, 1), done: make(chan struct{})}
}

func (s *releaseCDPStream) Receive(ctx context.Context) (gateway.Frame, error) {
	select {
	case frame := <-s.frames:
		return frame, nil
	case <-s.done:
		return gateway.Frame{}, io.EOF
	case <-ctx.Done():
		return gateway.Frame{}, ctx.Err()
	}
}

func (s *releaseCDPStream) Send(ctx context.Context, frame gateway.Frame) error {
	var request struct {
		ID int64 `json:"id"`
	}
	if frame.Type != gateway.TextFrame || json.Unmarshal(frame.Payload, &request) != nil || request.ID < 1 {
		return gateway.ErrDownstreamUnavailable
	}
	response, _ := json.Marshal(map[string]any{"id": request.ID, "result": map[string]any{"result": map[string]any{"type": "object", "value": map[string]any{"title": "phase4-release", "url": "https://example.test/"}}}})
	select {
	case s.frames <- gateway.Frame{Type: gateway.TextFrame, Payload: response}:
		return nil
	case <-s.done:
		return io.ErrClosedPipe
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *releaseCDPStream) Close(context.Context) error { s.close(); return nil }
func (s *releaseCDPStream) close()                      { s.once.Do(func() { close(s.done) }) }

func releaseLiveBrowserHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.TLS == nil || releasePeerAuthorizer(request.Context(), *request.TLS) != nil || request.Header.Get("Sec-WebSocket-Protocol") != releaseLivePrivateSubprotocol {
		http.Error(writer, "forbidden", http.StatusForbidden)
		return
	}
	reference := request.Header.Get("X-Sandbox-Browser-Reference")
	sessionID := request.Header.Get("X-Sandbox-Browser-Session")
	if !strings.HasPrefix(reference, "ref:browser-session:") || sessionID == "" || !strings.HasSuffix(reference, "."+sessionID) {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{releaseLivePrivateSubprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(32 << 10)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			kind, payload, err := connection.Read(ctx)
			if err != nil {
				return
			}
			if kind != websocket.MessageText || len(payload) > 32<<10 {
				return
			}
		}
	}()
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
	var sequence atomic.Uint32
	var timestamp atomic.Uint32
	for {
		select {
		case <-readDone:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			packet := &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 96, SequenceNumber: uint16(sequence.Add(1)), Timestamp: timestamp.Add(3000), SSRC: 0x50483431}, Payload: []byte{0x10, 0x00, 0x01}}
			payload, err := packet.Marshal()
			if err != nil || connection.Write(ctx, websocket.MessageBinary, payload) != nil {
				return
			}
		}
	}
}

var _ gateway.ReferenceResolver = (*releaseBrowserResolver)(nil)
var _ gateway.Stream = (*releaseCDPStream)(nil)
