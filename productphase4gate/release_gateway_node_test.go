//go:build phase4browsergate

package productphase4gate

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	recordinglocal "github.com/shell-echo/sandbox-runtime/product/adapter/recording/local"
)

const releaseLivePrivateSubprotocol = "sandbox-browser-live-private.v1"

func runReleaseGatewayNode(config nodeConfig) error { //nolint:cyclop
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, config.DSN)
	if err != nil {
		return err
	}
	defer pool.Close()
	store, err := productpostgres.New(pool, 3*time.Second)
	if err != nil {
		return err
	}
	grantKey, err := base64.RawStdEncoding.DecodeString(config.GrantKey)
	if err != nil {
		return err
	}
	grants, err := productpostgres.NewGrantRepository(store, "phase4-release-grant", grantKey)
	if err != nil {
		return err
	}
	audit, err := productpostgres.NewGatewayAuditRepository(store, product.CryptoIDGenerator{})
	if err != nil {
		return err
	}
	redisClient := releaseRedisClient(config.RedisAddress)
	defer redisClient.Close()
	capacity, err := releaseCapacity(redisClient)
	if err != nil {
		return err
	}
	if err := capacity.Verify(ctx); err != nil {
		return err
	}
	privateClient := mutualTLSClientFromConfig(config.CACertificate, config.GatewayCert, config.GatewayKey, "phase4-provider")
	if privateClient == nil {
		return errors.New("create private Browser client")
	}
	privateResolver, err := productgateway.NewPrivateBrowserResolver(productgateway.PrivateBrowserResolverOptions{
		Origin: "wss://" + config.ProviderAddress + "/private/browser", HTTPClient: privateClient, MaxMessageBytes: 32 << 10,
	})
	if err != nil {
		return err
	}
	automation, err := productgateway.NewBrowserAutomationHandler(productgateway.BrowserAutomationOptions{
		Grants: grants, FencedResolver: privateResolver, Audit: audit, Capacity: capacity,
		OriginPatterns: []string{"product.example.test"}, MaxMessageBytes: 32 << 10, MaxPendingActions: 4,
		AuthorityPollInterval: 20 * time.Millisecond, MaxReconnects: 2, ReconnectBackoff: 20 * time.Millisecond,
		MaxConnections: 8, MaxConnectionsPerSession: 1,
	})
	if err != nil {
		return err
	}
	recordingKey, err := base64.RawStdEncoding.DecodeString(config.RecordingKey)
	if err != nil {
		return err
	}
	content, err := recordinglocal.New(config.RecordingRoot, recordingKey)
	if err != nil {
		return err
	}
	redactor, err := product.NewPatternRedactor([]string{"SECRET"})
	if err != nil {
		return err
	}
	recordingService, err := product.NewRecordingService(store, content, redactor, product.CryptoIDGenerator{}, nil)
	if err != nil {
		return err
	}
	recorder, err := productgateway.NewProductBrowserLiveRecorder(recordingService, 3600)
	if err != nil {
		return err
	}
	live, err := productgateway.NewBrowserLiveHandler(productgateway.BrowserLiveOptions{
		Grants: grants, Media: &releaseLiveNetworkSource{client: privateClient, target: "wss://" + config.ProviderAddress + "/private/live"},
		Policy: releaseBrowserPolicySource{}, Transfers: releaseDenyTransfers{}, Audit: audit, Recorder: recorder,
		AllowedOrigins: []string{releaseOrigin}, MaxSignalingBytes: 96 << 10, MaxRTPQueue: 8, MaxInputQueue: 8,
		MaxPeers: 8, MaxPeersPerSession: 1, AuthorityPollInterval: 20 * time.Millisecond,
		ConnectionTimeout: 5 * time.Second, DisconnectGrace: 300 * time.Millisecond,
		MinKeyframeInterval: 100 * time.Millisecond, AllowHostCandidatesForTests: true,
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/browser/connect", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			automation.ServeHTTP(writer, request)
			return
		}
		live.ServeHTTP(writer, request)
	})
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || pool.Ping(request.Context()) != nil || redisClient.Ping(request.Context()).Err() != nil {
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusOK)
	})
	tlsConfig, err := serverTLSConfig(config.EdgeCert, config.EdgeKey, "", false)
	if err != nil {
		return err
	}
	return serveUntilSignal(config.GatewayAddress, mux, tlsConfig)
}

func releaseCapacity(client *goredis.Client) (*rediscapacity.Capacity, error) {
	return rediscapacity.New(rediscapacity.Options{
		Client: client, Namespace: "product-phase4-release", MaxTotal: 8, MaxPerTenant: 8, MaxPerSession: 1,
		LeaseTTL: 2 * time.Second, RenewInterval: 400 * time.Millisecond, RenewalSafetyMargin: 500 * time.Millisecond, OperationTimeout: 200 * time.Millisecond,
	})
}

type releaseBrowserPolicySource struct{}

func (releaseBrowserPolicySource) CurrentBrowserPolicy(context.Context, product.GatewayBinding) (product.BrowserPolicy, error) {
	return product.BrowserPolicy{Revision: 1, Input: product.BrowserInputPolicy{Keyboard: true, Pointer: true}}, nil
}

type releaseDenyTransfers struct{}

func (releaseDenyTransfers) AuthorizeBrowserTransfer(context.Context, product.GatewayBinding, product.BrowserPolicyAction) error {
	return product.ErrForbidden
}

type releaseLiveNetworkSource struct {
	client *http.Client
	target string
}

func (s *releaseLiveNetworkSource) Open(ctx context.Context, binding product.GatewayBinding, video productgateway.BrowserLiveVideoPolicy) (productgateway.BrowserLiveMediaSession, error) {
	if s == nil || s.client == nil || binding.HandoffReference == "" {
		return nil, product.ErrStoreUnavailable
	}
	header := http.Header{}
	header.Set("X-Sandbox-Browser-Reference", binding.HandoffReference)
	header.Set("X-Sandbox-Browser-Session", binding.SessionID)
	header.Set("X-Sandbox-Video-Policy", releaseJSON(video))
	connection, _, err := websocket.Dial(ctx, s.target, &websocket.DialOptions{
		HTTPClient: s.client, HTTPHeader: header, Subprotocols: []string{releaseLivePrivateSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	if connection.Subprotocol() != releaseLivePrivateSubprotocol {
		_ = connection.CloseNow()
		return nil, product.ErrStoreUnavailable
	}
	connection.SetReadLimit(32 << 10)
	return &releaseLiveNetworkSession{connection: connection}, nil
}

type releaseLiveNetworkSession struct {
	connection *websocket.Conn
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

func (s *releaseLiveNetworkSession) ReadRTP(ctx context.Context) ([]byte, error) {
	kind, payload, err := s.connection.Read(ctx)
	if err != nil || kind != websocket.MessageBinary || len(payload) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, product.ErrStoreUnavailable
	}
	return append([]byte(nil), payload...), nil
}

func (s *releaseLiveNetworkSession) HandleInput(ctx context.Context, input productgateway.BrowserLiveInput) (productgateway.BrowserLiveInputResult, error) {
	payload, err := json.Marshal(map[string]any{"type": "input", "sequence": input.Sequence, "kind": input.Action.Kind, "event": input.Event})
	if err != nil {
		return productgateway.BrowserLiveInputResult{}, product.ErrInvalid
	}
	if err := s.write(ctx, payload); err != nil {
		return productgateway.BrowserLiveInputResult{}, err
	}
	return productgateway.BrowserLiveInputResult{}, nil
}

func (s *releaseLiveNetworkSession) UpdateVideoPolicy(ctx context.Context, video productgateway.BrowserLiveVideoPolicy) error {
	payload, _ := json.Marshal(map[string]any{"type": "resize", "video": video})
	return s.write(ctx, payload)
}

func (s *releaseLiveNetworkSession) RequestKeyframe(ctx context.Context) error {
	return s.write(ctx, []byte(`{"type":"keyframe"}`))
}

func (s *releaseLiveNetworkSession) write(ctx context.Context, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.connection.Write(ctx, websocket.MessageText, payload); err != nil {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (s *releaseLiveNetworkSession) Close() error {
	var result error
	s.closeOnce.Do(func() { result = s.connection.Close(websocket.StatusNormalClosure, "closed") })
	return result
}

func releaseJSON(value any) string {
	document, _ := json.Marshal(value)
	return string(document)
}

func releasePeerAuthorizer(_ context.Context, state tls.ConnectionState) error {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != "phase4-gateway" {
		return gateway.ErrDownstreamUnavailable
	}
	return nil
}

var _ product.BrowserPolicySource = releaseBrowserPolicySource{}
var _ productgateway.BrowserLiveTransferAuthority = releaseDenyTransfers{}
var _ productgateway.BrowserLiveMediaSource = (*releaseLiveNetworkSource)(nil)
var _ productgateway.BrowserLiveMediaSession = (*releaseLiveNetworkSession)(nil)
