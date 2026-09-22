package roleprocess

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

// cdpBackend is the Browser executor's only runtime dependency. It connects
// to an operator-provided private CDP endpoint and never creates containers,
// writes Provider state, or receives Provider credentials.
type cdpBackend struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

func newCDPBackend(processConfig *config.DataPlaneProcessConfig, endpoint string, timeout time.Duration) (*cdpBackend, error) {
	if processConfig == nil {
		return nil, errors.New("invalid Browser executor configuration")
	}
	client, err := executorHTTPClient(processConfig, endpoint)
	if err != nil {
		return nil, err
	}
	return &cdpBackend{url: endpoint, client: client, timeout: timeout}, nil
}

func newCDPBackendWithClient(endpoint string, timeout time.Duration, client *http.Client) (*cdpBackend, error) {
	if !validBackendURL(endpoint) || timeout < 100*time.Millisecond || timeout > 30*time.Second || client == nil {
		return nil, errors.New("invalid Browser executor configuration")
	}
	return &cdpBackend{url: endpoint, client: client, timeout: timeout}, nil
}

func (b *cdpBackend) Ready(ctx context.Context) error {
	if b == nil || b.client == nil || ctx == nil {
		return errors.New("Browser CDP backend is unavailable")
	}
	probeContext, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	connection, _, err := websocket.Dial(probeContext, b.url, &websocket.DialOptions{HTTPClient: b.client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		return errors.New("Browser CDP backend is unavailable")
	}
	defer connection.CloseNow()
	open, err := browserProbeOpen()
	if err != nil {
		return errors.New("Browser CDP backend is unavailable")
	}
	document, _ := executorprotocol.Encode(open)
	if err := connection.Write(probeContext, websocket.MessageText, document); err != nil {
		return errors.New("Browser CDP backend is unavailable")
	}
	kind, responseDocument, err := connection.Read(probeContext)
	var response executorprotocol.Response
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(responseDocument, &response) != nil || response.Validate() != nil || response.RequestID != open.RequestID || response.Status != executorprotocol.StatusAccepted {
		return errors.New("Browser CDP backend is unavailable")
	}
	return connection.Close(websocket.StatusNormalClosure, "probe")
}

func (b *cdpBackend) Open(ctx context.Context, open executorprotocol.Open) (ExecutorSession, error) {
	if b == nil || b.client == nil || ctx == nil {
		return nil, errors.New("Browser CDP backend is unavailable")
	}
	if err := open.Validate(time.Now().UTC()); err != nil {
		return nil, err
	}
	connection, _, err := websocket.Dial(ctx, b.url, &websocket.DialOptions{
		HTTPClient:   b.client,
		Subprotocols: []string{executorprotocol.ProtocolID},
	})
	if err != nil {
		return nil, errors.New("Browser CDP backend is unavailable")
	}
	document, err := executorprotocol.Encode(open)
	if err != nil || connection.Write(ctx, websocket.MessageText, document) != nil {
		connection.CloseNow()
		return nil, errors.New("Browser CDP backend rejected authority")
	}
	kind, responseDocument, err := connection.Read(ctx)
	var response executorprotocol.Response
	if err != nil || kind != websocket.MessageText || executorprotocol.Decode(responseDocument, &response) != nil || response.Validate() != nil || response.RequestID != open.RequestID || response.Status != executorprotocol.StatusAccepted {
		connection.CloseNow()
		return nil, errors.New("Browser CDP backend rejected authority")
	}
	return websocketSession{connection: connection}, nil
}

func browserProbeOpen() (executorprotocol.Open, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return executorprotocol.Open{}, err
	}
	now := time.Now().UTC()
	requestID := "probe-" + hex.EncodeToString(value)
	open := executorprotocol.Open{
		Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleBrowser, RequestID: requestID,
		TenantBindingDigest: handoff.TenantBindingDigestPrefix + strings.Repeat("0", 64),
		ProviderRevisionID:  "probe-provider", SandboxID: "probe-sandbox", RuntimeSessionID: "probe-session",
		CapabilityProfileID: "browser-v1", MediaProfileID: "browser-cdp-v1", ControlProfileID: "browser-control-v1",
		HandoffReference: "ref:browser-probe:" + hex.EncodeToString(value), ConnectionGeneration: 1, ConnectionEpoch: "probe-1",
		Fence: hex.EncodeToString(append(value, value...)), AuthorityExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano),
		HandoffExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano), Codec: "application/json",
	}
	open.HandoffDigest = executorprotocol.ReferenceDigest(open.HandoffReference)
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	if err := open.Validate(now); err != nil {
		return executorprotocol.Open{}, err
	}
	return open, nil
}
