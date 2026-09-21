//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/internal/executorprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/handoff"
)

func runBrowserExecutorScenarios(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	primaryOpen := newBrowserOpen(t, "normal", time.Minute)
	primary, response := dialBrowserExecutor(t, ctx, environment, primaryOpen)
	if response.Status != executorprotocol.StatusAccepted {
		primary.CloseNow()
		t.Fatalf("Browser executor normal attach response=%#v", response)
	}
	if err := primary.Write(ctx, websocket.MessageText, []byte(`{"id":1,"method":"Browser.getVersion"}`)); err != nil {
		primary.CloseNow()
		t.Fatal(err)
	}
	messageType, payload, err := primary.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		primary.CloseNow()
		t.Fatalf("Browser.getVersion frame=%v err=%v", messageType, err)
	}
	var version struct {
		ID     int `json:"id"`
		Result struct {
			Product string `json:"product"`
		} `json:"result"`
	}
	if json.Unmarshal(payload, &version) != nil || version.ID != 1 || !strings.HasPrefix(version.Result.Product, "Chrome/151.") {
		primary.CloseNow()
		t.Fatalf("unexpected real Browser CDP response: %s", payload)
	}

	capacityOpen := newBrowserOpen(t, "capacity", time.Minute)
	capacity, capacityResponse := dialBrowserExecutor(t, ctx, environment, capacityOpen)
	capacity.CloseNow()
	if capacityResponse.Status != executorprotocol.StatusRejected {
		primary.CloseNow()
		t.Fatalf("Browser executor capacity response=%#v", capacityResponse)
	}
	_ = primary.Close(websocket.StatusNormalClosure, "normal Browser scenario complete")

	replay, replayResponse := dialBrowserExecutor(t, ctx, environment, primaryOpen)
	replay.CloseNow()
	if replayResponse.Status != executorprotocol.StatusRejected {
		t.Fatalf("Browser executor replay response=%#v", replayResponse)
	}

	expiredOpen := newBrowserOpen(t, "expired", -time.Second)
	expired, expiredResponse := dialBrowserExecutor(t, ctx, environment, expiredOpen)
	expired.CloseNow()
	if expiredResponse.Status != executorprotocol.StatusRejected {
		t.Fatalf("Browser executor expired authority response=%#v", expiredResponse)
	}

	driftOpen := newBrowserOpen(t, "drift", time.Minute)
	driftOpen.ConnectionGeneration++
	drift, driftResponse := dialBrowserExecutor(t, ctx, environment, driftOpen)
	drift.CloseNow()
	if driftResponse.Status != executorprotocol.StatusRejected {
		t.Fatalf("Browser executor generation drift response=%#v", driftResponse)
	}

	shortOpen := newBrowserOpen(t, "expiry-close", 1500*time.Millisecond)
	short, shortResponse := dialBrowserExecutor(t, ctx, environment, shortOpen)
	if shortResponse.Status != executorprotocol.StatusAccepted {
		short.CloseNow()
		t.Fatalf("Browser executor short authority response=%#v", shortResponse)
	}
	readContext, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if _, _, err := short.Read(readContext); err == nil {
		short.CloseNow()
		t.Fatal("Browser executor remained open after authority expiry")
	}
	short.CloseNow()
}

func newBrowserOpen(t *testing.T, label string, validity time.Duration) executorprotocol.Open {
	t.Helper()
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(random)
	now := time.Now().UTC()
	open := executorprotocol.Open{
		Protocol: executorprotocol.ProtocolID, Role: executorprotocol.RoleBrowser,
		RequestID:            "phase6-browser-" + label + "-" + suffix,
		TenantBindingDigest:  handoff.TenantBindingDigestPrefix + strings.Repeat("b", 64),
		ProviderRevisionID:   providerRevision,
		SandboxID:            gateSandboxID,
		RuntimeSessionID:     "browser-session-phase6",
		CapabilityProfileID:  "browser-v1",
		MediaProfileID:       "browser-cdp-v1",
		ControlProfileID:     "browser-control-v1",
		HandoffReference:     "ref:browser-session:" + suffix,
		ConnectionGeneration: 1,
		ConnectionEpoch:      "browser-epoch-1",
		Fence:                strings.Repeat("c", handoff.MinFenceBytes),
		AuthorityExpiresAt:   now.Add(validity).Format(time.RFC3339Nano),
		HandoffExpiresAt:     now.Add(validity).Format(time.RFC3339Nano),
		Codec:                "application/json",
	}
	open.HandoffDigest = executorprotocol.ReferenceDigest(open.HandoffReference)
	open.AuthorityDigest = open.CalculateAuthorityDigest()
	open.RequestDigest = open.CalculateRequestDigest()
	return open
}

func dialBrowserExecutor(t *testing.T, ctx context.Context, environment *gateEnvironment, open executorprotocol.Open) (*websocket.Conn, executorprotocol.Response) {
	t.Helper()
	client := environment.tls.ca.client("browser-role.phase6.test", mustLoadCertificate(t, environment.tls.providerExecutorCert, environment.tls.providerExecutorKey))
	connection, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://127.0.0.1:%d/executor", environment.ports.browser), &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{executorprotocol.ProtocolID}})
	if err != nil {
		t.Fatal(err)
	}
	document, err := executorprotocol.Encode(open)
	if err != nil {
		connection.CloseNow()
		t.Fatal(err)
	}
	if err := connection.Write(ctx, websocket.MessageText, document); err != nil {
		connection.CloseNow()
		t.Fatal(err)
	}
	messageType, responseDocument, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		connection.CloseNow()
		t.Fatalf("Browser executor handshake frame=%v err=%v", messageType, err)
	}
	var response executorprotocol.Response
	if executorprotocol.Decode(responseDocument, &response) != nil || response.Validate() != nil {
		connection.CloseNow()
		t.Fatalf("invalid Browser executor response: %s", responseDocument)
	}
	return connection, response
}

func runGuestReconnectScenario(t *testing.T, environment *gateEnvironment) {
	t.Helper()
	connections, healthResponses, connected := environment.guest.snapshot()
	if !connected || connections < 1 || healthResponses < 1 {
		t.Fatal("Guest did not establish its initial authenticated graph")
	}
	environment.guest.setAvailable(false)
	waitHTTPStatus(t, environment.roles["guest"], http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.guestProbe), http.StatusServiceUnavailable, 10*time.Second)
	environment.guest.setAvailable(true)
	waitHTTPStatus(t, environment.roles["guest"], http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.guestProbe), http.StatusNoContent, 10*time.Second)
	waitFor(t, 10*time.Second, "Guest bounded reconnect and health", func() bool {
		newConnections, newHealthResponses, newConnected := environment.guest.snapshot()
		return newConnected && newConnections > connections && newHealthResponses > healthResponses
	})
}

func runProviderDependencyLossScenario(t *testing.T, ctx context.Context, environment *gateEnvironment) {
	t.Helper()
	pauseContainer(t, ctx, environment.providerDB.container, true)
	waitHTTPStatus(t, environment.roles["provider"], http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.providerProbe), http.StatusServiceUnavailable, 10*time.Second)
	pauseContainer(t, ctx, environment.providerDB.container, false)
	waitHTTPStatus(t, environment.roles["provider"], http.DefaultClient, fmt.Sprintf("http://127.0.0.1:%d/readyz", environment.ports.providerProbe), http.StatusNoContent, 20*time.Second)
}

func mustLoadCertificate(t *testing.T, certificatePath, privateKeyPath string) tls.Certificate {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certificatePath, privateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
