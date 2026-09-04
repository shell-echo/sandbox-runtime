package caller

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// BrowserEdgeGrantPrefix lets the orchestrator prove that pre-upgrade probes
// never produced identity-bearing Gateway audit events.
const BrowserEdgeGrantPrefix = "grant-browser-edge-"

func browserRoundTrip(ctx context.Context, client *http.Client, config Config, handoff BrowserSessionHandoff, grantID string) error {
	expiresAt, err := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	if err != nil {
		return err
	}
	grantExpiry := time.Now().UTC().Add(2 * time.Minute)
	if !grantExpiry.Before(expiresAt) {
		grantExpiry = expiresAt
	}
	request := gatewayRequest{
		GrantID: grantID, CallerID: config.ControllerA.GatewayCallerID, TenantID: config.ControllerA.TenantID,
		SandboxID: handoff.SandboxID, BrowserSessionID: handoff.BrowserSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: grantExpiry,
		Bearer: config.ControllerA.GatewayToken,
	}
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, request)
	if err != nil {
		return gatewayDialError("Browser round trip", response, err)
	}
	defer connection.CloseNow()
	callCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	var version struct {
		Product string `json:"product"`
	}
	if err := browserCall(callCtx, connection, 1, "", "Browser.getVersion", nil, &version); err != nil || !strings.Contains(version.Product, "Chrome/151.0.7922.109") {
		return errors.Join(err, fmt.Errorf("Browser.getVersion = %#v", version))
	}
	if err := browserAllowedNavigation(callCtx, connection, "https://example.com/", "Example Domain"); err != nil {
		return err
	}
	return browserDeniedNavigation(callCtx, connection, "http://example.net/")
}

func verifyBrowserGatewayCapacity(ctx context.Context, client *http.Client, config Config, handoff BrowserSessionHandoff) error {
	expiresAt, err := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	if err != nil {
		return err
	}
	grantExpiry := time.Now().UTC().Add(time.Minute)
	if !grantExpiry.Before(expiresAt) {
		grantExpiry = expiresAt
	}
	primary, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL,
		browserGatewayRequest(config, handoff, "grant-browser-capacity-primary-1", grantExpiry))
	if err != nil {
		return gatewayDialError("primary Browser capacity connection", response, err)
	}
	defer primary.CloseNow()
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	if err := browserCall(callCtx, primary, 600, "", "Browser.getVersion", nil, nil); err != nil {
		cancel()
		return fmt.Errorf("establish primary Browser capacity connection: %w", err)
	}
	cancel()

	contender, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL,
		browserGatewayRequest(config, handoff, "grant-browser-capacity-contender-1", grantExpiry))
	if err != nil {
		return gatewayDialError("contending Browser capacity connection", response, err)
	}
	readCtx, readCancel := context.WithTimeout(ctx, 3*time.Second)
	_, _, readErr := contender.Read(readCtx)
	readContextErr := readCtx.Err()
	readCancel()
	contender.CloseNow()
	if readErr == nil {
		return errors.New("contending Browser connection remained open")
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(readContextErr, context.DeadlineExceeded) {
		return errors.New("contending Browser connection was not rejected by capacity")
	}

	callCtx, cancel = context.WithTimeout(ctx, 15*time.Second)
	if err := browserCall(callCtx, primary, 601, "", "Browser.getVersion", nil, nil); err != nil {
		cancel()
		return fmt.Errorf("capacity rejection interrupted the primary Browser connection: %w", err)
	}
	cancel()
	if err := primary.Close(websocket.StatusNormalClosure, "capacity release"); err != nil {
		return fmt.Errorf("close primary Browser capacity connection: %w", err)
	}

	var last error
	for attempt := 0; attempt < 20; attempt++ {
		replacement, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL,
			browserGatewayRequest(config, handoff, fmt.Sprintf("grant-browser-capacity-replacement-%d", attempt+1), grantExpiry))
		if err != nil {
			return gatewayDialError("replacement Browser capacity connection", response, err)
		}
		callCtx, cancel = context.WithTimeout(ctx, time.Second)
		last = browserCall(callCtx, replacement, 602, "", "Browser.getVersion", nil, nil)
		cancel()
		replacement.CloseNow()
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("Browser capacity was not released: %w", last)
}

func verifyBrowserGatewayEdgeLimits(ctx context.Context, client *http.Client, config Config, handoff BrowserSessionHandoff) error {
	if err := waitForDuration(ctx, 1100*time.Millisecond); err != nil {
		return err
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	if err != nil {
		return err
	}
	grantExpiry := time.Now().UTC().Add(time.Minute)
	if !grantExpiry.Before(expiresAt) {
		grantExpiry = expiresAt
	}

	const attempts = 16
	start := make(chan struct{})
	results := make(chan browserEdgeAttempt, attempts)
	for index := 0; index < attempts; index++ {
		go func(index int) {
			<-start
			request := browserGatewayRequest(config, handoff, fmt.Sprintf("%sburst-%02d", BrowserEdgeGrantPrefix, index+1), grantExpiry)
			request.Origin = "https://rejected-browser-origin.invalid"
			attemptCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			connection, response, err := gatewayConnect(attemptCtx, client, config.GatewayBaseURL, request)
			if connection != nil {
				_ = connection.CloseNow()
			}
			result := browserEdgeAttempt{err: err}
			if response != nil {
				result.status = response.StatusCode
				result.retryAfter = response.Header.Get("Retry-After")
				if response.Body != nil {
					_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
					_ = response.Body.Close()
				}
			}
			results <- result
		}(index)
	}
	close(start)

	forbidden, limited, maxRetrySeconds := 0, 0, int64(0)
	for index := 0; index < attempts; index++ {
		result := <-results
		if result.err == nil {
			return errors.New("wrong-origin Browser edge request was upgraded")
		}
		switch result.status {
		case http.StatusForbidden:
			if result.retryAfter != "" {
				return fmt.Errorf("ordinary origin rejection carried Retry-After %q", result.retryAfter)
			}
			forbidden++
		case http.StatusTooManyRequests:
			seconds, err := strconv.ParseInt(result.retryAfter, 10, 64)
			if err != nil || seconds < 1 || seconds > 60 {
				return fmt.Errorf("Browser edge Retry-After = %q", result.retryAfter)
			}
			if seconds > maxRetrySeconds {
				maxRetrySeconds = seconds
			}
			limited++
		default:
			return fmt.Errorf("wrong-origin Browser edge status = %d: %w", result.status, result.err)
		}
	}
	if forbidden == 0 || limited == 0 {
		return fmt.Errorf("Browser edge burst observed forbidden=%d limited=%d; want both", forbidden, limited)
	}
	if err := waitForDuration(ctx, time.Duration(maxRetrySeconds)*time.Second+150*time.Millisecond); err != nil {
		return err
	}
	recovery := browserGatewayRequest(config, handoff, BrowserEdgeGrantPrefix+"recovery", grantExpiry)
	recovery.Origin = "https://rejected-browser-origin.invalid"
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, recovery)
	if connection != nil {
		_ = connection.CloseNow()
		return errors.New("wrong-origin Browser recovery request was upgraded")
	}
	if response == nil {
		return fmt.Errorf("Browser edge recovery returned no response: %w", err)
	}
	if response.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
	}
	if response.StatusCode != http.StatusForbidden || response.Header.Get("Retry-After") != "" {
		return fmt.Errorf("Browser edge recovery status = %d retry=%q: %w", response.StatusCode, response.Header.Get("Retry-After"), err)
	}
	return nil
}

type browserEdgeAttempt struct {
	status     int
	retryAfter string
	err        error
}

func verifyBrowserGatewayTransportBounds(ctx context.Context, config Config) error {
	endpoint, err := url.Parse(config.GatewayBaseURL)
	if err != nil || endpoint.Host == "" {
		return errors.Join(err, errors.New("Browser Gateway endpoint is invalid"))
	}
	roots, err := loadGatewayRoots(config.CAFile)
	if err != nil {
		return err
	}

	legacy, err := dialGatewayTLS(ctx, endpoint.Host, roots, tls.VersionTLS12, tls.VersionTLS12, []string{"http/1.1"}, time.Second)
	if err == nil {
		_ = legacy.Close()
		return errors.New("Browser Gateway accepted TLS 1.2")
	}

	oversized, err := dialGatewayTLS(ctx, endpoint.Host, roots, tls.VersionTLS13, tls.VersionTLS13, []string{"h2", "http/1.1"}, 2*time.Second)
	if err != nil {
		return fmt.Errorf("connect Browser Gateway TLS 1.3: %w", err)
	}
	state := oversized.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" {
		_ = oversized.Close()
		return fmt.Errorf("Browser Gateway negotiated TLS=%x ALPN=%q", state.Version, state.NegotiatedProtocol)
	}
	request := "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Oversized: " + strings.Repeat("x", 32<<10) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(oversized, request); err != nil {
		_ = oversized.Close()
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(oversized), &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = oversized.Close()
		return fmt.Errorf("read oversized Browser Gateway rejection: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	_ = oversized.Close()
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		return fmt.Errorf("oversized Browser Gateway header status = %d, want 431", response.StatusCode)
	}

	slow, err := dialGatewayTLS(ctx, endpoint.Host, roots, tls.VersionTLS13, tls.VersionTLS13, []string{"http/1.1"}, 2*time.Second)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(slow, "GET /healthz HTTP/1.1\r\nHost: localhost"); err != nil {
		_ = slow.Close()
		return err
	}
	if err := slow.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		_ = slow.Close()
		return err
	}
	if _, err := slow.Read(make([]byte, 1)); err == nil {
		_ = slow.Close()
		return errors.New("slow Browser Gateway request header was not reclaimed")
	}
	_ = slow.Close()

	held := make([]net.Conn, 0, config.GatewayListenerLimit+4)
	defer func() {
		for _, connection := range held {
			_ = connection.Close()
		}
	}()
	for index := 0; index < config.GatewayListenerLimit+4; index++ {
		connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", endpoint.Host)
		if err != nil {
			return fmt.Errorf("fill Browser Gateway listener slot %d: %w", index+1, err)
		}
		held = append(held, connection)
	}
	if err := waitForDuration(ctx, 75*time.Millisecond); err != nil {
		return err
	}
	blocked, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", endpoint.Host)
	if err != nil {
		return fmt.Errorf("probe saturated Browser Gateway listener: %w", err)
	}
	blockedTLS := tls.Client(blocked, gatewayTLSConfig(roots, tls.VersionTLS13, tls.VersionTLS13, []string{"http/1.1"}))
	if err := blockedTLS.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		_ = blockedTLS.Close()
		return err
	}
	if err := blockedTLS.HandshakeContext(ctx); err == nil {
		_ = blockedTLS.Close()
		return errors.New("connection beyond Browser Gateway listener capacity completed TLS")
	}
	_ = blockedTLS.Close()
	for _, connection := range held {
		_ = connection.Close()
	}
	held = nil

	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: gatewayTLSConfig(roots, tls.VersionTLS13, tls.VersionTLS13, []string{"http/1.1"}),
		DisableKeepAlives: true, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	var health *http.Response
	for attempt := 0; attempt < 20; attempt++ {
		health, err = client.Get(config.GatewayBaseURL + "/healthz")
		if err == nil {
			break
		}
		if err := waitForDuration(ctx, 50*time.Millisecond); err != nil {
			return err
		}
	}
	if err != nil {
		return fmt.Errorf("Browser Gateway listener did not recover: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(health.Body, 4096))
	_ = health.Body.Close()
	if health.StatusCode != http.StatusOK {
		return fmt.Errorf("Browser Gateway recovery status = %d, want 200", health.StatusCode)
	}
	return nil
}

func loadGatewayRoots(path string) (*x509.CertPool, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Browser Gateway CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("Browser Gateway CA bundle is invalid")
	}
	return roots, nil
}

func dialGatewayTLS(ctx context.Context, address string, roots *x509.CertPool, minVersion, maxVersion uint16, protocols []string, timeout time.Duration) (*tls.Conn, error) {
	raw, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	connection := tls.Client(raw, gatewayTLSConfig(roots, minVersion, maxVersion, protocols))
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func gatewayTLSConfig(roots *x509.CertPool, minVersion, maxVersion uint16, protocols []string) *tls.Config {
	return &tls.Config{
		MinVersion: minVersion, MaxVersion: maxVersion, RootCAs: roots,
		ServerName: "localhost", NextProtos: append([]string(nil), protocols...),
	}
}

func waitForDuration(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func browserAllowedNavigation(ctx context.Context, connection *websocket.Conn, targetURL, expected string) error {
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		base := int64(10 + attempt*20)
		sessionID, err := browserPage(ctx, connection, base)
		if err != nil {
			return err
		}
		var navigation struct {
			ErrorText string `json:"errorText"`
		}
		err = browserCall(ctx, connection, base+4, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navigation)
		if err != nil {
			return err
		}
		if navigation.ErrorText != "" {
			last = fmt.Errorf("allowed Browser navigation failed: %s", navigation.ErrorText)
			if navigation.ErrorText == "net::ERR_CONNECTION_CLOSED" && attempt == 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(time.Second):
					continue
				}
			}
			return last
		}
		for id := base + 5; ; id++ {
			var evaluated struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			}
			err := browserCall(ctx, connection, id, sessionID, "Runtime.evaluate", map[string]any{
				"expression": "document.body ? document.body.innerText : ''", "returnByValue": true,
			}, &evaluated)
			if err == nil && strings.Contains(evaluated.Result.Value, expected) {
				return nil
			}
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), err)
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return last
}

func browserDeniedNavigation(ctx context.Context, connection *websocket.Conn, targetURL string) error {
	sessionID, err := browserPage(ctx, connection, 100)
	if err != nil {
		return err
	}
	var navigation struct {
		ErrorText string `json:"errorText"`
	}
	err = browserCall(ctx, connection, 104, sessionID, "Page.navigate", map[string]any{"url": targetURL}, &navigation)
	if err != nil {
		return fmt.Errorf("request denied Browser navigation result: %w", err)
	}
	if navigation.ErrorText == "" {
		return errors.New("navigation to denied Browser target succeeded")
	}
	return nil
}

func browserPage(ctx context.Context, connection *websocket.Conn, base int64) (string, error) {
	var created struct {
		TargetID string `json:"targetId"`
	}
	if err := browserCall(ctx, connection, base, "", "Target.createTarget", map[string]any{"url": "about:blank"}, &created); err != nil {
		return "", err
	}
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	if err := browserCall(ctx, connection, base+1, "", "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true}, &attached); err != nil || attached.SessionID == "" {
		return "", errors.Join(err, errors.New("Browser target returned no session ID"))
	}
	if err := browserCall(ctx, connection, base+2, attached.SessionID, "Page.enable", nil, nil); err != nil {
		return "", err
	}
	if err := browserCall(ctx, connection, base+3, attached.SessionID, "Runtime.enable", nil, nil); err != nil {
		return "", err
	}
	return attached.SessionID, nil
}

func browserCall(ctx context.Context, connection *websocket.Conn, id int64, sessionID, method string, params any, result any) error {
	request := map[string]any{"id": id, "method": method}
	if sessionID != "" {
		request["sessionId"] = sessionID
	}
	if params != nil {
		request["params"] = params
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := connection.Write(ctx, websocket.MessageText, encoded); err != nil {
		return err
	}
	for {
		messageType, payload, err := connection.Read(ctx)
		if err != nil {
			return err
		}
		if messageType != websocket.MessageText || len(payload) > 2<<20 {
			return errors.New("Browser Gateway returned an invalid bounded CDP frame")
		}
		var response struct {
			ID     int64           `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int64  `json:"code"`
				Message string `json:"message"`
			} `json:"error,omitempty"`
		}
		if err := json.Unmarshal(payload, &response); err != nil {
			return err
		}
		if response.ID != id {
			continue
		}
		if response.Error != nil {
			return fmt.Errorf("CDP %s failed: %d %s", method, response.Error.Code, response.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(response.Result, result)
	}
}

func verifyBrowserGatewayDenials(ctx context.Context, client *http.Client, config Config, handoff BrowserSessionHandoff) error {
	expiresAt, err := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
	if err != nil {
		return err
	}
	base := gatewayRequest{
		GrantID: "grant-browser-denied-1", CallerID: config.ControllerA.GatewayCallerID, TenantID: config.ControllerA.TenantID,
		SandboxID: handoff.SandboxID, BrowserSessionID: handoff.BrowserSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: expiresAt,
	}
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, base)
	if connection != nil {
		connection.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		return gatewayDialError("missing Browser Gateway bearer", response, err)
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}

	base.GrantID = "grant-browser-cross-tenant-1"
	base.Bearer = config.ControllerA.GatewayToken
	base.TenantID = config.ControllerB.TenantID
	connection, response, err = gatewayConnect(ctx, client, config.GatewayBaseURL, base)
	if err != nil {
		return gatewayDialError("cross-tenant Browser Gateway request", response, err)
	}
	defer connection.CloseNow()
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, _, err := connection.Read(readCtx); err == nil {
		return errors.New("cross-tenant Browser Gateway connection remained open")
	}
	return nil
}

func verifyBrowserGatewayExpiry(ctx context.Context, client *http.Client, config Config, handoff BrowserSessionHandoff) error {
	request := browserGatewayRequest(config, handoff, "grant-browser-expiry-1", time.Now().UTC().Add(750*time.Millisecond))
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, request)
	if err != nil {
		return gatewayDialError("Browser Gateway expiry", response, err)
	}
	defer connection.CloseNow()
	readCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for {
		if _, _, err := connection.Read(readCtx); err != nil {
			if errors.Is(readCtx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded) {
				return errors.New("Browser Gateway grant did not expire")
			}
			return nil
		}
	}
}

func verifyBrowserGatewayRevocation(ctx context.Context, client *http.Client, config Config, handoff BrowserSessionHandoff) error {
	const grantID = "grant-browser-revocation-1"
	request := browserGatewayRequest(config, handoff, grantID, time.Now().UTC().Add(time.Minute))
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, request)
	if err != nil {
		return gatewayDialError("Browser Gateway revocation", response, err)
	}
	defer connection.CloseNow()
	callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := browserCall(callCtx, connection, 500, "", "Browser.getVersion", nil, nil); err != nil {
		return err
	}
	revoke, err := http.NewRequestWithContext(ctx, http.MethodPost, config.GatewayBaseURL+"/v1/revoke/"+grantID, nil)
	if err != nil {
		return err
	}
	revoke.Header.Set("X-E2E-Admin-Token", config.GatewayAdminToken)
	result, err := client.Do(revoke)
	if err != nil {
		return err
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Browser Gateway revoke status = %d, want 204", result.StatusCode)
	}
	return waitForGatewayClose(ctx, 3*time.Second, func(readCtx context.Context) error {
		_, _, err := connection.Read(readCtx)
		return err
	})
}

func browserGatewayRequest(config Config, handoff BrowserSessionHandoff, grantID string, expiresAt time.Time) gatewayRequest {
	return gatewayRequest{
		GrantID: grantID, CallerID: config.ControllerA.GatewayCallerID, TenantID: config.ControllerA.TenantID,
		SandboxID: handoff.SandboxID, BrowserSessionID: handoff.BrowserSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: expiresAt,
		Bearer: config.ControllerA.GatewayToken,
	}
}
