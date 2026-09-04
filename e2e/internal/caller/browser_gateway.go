package caller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

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
