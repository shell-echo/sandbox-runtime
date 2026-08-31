package caller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
)

type gatewayRequest struct {
	GrantID              string
	CallerID             string
	TenantID             string
	SandboxID            string
	RuntimeSessionID     string
	CapabilityProfileID  string
	HandoffReference     string
	ConnectionGeneration int64
	ExpiresAt            time.Time
	Bearer               string
}

func gatewayConnect(ctx context.Context, client *http.Client, baseURL string, request gatewayRequest) (*websocket.Conn, *http.Response, error) {
	endpoint, err := url.Parse(baseURL + "/v1/connect")
	if err != nil {
		return nil, nil, err
	}
	endpoint.Scheme = "wss"
	query := endpoint.Query()
	query.Set("grant_id", request.GrantID)
	query.Set("caller_id", request.CallerID)
	query.Set("tenant_id", request.TenantID)
	query.Set("sandbox_id", request.SandboxID)
	query.Set("runtime_session_id", request.RuntimeSessionID)
	query.Set("capability_profile_id", request.CapabilityProfileID)
	query.Set("handoff_reference", request.HandoffReference)
	query.Set("connection_generation", strconv.FormatInt(request.ConnectionGeneration, 10))
	query.Set("expires_at", request.ExpiresAt.UTC().Format(time.RFC3339Nano))
	endpoint.RawQuery = query.Encode()
	header := http.Header{"Origin": []string{"https://reference-caller.invalid"}}
	if request.Bearer != "" {
		header.Set("Authorization", "Bearer "+request.Bearer)
	}
	connection, response, err := websocket.Dial(ctx, endpoint.String(), &websocket.DialOptions{HTTPClient: client, HTTPHeader: header})
	return connection, response, err
}

func terminalRoundTrip(ctx context.Context, client *http.Client, config Config, handoff RuntimeSessionHandoff, grantID, command, expected string) error {
	request := gatewayRequest{
		GrantID: grantID, CallerID: config.ControllerA.GatewayCallerID, TenantID: config.ControllerA.TenantID,
		SandboxID: handoff.SandboxID, RuntimeSessionID: handoff.RuntimeSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: time.Now().UTC().Add(time.Minute),
		Bearer: config.ControllerA.GatewayToken,
	}
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, request)
	if err != nil {
		return gatewayDialError("terminal round trip", response, err)
	}
	defer connection.CloseNow()
	if err := connection.Write(ctx, websocket.MessageBinary, []byte(command)); err != nil {
		return err
	}
	return readUntil(ctx, connection, expected)
}

func verifyGatewayDenials(ctx context.Context, client *http.Client, config Config, handoff RuntimeSessionHandoff) error {
	base := gatewayRequest{
		GrantID: "grant-denied-1", CallerID: config.ControllerA.GatewayCallerID, TenantID: config.ControllerA.TenantID,
		SandboxID: handoff.SandboxID, RuntimeSessionID: handoff.RuntimeSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: time.Now().UTC().Add(time.Minute),
	}
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, base)
	if connection != nil {
		connection.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		return gatewayDialError("missing Gateway bearer", response, err)
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}

	base.GrantID = "grant-cross-tenant-1"
	base.Bearer = config.ControllerA.GatewayToken
	base.TenantID = config.ControllerB.TenantID
	connection, response, err = gatewayConnect(ctx, client, config.GatewayBaseURL, base)
	if err != nil {
		return gatewayDialError("cross-tenant Gateway request", response, err)
	}
	defer connection.CloseNow()
	readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, _, err := connection.Read(readCtx); err == nil {
		return errors.New("cross-tenant Gateway connection remained open")
	}
	return nil
}

func verifyGatewayExpiry(ctx context.Context, client *http.Client, config Config, handoff RuntimeSessionHandoff) error {
	request := gatewayRequest{
		GrantID: "grant-expiry-1", CallerID: config.ControllerA.GatewayCallerID, TenantID: config.ControllerA.TenantID,
		SandboxID: handoff.SandboxID, RuntimeSessionID: handoff.RuntimeSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: time.Now().UTC().Add(750 * time.Millisecond),
		Bearer: config.ControllerA.GatewayToken,
	}
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, request)
	if err != nil {
		return gatewayDialError("Gateway expiry", response, err)
	}
	defer connection.CloseNow()
	readCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	for {
		if _, _, err := connection.Read(readCtx); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return errors.New("Gateway grant did not expire")
			}
			return nil
		}
	}
}

func verifyGatewayRevocation(ctx context.Context, client *http.Client, config Config, handoff RuntimeSessionHandoff) error {
	const grantID = "grant-revocation-1"
	request := gatewayRequest{
		GrantID: grantID, CallerID: config.ControllerA.GatewayCallerID, TenantID: config.ControllerA.TenantID,
		SandboxID: handoff.SandboxID, RuntimeSessionID: handoff.RuntimeSessionID,
		CapabilityProfileID: handoff.CapabilityProfileID, HandoffReference: handoff.InternalEndpointReference,
		ConnectionGeneration: handoff.ConnectionGeneration, ExpiresAt: time.Now().UTC().Add(time.Minute),
		Bearer: config.ControllerA.GatewayToken,
	}
	connection, response, err := gatewayConnect(ctx, client, config.GatewayBaseURL, request)
	if err != nil {
		return gatewayDialError("Gateway revocation", response, err)
	}
	defer connection.CloseNow()
	if err := connection.Write(ctx, websocket.MessageBinary, []byte("printf 'revoke-ready\\n'\n")); err != nil {
		return err
	}
	if err := readUntil(ctx, connection, "revoke-ready"); err != nil {
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
	_, _ = io.Copy(io.Discard, io.LimitReader(result.Body, 4096))
	_ = result.Body.Close()
	if result.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Gateway revoke status = %d, want 204", result.StatusCode)
	}
	return waitForGatewayClose(ctx, 3*time.Second, func(readCtx context.Context) error {
		_, _, err := connection.Read(readCtx)
		return err
	})
}

func waitForGatewayClose(ctx context.Context, timeout time.Duration, read func(context.Context) error) error {
	readCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		if err := read(readCtx); err != nil {
			if errors.Is(readCtx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded) {
				return errors.New("revoked Gateway connection remained open")
			}
			if errors.Is(readCtx.Err(), context.Canceled) {
				return readCtx.Err()
			}
			return nil
		}
	}
}

func readUntil(ctx context.Context, connection *websocket.Conn, expected string) error {
	readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var received strings.Builder
	for received.Len() < 64<<10 {
		_, payload, err := connection.Read(readCtx)
		if err != nil {
			return fmt.Errorf("read terminal response: %w (received=%q)", err, received.String())
		}
		received.Write(payload)
		if strings.Contains(received.String(), expected) {
			return nil
		}
	}
	return errors.New("terminal response exceeded caller bound")
}

func gatewayDialError(name string, response *http.Response, err error) error {
	if response == nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return fmt.Errorf("%s status = %d: %w", name, response.StatusCode, err)
}
