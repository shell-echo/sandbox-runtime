package orchestrator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	downstreamcaller "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
)

const downstreamCDPMaxPayloadBytes = 64 << 10

var downstreamCDPTargetPattern = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)

type downstreamCDPClient struct {
	caller       *downstreamCallerProcess
	connectionID string
	nextID       uint64
}

type downstreamCDPEnvelope struct {
	ID        uint64           `json:"id"`
	Result    json.RawMessage  `json:"result,omitempty"`
	Error     *downstreamError `json:"error,omitempty"`
	SessionID string           `json:"sessionId,omitempty"`
}

type downstreamError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func newDownstreamCDPClient(caller *downstreamCallerProcess, connectionID string) (*downstreamCDPClient, error) {
	if caller == nil || !downstreamLogicalName(connectionID) {
		return nil, errors.New("invalid downstream CDP client")
	}
	return &downstreamCDPClient{caller: caller, connectionID: connectionID}, nil
}

func (c *downstreamCDPClient) browserVersion(ctx context.Context, timeout time.Duration) error {
	_, err := c.call(ctx, "Browser.getVersion", nil, "", timeout)
	return err
}

func (c *downstreamCDPClient) createTarget(ctx context.Context, timeout time.Duration) (string, error) {
	result, err := c.call(ctx, "Target.createTarget", struct {
		URL string `json:"url"`
	}{URL: "about:blank"}, "", timeout)
	if err != nil {
		return "", err
	}
	var value struct {
		TargetID string `json:"targetId"`
	}
	if err := decodeDownstreamCDPObject(result, &value); err != nil || !downstreamCDPTargetPattern.MatchString(value.TargetID) {
		return "", errors.New("invalid downstream CDP target response")
	}
	return value.TargetID, nil
}

func (c *downstreamCDPClient) attachTarget(ctx context.Context, targetID string, timeout time.Duration) (string, error) {
	if !downstreamCDPTargetPattern.MatchString(targetID) {
		return "", errors.New("invalid downstream CDP target")
	}
	result, err := c.call(ctx, "Target.attachToTarget", struct {
		TargetID string `json:"targetId"`
		Flatten  bool   `json:"flatten"`
	}{TargetID: targetID, Flatten: true}, "", timeout)
	if err != nil {
		return "", err
	}
	var value struct {
		SessionID string `json:"sessionId"`
	}
	if err := decodeDownstreamCDPObject(result, &value); err != nil || !downstreamCDPOpaque(value.SessionID) {
		return "", errors.New("invalid downstream CDP session response")
	}
	return value.SessionID, nil
}

func (c *downstreamCDPClient) evaluateString(
	ctx context.Context,
	sessionID string,
	expression string,
	timeout time.Duration,
) (string, error) {
	result, err := c.call(ctx, "Runtime.evaluate", downstreamEvaluateParameters{
		Expression: expression, ReturnByValue: true, AwaitPromise: true,
	}, sessionID, timeout)
	if err != nil {
		return "", err
	}
	var value struct {
		Result struct {
			Type  string          `json:"type"`
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails,omitempty"`
	}
	if err := decodeDownstreamCDPObject(result, &value); err != nil || len(value.ExceptionDetails) != 0 ||
		value.Result.Type != "string" || len(value.Result.Value) == 0 {
		return "", errors.New("invalid downstream CDP evaluation response")
	}
	var resultString string
	if err := json.Unmarshal(value.Result.Value, &resultString); err != nil || !downstreamCDPText(resultString, 4096) {
		return "", errors.New("invalid downstream CDP evaluation value")
	}
	return resultString, nil
}

// prepareEvaluation reserves a fresh CDP id and returns one complete caller
// command. Queue scenarios use this to put an exact mutation on a suspended
// Gateway without bypassing the independent caller process.
func (c *downstreamCDPClient) prepareEvaluation(
	sessionID string,
	expression string,
	action string,
	timeout time.Duration,
) (downstreamcaller.Command, int, error) {
	return c.prepare("Runtime.evaluate", downstreamEvaluateParameters{
		Expression: expression, ReturnByValue: true, AwaitPromise: true,
	}, sessionID, action, timeout)
}

type downstreamEvaluateParameters struct {
	Expression    string `json:"expression"`
	ReturnByValue bool   `json:"returnByValue"`
	AwaitPromise  bool   `json:"awaitPromise"`
}

func (c *downstreamCDPClient) call(
	ctx context.Context,
	method string,
	params any,
	sessionID string,
	timeout time.Duration,
) (json.RawMessage, error) {
	command, _, err := c.prepare(method, params, sessionID, downstreamcaller.ActionCallCDP, timeout)
	if err != nil {
		return nil, err
	}
	response, err := c.caller.request(ctx, command)
	if err != nil || !response.OK || response.Outcome != downstreamcaller.OutcomeCompleted || response.ErrorCode != "" ||
		response.MessageType != downstreamcaller.MessageText || response.PayloadBase64 == "" {
		return nil, errors.New("downstream CDP call failed")
	}
	payload, err := base64.StdEncoding.DecodeString(response.PayloadBase64)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != response.PayloadBase64 || len(payload) == 0 || len(payload) > downstreamCDPMaxPayloadBytes {
		return nil, errors.New("invalid downstream CDP response encoding")
	}
	return decodeDownstreamCDPResponse(payload, c.nextID)
}

func (c *downstreamCDPClient) prepare(
	method string,
	params any,
	sessionID string,
	action string,
	timeout time.Duration,
) (downstreamcaller.Command, int, error) {
	if c == nil || c.caller == nil || !downstreamLogicalName(c.connectionID) || !downstreamCDPMethod(method) ||
		(sessionID != "" && !downstreamCDPOpaque(sessionID)) || timeout < 25*time.Millisecond || timeout > 60*time.Second ||
		(action != downstreamcaller.ActionCallCDP && action != downstreamcaller.ActionQueueCDP) || c.nextID == ^uint64(0) {
		return downstreamcaller.Command{}, 0, errors.New("invalid downstream CDP request")
	}
	c.nextID++
	envelope := struct {
		ID        uint64 `json:"id"`
		Method    string `json:"method"`
		Params    any    `json:"params,omitempty"`
		SessionID string `json:"sessionId,omitempty"`
	}{ID: c.nextID, Method: method, Params: params, SessionID: sessionID}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) == 0 || len(payload) > downstreamCDPMaxPayloadBytes {
		return downstreamcaller.Command{}, 0, errors.New("encode downstream CDP request")
	}
	return downstreamcaller.Command{
		Action: action, ConnectionID: c.connectionID, MessageType: downstreamcaller.MessageText,
		PayloadBase64: base64.StdEncoding.EncodeToString(payload), TimeoutMillis: timeout.Milliseconds(),
	}, len(payload), nil
}

func decodeDownstreamCDPResponse(payload []byte, requestID uint64) (json.RawMessage, error) {
	var response downstreamCDPEnvelope
	if err := decodeDownstreamCDPObject(payload, &response); err != nil || response.ID != requestID ||
		response.Error != nil || len(response.Result) == 0 || bytes.Equal(bytes.TrimSpace(response.Result), []byte("null")) ||
		(response.SessionID != "" && !downstreamCDPOpaque(response.SessionID)) {
		return nil, errors.New("invalid downstream CDP response")
	}
	return append(json.RawMessage(nil), response.Result...), nil
}

func decodeDownstreamCDPObject(payload []byte, destination any) error {
	if len(payload) == 0 || len(payload) > downstreamCDPMaxPayloadBytes || destination == nil || !downstreamUniqueJSON(payload) {
		return errors.New("invalid downstream CDP document")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid downstream CDP document")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("invalid downstream CDP document")
	}
	return nil
}

func downstreamUniqueJSON(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if !downstreamUniqueJSONValue(decoder) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func downstreamUniqueJSONValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, ok := func() (string, bool) {
				value, err := decoder.Token()
				key, ok := value.(string)
				return key, err == nil && ok
			}()
			if !ok || seen[key] || !downstreamUniqueJSONValue(decoder) {
				return false
			}
			seen[key] = true
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !downstreamUniqueJSONValue(decoder) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func downstreamCDPMethod(value string) bool {
	switch value {
	case "Browser.getVersion", "Target.createTarget", "Target.attachToTarget", "Runtime.evaluate":
		return true
	default:
		return false
	}
}

func downstreamCDPOpaque(value string) bool {
	return downstreamCDPText(value, 256) && !strings.ContainsAny(value, " \t\r\n")
}

func downstreamLogicalName(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func downstreamCDPText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (e downstreamError) String() string {
	return fmt.Sprintf("CDP error %d", e.Code)
}
