package orchestrator

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	downstreamcaller "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
)

func TestDownstreamCDPPrepareUsesFreshIDsAndCompleteBoundedPayloads(t *testing.T) {
	client := &downstreamCDPClient{caller: &downstreamCallerProcess{}, connectionID: "connection-a"}
	command, size, err := client.prepareEvaluation("session-opaque", `globalThis.marker = "first"`, downstreamcaller.ActionQueueCDP, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if command.Action != downstreamcaller.ActionQueueCDP || command.ConnectionID != "connection-a" ||
		command.MessageType != downstreamcaller.MessageText || command.TimeoutMillis != 1000 || size < 1 {
		t.Fatalf("prepared command = %#v, size=%d", command, size)
	}
	payload, err := base64.StdEncoding.DecodeString(command.PayloadBase64)
	if err != nil || len(payload) != size {
		t.Fatalf("payload = %q, %v", payload, err)
	}
	var envelope struct {
		ID        uint64                       `json:"id"`
		Method    string                       `json:"method"`
		Params    downstreamEvaluateParameters `json:"params"`
		SessionID string                       `json:"sessionId"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil || envelope.ID != 1 || envelope.Method != "Runtime.evaluate" ||
		envelope.SessionID != "session-opaque" || envelope.Params.Expression == "" || !envelope.Params.ReturnByValue || !envelope.Params.AwaitPromise {
		t.Fatalf("CDP envelope = %#v, %v", envelope, err)
	}
	second, _, err := client.prepare("Browser.getVersion", nil, "", downstreamcaller.ActionCallCDP, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(second.PayloadBase64)
	if err != nil || !strings.Contains(string(decoded), `"id":2`) || strings.Contains(string(decoded), "sessionId") {
		t.Fatalf("second payload = %q, %v", decoded, err)
	}
}

func TestDecodeDownstreamCDPResponseIsStrictAndCorrelated(t *testing.T) {
	valid := []byte(`{"id":7,"result":{"targetId":"0123456789abcdef0123456789abcdef"}}`)
	result, err := decodeDownstreamCDPResponse(valid, 7)
	if err != nil || !strings.Contains(string(result), "targetId") {
		t.Fatalf("valid response = %s, %v", result, err)
	}
	for name, payload := range map[string][]byte{
		"wrong id":       []byte(`{"id":8,"result":{}}`),
		"error":          []byte(`{"id":7,"error":{"code":-1,"message":"failed"}}`),
		"unknown":        []byte(`{"id":7,"result":{},"private":"value"}`),
		"duplicate":      []byte(`{"id":7,"id":7,"result":{}}`),
		"missing result": []byte(`{"id":7}`),
		"null result":    []byte(`{"id":7,"result":null}`),
		"trailing":       append(append([]byte(nil), valid...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeDownstreamCDPResponse(payload, 7); err == nil || strings.Contains(err.Error(), "value") || strings.Contains(err.Error(), "failed") {
				t.Fatalf("decode error = %v", err)
			}
		})
	}
}

func TestDownstreamCDPRequestValidationFailsClosed(t *testing.T) {
	client := &downstreamCDPClient{caller: &downstreamCallerProcess{}, connectionID: "connection-a"}
	for _, test := range []struct {
		method, session, action string
		timeout                 time.Duration
	}{
		{method: "Page.navigate", action: downstreamcaller.ActionCallCDP, timeout: time.Second},
		{method: "Browser.getVersion", session: "bad session", action: downstreamcaller.ActionCallCDP, timeout: time.Second},
		{method: "Browser.getVersion", action: "write", timeout: time.Second},
		{method: "Browser.getVersion", action: downstreamcaller.ActionCallCDP, timeout: time.Millisecond},
	} {
		if _, _, err := client.prepare(test.method, nil, test.session, test.action, test.timeout); err == nil {
			t.Fatalf("invalid request accepted: %#v", test)
		}
	}
	if _, err := newDownstreamCDPClient(nil, "connection"); err == nil {
		t.Fatal("nil caller accepted")
	}
}
