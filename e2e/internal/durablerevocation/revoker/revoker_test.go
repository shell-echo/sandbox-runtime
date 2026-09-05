package revoker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const testRawGrant = "sensitive-raw-grant-value"

type recordingWriter struct {
	subject gateway.RevocationSubject
	err     error
}

func (w *recordingWriter) Revoke(_ context.Context, subject gateway.RevocationSubject) error {
	w.subject = subject
	return w.err
}

func TestRevokeUsesConfiguredSubjectAndWritesSanitizedControlLog(t *testing.T) {
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Millisecond)
	path := filepath.Join(t.TempDir(), "control.jsonl")
	log, err := openControlLog(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := &recordingWriter{}
	revoker := newRevoker(writer, nil, log, map[string]resolvedGrantBinding{
		"binding-a": {grantID: testRawGrant, expiresAt: expiresAt},
	})
	times := []time.Time{
		time.Date(2026, 9, 5, 1, 2, 3, 0, time.UTC),
		time.Date(2026, 9, 5, 1, 2, 3, 17_000_000, time.UTC),
	}
	revoker.clock = func() time.Time {
		result := times[0]
		times = times[1:]
		return result
	}

	response := revoker.Execute(context.Background(), wire.Command{
		Version: wire.ProtocolVersion, Sequence: 41, Action: wire.ActionRevoke,
		GrantBindingID: "binding-a", TimeoutMillis: 2000,
	})
	if !response.OK || response.Outcome != wire.OutcomeRevoked || response.ErrorCode != "" {
		t.Fatalf("response = %#v", response)
	}
	if writer.subject.GrantID != testRawGrant || !writer.subject.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("writer subject = %#v", writer.subject)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(content), &record); err != nil {
		t.Fatal(err)
	}
	if len(record) != 4 || record["sequence"] != float64(1) || record["type"] != "revoke_committed" ||
		record["timestamp"] != "2026-09-05T01:02:03.017Z" || record["duration_millis"] != float64(17) {
		t.Fatalf("control record = %#v", record)
	}
	for _, forbidden := range []string{testRawGrant, "binding-a", "redis", "127.0.0.1"} {
		if strings.Contains(string(content), forbidden) {
			t.Fatalf("control log leaked %q: %s", forbidden, content)
		}
	}
	if err := revoker.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRevokerReturnsStableErrorsWithoutLeakingDiagnostics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.jsonl")
	log, err := openControlLog(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := &recordingWriter{err: errors.New("redis://sensitive-user:sensitive-password@127.0.0.1:6379 private diagnostic")}
	revoker := newRevoker(writer, nil, log, map[string]resolvedGrantBinding{
		"binding-a": {grantID: testRawGrant, expiresAt: time.Now().UTC().Add(10 * time.Minute)},
	})
	defer revoker.Close()

	tests := []struct {
		command wire.Command
		want    string
	}{
		{command: wire.Command{Version: 99, Sequence: 1, Action: wire.ActionRevoke}, want: wire.ErrorInvalidCommand},
		{command: wire.Command{Version: 1, Sequence: 1, Action: wire.ActionRevoke, GrantBindingID: "missing", TimeoutMillis: 100}, want: wire.ErrorUnknownGrantBinding},
		{command: wire.Command{Version: 1, Sequence: 2, Action: wire.ActionRevoke, GrantBindingID: "binding-a", TimeoutMillis: 100}, want: wire.ErrorRevocationUnavailable},
	}
	for _, test := range tests {
		response := revoker.Execute(context.Background(), test.command)
		if response.OK || response.ErrorCode != test.want {
			t.Fatalf("response = %#v, want %s", response, test.want)
		}
		encoded, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{testRawGrant, "sensitive-password", "private diagnostic"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("response leaked %q: %s", forbidden, encoded)
			}
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("failed writes entered control evidence: %s", content)
	}
}

func TestCommittedRevokeWithControlLogFailureIsEvidenceFailure(t *testing.T) {
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	path := filepath.Join(t.TempDir(), "control.jsonl")
	log, err := openControlLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	writer := &recordingWriter{}
	revoker := newRevoker(writer, nil, log, map[string]resolvedGrantBinding{
		"binding-a": {grantID: testRawGrant, expiresAt: expiresAt},
	})
	response := revoker.Execute(context.Background(), wire.Command{
		Version: wire.ProtocolVersion, Sequence: 1, Action: wire.ActionRevoke,
		GrantBindingID: "binding-a", TimeoutMillis: 2000,
	})
	if writer.subject.GrantID != testRawGrant || !writer.subject.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("durable writer did not receive the configured subject: %#v", writer.subject)
	}
	if response.OK || response.Outcome != "" || response.ErrorCode != wire.ErrorControlLogUnavailable {
		t.Fatalf("response = %#v; committed mutation without evidence must fail the control command", response)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("failed control log append produced partial evidence: %s", content)
	}
}

func TestLoadConfigStrictValidation(t *testing.T) {
	config := validRevokerConfig(t)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(writePrivateConfig(t, encoded)); err != nil {
		t.Fatal(err)
	}

	invalidJSON := map[string][]byte{
		"unknown":          bytes.Replace(encoded, []byte(`"redis_url"`), []byte(`"unknown":true,"redis_url"`), 1),
		"duplicate nested": bytes.Replace(encoded, []byte(`"grant_id":"`+testRawGrant+`"`), []byte(`"grant_id":"`+testRawGrant+`","grant_id":"other"`), 1),
		"trailing":         append(append([]byte(nil), encoded...), []byte(` {}`)...),
	}
	for name, content := range invalidJSON {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writePrivateConfig(t, content)); err == nil {
				t.Fatal("LoadConfig accepted invalid JSON")
			}
		})
	}

	mutations := map[string]func(*wire.RevokerConfig){
		"external Redis":      func(config *wire.RevokerConfig) { config.RedisURL = "redis://example.com:6379/0" },
		"relative log":        func(config *wire.RevokerConfig) { config.ControlLogFile = "control.jsonl" },
		"unsafe policy":       func(config *wire.RevokerConfig) { config.RevocationPolicy.OperationTimeoutMillis = 101 },
		"missing owner":       func(config *wire.RevokerConfig) { config.GrantBindings[0].PrincipalID = "" },
		"noncanonical expiry": func(config *wire.RevokerConfig) { config.GrantBindings[0].ExpiresAt = "2026-09-05T01:02:03+00:00" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := config
			candidate.GrantBindings = append([]wire.GrantBinding(nil), config.GrantBindings...)
			mutate(&candidate)
			if _, err := prepareConfig(candidate); err == nil {
				t.Fatal("prepareConfig accepted unsafe config")
			}
		})
	}
}

func TestControlCommandCannotCarryRawGrantOrExpiry(t *testing.T) {
	for _, line := range []string{
		`{"version":1,"sequence":1,"action":"revoke","grant_binding_id":"binding-a","timeout_millis":100,"grant_id":"` + testRawGrant + `"}`,
		`{"version":1,"sequence":1,"action":"revoke","grant_binding_id":"binding-a","timeout_millis":100,"expires_at":"2026-09-05T01:02:03Z"}`,
		`{"version":1,"sequence":1,"sequence":2,"action":"shutdown"}`,
	} {
		if _, ok := decodeCommand([]byte(line)); ok {
			t.Fatalf("decodeCommand accepted forbidden control input: %s", line)
		}
	}
}

func validRevokerConfig(t *testing.T) wire.RevokerConfig {
	t.Helper()
	return wire.RevokerConfig{
		RedisURL: "redis://127.0.0.1:16379/0", RevocationNamespace: "durable-revocation-e2e",
		RevocationPolicy: wire.RevocationPolicy{
			MaxGrantLifetimeMillis: 900000, PollIntervalMillis: 100, OperationTimeoutMillis: 100,
		},
		ControlLogFile: filepath.Join(t.TempDir(), "control.jsonl"),
		GrantBindings: []wire.GrantBinding{{
			ID: "binding-a", GrantID: testRawGrant, PrincipalID: "principal-a", EndpointID: "endpoint-a",
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano),
		}},
	}
}

func writePrivateConfig(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revoker.json")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
