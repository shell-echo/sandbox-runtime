package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
)

func TestDecodeInputRejectsNonCanonicalOrIncomplete(t *testing.T) {
	valid := input{Protocol: inputProtocol, RunID: strings.Repeat("a", 32),
		PlanDigest: "sha256:" + strings.Repeat("b", 64), VaultEndpoint: "https://vault.sandbox-runtime.test:8200",
		ClientPrivateKeyPEM: []byte("private"), OperatorToken: []byte("secret"),
		TokenExpiresAt: time.Now().UTC().Add(time.Minute)}
	canonical, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeInput(canonical); err != nil {
		t.Fatalf("canonical envelope rejected: %v", err)
	}
	cases := [][]byte{
		nil,
		append(bytes.Clone(canonical), '\n'),
		append(bytes.Clone(canonical), []byte("{}")...),
		bytes.Replace(canonical, []byte(`"protocol":`), []byte(`"unknown":1,"protocol":`), 1),
		bytes.Replace(canonical, []byte(`"protocol":`), []byte(`"protocol":"duplicate","protocol":`), 1),
		bytes.Repeat([]byte{'x'}, maxInputBytes+1),
	}
	for index, document := range cases {
		if _, err := decodeInput(document); err == nil {
			t.Fatalf("unsafe envelope %d accepted", index)
		}
	}
	invalid := valid
	invalid.OperatorToken = nil
	encoded, err := json.Marshal(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeInput(encoded); err == nil {
		t.Fatal("missing operator token accepted")
	}
}

func TestDecodeInputV2CannotDowngradeOrOmitExternalPostgres(t *testing.T) {
	value := input{Protocol: inputProtocolV2, RunID: strings.Repeat("a", 32),
		PlanDigest:          "sha256:" + strings.Repeat("b", 64),
		ClientPrivateKeyPEM: []byte("private"), OperatorToken: []byte("secret"),
		TokenExpiresAt:   time.Now().UTC().Add(time.Minute),
		ExternalPostgres: &phase6terminalcleanup.ExternalPostgresRecord{Protocol: phase6terminalcleanup.ExternalPostgresRecordProtocol}}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeInput(encoded); err != nil {
		t.Fatal("canonical v2 envelope rejected")
	}
	for name, mutate := range map[string]func(*input){
		"v1 with external":    func(v *input) { v.Protocol = inputProtocol },
		"v2 without external": func(v *input) { v.ExternalPostgres = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := value
			mutate(&changed)
			invalid, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeInput(invalid); err == nil {
				t.Fatal("mixed v1/v2 input accepted")
			}
		})
	}
}

func TestRunRejectsBoundedInputAndCancellationWithoutOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		reader io.Reader
		ctx    context.Context
	}{
		{"oversized", bytes.NewReader(bytes.Repeat([]byte{'x'}, maxInputBytes+1)), context.Background()},
		{"malformed", strings.NewReader(`{"protocol":"wrong"}`), context.Background()},
		{"cancelled", strings.NewReader("{}"), cancelledContext()},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			var stage cleanupStage
			if err := run(test.ctx, test.reader, &output); err == nil ||
				!errors.As(err, &stage) || stage == "" || output.Len() != 0 {
				t.Fatal("invalid input produced a success or a receipt")
			}
		})
	}
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
