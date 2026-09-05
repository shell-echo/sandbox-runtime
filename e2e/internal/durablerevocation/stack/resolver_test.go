package stack

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
)

func TestExactResolverUsesRFC6455EchoAndMinimalObservations(t *testing.T) {
	config := validConfig(t)
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	writer, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver := newExactResolver(config.Endpoints, &observationRecorder{writer: writer})
	request := endpointRequest(config)
	expiresAt, err := parseCanonicalExpiry(config.GrantBindings[0].ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	input := connectionInput{
		grantID: config.GrantBindings[0].GrantID, expiresAtRaw: config.GrantBindings[0].ExpiresAt,
		connectionGeneration: config.Endpoints[0].ConnectionGeneration, expiresAt: expiresAt, request: request,
	}
	ctx := context.WithValue(context.Background(), connectionContextKey{}, input)
	endpoint, err := resolver.Resolve(ctx, request.HandoffReference)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := endpoint.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := adapter.NewBrowserStream(raw, adapter.BrowserOptions{MaxFrameBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	want := gateway.Frame{Type: gateway.BinaryFrame, Payload: []byte("bounded-opaque-frame")}
	if err := stream.Send(callCtx, want); err != nil {
		t.Fatal(err)
	}
	got, err := stream.Receive(callCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || string(got.Payload) != string(want.Payload) {
		t.Fatalf("echo frame = %#v, want %#v", got, want)
	}
	if err := stream.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "{\"sequence\":1,\"kind\":\"resolve\"}\n{\"sequence\":2,\"kind\":\"dial\"}\n" {
		t.Fatalf("observations = %s", content)
	}
	for _, secret := range []string{
		config.Principals[0].Token, config.GrantBindings[0].GrantID,
		config.GrantBindings[0].ExpiresAt, config.Endpoints[0].HandoffReference,
	} {
		if strings.Contains(string(content), secret) {
			t.Fatalf("observation leaked %q: %s", secret, content)
		}
	}
}

func TestExactResolverRejectsMismatchedBindingWithoutObservation(t *testing.T) {
	config := validConfig(t)
	path := filepath.Join(t.TempDir(), "observations.jsonl")
	writer, err := newEvidenceWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver := newExactResolver(config.Endpoints, &observationRecorder{writer: writer})
	request := endpointRequest(config)
	request.SandboxID = "sandbox-other"
	ctx := context.WithValue(context.Background(), connectionContextKey{}, connectionInput{
		connectionGeneration: 1, expiresAt: time.Now().UTC().Add(time.Minute), request: request,
	})
	if _, err := resolver.Resolve(ctx, config.Endpoints[0].HandoffReference); err == nil {
		t.Fatal("Resolve() accepted a mismatched binding")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Fatalf("rejected resolve wrote observations: %q", content)
	}
}
