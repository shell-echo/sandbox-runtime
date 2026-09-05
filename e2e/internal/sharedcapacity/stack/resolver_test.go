package stack

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
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
	input := connectionInput{
		grantID: "grant-1", connectionGeneration: 1,
		expiresAt: time.Now().UTC().Add(time.Minute), request: request,
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
	for sequence := 1; sequence <= 8; sequence++ {
		want := gateway.Frame{Type: gateway.TextFrame, Payload: []byte(`{"id":1,"method":"Browser.getVersion"}`)}
		want.Payload[6] = byte('0' + sequence)
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
	for _, secret := range []string{config.Endpoints[0].TenantID, config.Endpoints[0].HandoffReference, config.Principals[0].Token} {
		if strings.Contains(string(content), secret) {
			t.Fatalf("observation leaked %q: %s", secret, content)
		}
	}
}

func TestEchoStreamClearsCanceledReadAndWriteDeadlines(t *testing.T) {
	connection, peer := net.Pipe()
	observed := &observedConnection{
		Conn: connection, readStarted: make(chan struct{}), writeStarted: make(chan struct{}),
	}
	stream := &echoStream{connection: observed}
	t.Cleanup(func() {
		_ = stream.Close()
		_ = peer.Close()
	})

	readCtx, cancelRead := context.WithCancel(context.Background())
	readResult := make(chan error, 1)
	go func() {
		_, err := stream.Read(readCtx, make([]byte, 1))
		readResult <- err
	}()
	<-observed.readStarted
	cancelRead()
	if err := <-readResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Read() error = %v", err)
	}
	go func() { _, _ = peer.Write([]byte("r")) }()
	validCtx, cancelValid := context.WithTimeout(context.Background(), time.Second)
	buffer := make([]byte, 1)
	if n, err := stream.Read(validCtx, buffer); err != nil || n != 1 || string(buffer) != "r" {
		t.Fatalf("Read() after cancellation = %d %q, %v", n, buffer, err)
	}
	cancelValid()

	writeCtx, cancelWrite := context.WithCancel(context.Background())
	writeResult := make(chan error, 1)
	go func() {
		_, err := stream.Write(writeCtx, []byte("blocked"))
		writeResult <- err
	}()
	<-observed.writeStarted
	cancelWrite()
	if err := <-writeResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Write() error = %v", err)
	}
	peerRead := make(chan string, 1)
	go func() {
		value := make([]byte, 1)
		_, _ = peer.Read(value)
		peerRead <- string(value)
	}()
	validCtx, cancelValid = context.WithTimeout(context.Background(), time.Second)
	if n, err := stream.Write(validCtx, []byte("w")); err != nil || n != 1 {
		t.Fatalf("Write() after cancellation = %d, %v", n, err)
	}
	cancelValid()
	if got := <-peerRead; got != "w" {
		t.Fatalf("peer read = %q, want w", got)
	}
}

type observedConnection struct {
	net.Conn
	readStarted  chan struct{}
	writeStarted chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
}

func (c *observedConnection) Read(value []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(value)
}

func (c *observedConnection) Write(value []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(value)
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

func endpointRequest(config wire.GatewayConfig) gateway.ConnectRequest {
	principal, endpoint := config.Principals[0], config.Endpoints[0]
	return gateway.ConnectRequest{
		CallerID: principal.CallerID, TenantID: principal.TenantID, SandboxID: endpoint.SandboxID,
		BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
		HandoffReference: endpoint.HandoffReference,
	}
}
