package desktopbroker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadyDescriptorIsExact(t *testing.T) {
	descriptor := ReadyDescriptor()
	if err := descriptor.Validate(); err != nil {
		t.Fatal(err)
	}
	if descriptor.AudioOutput || strings.Join(descriptor.PrivateInputModes, "\x00") != "keyboard\x00pointer" {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	invalid := descriptor
	invalid.DisplayReference = "/tmp/.X11-unix/X99"
	if !errors.Is(invalid.Validate(), ErrInvalidRequest) {
		t.Fatal("raw display coordinate was accepted")
	}
}

func TestProtocolProbeDescribeAndStrictBounds(t *testing.T) {
	socketPath := "/tmp/sandbox-runtime-desktop-0123456789abcdef0123456789abcdef.sock"
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProtocol(ctx, socketPath, ReadyDescriptor(), make(chan error)) }()
	waitForSocket(t, socketPath)

	for _, method := range []string{"probe", "describe"} {
		response, err := request(context.Background(), socketPath, method)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if response.Descriptor == nil || response.Descriptor.DisplayReference != DisplayReference {
			t.Fatalf("%s response = %+v", method, response)
		}
	}
	info, err := os.Stat(socketPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, %v", info, err)
	}

	tests := map[string]string{
		"unknown":              `{"protocol":"sandbox.runtime/desktop-broker/v1","request_id":"bad-1","method":"probe","unknown":true}`,
		"method":               `{"protocol":"sandbox.runtime/desktop-broker/v1","request_id":"bad-2","method":"exec"}`,
		"protocol":             `{"protocol":"other","request_id":"bad-3","method":"probe"}`,
		"v2 probe unavailable": `{"protocol":"sandbox.runtime/desktop-broker/v1","request_id":"bad-v2","method":"probe.v2"}`,
		"trailing":             `{"protocol":"sandbox.runtime/desktop-broker/v1","request_id":"bad-4","method":"probe"}{}`,
	}
	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			response := rawRequest(t, socketPath, document)
			if response.Status != "error" || response.ErrorCode != "invalid_request" || response.Descriptor != nil {
				t.Fatalf("response = %+v", response)
			}
		})
	}

	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = connection.Write(bytes.Repeat([]byte("x"), MaxRequestBytes+1))
	if unix, ok := connection.(*net.UnixConn); ok {
		_ = unix.CloseWrite()
	}
	data, _ := ioReadAllBounded(connection, MaxResponseBytes)
	_ = connection.Close()
	if len(data) != 0 {
		t.Fatalf("oversized request received response %q", data)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestBridgeProbeRequiresConfiguredV2Authority(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := "/tmp/sandbox-runtime-desktop-abcdefabcdefabcdefabcdefabcdefab.sock"
	_ = os.Remove(socketPath)
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	keys := map[string]ed25519.PublicKey{"provider-desktop-v2": make([]byte, ed25519.PublicKeySize)}
	go func() {
		done <- serveProtocolWithBridgeLedger(ctx, socketPath, ReadyDescriptor(), make(chan error), keys, filepath.Join(directory, "replay.json"))
	}()
	waitForSocket(t, socketPath)
	response := rawRequest(t, socketPath, `{"protocol":"sandbox.runtime/desktop-broker/v1","request_id":"probe-v2","method":"probe.v2"}`)
	if response.Status != "ok" || response.Descriptor == nil {
		t.Fatalf("v2 bridge probe response = %#v", response)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("server error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestRunRejectsOverridesAndPrintsDescribe(t *testing.T) {
	var output, errorOutput bytes.Buffer
	if err := Run(context.Background(), []string{"serve", "--display", ":1"}, &output, &errorOutput); !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("override error = %v", err)
	}
	if err := Run(context.Background(), []string{"exec"}, &output, &errorOutput); !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("exec error = %v", err)
	}
}

func TestRequestAndResponseValidationMatrix(t *testing.T) {
	for name, value := range map[string]Request{
		"empty":      {},
		"bad id":     {Protocol: ProtocolID, RequestID: strings.Repeat("x", 129), Method: "probe"},
		"bad method": {Protocol: ProtocolID, RequestID: "request-1", Method: "stop"},
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(value.Validate(), ErrInvalidRequest) {
				t.Fatalf("Validate() = %v", value.Validate())
			}
		})
	}
	response := Response{Protocol: ProtocolID, RequestID: "request-1", Status: "ok", Descriptor: pointer(ReadyDescriptor())}
	if err := response.Validate(); err != nil {
		t.Fatal(err)
	}
	response.ErrorCode = "private detail"
	if !errors.Is(response.Validate(), ErrInvalidRequest) {
		t.Fatal("mixed success/error response accepted")
	}
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("broker socket did not appear")
}

func rawRequest(t *testing.T, path, document string) Response {
	t.Helper()
	connectionValue, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	connection := connectionValue.(*net.UnixConn)
	defer connection.Close()
	if _, err := connection.Write([]byte(document)); err != nil {
		t.Fatal(err)
	}
	_ = connection.CloseWrite()
	var response Response
	decoder := json.NewDecoder(connection)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	return response
}

func ioReadAllBounded(connection net.Conn, maximum int64) ([]byte, error) {
	var output bytes.Buffer
	_, err := output.ReadFrom(&limitedReader{reader: connection, remaining: maximum})
	return output.Bytes(), err
}

type limitedReader struct {
	reader    net.Conn
	remaining int64
}

func (r *limitedReader) Read(buffer []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	count, err := r.reader.Read(buffer)
	r.remaining -= int64(count)
	return count, err
}

func pointer[T any](value T) *T { return &value }
