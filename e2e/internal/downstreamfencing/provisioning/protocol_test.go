package provisioning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProvisioningFramesRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		write func(io.Writer) error
		read  func(io.Reader) (any, error)
		want  any
	}{
		{
			name: "request",
			write: func(writer io.Writer) error {
				return WriteRequest(writer, validRequestFrame())
			},
			read: func(reader io.Reader) (any, error) {
				return ReadRequest(reader)
			},
			want: validRequestFrame(),
		},
		{
			name: "endpoint",
			write: func(writer io.Writer) error {
				return WriteEndpoint(writer, validEndpointFrame())
			},
			read: func(reader io.Reader) (any, error) {
				return ReadEndpoint(reader)
			},
			want: validEndpointFrame(),
		},
		{
			name: "final configuration",
			write: func(writer io.Writer) error {
				return WriteFinalConfiguration(writer, validFinalFrame())
			},
			read: func(reader io.Reader) (any, error) {
				return ReadFinalConfiguration(reader)
			},
			want: validFinalFrame(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var encoded chunkWriter
			if err := test.write(&encoded); err != nil {
				t.Fatal(err)
			}
			if !bytes.HasSuffix(encoded.Bytes(), []byte("\n")) {
				t.Fatal("frame is not newline terminated")
			}
			got, err := test.read(bytes.NewReader(encoded.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			gotJSON, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			wantJSON, err := json.Marshal(test.want)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Fatalf("round trip = %s, want %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestReadRequestIsStrictBoundedAndCorrelated(t *testing.T) {
	valid := `{"version":1,"request_id":"request-a","controller_subject":"spiffe://downstream/controller-a","tenant_id":"tenant-a","sandbox_id":"sandbox-a","browser_session_id":"session-a","capability_profile_id":"browser-v1"}`
	tests := []string{
		`null`,
		`{}`,
		strings.TrimSuffix(valid, "}"),
		strings.TrimSuffix(valid, `"}`),
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"version":1`, `"Version":1`, 1),
		strings.Replace(valid, `"request_id":"request-a"`, `"request_id":"request-a","request_id":"request-b"`, 1),
		strings.Replace(valid, `"controller_subject":"spiffe://downstream/controller-a"`, `"controller_subject":"https://downstream/controller-a"`, 1),
		strings.Replace(valid, `"capability_profile_id":"browser-v1"`, `"capability_profile_id":"browser-v2"`, 1),
		strings.TrimSuffix(valid, "}") + `,"unknown":true}`,
		valid + `{}`,
		valid + strings.Repeat(" ", int(MaxRequestBytes)),
	}
	for _, document := range tests {
		if _, err := ReadRequest(strings.NewReader(document)); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ReadRequest(%q) error = %v", boundedText(document), err)
		}
	}
	if _, err := ReadRequest(errorReader{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("reader error = %v", err)
	}
	var reader *bytes.Reader
	if _, err := ReadRequest(reader); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("typed-nil reader error = %v", err)
	}
	invalidUTF8 := append([]byte(valid), 0xff)
	if _, err := ReadRequest(bytes.NewReader(invalidUTF8)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
}

func TestReadRequestWaitsForPipeEOF(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	encoded, err := json.Marshal(validRequestFrame())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := write.Write(append(encoded, '\n')); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		_, readErr := ReadRequest(read)
		result <- readErr
	}()
	select {
	case err := <-result:
		t.Fatalf("ReadRequest returned before EOF: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadRequest did not complete after EOF")
	}
}

func TestEndpointAcceptsContractReferenceAndRejectsDrift(t *testing.T) {
	frame := validEndpointFrame()
	frame.Endpoint.HandoffReference = "ref:browser-session:contract.valid_reference-1"
	var encoded bytes.Buffer
	if err := WriteEndpoint(&encoded, frame); err != nil {
		t.Fatalf("Contract-valid reference rejected: %v", err)
	}
	if _, err := ReadEndpoint(&encoded); err != nil {
		t.Fatalf("Contract-valid reference did not round trip: %v", err)
	}

	tests := []EndpointEnvelope{validEndpointFrame(), validEndpointFrame(), validEndpointFrame(), validEndpointFrame()}
	tests[0].RequestID = ""
	tests[1].Endpoint.HandoffReference = "ref:browser-session:invalid/reference"
	tests[2].GrantBinding.EndpointID = "another-endpoint"
	tests[3].GrantBinding.ExpiresAt = "2030-01-01T00:00:02Z"
	for _, invalid := range tests {
		if err := WriteEndpoint(io.Discard, invalid); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("invalid endpoint error = %v", err)
		}
	}

	duplicateNested := `{"version":1,"request_id":"request-a","endpoint":{"id":"endpoint-a","id":"endpoint-b","tenant_id":"tenant-a","sandbox_id":"sandbox-a","browser_session_id":"session-a","capability_profile_id":"browser-v1","handoff_reference":"ref:browser-session:opaque-a","connection_generation":1},"grant_binding":{"id":"binding-a","grant_id":"grant-a","principal_id":"principal-a","endpoint_id":"endpoint-a","expires_at":"2030-01-01T00:00:00Z"},"handoff_expires_at":"2030-01-01T00:00:01Z"}`
	if _, err := ReadEndpoint(strings.NewReader(duplicateNested)); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("nested duplicate error = %v", err)
	}
	wrongCase := strings.Replace(duplicateNested, `"id":"endpoint-a","id":"endpoint-b"`, `"ID":"endpoint-a"`, 1)
	if _, err := ReadEndpoint(strings.NewReader(wrongCase)); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("non-canonical nested field error = %v", err)
	}
	unknownNested := strings.Replace(duplicateNested, `"id":"endpoint-a","id":"endpoint-b"`, `"id":"endpoint-a","unknown":true`, 1)
	if _, err := ReadEndpoint(strings.NewReader(unknownNested)); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("unknown nested field error = %v", err)
	}
	truncated := strings.TrimSuffix(strings.Replace(duplicateNested, `"id":"endpoint-a","id":"endpoint-b"`, `"id":"endpoint-a"`, 1), "}")
	if _, err := ReadEndpoint(strings.NewReader(truncated)); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("truncated endpoint error = %v", err)
	}
}

func TestFinalConfigurationRequiresOneStrictObject(t *testing.T) {
	tests := []string{
		`{"version":1,"request_id":"request-a","config":null}`,
		`{"version":1,"request_id":"request-a","config":[]}`,
		`{"version":1,"request_id":"request-a","config":{"token":"a","token":"b"}}`,
		`{"version":1,"request_id":"request-a","config":{}} {}`,
		`{"version":1,"request_id":"request-a","config":{},"unknown":true}`,
		strings.Repeat(" ", int(MaxFinalConfigurationBytes)+1),
	}
	for _, document := range tests {
		if _, err := ReadFinalConfiguration(strings.NewReader(document)); !errors.Is(err, ErrInvalidFinalConfiguration) {
			t.Fatalf("ReadFinalConfiguration(%q) error = %v", boundedText(document), err)
		}
	}

	frame := validFinalFrame()
	frame.Config = json.RawMessage(`{"token":"a","token":"b"}`)
	if err := WriteFinalConfiguration(io.Discard, frame); !errors.Is(err, ErrInvalidFinalConfiguration) {
		t.Fatalf("duplicate raw configuration error = %v", err)
	}
	frame.Config = json.RawMessage(`"not-an-object"`)
	if err := WriteFinalConfiguration(io.Discard, frame); !errors.Is(err, ErrInvalidFinalConfiguration) {
		t.Fatalf("non-object raw configuration error = %v", err)
	}
}

func TestWriteFailuresAreFixedAndTypedNilSafe(t *testing.T) {
	var writer *bytes.Buffer
	if err := WriteRequest(writer, validRequestFrame()); !errors.Is(err, ErrRequestDeliveryFailed) {
		t.Fatalf("typed-nil request writer error = %v", err)
	}
	if err := WriteEndpoint(errorWriter{}, validEndpointFrame()); !errors.Is(err, ErrEndpointDeliveryFailed) {
		t.Fatalf("endpoint writer error = %v", err)
	}
	if err := WriteFinalConfiguration(zeroWriter{}, validFinalFrame()); !errors.Is(err, ErrFinalConfigurationDelivery) {
		t.Fatalf("final writer error = %v", err)
	}
	invalid := validRequestFrame()
	invalid.Version = 0
	if err := WriteRequest(errorWriter{}, invalid); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid request error = %v", err)
	}
}

func TestFormattingAndErrorsDoNotExposePrivateMaterial(t *testing.T) {
	request := validRequestFrame()
	endpoint := validEndpointFrame()
	final := validFinalFrame()
	values := []any{request, request.String(), endpoint.Endpoint, endpoint.GrantBinding, endpoint, final}
	private := []string{
		request.RequestID, request.ControllerSubject, request.TenantID, request.SandboxID, request.BrowserSessionID,
		endpoint.Endpoint.HandoffReference, endpoint.GrantBinding.GrantID, endpoint.GrantBinding.ExpiresAt,
		endpoint.HandoffExpiresAt, "private-token-value",
	}
	for _, value := range values {
		projection := fmt.Sprintf("%v|%+v|%#v", value, value, value)
		assertNoPrivateText(t, projection, private)
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	logger.Info("frames", "request", request, "endpoint", endpoint, "final", final)
	assertNoPrivateText(t, output.String(), private)
	for _, err := range []error{
		ErrInvalidRequest, ErrRequestDeliveryFailed, ErrInvalidEndpoint, ErrEndpointDeliveryFailed,
		ErrInvalidFinalConfiguration, ErrFinalConfigurationDelivery,
	} {
		assertNoPrivateText(t, err.Error(), private)
	}
}

func validRequestFrame() Request {
	return Request{
		Version: ProtocolVersion, RequestID: "request-a", ControllerSubject: "spiffe://downstream/controller-a",
		TenantID: "tenant-a", SandboxID: "sandbox-a", BrowserSessionID: "session-a", CapabilityProfileID: "browser-v1",
	}
}

func validEndpointFrame() EndpointEnvelope {
	return EndpointEnvelope{
		Version: ProtocolVersion, RequestID: "request-a",
		Endpoint: Endpoint{
			ID: "endpoint-a", TenantID: "tenant-a", SandboxID: "sandbox-a", BrowserSessionID: "session-a",
			CapabilityProfileID: "browser-v1", HandoffReference: "ref:browser-session:opaque-a", ConnectionGeneration: 1,
		},
		GrantBinding: GrantBinding{
			ID: "binding-a", GrantID: "grant-a", PrincipalID: "principal-a", EndpointID: "endpoint-a",
			ExpiresAt: "2030-01-01T00:00:00Z",
		},
		HandoffExpiresAt: "2030-01-01T00:00:01Z",
	}
}

func validFinalFrame() FinalConfiguration {
	return FinalConfiguration{
		Version: ProtocolVersion, RequestID: "request-a",
		Config: json.RawMessage(`{"principal":{"token":"private-token-value"}}`),
	}
}

type chunkWriter struct{ bytes.Buffer }

func (w *chunkWriter) Write(content []byte) (int, error) {
	if len(content) > 7 {
		content = content[:7]
	}
	return w.Buffer.Write(content)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("private reader error") }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errors.New("private writer error") }

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func assertNoPrivateText(t *testing.T, output string, private []string) {
	t.Helper()
	for _, value := range private {
		if value != "" && strings.Contains(output, value) {
			t.Fatalf("private value %q escaped through %q", value, output)
		}
	}
}

func boundedText(value string) string {
	if len(value) <= 256 {
		return value
	}
	return value[:256]
}
