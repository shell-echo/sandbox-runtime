package provisioning

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const ProtocolVersion = 1

const (
	MaxRequestBytes            int64 = 4 << 10
	MaxEndpointBytes           int64 = 4 << 10
	MaxFinalConfigurationBytes int64 = (1 << 20) + (16 << 10)
	maxEmbeddedConfigBytes           = 1 << 20
)

var (
	ErrInvalidRequest             = errors.New("invalid provisioning request")
	ErrRequestDeliveryFailed      = errors.New("provisioning request delivery failed")
	ErrInvalidEndpoint            = errors.New("invalid provisioning endpoint")
	ErrEndpointDeliveryFailed     = errors.New("provisioning endpoint delivery failed")
	ErrInvalidFinalConfiguration  = errors.New("invalid final caller configuration")
	ErrFinalConfigurationDelivery = errors.New("final caller configuration delivery failed")
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	referencePattern  = regexp.MustCompile(`^ref:browser-session:[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)
)

// Request correlates one caller-owned Provider bootstrap with its dedicated
// provisioning pipes. It contains identity only; credentials and bootstrap
// configuration remain in the caller's private configuration files.
type Request struct {
	Version             int    `json:"version"`
	RequestID           string `json:"request_id"`
	ControllerSubject   string `json:"controller_subject"`
	TenantID            string `json:"tenant_id"`
	SandboxID           string `json:"sandbox_id"`
	BrowserSessionID    string `json:"browser_session_id"`
	CapabilityProfileID string `json:"capability_profile_id"`
}

// Endpoint is the private Provider handoff material needed by the caller-owned
// Gateway. It must never be projected into stdout, stderr, logs, or evidence.
type Endpoint struct {
	ID                   string `json:"id"`
	TenantID             string `json:"tenant_id"`
	SandboxID            string `json:"sandbox_id"`
	BrowserSessionID     string `json:"browser_session_id"`
	CapabilityProfileID  string `json:"capability_profile_id"`
	HandoffReference     string `json:"handoff_reference"`
	ConnectionGeneration int64  `json:"connection_generation"`
}

// GrantBinding is transferred with its exact endpoint so the orchestrator can
// provision identical caller and Gateway authorization state.
type GrantBinding struct {
	ID          string `json:"id"`
	GrantID     string `json:"grant_id"`
	PrincipalID string `json:"principal_id"`
	EndpointID  string `json:"endpoint_id"`
	ExpiresAt   string `json:"expires_at"`
}

// EndpointEnvelope is the single FD 4 result for one correlated request.
type EndpointEnvelope struct {
	Version          int          `json:"version"`
	RequestID        string       `json:"request_id"`
	Endpoint         Endpoint     `json:"endpoint"`
	GrantBinding     GrantBinding `json:"grant_binding"`
	HandoffExpiresAt string       `json:"handoff_expires_at"`
}

// FinalConfiguration is the single FD 5 response. Config stays raw here to
// avoid a dependency from the shared provisioning protocol back to caller.
// The caller must decode it again into its strict Config type before use.
type FinalConfiguration struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	Config    json.RawMessage `json:"config"`
}

func ReadRequest(reader io.Reader) (Request, error) {
	var frame Request
	if err := readFrame(reader, MaxRequestBytes, &frame, validRequestDocument, func() bool { return validRequest(frame) }); err != nil {
		return Request{}, ErrInvalidRequest
	}
	return frame, nil
}

func WriteRequest(writer io.Writer, frame Request) error {
	if !validRequest(frame) {
		return ErrInvalidRequest
	}
	if err := writeFrame(writer, MaxRequestBytes, frame); err != nil {
		return ErrRequestDeliveryFailed
	}
	return nil
}

func ReadEndpoint(reader io.Reader) (EndpointEnvelope, error) {
	var frame EndpointEnvelope
	if err := readFrame(reader, MaxEndpointBytes, &frame, validEndpointDocument, func() bool { return validEndpointEnvelope(frame) }); err != nil {
		return EndpointEnvelope{}, ErrInvalidEndpoint
	}
	return frame, nil
}

func WriteEndpoint(writer io.Writer, frame EndpointEnvelope) error {
	if !validEndpointEnvelope(frame) {
		return ErrInvalidEndpoint
	}
	if err := writeFrame(writer, MaxEndpointBytes, frame); err != nil {
		return ErrEndpointDeliveryFailed
	}
	return nil
}

func ReadFinalConfiguration(reader io.Reader) (FinalConfiguration, error) {
	var frame FinalConfiguration
	if err := readFrame(reader, MaxFinalConfigurationBytes, &frame, validFinalDocument, func() bool { return validFinalConfiguration(frame) }); err != nil {
		return FinalConfiguration{}, ErrInvalidFinalConfiguration
	}
	frame.Config = append(json.RawMessage(nil), frame.Config...)
	return frame, nil
}

func WriteFinalConfiguration(writer io.Writer, frame FinalConfiguration) error {
	if !validFinalConfiguration(frame) {
		return ErrInvalidFinalConfiguration
	}
	if err := writeFrame(writer, MaxFinalConfigurationBytes, frame); err != nil {
		return ErrFinalConfigurationDelivery
	}
	return nil
}

func readFrame(reader io.Reader, maximum int64, destination any, validDocument func([]byte) bool, valid func() bool) error {
	if nilInterface(reader) || destination == nil || validDocument == nil || valid == nil || maximum < 1 {
		return errors.New("invalid frame")
	}
	content, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum || !utf8.Valid(content) ||
		validateUniqueJSONFields(content) != nil || !validDocument(content) {
		return errors.New("invalid frame")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid frame")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !valid() {
		return errors.New("invalid frame")
	}
	return nil
}

func writeFrame(writer io.Writer, maximum int64, frame any) error {
	if nilInterface(writer) || maximum < 1 {
		return errors.New("invalid writer")
	}
	content, err := json.Marshal(frame)
	if err != nil || int64(len(content)+1) > maximum {
		return errors.New("invalid frame")
	}
	content = append(content, '\n')
	for len(content) > 0 {
		written, writeErr := writer.Write(content)
		if writeErr != nil || written <= 0 || written > len(content) {
			return errors.New("write frame")
		}
		content = content[written:]
	}
	return nil
}

func validRequest(frame Request) bool {
	return frame.Version == ProtocolVersion && validIdentifier(frame.RequestID) && validSPIFFE(frame.ControllerSubject) &&
		validIdentifier(frame.TenantID) && validIdentifier(frame.SandboxID) && validIdentifier(frame.BrowserSessionID) &&
		frame.CapabilityProfileID == "browser-v1"
}

func validEndpointEnvelope(frame EndpointEnvelope) bool {
	if frame.Version != ProtocolVersion || !validIdentifier(frame.RequestID) || !validEndpoint(frame.Endpoint) ||
		!validGrantBinding(frame.GrantBinding) || frame.GrantBinding.EndpointID != frame.Endpoint.ID {
		return false
	}
	grantExpiry, grantOK := canonicalExpiry(frame.GrantBinding.ExpiresAt)
	handoffExpiry, handoffOK := canonicalExpiry(frame.HandoffExpiresAt)
	return grantOK && handoffOK && !grantExpiry.After(handoffExpiry)
}

func validEndpoint(endpoint Endpoint) bool {
	return validIdentifier(endpoint.ID) && validIdentifier(endpoint.TenantID) && validIdentifier(endpoint.SandboxID) &&
		validIdentifier(endpoint.BrowserSessionID) && endpoint.CapabilityProfileID == "browser-v1" &&
		referencePattern.MatchString(endpoint.HandoffReference) && endpoint.ConnectionGeneration > 0
}

func validGrantBinding(binding GrantBinding) bool {
	_, expiryOK := canonicalExpiry(binding.ExpiresAt)
	return validIdentifier(binding.ID) && validIdentifier(binding.GrantID) && validIdentifier(binding.PrincipalID) &&
		validIdentifier(binding.EndpointID) && expiryOK
}

func validFinalConfiguration(frame FinalConfiguration) bool {
	return frame.Version == ProtocolVersion && validIdentifier(frame.RequestID) && validJSONObject(frame.Config, maxEmbeddedConfigBytes)
}

func validRequestDocument(content []byte) bool {
	return exactObjectFields(content, []string{
		"version", "request_id", "controller_subject", "tenant_id", "sandbox_id", "browser_session_id", "capability_profile_id",
	})
}

func validEndpointDocument(content []byte) bool {
	outer, ok := rawObject(content)
	if !ok || !exactFields(outer, []string{"version", "request_id", "endpoint", "grant_binding", "handoff_expires_at"}) {
		return false
	}
	return exactObjectFields(outer["endpoint"], []string{
		"id", "tenant_id", "sandbox_id", "browser_session_id", "capability_profile_id", "handoff_reference", "connection_generation",
	}) && exactObjectFields(outer["grant_binding"], []string{
		"id", "grant_id", "principal_id", "endpoint_id", "expires_at",
	})
}

func validFinalDocument(content []byte) bool {
	return exactObjectFields(content, []string{"version", "request_id", "config"})
}

func exactObjectFields(content []byte, fields []string) bool {
	object, ok := rawObject(content)
	return ok && exactFields(object, fields)
}

func rawObject(content []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	var trailing any
	return object, errors.Is(decoder.Decode(&trailing), io.EOF)
}

func exactFields(object map[string]json.RawMessage, fields []string) bool {
	if len(object) != len(fields) {
		return false
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool { return identifierPattern.MatchString(value) }

func validSPIFFE(value string) bool {
	if len(value) == 0 || len(value) > 200 {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "spiffe" && parsed.Host != "" && parsed.Path != "" && parsed.RawPath == "" &&
		parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && parsed.Opaque == ""
}

func canonicalExpiry(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func validJSONObject(content []byte, maximum int) bool {
	if len(content) == 0 || len(content) > maximum || !utf8.Valid(content) || validateUniqueJSONFields(content) != nil {
		return false
	}
	_, ok := rawObject(content)
	return ok
}

func validateUniqueJSONFields(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := validateUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing input")
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("JSON object key is invalid or duplicated")
			}
			seen[key] = true
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := validateUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is incomplete")
		}
	default:
		return errors.New("JSON delimiter is invalid")
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return reflected.IsNil()
	default:
		return false
	}
}

func (r Request) String() string {
	return "ProvisioningRequest{version:" + strconv.Itoa(r.Version) + ",configured:" + strconv.FormatBool(validRequest(r)) + "}"
}

func (r Request) GoString() string { return r.String() }

func (r Request) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("version", r.Version), slog.Bool("configured", validRequest(r)))
}

func (e Endpoint) String() string {
	return "ProvisioningEndpoint{configured:" + strconv.FormatBool(validEndpoint(e)) + "}"
}

func (e Endpoint) GoString() string { return e.String() }

func (e Endpoint) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("configured", validEndpoint(e)))
}

func (g GrantBinding) String() string {
	return "ProvisioningGrantBinding{configured:" + strconv.FormatBool(validGrantBinding(g)) + "}"
}

func (g GrantBinding) GoString() string { return g.String() }

func (g GrantBinding) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("configured", validGrantBinding(g)))
}

func (e EndpointEnvelope) String() string {
	return "ProvisioningEndpointEnvelope{version:" + strconv.Itoa(e.Version) + ",configured:" + strconv.FormatBool(validEndpointEnvelope(e)) + "}"
}

func (e EndpointEnvelope) GoString() string { return e.String() }

func (e EndpointEnvelope) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("version", e.Version), slog.Bool("configured", validEndpointEnvelope(e)))
}

func (f FinalConfiguration) String() string {
	return "ProvisioningFinalConfiguration{version:" + strconv.Itoa(f.Version) + ",configured:" + strconv.FormatBool(validFinalConfiguration(f)) + "}"
}

func (f FinalConfiguration) GoString() string { return f.String() }

func (f FinalConfiguration) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("version", f.Version), slog.Bool("configured", validFinalConfiguration(f)))
}
