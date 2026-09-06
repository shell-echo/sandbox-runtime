package caller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	providercaller "github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/provisioning"
)

const bootstrapTemplateReference = "ref:browser-session:bootstrap-template"

const (
	minBootstrapGrantLifetimeMillis = int64(1000)
	maxBootstrapGrantLifetimeMillis = int64(15 * 60 * 1000)
	minBootstrapGrantRemaining      = time.Second
	bootstrapValidationExpiry       = "1970-01-01T00:00:01Z"
)

var errBootstrappedCaller = errors.New("bootstrapped caller failed")

// BootstrapEndpointTemplate fixes the public identity expected from one
// Provider bootstrap without accepting orchestration-supplied handoff data.
type BootstrapEndpointTemplate struct {
	ID                  string `json:"id"`
	TenantID            string `json:"tenant_id"`
	SandboxID           string `json:"sandbox_id"`
	BrowserSessionID    string `json:"browser_session_id"`
	CapabilityProfileID string `json:"capability_profile_id"`
}

// BootstrapGrantBinding keeps caller authority static while allowing the
// absolute grant expiry to be derived only after the Provider handoff exists.
type BootstrapGrantBinding struct {
	ID             string `json:"id"`
	GrantID        string `json:"grant_id"`
	PrincipalID    string `json:"principal_id"`
	EndpointID     string `json:"endpoint_id"`
	LifetimeMillis int64  `json:"lifetime_millis"`
}

// BootstrapCallerConfig contains only the immutable caller configuration and
// the exact endpoint identity that a Provider bootstrap must bind. The opaque
// handoff and connection generation never enter this file.
type BootstrapCallerConfig struct {
	CAFile       string                    `json:"ca_file"`
	Gateways     map[string]string         `json:"gateways"`
	Principal    Principal                 `json:"principal"`
	Endpoint     BootstrapEndpointTemplate `json:"endpoint"`
	GrantBinding BootstrapGrantBinding     `json:"grant_binding"`
}

func (c BootstrapCallerConfig) String() string {
	return "BootstrapCallerConfig{configured:" + boolText(c.CAFile != "") + "}"
}

func (c BootstrapCallerConfig) GoString() string { return c.String() }

func (c BootstrapCallerConfig) LogValue() slog.Value {
	return slog.GroupValue(slog.Bool("configured", c.CAFile != ""))
}

// LoadBootstrapCallerConfig reads one strict, bounded, private regular JSON
// file. It deliberately does not accept a FIFO or symlink.
func LoadBootstrapCallerConfig(path string) (BootstrapCallerConfig, error) {
	if !filepath.IsAbs(path) {
		return BootstrapCallerConfig{}, errors.New("invalid bootstrap caller configuration")
	}
	contents, err := readBoundedRegularFile(path, maxConfigBytes, true)
	if err != nil || validateUniqueJSONFields(contents) != nil {
		return BootstrapCallerConfig{}, errors.New("invalid bootstrap caller configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var config BootstrapCallerConfig
	if err := decoder.Decode(&config); err != nil {
		return BootstrapCallerConfig{}, errors.New("invalid bootstrap caller configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return BootstrapCallerConfig{}, errors.New("invalid bootstrap caller configuration")
	}
	if err := validateBootstrapCallerConfig(config); err != nil {
		return BootstrapCallerConfig{}, errors.New("invalid bootstrap caller configuration")
	}
	return cloneBootstrapCallerConfig(config), nil
}

// RunBootstrapped obtains one Provider-owned Browser handoff, binds it to the
// immutable caller template, and only then enters the existing persistent
// JSONL command loop.
func RunBootstrapped(ctx context.Context, config BootstrapCallerConfig, providerConfig providercaller.BrowserBootstrapConfig, in io.Reader, out io.Writer) error {
	return runBootstrapped(ctx, config, providerConfig, in, out, bootstrapProviderEndpoint)
}

// RunProvisioned performs one correlated FD 3/4/5 provisioning handshake
// before entering the ordinary stdin/stdout JSONL loop. The inherited pipes
// are consumed, closed, and never reused after an ambiguous delivery.
func RunProvisioned(
	ctx context.Context,
	config BootstrapCallerConfig,
	providerConfig providercaller.BrowserBootstrapConfig,
	files *InheritedProvisioning,
	in io.Reader,
	out io.Writer,
) error {
	if ctx == nil || files == nil || files.request == nil || files.result == nil || files.final == nil {
		return errBootstrappedCaller
	}
	request, result, final := files.request, files.result, files.final
	files.request, files.result, files.final = nil, nil, nil
	return runProvisioned(ctx, config, providerConfig, request, result, final, in, out, bootstrapProviderEndpoint)
}

type bootstrapEndpointFunc func(
	context.Context,
	providercaller.BrowserBootstrapConfig,
	providercaller.BrowserBootstrapEndpointSink,
) error

func bootstrapProviderEndpoint(
	ctx context.Context,
	config providercaller.BrowserBootstrapConfig,
	sink providercaller.BrowserBootstrapEndpointSink,
) error {
	result, err := providercaller.BootstrapBrowser(ctx, config)
	if err != nil {
		return err
	}
	return result.BindEndpoint(sink)
}

func runBootstrapped(
	ctx context.Context,
	config BootstrapCallerConfig,
	providerConfig providercaller.BrowserBootstrapConfig,
	in io.Reader,
	out io.Writer,
	bootstrap bootstrapEndpointFunc,
) error {
	config = cloneBootstrapCallerConfig(config)
	if ctx == nil || nilInterface(in) || nilInterface(out) || validateBootstrapCallerConfig(config) != nil ||
		!bootstrapIdentityMatches(config, providerConfig) {
		return errBootstrappedCaller
	}
	if bootstrap == nil {
		return errBootstrappedCaller
	}
	binding := &bootstrapEndpointBinding{template: config}
	if err := bootstrap(ctx, providerConfig, binding); err != nil || !binding.bound {
		return errBootstrappedCaller
	}
	if err := runWithPrivate(ctx, binding.config, in, out, []string{binding.handoffExpiry}); err != nil {
		return errBootstrappedCaller
	}
	return nil
}

func runProvisioned(
	ctx context.Context,
	config BootstrapCallerConfig,
	providerConfig providercaller.BrowserBootstrapConfig,
	requestInput io.ReadCloser,
	endpointOutput io.WriteCloser,
	finalInput io.ReadCloser,
	in io.Reader,
	out io.Writer,
	bootstrap bootstrapEndpointFunc,
) error {
	config = cloneBootstrapCallerConfig(config)
	if nilInterface(requestInput) || nilInterface(endpointOutput) || nilInterface(finalInput) {
		return errBootstrappedCaller
	}
	requestCloser := &provisioningCloser{closer: requestInput}
	endpointCloser := &provisioningCloser{closer: endpointOutput}
	finalCloser := &provisioningCloser{closer: finalInput}
	defer requestCloser.Close()
	defer endpointCloser.Close()
	defer finalCloser.Close()
	if ctx == nil || nilInterface(in) || nilInterface(out) ||
		bootstrap == nil || validateBootstrapCallerConfig(config) != nil || !bootstrapIdentityMatches(config, providerConfig) {
		return errBootstrappedCaller
	}

	var request provisioning.Request
	if err := runProvisioningPhase(ctx, requestCloser, func() error {
		var readErr error
		request, readErr = provisioning.ReadRequest(requestInput)
		return readErr
	}); err != nil || !provisioningRequestMatches(request, providerConfig) {
		return errBootstrappedCaller
	}

	binding := &bootstrapEndpointBinding{template: config}
	if err := bootstrap(ctx, providerConfig, binding); err != nil || !binding.bound {
		return errBootstrappedCaller
	}
	envelope := binding.provisioningEnvelope(request.RequestID)
	if err := runProvisioningPhase(ctx, endpointCloser, func() error {
		return provisioning.WriteEndpoint(endpointOutput, envelope)
	}); err != nil {
		return errBootstrappedCaller
	}

	var final provisioning.FinalConfiguration
	if err := runProvisioningPhase(ctx, finalCloser, func() error {
		var readErr error
		final, readErr = provisioning.ReadFinalConfiguration(finalInput)
		return readErr
	}); err != nil || final.Version != provisioning.ProtocolVersion || final.RequestID != request.RequestID {
		return errBootstrappedCaller
	}
	finalConfig, err := decodeConfig(final.Config)
	if err != nil || !reflect.DeepEqual(finalConfig, binding.config) || !binding.stillValid(time.Now().UTC()) {
		return errBootstrappedCaller
	}
	if err := runWithPrivate(ctx, finalConfig, in, out, []string{binding.handoffExpiry}); err != nil {
		return errBootstrappedCaller
	}
	return nil
}

func provisioningRequestMatches(request provisioning.Request, providerConfig providercaller.BrowserBootstrapConfig) bool {
	return request.Version == provisioning.ProtocolVersion && request.ControllerSubject == providerConfig.Controller.ControllerSubject &&
		request.TenantID == providerConfig.TenantID && request.SandboxID == providerConfig.SandboxID &&
		request.BrowserSessionID == providerConfig.BrowserSessionID && request.CapabilityProfileID == lockedCapabilityProfileID
}

type provisioningCloser struct {
	closer io.Closer
	once   sync.Once
	err    error
}

func (c *provisioningCloser) Close() error {
	if c == nil || nilInterface(c.closer) {
		return errBootstrappedCaller
	}
	c.once.Do(func() {
		c.err = c.closer.Close()
	})
	return c.err
}

func runProvisioningPhase(ctx context.Context, file io.Closer, operation func() error) error {
	if ctx == nil || nilInterface(file) || operation == nil {
		return errBootstrappedCaller
	}
	closer := &provisioningCloser{closer: file}
	finished := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = closer.Close()
		case <-finished:
		}
	}()
	err := operation()
	close(finished)
	closeErr := closer.Close()
	<-watcherDone
	if err != nil || closeErr != nil || ctx.Err() != nil {
		return errBootstrappedCaller
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

type bootstrapEndpointBinding struct {
	template      BootstrapCallerConfig
	config        Config
	handoffExpiry string
	bound         bool
}

func (b *bootstrapEndpointBinding) provisioningEnvelope(requestID string) provisioning.EndpointEnvelope {
	endpoint := b.config.Endpoints[0]
	grant := b.config.GrantBindings[0]
	return provisioning.EndpointEnvelope{
		Version:   provisioning.ProtocolVersion,
		RequestID: requestID,
		Endpoint: provisioning.Endpoint{
			ID: endpoint.ID, TenantID: endpoint.TenantID, SandboxID: endpoint.SandboxID,
			BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
			HandoffReference: endpoint.HandoffReference, ConnectionGeneration: endpoint.ConnectionGeneration,
		},
		GrantBinding: provisioning.GrantBinding{
			ID: grant.ID, GrantID: grant.GrantID, PrincipalID: grant.PrincipalID,
			EndpointID: grant.EndpointID, ExpiresAt: grant.ExpiresAt,
		},
		HandoffExpiresAt: b.handoffExpiry,
	}
}

func (b *bootstrapEndpointBinding) stillValid(now time.Time) bool {
	if b == nil || !b.bound || len(b.config.GrantBindings) != 1 {
		return false
	}
	grantExpiry, grantOK := parseCanonicalExpiry(b.config.GrantBindings[0].ExpiresAt)
	handoffExpiry, handoffOK := parseCanonicalExpiry(b.handoffExpiry)
	return grantOK && handoffOK && grantExpiry.After(now) && handoffExpiry.After(now) && !grantExpiry.After(handoffExpiry)
}

func (b *bootstrapEndpointBinding) BindBrowserBootstrapEndpoint(
	tenantID, sandboxID, browserSessionID, capabilityProfileID, handoffReference string,
	connectionGeneration int64,
	expiresAt time.Time,
) error {
	if b == nil || b.bound || tenantID != b.template.Endpoint.TenantID || sandboxID != b.template.Endpoint.SandboxID ||
		browserSessionID != b.template.Endpoint.BrowserSessionID || capabilityProfileID != b.template.Endpoint.CapabilityProfileID ||
		!referencePattern.MatchString(handoffReference) || connectionGeneration < 1 {
		return errBootstrappedCaller
	}
	now := time.Now().UTC()
	if !validBootstrapGrantLifetime(b.template.GrantBinding.LifetimeMillis) ||
		expiresAt.Sub(now) < minBootstrapGrantRemaining {
		return errBootstrappedCaller
	}
	grantExpiry := now.Add(time.Duration(b.template.GrantBinding.LifetimeMillis) * time.Millisecond)
	if grantExpiry.After(expiresAt) {
		grantExpiry = expiresAt
	}
	config := materializeBootstrapCallerConfig(
		b.template,
		handoffReference,
		connectionGeneration,
		grantExpiry.UTC().Format(time.RFC3339Nano),
	)
	if _, err := prepareConfig(config); err != nil {
		return errBootstrappedCaller
	}
	b.config = config
	b.handoffExpiry = expiresAt.UTC().Format(time.RFC3339Nano)
	b.bound = true
	return nil
}

func validateBootstrapCallerConfig(config BootstrapCallerConfig) error {
	if len(config.Gateways) != maxGateways || config.Gateways["gateway-a"] == "" || config.Gateways["gateway-b"] == "" ||
		config.Principal.TenantID != config.Endpoint.TenantID || config.Endpoint.CapabilityProfileID != lockedCapabilityProfileID ||
		config.GrantBinding.PrincipalID != config.Principal.ID || config.GrantBinding.EndpointID != config.Endpoint.ID ||
		!validBootstrapGrantLifetime(config.GrantBinding.LifetimeMillis) {
		return errBootstrappedCaller
	}
	validation := materializeBootstrapCallerConfig(config, bootstrapTemplateReference, 1, bootstrapValidationExpiry)
	if _, err := prepareConfig(validation); err != nil {
		return errBootstrappedCaller
	}
	return nil
}

func bootstrapIdentityMatches(config BootstrapCallerConfig, providerConfig providercaller.BrowserBootstrapConfig) bool {
	return config.Endpoint.TenantID == providerConfig.TenantID && config.Endpoint.SandboxID == providerConfig.SandboxID &&
		config.Endpoint.BrowserSessionID == providerConfig.BrowserSessionID && config.Endpoint.CapabilityProfileID == lockedCapabilityProfileID
}

func materializeBootstrapCallerConfig(
	config BootstrapCallerConfig,
	handoffReference string,
	connectionGeneration int64,
	grantExpiry string,
) Config {
	return Config{
		CAFile:     config.CAFile,
		Gateways:   cloneGateways(config.Gateways),
		Principals: []Principal{config.Principal},
		Endpoints: []Endpoint{{
			ID: config.Endpoint.ID, TenantID: config.Endpoint.TenantID, SandboxID: config.Endpoint.SandboxID,
			BrowserSessionID: config.Endpoint.BrowserSessionID, CapabilityProfileID: config.Endpoint.CapabilityProfileID,
			HandoffReference: handoffReference, ConnectionGeneration: connectionGeneration,
		}},
		GrantBindings: []GrantBinding{{
			ID: config.GrantBinding.ID, GrantID: config.GrantBinding.GrantID,
			PrincipalID: config.GrantBinding.PrincipalID, EndpointID: config.GrantBinding.EndpointID,
			ExpiresAt: grantExpiry,
		}},
	}
}

func validBootstrapGrantLifetime(value int64) bool {
	return value >= minBootstrapGrantLifetimeMillis && value <= maxBootstrapGrantLifetimeMillis
}

func cloneBootstrapCallerConfig(config BootstrapCallerConfig) BootstrapCallerConfig {
	config.Gateways = cloneGateways(config.Gateways)
	return config
}

func cloneGateways(gateways map[string]string) map[string]string {
	cloned := make(map[string]string, len(gateways))
	for key, value := range gateways {
		cloned[key] = value
	}
	return cloned
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
