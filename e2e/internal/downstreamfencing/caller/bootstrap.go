package caller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	providercaller "github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
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
	if ctx == nil || in == nil || out == nil || validateBootstrapCallerConfig(config) != nil ||
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

type bootstrapEndpointBinding struct {
	template      BootstrapCallerConfig
	config        Config
	handoffExpiry string
	bound         bool
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
