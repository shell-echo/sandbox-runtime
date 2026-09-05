package stack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
	providerbrowser "github.com/shell-echo/sandbox-runtime/provider/browser"
	browserapplication "github.com/shell-echo/sandbox-runtime/provider/browser/application"
	browserdocker "github.com/shell-echo/sandbox-runtime/provider/browser/driver/docker"
	browserlifecycle "github.com/shell-echo/sandbox-runtime/provider/browser/lifecycle"
	browsernetworkdocker "github.com/shell-echo/sandbox-runtime/provider/browser/network/docker"
	browsernetworkgateway "github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
	browserprovenance "github.com/shell-echo/sandbox-runtime/provider/browser/provenance/ghcli"
	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
	browserreferencefile "github.com/shell-echo/sandbox-runtime/provider/browser/reference/repository/file"
	browserfile "github.com/shell-echo/sandbox-runtime/provider/browser/repository/file"
	browserusage "github.com/shell-echo/sandbox-runtime/provider/browser/usage"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
	lifecycleapplication "github.com/shell-echo/sandbox-runtime/provider/lifecycle/application"
	lifecyclefile "github.com/shell-echo/sandbox-runtime/provider/lifecycle/repository/file"
	provideroperation "github.com/shell-echo/sandbox-runtime/provider/operation"
	"github.com/shell-echo/sandbox-runtime/provider/usage"
	usagefile "github.com/shell-echo/sandbox-runtime/provider/usage/repository/file"
	"github.com/shell-echo/sandbox-runtime/providerapi"
)

const browserProvenanceTimeoutSeconds = 300

type browserProviderServer interface {
	Startup(context.Context) error
	Shutdown(context.Context) error
}

type browserProviderResolver interface {
	Resolve(context.Context, string) (browserreference.Endpoint, error)
}

// BrowserProvider owns the Browser Provider server, runtime, durable state,
// and opaque-reference resolver without composing a public Gateway.
type BrowserProvider struct {
	server   browserProviderServer
	resolver browserProviderResolver
	closers  []func() error

	closeOnce sync.Once
	closeErr  error
}

func openBrowser(ctx context.Context, config Config) (_ *Stack, result error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	browserProvider, err := OpenBrowserProvider(ctx, config.browserProviderConfig())
	if err != nil {
		return nil, err
	}
	stack := &Stack{provider: browserProvider}
	stack.addCloser(browserProvider.Close)
	defer func() {
		if result != nil {
			result = errors.Join(result, stack.Close())
		}
	}()

	referenceGateway, err := newReferenceGateway(config, nil, browserProvider)
	if err != nil {
		return nil, err
	}
	stack.addCloser(referenceGateway.Close)
	stack.gateway, err = newPublicGatewayServer(config, referenceGateway.Handler())
	if err != nil {
		return nil, err
	}
	return stack, nil
}

// OpenBrowserProvider initializes the reusable Provider-only Browser stack.
// The caller remains responsible for coordinating Startup and Shutdown before
// closing the owned runtime and repository resources.
func OpenBrowserProvider(ctx context.Context, config BrowserProviderConfig) (_ *BrowserProvider, result error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		return nil, err
	}
	browserConfig := config.Browser
	if browserConfig == nil {
		return nil, errors.New("Browser reference configuration is unavailable")
	}
	providerStack := &BrowserProvider{}
	defer func() {
		if result != nil {
			result = errors.Join(result, providerStack.Close())
		}
	}()

	sessions, err := browserfile.NewRepository(filepath.Join(config.StateRoot, "browser-sessions.json"))
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(sessions.Close)
	references, err := browserreferencefile.NewRegistry(filepath.Join(config.StateRoot, "browser-references.json"))
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(references.Close)
	verifier, err := browserprovenance.New(browserprovenance.Options{
		ExecutablePath: browserConfig.ProvenanceExecutablePath, ExecutableDigest: browserConfig.ProvenanceExecutableDigest,
	})
	if err != nil {
		return nil, err
	}
	network, err := browsernetworkdocker.New(ctx, browsernetworkdocker.Options{
		GatewayImage: browserConfig.GatewayImage, UplinkNetwork: browserConfig.UplinkNetwork,
		Namespace: browserConfig.Namespace, ControllerID: config.RuntimeControllerID,
		Policies: []browsernetworkgateway.Policy{{
			Reference: browserConfig.NetworkPolicyReference, AllowedHosts: append([]string(nil), browserConfig.AllowedHosts...),
		}},
		MemoryBytes: 128 << 20, NanoCPUs: 500_000_000, PidsLimit: 64,
		OperationTimeoutSeconds: 90, StopTimeoutSeconds: 10,
	})
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(network.Close)
	runtime, err := browserdocker.New(ctx, browserdocker.Options{
		Image: config.RuntimeImage, PullPolicy: browserdocker.PullIfNotPresent,
		MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
		InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
		OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: browserProvenanceTimeoutSeconds, PullTimeoutSeconds: 120, StopTimeoutSeconds: 10,
		DataRoot: config.RuntimeDataRoot, ManifestPath: browserConfig.ManifestPath, SeccompPath: browserConfig.SeccompPath,
		Namespace: browserConfig.Namespace, ControllerID: config.RuntimeControllerID,
		NetworkPolicyReference: browserConfig.NetworkPolicyReference,
		MaxSessionsPerSandbox:  1, MaxSessionsPerController: 4, Clock: clock{},
	}, verifier, network)
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(runtime.Close)
	readiness, err := browserlifecycle.New(runtime, browserConfig.NetworkPolicyReference)
	if err != nil {
		return nil, err
	}
	lifecycleRepo, err := lifecyclefile.NewRepository(filepath.Join(config.StateRoot, "browser-lifecycle.json"))
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(lifecycleRepo.Close)
	lifecycleApp, err := lifecycleapplication.New(lifecycleRepo, readiness, clock{})
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(lifecycleApp.Close)
	if err := lifecycleApp.Recover(ctx); err != nil {
		return nil, err
	}

	usageRepo, err := usagefile.NewRepository(filepath.Join(config.StateRoot, "browser-usage.json"), clock{})
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(usageRepo.Close)
	registrar, err := browserreference.NewRegistrar(references, clock{}, nil)
	if err != nil {
		return nil, err
	}
	vertical, err := browserapplication.NewVerticalWithHandoffRegistrar(
		sessions, runtime, lifecycleApp,
		browserapplication.BrowserProfile{RuntimeProfileID: lifecycle.BrowserRuntimeProfile, CapabilityProfileID: providerbrowser.CapabilityProfileID},
		browserRegistrar{registrar: registrar}, clock{},
	)
	if err != nil {
		return nil, err
	}
	resolver, err := browserreference.NewResolver(references, sessions, runtime, clock{})
	if err != nil {
		return nil, err
	}
	usageReader, err := browserusage.NewReader(sessions, usageRepo, time.Hour)
	if err != nil {
		return nil, err
	}
	browserApp := &browserProviderApplication{
		vertical: vertical, sessions: sessions, runtime: runtime, references: references, clock: clock{}, cleanupTimeout: 45 * time.Second,
	}
	if _, err := vertical.Recover(ctx); err != nil {
		return nil, err
	}
	providerStack.addCloser(browserApp.Close)

	lifecycleReader, err := provideroperation.NewLifecycleReader(lifecycleApp)
	if err != nil {
		return nil, err
	}
	browserReader, err := provideroperation.NewBrowserSessionReader(browserApp)
	if err != nil {
		return nil, err
	}
	operationReader, err := provideroperation.NewAggregator(lifecycleReader, browserReader)
	if err != nil {
		return nil, err
	}
	protected, closeAdmission, err := protectedOptions(config.StateRoot, config.TrustedJWSKeys)
	if err != nil {
		return nil, err
	}
	providerStack.addCloser(closeAdmission)
	protected.Application = lifecycleApp
	protected.BrowserApplication = browserApp
	protected.UsageEvidenceReader = usageReader
	protected.OperationReader = operationReader

	capabilities, err := browserCapabilitySource(config.ProviderRevisionID, browserConfig.RuntimeArchitecture)
	if err != nil {
		return nil, err
	}
	providerHost, providerPort, err := splitAddress(config.ProviderAddress)
	if err != nil {
		return nil, err
	}
	providerServer, err := providerapi.NewServer(ctx, providerapi.TransportOptions{
		Address:               option.HTTP{Host: providerHost, Port: providerPort},
		ServerCertificateFile: config.ProviderCertificateFile, ServerPrivateKeyFile: config.ProviderPrivateKeyFile,
		ClientCABundleFile: config.ClientCAFile, AllowedClientURIIdentities: append([]string(nil), config.AllowedClientURIs...),
		Protected: protected,
	}, capabilities)
	if err != nil {
		return nil, err
	}
	providerStack.server = providerServer
	providerStack.resolver = resolver
	return providerStack, nil
}

func (p *BrowserProvider) Startup(ctx context.Context) error {
	if p == nil || p.server == nil {
		return errors.New("Browser Provider is unavailable")
	}
	return p.server.Startup(ctx)
}

func (p *BrowserProvider) Shutdown(ctx context.Context) error {
	if p == nil || p.server == nil {
		return errors.New("Browser Provider is unavailable")
	}
	return p.server.Shutdown(ctx)
}

func (p *BrowserProvider) Resolve(ctx context.Context, reference string) (browserreference.Endpoint, error) {
	if p == nil || p.resolver == nil {
		return browserreference.Endpoint{}, browserreference.ErrUnavailable
	}
	return p.resolver.Resolve(ctx, reference)
}

func (p *BrowserProvider) Close() error {
	if p == nil {
		return nil
	}
	p.closeOnce.Do(func() {
		for index := len(p.closers) - 1; index >= 0; index-- {
			p.closeErr = errors.Join(p.closeErr, p.closers[index]())
		}
		p.closers = nil
	})
	return p.closeErr
}

func (p *BrowserProvider) addCloser(closer func() error) {
	p.closers = append(p.closers, closer)
}

type browserRegistrar struct{ registrar *browserreference.Registrar }

func (r browserRegistrar) RegisterHandoff(ctx context.Context, source providerbrowser.Record) (providerbrowser.EndpointEvidence, error) {
	registration, err := r.registrar.Register(ctx, source)
	return registration.Evidence, err
}

type browserProviderApplication struct {
	vertical       *browserapplication.Vertical
	sessions       providerbrowser.CoordinationAuthority
	runtime        providerbrowser.Runtime
	references     browserreference.Store
	clock          clock
	cleanupTimeout time.Duration
	closeOnce      sync.Once
	closeErr       error
}

func (a *browserProviderApplication) Open(ctx context.Context, request providerbrowser.OpenRequest) (browserapplication.Operation, error) {
	return a.vertical.Open(ctx, request)
}

func (a *browserProviderApplication) GetOperation(ctx context.Context, operationID string) (browserapplication.Operation, error) {
	return a.vertical.GetOperation(ctx, operationID)
}

func (a *browserProviderApplication) GetHandoff(ctx context.Context, operationID string) (browserapplication.Handoff, error) {
	return a.vertical.GetHandoff(ctx, operationID)
}

func (a *browserProviderApplication) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), a.cleanupTimeout)
		defer cancel()
		records, err := a.sessions.ListOpen(ctx)
		if err != nil {
			a.closeErr = err
			return
		}
		now := a.clock.Now()
		for _, record := range records {
			if record.Allocation == nil || !browserNeedsShutdownCleanup(record, now) {
				continue
			}
			if record.Handoff != nil {
				err = errors.Join(err, ignoreBrowserReferenceNotFound(a.references.Revoke(ctx, record.Handoff.InternalEndpointReference, now)))
			} else if record.Status == providerbrowser.StatusRunning {
				registration, findErr := a.references.FindRunning(ctx, record)
				if findErr == nil {
					err = errors.Join(err, ignoreBrowserReferenceNotFound(a.references.Revoke(ctx, registration.Reference, now)))
				} else if !errors.Is(findErr, browserreference.ErrNotFound) {
					err = errors.Join(err, findErr)
				}
			}
			err = errors.Join(err, a.runtime.Cleanup(ctx, record.Allocation.Receipt))
		}
		a.closeErr = err
	})
	return a.closeErr
}

func browserNeedsShutdownCleanup(record providerbrowser.Record, now time.Time) bool {
	switch record.Status {
	case providerbrowser.StatusSucceeded:
		return !now.Before(record.Request.ExpiresAt)
	case providerbrowser.StatusAccepted:
		return false
	default:
		return true
	}
}

func ignoreBrowserReferenceNotFound(err error) error {
	if errors.Is(err, browserreference.ErrNotFound) {
		return nil
	}
	return err
}

func browserCapabilitySource(providerRevisionID, architecture string) (*provider.StaticCapabilitySource, error) {
	workspace := int64(1 << 30)
	gpu := int64(0)
	snapshot, err := provider.NewCapabilitySnapshotWithAdvertisements(providerRevisionID, provider.Limits{
		MaxCPUMillis: 2000, MaxMemoryBytes: 2 << 30, MaxEphemeralStorageBytes: 2 << 30,
		MaxWorkspaceBytes: &workspace, MaxGPUCount: &gpu, MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
	}, []provider.Capability{{
		ID: "sandbox.browser", Versions: []string{"1.0.0"}, Profiles: []string{providerbrowser.CapabilityProfileID},
	}}, []provider.RuntimeProfile{{
		ID: lifecycle.BrowserRuntimeProfile, IsolationClass: "container", RuntimeClassName: "sandbox-runtime-browser",
		Architecture: []string{architecture}, CapabilityProfileIDs: []string{providerbrowser.CapabilityProfileID},
	}}, []provider.SnapshotRestoreProfile{{
		ProfileID: "sandbox-snapshot-workspace-v1", Level: provider.SnapshotLevelWorkspace,
		SuiteID: provider.CompatibilitySuiteSandboxProvider, SuiteVersion: "1.0.0",
		SuiteDigest: provider.SHA256Digest("sha256:" + strings.Repeat("a", 64)),
	}})
	if err != nil {
		return nil, fmt.Errorf("construct Browser reference capability snapshot: %w", err)
	}
	return provider.NewStaticCapabilitySource(snapshot)
}

var _ providerapi.BrowserApplication = (*browserProviderApplication)(nil)
var _ usage.EvidenceReader = (*browserusage.Reader)(nil)
