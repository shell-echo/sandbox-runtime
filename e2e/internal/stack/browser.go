package stack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

func openBrowser(ctx context.Context, config Config) (_ *Stack, result error) {
	if err := os.MkdirAll(config.StateRoot, 0o700); err != nil {
		return nil, err
	}
	browserConfig := config.Browser
	if browserConfig == nil {
		return nil, errors.New("Browser reference configuration is unavailable")
	}
	stack := &Stack{}
	defer func() {
		if result != nil {
			result = errors.Join(result, stack.Close())
		}
	}()

	sessions, err := browserfile.NewRepository(filepath.Join(config.StateRoot, "browser-sessions.json"))
	if err != nil {
		return nil, err
	}
	stack.addCloser(sessions.Close)
	references, err := browserreferencefile.NewRegistry(filepath.Join(config.StateRoot, "browser-references.json"))
	if err != nil {
		return nil, err
	}
	stack.addCloser(references.Close)
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
	stack.addCloser(network.Close)
	runtime, err := browserdocker.New(ctx, browserdocker.Options{
		Image: config.RuntimeImage, PullPolicy: browserdocker.PullIfNotPresent,
		MemoryBytes: 1 << 30, NanoCPUs: 1_000_000_000, PidsLimit: 256,
		InputsBytes: 16 << 20, TmpfsBytes: 256 << 20, WorkspaceBytes: 256 << 20, OutputsBytes: 128 << 20,
		OperationTimeoutSeconds: 90, ProvenanceTimeoutSeconds: 120, PullTimeoutSeconds: 120, StopTimeoutSeconds: 10,
		DataRoot: config.RuntimeDataRoot, ManifestPath: browserConfig.ManifestPath, SeccompPath: browserConfig.SeccompPath,
		Namespace: browserConfig.Namespace, ControllerID: config.RuntimeControllerID,
		NetworkPolicyReference: browserConfig.NetworkPolicyReference,
		MaxSessionsPerSandbox:  1, MaxSessionsPerController: 4, Clock: clock{},
	}, verifier, network)
	if err != nil {
		return nil, err
	}
	stack.addCloser(runtime.Close)
	readiness, err := browserlifecycle.New(runtime, browserConfig.NetworkPolicyReference)
	if err != nil {
		return nil, err
	}
	lifecycleRepo, err := lifecyclefile.NewRepository(filepath.Join(config.StateRoot, "browser-lifecycle.json"))
	if err != nil {
		return nil, err
	}
	stack.addCloser(lifecycleRepo.Close)
	lifecycleApp, err := lifecycleapplication.New(lifecycleRepo, readiness, clock{})
	if err != nil {
		return nil, err
	}
	stack.addCloser(lifecycleApp.Close)
	if err := lifecycleApp.Recover(ctx); err != nil {
		return nil, err
	}

	usageRepo, err := usagefile.NewRepository(filepath.Join(config.StateRoot, "browser-usage.json"), clock{})
	if err != nil {
		return nil, err
	}
	stack.addCloser(usageRepo.Close)
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
	stack.addCloser(browserApp.Close)

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
	protected, closeAdmission, err := protectedOptions(config)
	if err != nil {
		return nil, err
	}
	stack.addCloser(closeAdmission)
	protected.Application = lifecycleApp
	protected.BrowserApplication = browserApp
	protected.UsageEvidenceReader = usageReader
	protected.OperationReader = operationReader

	capabilities, err := browserCapabilitySource(config.ProviderRevisionID)
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
	stack.provider = providerServer

	referenceGateway, err := newReferenceGateway(config, nil, resolver)
	if err != nil {
		return nil, err
	}
	stack.addCloser(referenceGateway.Close)
	stack.gateway = &http.Server{
		Addr: config.GatewayAddress, Handler: referenceGateway.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	return stack, nil
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

func browserCapabilitySource(providerRevisionID string) (*provider.StaticCapabilitySource, error) {
	workspace := int64(1 << 30)
	gpu := int64(0)
	snapshot, err := provider.NewCapabilitySnapshotWithAdvertisements(providerRevisionID, provider.Limits{
		MaxCPUMillis: 2000, MaxMemoryBytes: 2 << 30, MaxEphemeralStorageBytes: 2 << 30,
		MaxWorkspaceBytes: &workspace, MaxGPUCount: &gpu, MaxLeaseSeconds: 3600, MaxExecSeconds: 300,
	}, nil, nil, []provider.SnapshotRestoreProfile{{
		ProfileID: "sandbox-snapshot-workspace-v1", Level: provider.SnapshotLevelWorkspace,
		SuiteID: provider.CompatibilitySuiteSandboxProvider, SuiteVersion: "1.0.0",
		SuiteDigest: provider.SHA256Digest("sha256:" + strings.Repeat("a", 64)),
	}})
	if err != nil {
		return nil, fmt.Errorf("construct pre-advertisement Browser capability snapshot: %w", err)
	}
	return provider.NewStaticCapabilitySource(snapshot)
}

var _ providerapi.BrowserApplication = (*browserProviderApplication)(nil)
var _ usage.EvidenceReader = (*browserusage.Reader)(nil)
