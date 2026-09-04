package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/stack"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
)

const (
	browserReferenceNamespace       = "reference-browser-e2e"
	browserReferenceController      = "reference-browser-e2e-controller"
	browserListenerReadinessTimeout = 330 * time.Second
)

// RunBrowser launches a Browser-only reference stack and a separately built
// black-box caller in initial and reconstructed phases.
func RunBrowser(ctx context.Context, options Options) (_ Result, resultErr error) {
	moduleRoot, err := filepath.Abs(options.ModuleRoot)
	if err != nil {
		return Result{}, err
	}
	providerRoot, err := filepath.Abs(options.ProviderRoot)
	if err != nil {
		return Result{}, err
	}
	if err := lock.Verify(providerRoot); err != nil {
		return Result{}, err
	}
	harnessCommit, err := lock.HarnessRevision(moduleRoot)
	if err != nil {
		return Result{}, err
	}
	evidenceRoot, err := filepath.Abs(options.EvidenceRoot)
	if err != nil {
		return Result{}, err
	}
	evidenceDirectory := filepath.Join(evidenceRoot, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		return Result{}, err
	}
	temporaryRoot := filepath.Join(moduleRoot, "tmp")
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		return Result{}, err
	}
	runRoot, err := os.MkdirTemp(temporaryRoot, runRootPrefix)
	if err != nil {
		return Result{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupRunRoot(temporaryRoot, runRoot)) }()
	if err := os.Chmod(runRoot, 0o700); err != nil {
		return Result{}, err
	}

	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		return Result{}, fmt.Errorf("create Docker client: %w", err)
	}
	defer dockerClient.Close()
	server, err := dockerClient.ServerVersion(ctx, client.ServerVersionOptions{})
	if err != nil {
		return Result{}, fmt.Errorf("connect to Docker: %w", err)
	}
	architecture := server.Arch
	if architecture != "amd64" && architecture != "arm64" {
		return Result{}, fmt.Errorf("Browser E2E Docker architecture %q is unsupported", architecture)
	}
	if err := cleanupBrowserResources(ctx, dockerClient, browserReferenceNamespace); err != nil {
		return Result{}, err
	}

	binRoot := filepath.Join(runRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o700); err != nil {
		return Result{}, err
	}
	goCache := filepath.Join(runRoot, "go-cache")
	referenceStackBinary := filepath.Join(binRoot, "reference-stack")
	callerBinary := filepath.Join(binRoot, "browser-caller")
	gatewayBinary := filepath.Join(binRoot, "browser-egress-gateway")
	if err := build(ctx, moduleRoot, goCache, nil, referenceStackBinary, "./cmd/reference-stack"); err != nil {
		return Result{}, err
	}
	if err := build(ctx, moduleRoot, goCache, nil, callerBinary, "./cmd/browser-caller"); err != nil {
		return Result{}, err
	}
	if err := build(ctx, providerRoot, goCache, []string{"GOOS=linux", "GOARCH=" + architecture, "CGO_ENABLED=0"}, gatewayBinary, "./cmd/browser-egress-gateway"); err != nil {
		return Result{}, err
	}
	publication := browserimage.LockedPublication()
	if err := ensureBrowserImage(ctx, dockerClient, publication.Image(), architecture); err != nil {
		return Result{}, err
	}
	gatewayImage, cleanupGatewayImage, err := prepareBrowserGatewayImage(ctx, dockerClient, runRoot, gatewayBinary, architecture)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupGatewayImage(cleanupCtx))
	}()
	uplinkName, cleanupUplink, err := createBrowserUplink(ctx, dockerClient, browserReferenceNamespace)
	if err != nil {
		return Result{}, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupUplink(cleanupCtx))
	}()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupBrowserResources(cleanupCtx, dockerClient, browserReferenceNamespace))
	}()

	secretsRoot := filepath.Join(runRoot, "secrets")
	material, err := testenv.GeneratePKI(secretsRoot, time.Now().UTC())
	if err != nil {
		return Result{}, err
	}
	providerAddress, err := allocateAddress()
	if err != nil {
		return Result{}, err
	}
	gatewayAddress, err := allocateAddress()
	if err != nil {
		return Result{}, err
	}
	for gatewayAddress == providerAddress {
		gatewayAddress, err = allocateAddress()
		if err != nil {
			return Result{}, err
		}
	}
	stateRoot := filepath.Join(runRoot, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return Result{}, err
	}
	tokenA, err := randomSecret("browser-gateway-a-")
	if err != nil {
		return Result{}, err
	}
	tokenB, err := randomSecret("browser-gateway-b-")
	if err != nil {
		return Result{}, err
	}
	adminToken, err := randomSecret("browser-gateway-admin-")
	if err != nil {
		return Result{}, err
	}
	ghPath, ghDigest, err := provenanceExecutable()
	if err != nil {
		return Result{}, err
	}
	providerRevisionID := "provider-revision-browser-e2e-v1"
	providerAudience := "urn:shell-echo:sandbox-runtime:provider-instance:browser-e2e"
	stackConfig := stack.Config{
		Profile: stack.ProfileBrowser, ProviderAddress: providerAddress, GatewayAddress: gatewayAddress,
		ProviderCertificateFile: material.ProviderCertificateFile, ProviderPrivateKeyFile: material.ProviderPrivateKeyFile,
		GatewayCertificateFile: material.GatewayCertificateFile, GatewayPrivateKeyFile: material.GatewayPrivateKeyFile,
		ClientCAFile: material.CAFile, AllowedClientURIs: []string{material.ControllerA.URI, material.ControllerB.URI},
		TrustedJWSKeys: []stack.TrustedJWSKey{
			{ID: material.ControllerA.JWSKeyID, Algorithm: "EdDSA", Path: material.ControllerA.JWSPublicFile},
			{ID: material.ControllerB.JWSKeyID, Algorithm: "EdDSA", Path: material.ControllerB.JWSPublicFile},
		},
		ProviderRevisionID: providerRevisionID, ProviderInstanceAudience: providerAudience,
		StateRoot: stateRoot, RuntimeDataRoot: filepath.Join(runRoot, "browser-runtime"), RuntimeImage: publication.Image(),
		RuntimeControllerID: browserReferenceController,
		GatewayPrincipals: []stack.GatewayPrincipal{
			{Token: tokenA, CallerID: "browser-reference-caller-a", TenantID: "tenant-browser-e2e-a"},
			{Token: tokenB, CallerID: "browser-reference-caller-b", TenantID: "tenant-browser-e2e-b"},
		},
		GatewayAdminToken: adminToken, GatewayAuditFile: filepath.Join(stateRoot, "browser-gateway-audit.jsonl"),
		Browser: &stack.BrowserConfig{
			GatewayImage: gatewayImage, UplinkNetwork: uplinkName, Namespace: browserReferenceNamespace,
			RuntimeArchitecture:      architecture,
			ManifestPath:             filepath.Join(providerRoot, "profiles/browser/image/manifest.json"),
			SeccompPath:              filepath.Join(providerRoot, "profiles/browser/image/chromium-seccomp.json"),
			ProvenanceExecutablePath: ghPath, ProvenanceExecutableDigest: ghDigest,
			NetworkPolicyReference: "browser-egress-policy-1", AllowedHosts: []string{"example.com"},
		},
	}
	stackConfigPath := filepath.Join(secretsRoot, "browser-stack.json")
	stackConfigDigest, err := writeJSON(stackConfigPath, stackConfig)
	if err != nil {
		return Result{}, err
	}
	callerConfig := caller.Config{
		Profile: caller.ProfileBrowser, Phase: caller.PhaseInitial,
		ProviderBaseURL: "https://" + providerAddress, GatewayBaseURL: "https://" + gatewayAddress,
		CAFile: material.CAFile, ProviderRevisionID: providerRevisionID, ProviderInstanceAudience: providerAudience,
		RuntimeImageReference: publication.Repository, RuntimeImageDigest: publication.Digest, RuntimeArchitecture: architecture,
		GatewayAdminToken: adminToken,
		ControllerA: caller.IdentityConfig{
			ControllerSubject: material.ControllerA.URI, CertificateFile: material.ControllerA.CertificateFile,
			PrivateKeyFile: material.ControllerA.PrivateKeyFile, JWSPrivateKeyFile: material.ControllerA.JWSPrivateFile,
			JWSKeyID: material.ControllerA.JWSKeyID, GatewayToken: tokenA, GatewayCallerID: "browser-reference-caller-a",
			TenantID: "tenant-browser-e2e-a", WorkOrderID: "work-order-browser-e2e-a",
		},
		ControllerB: caller.IdentityConfig{
			ControllerSubject: material.ControllerB.URI, CertificateFile: material.ControllerB.CertificateFile,
			PrivateKeyFile: material.ControllerB.PrivateKeyFile, JWSPrivateKeyFile: material.ControllerB.JWSPrivateFile,
			JWSKeyID: material.ControllerB.JWSKeyID, GatewayToken: tokenB, GatewayCallerID: "browser-reference-caller-b",
			TenantID: "tenant-browser-e2e-b", WorkOrderID: "work-order-browser-e2e-b",
		},
	}
	callerConfigPath := filepath.Join(secretsRoot, "browser-caller.json")
	initialConfigDigest, err := writeJSON(callerConfigPath, callerConfig)
	if err != nil {
		return Result{}, err
	}

	initialStack, err := startStack(referenceStackBinary, stackConfigPath, filepath.Join(evidenceDirectory, "browser-reference-stack-initial.log"))
	if err != nil {
		return Result{}, err
	}
	if err := waitForListenersWithin(ctx, initialStack, browserListenerReadinessTimeout, providerAddress, gatewayAddress); err != nil {
		_ = initialStack.Stop()
		return Result{}, err
	}
	initialReportPath := filepath.Join(evidenceDirectory, "browser-caller-initial.json")
	initialReport, err := runCaller(ctx, callerBinary, callerConfigPath, initialReportPath, filepath.Join(evidenceDirectory, "browser-caller-initial.log"))
	stopErr := initialStack.Stop()
	if err != nil || stopErr != nil {
		return Result{}, errors.Join(err, stopErr)
	}

	callerConfig.Phase = caller.PhaseResume
	resumeConfigDigest, err := writeJSON(callerConfigPath, callerConfig)
	if err != nil {
		return Result{}, err
	}
	resumeStack, err := startStack(referenceStackBinary, stackConfigPath, filepath.Join(evidenceDirectory, "browser-reference-stack-resume.log"))
	if err != nil {
		return Result{}, err
	}
	if err := waitForListenersWithin(ctx, resumeStack, browserListenerReadinessTimeout, providerAddress, gatewayAddress); err != nil {
		_ = resumeStack.Stop()
		return Result{}, err
	}
	resumeReportPath := filepath.Join(evidenceDirectory, "browser-caller-resume.json")
	resumeReport, err := runCaller(ctx, callerBinary, callerConfigPath, resumeReportPath, filepath.Join(evidenceDirectory, "browser-caller-resume.log"))
	stopErr = resumeStack.Stop()
	if err != nil || stopErr != nil {
		return Result{}, errors.Join(err, stopErr)
	}
	if err := assertBrowserRuntimeResourcesAbsent(ctx, dockerClient, browserReferenceNamespace, browserReferenceController); err != nil {
		return Result{}, err
	}
	if err := cleanupUplink(ctx); err != nil {
		return Result{}, err
	}
	if err := assertBrowserManagedResourcesAbsent(ctx, dockerClient, browserReferenceNamespace); err != nil {
		return Result{}, err
	}
	if err := copyFile(filepath.Join(stateRoot, "browser-gateway-audit.jsonl"), filepath.Join(evidenceDirectory, "browser-gateway-audit.jsonl")); err != nil {
		return Result{}, err
	}
	manifest := evidenceManifest{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), CallerKind: "browser-reference",
		HarnessCommit: harnessCommit, ProviderCommit: lock.ProviderCommit,
		ContractRevision: lock.ContractRevision, ContractTree: lock.ContractTree, SuiteCases: lock.SuiteCases,
		RuntimeImage: publication.Image(), RuntimePlatform: "linux/" + architecture,
		RuntimePreparation: "locked signed Browser image with real GitHub OIDC/Sigstore verification",
		SupportImages:      []string{gatewayImage}, VerifierDigest: ghDigest,
		StackConfigDigest: stackConfigDigest, CallerConfigDigests: []string{initialConfigDigest, resumeConfigDigest},
		Reports: []string{filepath.Base(initialReportPath), filepath.Base(resumeReportPath)},
		Commands: []string{
			"go build ./cmd/reference-stack", "go build ./cmd/browser-caller",
			"GOOS=linux GOARCH=" + architecture + " go build ./cmd/browser-egress-gateway",
			"browser reference-stack -config <ephemeral>", "browser-caller -config <ephemeral> (initial)",
			"browser reference-stack -config <same-state> (reconstructed)", "browser-caller -config <ephemeral> (resume)",
		},
		EvidenceBoundary: "Browser external-caller E2E against an independent reference process; not capability advertisement, aggregate conformance, real Agent Platform, multi-controller, hostile multi-tenant, deployment, or production readiness",
	}
	if _, err := writeJSON(filepath.Join(evidenceDirectory, "manifest.json"), manifest); err != nil {
		return Result{}, err
	}
	return Result{
		EvidenceDirectory: evidenceDirectory, RuntimeImage: publication.Image(),
		InitialScenarios: len(initialReport.Scenarios), ResumeScenarios: len(resumeReport.Scenarios),
	}, nil
}

func provenanceExecutable() (string, string, error) {
	path, err := exec.LookPath("gh")
	if err != nil {
		return "", "", fmt.Errorf("locate gh provenance verifier: %w", err)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", "", err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	digest := sha256.Sum256(content)
	return path, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ensureBrowserImage(ctx context.Context, apiClient *client.Client, reference, architecture string) error {
	inspection, err := apiClient.ImageInspect(ctx, reference)
	if cerrdefs.IsNotFound(err) || (err == nil && (inspection.Os != "linux" || inspection.Architecture != architecture)) {
		platform := "linux/" + architecture
		if architecture == "arm64" {
			platform = "linux/arm64/v8"
		}
		if _, err := runDockerCommand(ctx, "pull", "--platform", platform, reference); err != nil {
			return fmt.Errorf("pull locked Browser image: %w", err)
		}
		inspection, err = apiClient.ImageInspect(ctx, reference)
	}
	if err != nil {
		return fmt.Errorf("inspect locked Browser image: %w", err)
	}
	if inspection.Os != "linux" || inspection.Architecture != architecture {
		return fmt.Errorf("Browser image platform = %s/%s, want linux/%s", inspection.Os, inspection.Architecture, architecture)
	}
	return nil
}

func prepareBrowserGatewayImage(ctx context.Context, apiClient *client.Client, runRoot, binary, architecture string) (string, func(context.Context) error, error) {
	buildRoot := filepath.Join(runRoot, "browser-gateway-image")
	if err := os.MkdirAll(buildRoot, 0o700); err != nil {
		return "", nil, err
	}
	content, err := os.ReadFile(binary)
	if err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(filepath.Join(buildRoot, "browser-egress-gateway"), content, 0o555); err != nil {
		return "", nil, err
	}
	const dockerfile = `FROM scratch
COPY browser-egress-gateway /browser-egress-gateway
LABEL io.github.shell-echo.sandbox-runtime.component="browser-egress-gateway-v1"
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER 65532:65532
WORKDIR /
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=5 CMD ["/browser-egress-gateway", "healthcheck"]
ENTRYPOINT ["/browser-egress-gateway"]
CMD ["serve"]
`
	if err := os.WriteFile(filepath.Join(buildRoot, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		return "", nil, err
	}
	token, err := randomSecret("")
	if err != nil {
		return "", nil, err
	}
	tag := "shell-echo/sandbox-runtime-browser-e2e-gateway:" + token[:16]
	command := exec.CommandContext(ctx, "docker", "build", "--platform", "linux/"+architecture, "--provenance=false", "--tag", tag, buildRoot)
	combined, err := command.CombinedOutput()
	if err != nil {
		return "", nil, fmt.Errorf("build Browser E2E Gateway image: %w: %s", err, strings.TrimSpace(string(combined)))
	}
	cleanup := func(cleanupCtx context.Context) error {
		_, err := apiClient.ImageRemove(cleanupCtx, tag, client.ImageRemoveOptions{Force: true})
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	cleanupFailure := func(cause error) error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return errors.Join(cause, cleanup(cleanupCtx))
	}
	inspection, err := apiClient.ImageInspect(ctx, tag)
	if err != nil {
		return "", nil, cleanupFailure(err)
	}
	if inspection.Os != "linux" || inspection.Architecture != architecture || !isImageDigest(inspection.ID) {
		return "", nil, cleanupFailure(errors.New("Browser Gateway image identity or platform is invalid"))
	}
	return inspection.ID, cleanup, nil
}

func createBrowserUplink(ctx context.Context, apiClient *client.Client, namespace string) (string, func(context.Context) error, error) {
	token, err := randomSecret("")
	if err != nil {
		return "", nil, err
	}
	name := "sandbox-runtime-browser-e2e-uplink-" + token[:16]
	enableIPv4, enableIPv6 := true, false
	created, err := apiClient.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge", Scope: "local", EnableIPv4: &enableIPv4, EnableIPv6: &enableIPv6,
		Labels: map[string]string{
			"io.github.shell-echo.sandbox-runtime.managed":   "true",
			"io.github.shell-echo.sandbox-runtime.owner":     "browser-egress-uplink",
			"io.github.shell-echo.sandbox-runtime.namespace": namespace,
		},
	})
	if err != nil {
		return "", nil, err
	}
	cleanup := func(cleanupCtx context.Context) error {
		_, err := apiClient.NetworkRemove(cleanupCtx, created.ID, client.NetworkRemoveOptions{})
		if cerrdefs.IsNotFound(err) {
			return nil
		}
		return err
	}
	return name, cleanup, nil
}

func cleanupBrowserResources(ctx context.Context, apiClient *client.Client, namespace string) error {
	filters := make(client.Filters).
		Add("label", "io.github.shell-echo.sandbox-runtime.managed=true").
		Add("label", "io.github.shell-echo.sandbox-runtime.namespace="+namespace)
	containers, err := apiClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return err
	}
	var result error
	for _, item := range containers.Items {
		_, removeErr := apiClient.ContainerRemove(ctx, item.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
		result = errors.Join(result, removeErr)
	}
	networks, err := apiClient.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil {
		return errors.Join(result, err)
	}
	for _, item := range networks.Items {
		_, removeErr := apiClient.NetworkRemove(ctx, item.ID, client.NetworkRemoveOptions{})
		result = errors.Join(result, removeErr)
	}
	return result
}

func assertBrowserRuntimeResourcesAbsent(ctx context.Context, apiClient *client.Client, namespace, controller string) error {
	filters := make(client.Filters).
		Add("label", "io.github.shell-echo.sandbox-runtime.managed=true").
		Add("label", "io.github.shell-echo.sandbox-runtime.namespace="+namespace).
		Add("label", "io.github.shell-echo.sandbox-runtime.controller-id="+controller)
	containers, err := apiClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return err
	}
	networks, err := apiClient.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil {
		return err
	}
	if len(containers.Items) != 0 || len(networks.Items) != 0 {
		return fmt.Errorf("Browser runtime resources remain after expiry cleanup: containers=%d networks=%d", len(containers.Items), len(networks.Items))
	}
	return nil
}

func assertBrowserManagedResourcesAbsent(ctx context.Context, apiClient *client.Client, namespace string) error {
	filters := make(client.Filters).
		Add("label", "io.github.shell-echo.sandbox-runtime.managed=true").
		Add("label", "io.github.shell-echo.sandbox-runtime.namespace="+namespace)
	containers, err := apiClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return err
	}
	networks, err := apiClient.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
	if err != nil {
		return err
	}
	if len(containers.Items) != 0 || len(networks.Items) != 0 {
		return fmt.Errorf("Browser E2E managed resources remain after harness cleanup: containers=%d networks=%d", len(containers.Items), len(networks.Items))
	}
	return nil
}
