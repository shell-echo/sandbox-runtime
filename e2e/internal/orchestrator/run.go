package orchestrator

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/stack"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
)

const (
	referenceNamespace  = "reference-e2e"
	referenceController = "reference-e2e-controller"
	runRootPrefix       = "sandbox-runtime-e2e-"
	registryImage       = "registry:2"
)

type Options struct {
	ModuleRoot   string
	ProviderRoot string
	EvidenceRoot string
	SourceImage  string
	CallerKind   CallerKind
}

// CallerKind identifies the independently launched caller process used by a
// run. The default remains the co-located reference caller.
type CallerKind string

const (
	CallerReference         CallerKind = "reference"
	CallerPlatformCandidate CallerKind = "agent-platform-candidate"
)

func selectCaller(kind CallerKind) (CallerKind, string, string, string, error) {
	if kind == "" {
		kind = CallerReference
	}
	switch kind {
	case CallerReference:
		return kind, "caller", "./cmd/caller", "reference external-caller P2.5i only; not Agent Platform, aggregate conformance, multi-controller, multi-tenant, deployment, or production readiness", nil
	case CallerPlatformCandidate:
		return kind, "platform-caller", "./cmd/platform-caller", "Agent Platform candidate integration only; not real Veronica, aggregate conformance, multi-controller, hostile multi-tenant, deployment, or production readiness", nil
	default:
		return "", "", "", "", fmt.Errorf("unsupported E2E caller kind %q", kind)
	}
}

type Result struct {
	EvidenceDirectory string
	RuntimeImage      string
	InitialScenarios  int
	ResumeScenarios   int
}

type evidenceManifest struct {
	CreatedAt           string   `json:"created_at"`
	CallerKind          string   `json:"caller_kind"`
	HarnessCommit       string   `json:"harness_commit"`
	ProviderCommit      string   `json:"provider_commit"`
	ContractRevision    string   `json:"contract_revision"`
	ContractTree        string   `json:"contract_tree"`
	SuiteCases          int      `json:"suite_cases"`
	RuntimeImage        string   `json:"runtime_image"`
	RuntimePlatform     string   `json:"runtime_platform"`
	RuntimePreparation  string   `json:"runtime_preparation"`
	StackConfigDigest   string   `json:"stack_config_digest"`
	CallerConfigDigests []string `json:"caller_config_digests"`
	Reports             []string `json:"reports"`
	CandidateReports    []string `json:"candidate_reports,omitempty"`
	CandidateBoundary   string   `json:"candidate_evidence_boundary,omitempty"`
	Commands            []string `json:"commands"`
	EvidenceBoundary    string   `json:"evidence_boundary"`
}

func Run(ctx context.Context, options Options) (_ Result, resultErr error) {
	callerKind, callerBinaryName, callerPackage, evidenceBoundary, err := selectCaller(options.CallerKind)
	if err != nil {
		return Result{}, err
	}
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
	defer func() {
		resultErr = errors.Join(resultErr, cleanupRunRoot(temporaryRoot, runRoot))
	}()
	if err := os.Chmod(runRoot, 0o700); err != nil {
		return Result{}, err
	}

	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		return Result{}, fmt.Errorf("create Docker client: %w", err)
	}
	defer dockerClient.Close()
	if _, err := dockerClient.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true}); err != nil {
		return Result{}, fmt.Errorf("connect to Docker: %w", err)
	}
	if err := cleanupContainers(ctx, dockerClient); err != nil {
		return Result{}, fmt.Errorf("clean stale reference containers: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupContainers(cleanupCtx, dockerClient))
	}()

	sourceImage := options.SourceImage
	if sourceImage == "" {
		sourceImage = "docker.io/library/alpine:3.23"
	}
	binRoot := filepath.Join(runRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o700); err != nil {
		return Result{}, err
	}
	goCache := filepath.Join(runRoot, "go-cache")
	referenceStackBinary := filepath.Join(binRoot, "reference-stack")
	callerBinary := filepath.Join(binRoot, callerBinaryName)
	terminalBrokerBinary := filepath.Join(binRoot, "terminal-broker")
	referenceRuntimeBinary := filepath.Join(binRoot, "reference-runtime")
	if err := build(ctx, moduleRoot, goCache, nil, referenceStackBinary, "./cmd/reference-stack"); err != nil {
		return Result{}, err
	}
	if err := build(ctx, moduleRoot, goCache, nil, callerBinary, callerPackage); err != nil {
		return Result{}, err
	}
	if err := build(ctx, providerRoot, goCache, []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"}, terminalBrokerBinary, "./cmd/terminal-broker"); err != nil {
		return Result{}, err
	}
	if err := build(ctx, moduleRoot, goCache, []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"}, referenceRuntimeBinary, "./cmd/reference-runtime"); err != nil {
		return Result{}, err
	}
	var runtimeImage, runtimeImageReference, runtimeDigest string
	var restoreImage func(context.Context) error
	var imageErr error
	if sourceImage == "local" {
		imageErr = errors.New("local runtime image requested")
	} else {
		runtimeImage, runtimeDigest, restoreImage, imageErr = prepareAMD64Image(ctx, dockerClient, sourceImage)
		if imageErr == nil {
			runtimeImageReference = strings.Split(runtimeImage, "@")[0]
		}
	}
	runtimePreparation := "pulled linux/amd64 image"
	if imageErr != nil {
		runtimeImage, runtimeImageReference, runtimeDigest, restoreImage, err = prepareLocalAMD64Image(ctx, dockerClient, runRoot, referenceRuntimeBinary)
		if err != nil {
			return Result{}, errors.Join(fmt.Errorf("pull configured runtime image: %w", imageErr), fmt.Errorf("build local runtime image: %w", err))
		}
		runtimePreparation = "locally built linux/amd64 scratch image"
		if sourceImage != "local" {
			runtimePreparation += " after registry pull was unavailable"
		}
	}
	defer func() {
		restoreCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupContainers(restoreCtx, dockerClient), restoreImage(restoreCtx))
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
	runtimeDataRoot := filepath.Join(runRoot, "runtime")
	if err := installTerminalBroker(runtimeDataRoot, terminalBrokerBinary); err != nil {
		return Result{}, err
	}
	stateRoot := filepath.Join(runRoot, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return Result{}, err
	}
	tokenA, err := randomSecret("gateway-a-")
	if err != nil {
		return Result{}, err
	}
	tokenB, err := randomSecret("gateway-b-")
	if err != nil {
		return Result{}, err
	}
	adminToken, err := randomSecret("gateway-admin-")
	if err != nil {
		return Result{}, err
	}
	providerRevisionID := "provider-revision-reference-e2e-v1"
	providerAudience := "urn:shell-echo:sandbox-runtime:provider-instance:reference-e2e"
	stackConfig := stack.Config{
		ProviderAddress: providerAddress, GatewayAddress: gatewayAddress,
		ProviderCertificateFile: material.ProviderCertificateFile, ProviderPrivateKeyFile: material.ProviderPrivateKeyFile,
		GatewayCertificateFile: material.GatewayCertificateFile, GatewayPrivateKeyFile: material.GatewayPrivateKeyFile,
		ClientCAFile:      material.CAFile,
		AllowedClientURIs: []string{material.ControllerA.URI, material.ControllerB.URI},
		TrustedJWSKeys: []stack.TrustedJWSKey{
			{ID: material.ControllerA.JWSKeyID, Algorithm: "EdDSA", Path: material.ControllerA.JWSPublicFile},
			{ID: material.ControllerB.JWSKeyID, Algorithm: "EdDSA", Path: material.ControllerB.JWSPublicFile},
		},
		ProviderRevisionID: providerRevisionID, ProviderInstanceAudience: providerAudience,
		StateRoot: stateRoot, RuntimeDataRoot: runtimeDataRoot, RuntimeImage: runtimeImage,
		RuntimeControllerID: referenceController, TerminalBrokerPath: "/inputs/terminal-broker",
		GatewayPrincipals: []stack.GatewayPrincipal{
			{Token: tokenA, CallerID: "reference-caller-a", TenantID: "tenant-e2e-a"},
			{Token: tokenB, CallerID: "reference-caller-b", TenantID: "tenant-e2e-b"},
		},
		GatewayAdminToken: adminToken, GatewayAuditFile: filepath.Join(stateRoot, "gateway-audit.jsonl"),
	}
	stackConfigPath := filepath.Join(secretsRoot, "stack.json")
	stackConfigDigest, err := writeJSON(stackConfigPath, stackConfig)
	if err != nil {
		return Result{}, err
	}
	callerConfig := caller.Config{
		Phase:           caller.PhaseInitial,
		ProviderBaseURL: "https://" + providerAddress, GatewayBaseURL: "https://" + gatewayAddress,
		CAFile: material.CAFile, ProviderRevisionID: providerRevisionID, ProviderInstanceAudience: providerAudience,
		RuntimeImageReference: runtimeImageReference, RuntimeImageDigest: runtimeDigest, GatewayAdminToken: adminToken,
		ControllerA: caller.IdentityConfig{
			ControllerSubject: material.ControllerA.URI, CertificateFile: material.ControllerA.CertificateFile,
			PrivateKeyFile: material.ControllerA.PrivateKeyFile, JWSPrivateKeyFile: material.ControllerA.JWSPrivateFile,
			JWSKeyID: material.ControllerA.JWSKeyID, GatewayToken: tokenA, GatewayCallerID: "reference-caller-a",
			TenantID: "tenant-e2e-a", WorkOrderID: "work-order-e2e-a",
		},
		ControllerB: caller.IdentityConfig{
			ControllerSubject: material.ControllerB.URI, CertificateFile: material.ControllerB.CertificateFile,
			PrivateKeyFile: material.ControllerB.PrivateKeyFile, JWSPrivateKeyFile: material.ControllerB.JWSPrivateFile,
			JWSKeyID: material.ControllerB.JWSKeyID, GatewayToken: tokenB, GatewayCallerID: "reference-caller-b",
			TenantID: "tenant-e2e-b", WorkOrderID: "work-order-e2e-b",
		},
	}
	callerConfigPath := filepath.Join(secretsRoot, "caller.json")
	initialConfigDigest, err := writeJSON(callerConfigPath, callerConfig)
	if err != nil {
		return Result{}, err
	}

	initialStack, err := startStack(referenceStackBinary, stackConfigPath, filepath.Join(evidenceDirectory, "reference-stack-initial.log"))
	if err != nil {
		return Result{}, err
	}
	if err := waitForListeners(ctx, initialStack, providerAddress, gatewayAddress); err != nil {
		_ = initialStack.Stop()
		return Result{}, err
	}
	initialReportPath := filepath.Join(evidenceDirectory, "caller-initial.json")
	initialReport, err := runCaller(ctx, callerBinary, callerConfigPath, initialReportPath, filepath.Join(evidenceDirectory, "caller-initial.log"))
	stopErr := initialStack.Stop()
	if err != nil || stopErr != nil {
		return Result{}, errors.Join(err, stopErr)
	}

	callerConfig.Phase = caller.PhaseResume
	resumeConfigDigest, err := writeJSON(callerConfigPath, callerConfig)
	if err != nil {
		return Result{}, err
	}
	resumeStack, err := startStack(referenceStackBinary, stackConfigPath, filepath.Join(evidenceDirectory, "reference-stack-resume.log"))
	if err != nil {
		return Result{}, err
	}
	if err := waitForListeners(ctx, resumeStack, providerAddress, gatewayAddress); err != nil {
		_ = resumeStack.Stop()
		return Result{}, err
	}
	resumeReportPath := filepath.Join(evidenceDirectory, "caller-resume.json")
	resumeReport, err := runCaller(ctx, callerBinary, callerConfigPath, resumeReportPath, filepath.Join(evidenceDirectory, "caller-resume.log"))
	stopErr = resumeStack.Stop()
	if err != nil || stopErr != nil {
		return Result{}, errors.Join(err, stopErr)
	}
	if err := copyFile(filepath.Join(stateRoot, "gateway-audit.jsonl"), filepath.Join(evidenceDirectory, "gateway-audit.jsonl")); err != nil {
		return Result{}, err
	}
	manifest := evidenceManifest{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), CallerKind: string(callerKind), HarnessCommit: harnessCommit, ProviderCommit: lock.ProviderCommit,
		ContractRevision: lock.ContractRevision, ContractTree: lock.ContractTree, SuiteCases: lock.SuiteCases,
		RuntimeImage: runtimeImage, RuntimePlatform: "linux/amd64", RuntimePreparation: runtimePreparation, StackConfigDigest: stackConfigDigest,
		CallerConfigDigests: []string{initialConfigDigest, resumeConfigDigest},
		Reports:             []string{filepath.Base(initialReportPath), filepath.Base(resumeReportPath)},
		Commands: []string{
			"go build ./cmd/reference-stack", "go build " + callerPackage, "GOOS=linux GOARCH=amd64 go build ./cmd/terminal-broker", "GOOS=linux GOARCH=amd64 go build ./cmd/reference-runtime",
			"reference-stack -config <ephemeral>", callerBinaryName + " -config <ephemeral> (initial)",
			"reference-stack -config <same-state> (reconstructed)", callerBinaryName + " -config <ephemeral> (resume)",
		},
		EvidenceBoundary: evidenceBoundary,
	}
	if callerKind == CallerPlatformCandidate {
		manifest.CandidateReports = []string{filepath.Base(initialReportPath), filepath.Base(resumeReportPath)}
		manifest.CandidateBoundary = evidenceBoundary
	}
	if _, err := writeJSON(filepath.Join(evidenceDirectory, "manifest.json"), manifest); err != nil {
		return Result{}, err
	}
	return Result{
		EvidenceDirectory: evidenceDirectory, RuntimeImage: runtimeImage,
		InitialScenarios: len(initialReport.Scenarios), ResumeScenarios: len(resumeReport.Scenarios),
	}, nil
}

func prepareAMD64Image(ctx context.Context, apiClient *client.Client, source string) (string, string, func(context.Context) error, error) {
	previous, previousErr := apiClient.ImageInspect(ctx, source)
	previousFound := previousErr == nil
	if previousErr != nil && !cerrdefs.IsNotFound(previousErr) {
		return "", "", nil, fmt.Errorf("inspect existing runtime image: %w", previousErr)
	}
	response, err := apiClient.ImagePull(ctx, source, client.ImagePullOptions{Platforms: []ocispec.Platform{{OS: "linux", Architecture: "amd64"}}})
	if err != nil {
		return "", "", nil, fmt.Errorf("pull linux/amd64 runtime image: %w", err)
	}
	if err := response.Wait(ctx); err != nil {
		return "", "", nil, fmt.Errorf("wait for linux/amd64 runtime image: %w", err)
	}
	inspection, err := apiClient.ImageInspect(ctx, source)
	if err != nil {
		return "", "", nil, fmt.Errorf("inspect pulled runtime image: %w", err)
	}
	if inspection.Os != "linux" || inspection.Architecture != "amd64" {
		return "", "", nil, fmt.Errorf("pulled runtime image platform = %s/%s, want linux/amd64", inspection.Os, inspection.Architecture)
	}
	pinned := ""
	for _, candidate := range inspection.RepoDigests {
		candidateInspection, candidateErr := apiClient.ImageInspect(ctx, candidate)
		if candidateErr == nil && candidateInspection.Os == "linux" && candidateInspection.Architecture == "amd64" {
			pinned = candidate
			break
		}
	}
	if pinned == "" {
		return "", "", nil, errors.New("pulled amd64 image has no locally resolvable digest reference")
	}
	digestIndex := strings.LastIndex(pinned, "@sha256:")
	if digestIndex < 0 {
		return "", "", nil, errors.New("runtime image digest reference is invalid")
	}
	digest := pinned[digestIndex+1:]
	restore := func(restoreCtx context.Context) error {
		if !previousFound || previous.ID == inspection.ID {
			return nil
		}
		_, err := apiClient.ImageTag(restoreCtx, client.ImageTagOptions{Source: previous.ID, Target: source})
		return err
	}
	return pinned, digest, restore, nil
}

func prepareLocalAMD64Image(ctx context.Context, apiClient *client.Client, runRoot, runtimeBinary string) (string, string, string, func(context.Context) error, error) {
	buildRoot := filepath.Join(runRoot, "runtime-image")
	if err := os.MkdirAll(buildRoot, 0o700); err != nil {
		return "", "", "", nil, err
	}
	binary, err := os.ReadFile(runtimeBinary)
	if err != nil {
		return "", "", "", nil, err
	}
	if err := os.WriteFile(filepath.Join(buildRoot, "reference-runtime"), binary, 0o555); err != nil {
		return "", "", "", nil, err
	}
	const dockerfile = `FROM scratch
COPY reference-runtime /bin/sh
COPY reference-runtime /bin/e2e-workload
COPY reference-runtime /bin/e2e-shell
USER 65532:65532
WORKDIR /workspace
`
	if err := os.WriteFile(filepath.Join(buildRoot, "Dockerfile"), []byte(dockerfile), 0o600); err != nil {
		return "", "", "", nil, err
	}
	token, err := randomSecret("")
	if err != nil {
		return "", "", "", nil, err
	}
	tag := "shell-echo/sandbox-runtime-e2e-runtime:" + token[:16]
	registry, err := startLocalRegistry(ctx, apiClient)
	if err != nil {
		return "", "", "", nil, err
	}
	registryTag := registry.address + "/sandbox-runtime-e2e/runtime:" + token[:16]
	pinned := ""
	cleanupComplete := false
	cleanupArtifacts := func(cleanupCtx context.Context) error {
		var result error
		for _, image := range []string{registryTag, tag, pinned} {
			if image == "" {
				continue
			}
			_, removeErr := apiClient.ImageRemove(cleanupCtx, image, client.ImageRemoveOptions{Force: true})
			if !cerrdefs.IsNotFound(removeErr) {
				result = errors.Join(result, removeErr)
			}
		}
		result = errors.Join(result, removeLocalRegistry(cleanupCtx, apiClient, registry))
		return result
	}
	defer func() {
		if cleanupComplete {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = cleanupArtifacts(cleanupCtx)
	}()
	command := exec.CommandContext(ctx, "docker", "build", "--platform", "linux/amd64", "--provenance=false", "--tag", tag, buildRoot)
	combined, err := command.CombinedOutput()
	if err != nil {
		return "", "", "", nil, fmt.Errorf("docker build local runtime: %w: %s", err, strings.TrimSpace(string(combined)))
	}
	if _, err := runDockerCommand(ctx, "tag", tag, registryTag); err != nil {
		return "", "", "", nil, fmt.Errorf("tag local runtime for temporary registry: %w", err)
	}
	if _, err := runDockerCommand(ctx, "push", "--platform", "linux/amd64", registryTag); err != nil {
		return "", "", "", nil, fmt.Errorf("push local runtime to temporary registry: %w", err)
	}
	inspection, err := apiClient.ImageInspect(ctx, tag)
	if err != nil {
		return "", "", "", nil, err
	}
	if inspection.Os != "linux" || inspection.Architecture != "amd64" {
		return "", "", "", nil, fmt.Errorf("local runtime image platform = %s/%s, want linux/amd64", inspection.Os, inspection.Architecture)
	}
	for _, candidate := range inspection.RepoDigests {
		candidateInspection, candidateErr := apiClient.ImageInspect(ctx, candidate)
		if candidateErr == nil && candidateInspection.Os == "linux" && candidateInspection.Architecture == "amd64" {
			pinned = candidate
			break
		}
	}
	if pinned == "" {
		return "", "", "", nil, errors.New("locally built amd64 image has no registry-backed digest reference")
	}
	digest, err := imageDigestFromReference(pinned)
	if err != nil {
		return "", "", "", nil, fmt.Errorf("temporary registry image digest reference is invalid: %w", err)
	}
	cleanup := func(cleanupCtx context.Context) error {
		cleanupComplete = true
		return cleanupArtifacts(cleanupCtx)
	}
	cleanupComplete = true
	return pinned, registryTag, digest, cleanup, nil
}

type localRegistry struct {
	address     string
	containerID string
}

func startLocalRegistry(ctx context.Context, apiClient *client.Client) (localRegistry, error) {
	address, err := allocateAddress()
	if err != nil {
		return localRegistry{}, fmt.Errorf("allocate temporary registry address: %w", err)
	}
	token, err := randomSecret("")
	if err != nil {
		return localRegistry{}, err
	}
	name := "sandbox-runtime-e2e-registry-" + token[:16]
	output, err := runDockerCommand(ctx,
		"run", "--detach", "--name", name,
		"--publish", address+":5000",
		"--label", "io.github.shell-echo.sandbox-runtime.managed=true",
		"--label", "io.github.shell-echo.sandbox-runtime.namespace="+referenceNamespace,
		"--label", "io.github.shell-echo.sandbox-runtime.controller-id="+referenceController,
		"--label", "io.github.shell-echo.sandbox-runtime.role=registry",
		registryImage,
	)
	if err != nil {
		return localRegistry{}, fmt.Errorf("start temporary registry: %w", err)
	}
	fields := strings.Fields(output)
	if len(fields) == 0 {
		return localRegistry{}, errors.New("start temporary registry returned no container ID")
	}
	containerID := strings.TrimSpace(fields[0])
	registry := localRegistry{address: address, containerID: containerID}
	if err := waitForRegistry(ctx, address); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = removeLocalRegistry(cleanupCtx, apiClient, registry)
		return localRegistry{}, err
	}
	return registry, nil
}

func removeLocalRegistry(ctx context.Context, apiClient *client.Client, registry localRegistry) error {
	if registry.containerID == "" {
		return nil
	}
	_, err := apiClient.ContainerRemove(ctx, registry.containerID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	if cerrdefs.IsNotFound(err) {
		return nil
	}
	return err
}

func waitForRegistry(ctx context.Context, address string) error {
	return waitForRegistryWithClient(ctx, address, &http.Client{Timeout: 500 * time.Millisecond})
}

func waitForRegistryWithClient(ctx context.Context, address string, httpClient *http.Client) error {
	deadline, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(deadline, http.MethodGet, "http://"+address+"/v2/", nil)
		if err == nil {
			response, requestErr := httpClient.Do(request)
			if requestErr == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
				_ = response.Body.Close()
				if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
					return nil
				}
			}
		}
		select {
		case <-deadline.Done():
			return fmt.Errorf("wait for temporary registry %s: %w", address, deadline.Err())
		case <-ticker.C:
		}
	}
}

func runDockerCommand(ctx context.Context, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if len(detail) > 4096 {
			detail = detail[:4096] + "..."
		}
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, detail)
	}
	return stdout.String(), nil
}

func isImageDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func imageDigestFromReference(reference string) (string, error) {
	digest := reference
	if at := strings.LastIndex(reference, "@"); at >= 0 {
		digest = reference[at+1:]
	}
	if !isImageDigest(digest) {
		return "", errors.New("image reference does not contain a SHA-256 digest")
	}
	return digest, nil
}

func build(ctx context.Context, root, goCache string, additionalEnv []string, output, packagePath string) error {
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", output, packagePath)
	command.Dir = root
	command.Env = append(os.Environ(), "GOCACHE="+goCache)
	command.Env = append(command.Env, additionalEnv...)
	combined, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build %s: %w: %s", packagePath, err, strings.TrimSpace(string(combined)))
	}
	return nil
}

func allocateAddress() (string, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", err
	}
	return address, nil
}

func installTerminalBroker(runtimeRoot, binary string) error {
	sum := sha256.Sum256([]byte(caller.ReferenceSandboxID))
	sandboxRoot := filepath.Join(runtimeRoot, hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(sandboxRoot, 0o700); err != nil {
		return err
	}
	inputs := filepath.Join(sandboxRoot, "inputs")
	if err := os.Mkdir(inputs, 0o700); err != nil {
		return err
	}
	content, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(inputs, "terminal-broker"), content, 0o555); err != nil {
		return err
	}
	return os.Chmod(inputs, 0o555)
}

func randomSecret(prefix string) (string, error) {
	var value [24]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func writeJSON(path string, value any) (string, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

type childProcess struct {
	command *exec.Cmd
	log     *os.File
	done    chan struct{}
	mu      sync.Mutex
	err     error
}

func startStack(binary, config, logPath string) (*childProcess, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	command := exec.Command(binary, "-config", config)
	command.Stdout = logFile
	command.Stderr = logFile
	child := &childProcess{command: command, log: logFile, done: make(chan struct{})}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return nil, err
	}
	go func() {
		err := command.Wait()
		child.mu.Lock()
		child.err = err
		child.mu.Unlock()
		_ = logFile.Close()
		close(child.done)
	}()
	return child, nil
}

func (c *childProcess) Stop() error {
	select {
	case <-c.done:
		return c.result()
	default:
	}
	if err := c.command.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case <-c.done:
		return c.result()
	case <-time.After(15 * time.Second):
		if err := c.command.Process.Kill(); err != nil {
			return err
		}
		<-c.done
		return errors.New("reference stack required forced termination")
	}
}

func (c *childProcess) result() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func waitForListeners(ctx context.Context, child *childProcess, addresses ...string) error {
	deadline := time.Now().Add(20 * time.Second)
	for _, address := range addresses {
		for {
			select {
			case <-child.done:
				return fmt.Errorf("reference stack exited before readiness: %w", child.result())
			default:
			}
			connection, err := net.DialTimeout("tcp4", address, 200*time.Millisecond)
			if err == nil {
				_ = connection.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("listener %s did not become ready: %w", address, err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	return nil
}

func runCaller(ctx context.Context, binary, config, reportPath, logPath string) (caller.Report, error) {
	reportFile, err := os.OpenFile(reportPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return caller.Report{}, err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		_ = reportFile.Close()
		return caller.Report{}, err
	}
	command := exec.CommandContext(ctx, binary, "-config", config)
	command.Stdout = reportFile
	command.Stderr = logFile
	runErr := command.Run()
	closeErr := errors.Join(reportFile.Close(), logFile.Close())
	if runErr != nil || closeErr != nil {
		return caller.Report{}, errors.Join(runErr, closeErr)
	}
	content, err := os.ReadFile(reportPath)
	if err != nil {
		return caller.Report{}, err
	}
	var report caller.Report
	if err := json.Unmarshal(content, &report); err != nil {
		return caller.Report{}, err
	}
	if len(report.Scenarios) == 0 {
		return caller.Report{}, errors.New("caller report has no passed scenarios")
	}
	return report, nil
}

func cleanupContainers(ctx context.Context, apiClient *client.Client) error {
	filters := client.Filters{}
	filters = filters.Add("label", "io.github.shell-echo.sandbox-runtime.managed=true")
	filters = filters.Add("label", "io.github.shell-echo.sandbox-runtime.namespace="+referenceNamespace)
	filters = filters.Add("label", "io.github.shell-echo.sandbox-runtime.controller-id="+referenceController)
	listed, err := apiClient.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return err
	}
	var result error
	for _, container := range listed.Items {
		if container.Labels["io.github.shell-echo.sandbox-runtime.managed"] != "true" ||
			container.Labels["io.github.shell-echo.sandbox-runtime.namespace"] != referenceNamespace ||
			container.Labels["io.github.shell-echo.sandbox-runtime.controller-id"] != referenceController {
			continue
		}
		_, removeErr := apiClient.ContainerRemove(ctx, container.ID, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
		result = errors.Join(result, removeErr)
	}
	return result
}

func cleanupRunRoot(temporaryRoot, runRoot string) error {
	temporaryRoot = filepath.Clean(temporaryRoot)
	runRoot = filepath.Clean(runRoot)
	if filepath.Dir(runRoot) != temporaryRoot || len(filepath.Base(runRoot)) <= len(runRootPrefix) || !strings.HasPrefix(filepath.Base(runRoot), runRootPrefix) {
		return errors.New("refusing to clean an unrecognized E2E run root")
	}
	if err := filepath.WalkDir(runRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.Chmod(path, info.Mode().Perm()|0o700)
	}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("restore E2E run root permissions: %w", err)
	}
	if err := os.RemoveAll(runRoot); err != nil {
		return fmt.Errorf("remove E2E run root: %w", err)
	}
	return nil
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, io.LimitReader(input, 2<<20))
	return errors.Join(copyErr, output.Close())
}
