package qualificationoperator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/providercontract"
	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationarchive"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationsupervisor"
)

var ErrQualificationRun = errors.New("external-caller qualification execution failed")

type RunConfiguration struct {
	SourceRoot             string
	RunRoot                string
	ProviderExecutable     string
	OperatorExecutable     string
	CandidateDirectory     string
	ProviderSourceRevision string
	ExternalSourceRevision string
	DockerSocket           string
}

type ExecutionCheckpoint struct {
	FormatVersion           int                                             `json:"format_version"`
	CheckpointType          string                                          `json:"checkpoint_type"`
	ProfileID               string                                          `json:"profile_id"`
	ProfileVersion          string                                          `json:"profile_version"`
	ProfileDigest           string                                          `json:"profile_digest"`
	StaticConfiguration     string                                          `json:"static_configuration_digest"`
	RuntimeCommitment       string                                          `json:"runtime_commitment_digest"`
	Initial                 qualificationharness.InitialPhaseResult         `json:"initial_phase"`
	Reconstruction          qualificationharness.ReconstructionPhaseResult  `json:"reconstruction_phase"`
	Observation             qualificationharness.ExecutionObservationResult `json:"execution_observation"`
	Cleanup                 qualificationharness.CleanupResult              `json:"cleanup"`
	EvidenceFinalization    qualificationharness.EvidenceFinalizationResult `json:"evidence_finalization"`
	AdapterTranscriptDigest string                                          `json:"adapter_transcript_digest"`
	CompletedAt             time.Time                                       `json:"completed_at"`
}

type RunResult struct {
	CheckpointPath   string
	CheckpointDigest string
	Checkpoint       ExecutionCheckpoint
	EvidenceRoot     string
	Evidence         qualificationharness.EvidenceFinalizationResult
	Archive          qualificationarchive.Result
	EnvelopePath     string
	EnvelopeDigest   string
}

type staticIdentityObserver struct {
	observation qualificationharness.RuntimeObservation
}

func (o staticIdentityObserver) Observe(context.Context) (qualificationharness.RuntimeObservation, error) {
	return o.observation, nil
}

type providerManager struct {
	mu            sync.Mutex
	configuration ProviderConfiguration
	processes     *ProcessObserver
	process       *ProviderProcess
	occurrence    int
}

func (m *providerManager) Start(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.process != nil {
		return "", ErrProviderProcess
	}
	process, err := StartProvider(ctx, m.configuration)
	if err != nil {
		return "", fmt.Errorf("%w: process-start", ErrProviderProcess)
	}
	m.process = process
	m.occurrence++
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = m.processes.WaitOccurrence(wait, "provider", m.occurrence)
	cancel()
	if err != nil {
		_ = process.Stop()
		m.process = nil
		return "", fmt.Errorf("%w: process-observation", ErrProviderProcess)
	}
	return randomLabel("provider-process-")
}

func (m *providerManager) Restart(ctx context.Context) (string, error) {
	if err := m.Stop(); err != nil {
		return "", err
	}
	return m.Start(ctx)
}

func (m *providerManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.process == nil {
		return nil
	}
	process := m.process
	m.process = nil
	return process.Stop()
}

func Run(ctx context.Context, configuration RunConfiguration) (_ RunResult, resultErr error) {
	if ctx == nil || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || !validRunConfiguration(configuration) {
		return RunResult{}, ErrQualificationRun
	}
	if err := ctx.Err(); err != nil {
		return RunResult{}, errors.Join(ErrQualificationRun, err)
	}
	if err := os.Mkdir(configuration.RunRoot, 0o700); err != nil {
		return RunResult{}, ErrQualificationRun
	}
	paths, err := prepareRunPaths(configuration.RunRoot)
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	profileDocument, err := os.ReadFile(filepath.Join(configuration.SourceRoot, qualificationprofile.ProfilePath))
	if err != nil || len(profileDocument) == 0 || os.WriteFile(paths.profile, profileDocument, 0o400) != nil || os.Chmod(paths.profile, 0o400) != nil {
		return RunResult{}, qualificationStage("profile-snapshot", err)
	}

	adapterPath := filepath.Join(configuration.CandidateDirectory, "qualification-adapter")
	callerPath := filepath.Join(configuration.CandidateDirectory, "external-caller")
	gatewayPath := filepath.Join(configuration.CandidateDirectory, "caller-gateway")
	digests := make(map[string]string, 5)
	for id, path := range map[string]string{
		"provider": configuration.ProviderExecutable, "qualification_adapter": adapterPath,
		"external_caller": callerPath, "caller_gateway": gatewayPath, "operator": configuration.OperatorExecutable,
	} {
		digest, _, digestErr := digestFile(path, qualificationsupervisor.MaxExecutableBytes)
		if digestErr != nil {
			return RunResult{}, ErrQualificationRun
		}
		digests[id] = digest
	}
	for id, path := range map[string]string{
		"candidate_manifest": filepath.Join(filepath.Dir(configuration.CandidateDirectory), "release-manifest.json"),
		"candidate_source":   filepath.Join(filepath.Dir(configuration.CandidateDirectory), "source.tar"),
	} {
		digest, _, digestErr := digestFile(path, 64<<20)
		if digestErr != nil {
			return RunResult{}, ErrQualificationRun
		}
		digests[id] = digest
	}

	providerPort, err := availablePort("127.0.0.1")
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	providerProxyPort, err := availablePort("127.0.0.1")
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	apiPort, err := availablePort("127.0.0.1")
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	gatewayPort, err := availablePort("127.0.0.1")
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	gatewayHost := "gateway.qual.test"
	providerOrigin := "https://" + address(providerProxyPort)
	gatewayEndpoint := fmt.Sprintf("https://%s:%d/terminal", gatewayHost, gatewayPort)

	preparedConfiguration, err := qualificationsupervisor.PrepareConfiguration(ctx, qualificationsupervisor.LocationConfiguration{
		ProfilePath: paths.profile, ProviderOrigin: providerOrigin,
		GatewayProbeEndpoint: gatewayEndpoint, CallerStateRoot: paths.supervisorCallerState,
		WorkingDirectory: paths.work, EvidenceRoot: paths.supervisorEvidence,
	})
	if err != nil {
		return RunResult{}, qualificationStage("supervisor-configuration", err)
	}
	locationFiles, err := qualificationsupervisor.OpenLocationFiles(ctx, preparedConfiguration)
	if err != nil {
		return RunResult{}, qualificationStage("supervisor-location-files", err)
	}
	executable, err := qualificationsupervisor.OpenExecutable(ctx, preparedConfiguration, adapterPath, digests["qualification_adapter"], qualificationsupervisor.MaxExecutableBytes)
	if err != nil {
		_ = locationFiles.Close()
		return RunResult{}, qualificationStage("supervisor-executable", err)
	}
	preflight, err := qualificationsupervisor.FinalizePreflight(ctx, preparedConfiguration, locationFiles, executable)
	if err != nil {
		_ = locationFiles.Close()
		_ = executable.Close()
		return RunResult{}, qualificationStage("supervisor-preflight", err)
	}
	defer func() { resultErr = errors.Join(resultErr, preflight.Close()) }()
	codec, err := protocol.NewCodec(ctx, configuration.SourceRoot)
	if err != nil {
		return RunResult{}, qualificationStage("protocol-codec", err)
	}

	namespace, err := randomLabel("qualification-")
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	controller, err := randomLabel("controller-")
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	static, err := freezeConfiguration(ctx, configuration.SourceRoot, preflight.Digest(), digests, namespace)
	if err != nil {
		return RunResult{}, err
	}
	frozen, observation, teardownArtifactDigest, teardownConfigurationDigest, err := runtimeIdentity(configuration, static, digests)
	if err != nil {
		return RunResult{}, err
	}

	processes, err := StartProcessObserver(ctx, map[string]string{
		"provider": configuration.ProviderExecutable, "external_caller": callerPath,
		"qualification_adapter": adapterPath, "caller_gateway": gatewayPath,
	})
	if err != nil {
		return RunResult{}, qualificationStage("process-observer-start", err)
	}
	defer func() { resultErr = errors.Join(resultErr, processes.Close()) }()

	manager := &providerManager{processes: processes}
	resources, err := NewDockerResources(configuration.DockerSocket, namespace, controller, teardownArtifactDigest, teardownConfigurationDigest, frozen.RuntimeLimits(), manager.Stop)
	if err != nil {
		return RunResult{}, qualificationStage("resource-inspector-prepare", err)
	}
	emergency := true
	defer func() {
		if emergency {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			resultErr = errors.Join(resultErr, resources.EmergencyCleanup(cleanup))
			cancel()
		}
	}()
	prepared, err := qualificationharness.PrepareRuntime(ctx, frozen, qualificationharness.RuntimeInput{
		OwnershipSelectorDigest: mustCanonicalDigest(map[string]any{"namespace": namespace, "controller": controller}),
		PersistentStateRoot:     paths.harnessState,
	}, staticIdentityObserver{observation: observation}, resources)
	if err != nil {
		return RunResult{}, qualificationStage("runtime-preflight", err)
	}

	credentials, err := PrepareCredentials(paths.credentials, gatewayHost, time.Now().UTC())
	if err != nil {
		return RunResult{}, qualificationStage("credential-preparation", err)
	}
	defer credentials.Destroy()
	manager.configuration = ProviderConfiguration{
		Executable: configuration.ProviderExecutable, ConfigurationFile: filepath.Join(paths.providerState, "provider.toml"),
		StateRoot: paths.providerState, RuntimeStateRoot: paths.runtimeState, ProviderPort: providerPort, APIPort: apiPort,
		Namespace: namespace, ControllerID: controller, Credentials: credentials,
	}
	if err := PrepareProviderConfiguration(manager.configuration); err != nil {
		return RunResult{}, qualificationStage("provider-configuration", err)
	}
	dns, err := StartRotatingDNS("127.0.0.1:53", gatewayHost)
	if err != nil {
		return RunResult{}, qualificationStage("dns-observer-start", err)
	}
	defer dns.Close()
	proxy, err := StartObservationProxy(address(providerProxyPort), address(gatewayPort), "https://"+address(providerPort), net.JoinHostPort("127.0.0.2", fmt.Sprint(gatewayPort)), gatewayHost, credentials, dns.UsePrivate)
	if err != nil {
		return RunResult{}, qualificationStage("network-observers-start", err)
	}
	defer proxy.Close()
	routing, err := NewGatewayRouting(dns, processes, net.JoinHostPort("127.0.0.2", fmt.Sprint(gatewayPort)))
	if err != nil {
		return RunResult{}, qualificationStage("gateway-routing-prepare", err)
	}
	initialProviderIdentity, err := manager.Start(ctx)
	if err != nil {
		return RunResult{}, qualificationStage("provider-initial-start", err)
	}
	executor, err := NewPhaseExecutor(preflight, codec, credentials, manager, routing, initialProviderIdentity)
	if err != nil {
		return RunResult{}, qualificationStage("phase-executor-prepare", err)
	}
	initial, err := qualificationharness.RunInitial(ctx, prepared, executor)
	if err != nil {
		// The candidate process can fail immediately after closing its final
		// Provider connection. Drain in-flight proxy handlers before projecting
		// the sanitized diagnostic, otherwise the failure summary races the
		// observation append performed by the handler defer.
		_ = proxy.Close()
		progress := executor.Progress("initial")
		lastCase := "none"
		if len(progress) != 0 {
			lastCase = progress[len(progress)-1].CaseID
		}
		return RunResult{}, fmt.Errorf("%w: initial-phase: %v; adapter_error=%s; progress=%d; last_completed_case=%s; process_counts=%v; observations=%s", ErrQualificationRun, err, executor.TerminalErrorCode("initial"), len(progress), lastCase, processes.Counts(), proxy.SafeSummary())
	}
	reconstruction, err := qualificationharness.RunReconstruction(ctx, prepared, executor)
	if err != nil {
		_ = proxy.Close()
		progress := executor.Progress("reconstruction")
		lastCase := "none"
		if len(progress) != 0 {
			lastCase = progress[len(progress)-1].CaseID
		}
		return RunResult{}, fmt.Errorf("%w: reconstruction-phase: %v; adapter_error=%s; progress=%d; last_completed_case=%s; process_counts=%v; observations=%s", ErrQualificationRun, err, executor.TerminalErrorCode("reconstruction"), len(progress), lastCase, processes.Counts(), proxy.SafeSummary())
	}

	transcript, err := finalizeTranscript(preflight, executor, digests, static)
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	report, err := qualificationprofile.VerifyCodingShellV1(ctx, configuration.SourceRoot)
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	contract, err := providercontract.Load(ctx, filepath.Join(configuration.SourceRoot, "compatibility/sandbox-runtime/contract.lock.json"), configuration.SourceRoot)
	if err != nil {
		return RunResult{}, qualificationStage("provider-contract-projection", err)
	}
	bundle, err := NewObserverBundle(ObserverBundleInput{
		RuntimeDigest: prepared.Digest(), Observation: prepared.Observation(), Limits: prepared.RuntimeLimits(),
		Plan: report.ObservationPlan(), Reconstruction: report.Reconstruction(), Proxy: proxy, Executor: executor,
		Processes: processes, Resources: resources, Transcript: transcript, Contract: contract,
	})
	if err != nil {
		return RunResult{}, ErrQualificationRun
	}
	observed, err := qualificationharness.ObserveExecution(ctx, prepared, qualificationharness.ExecutionObservers{
		Provider: bundle, Gateway: bundle, Processes: bundle, Resources: bundle,
	})
	if err != nil {
		return RunResult{}, fmt.Errorf("%w: observation: %v; observation_stage=%s; process_counts=%v; observations=%s", ErrQualificationRun, err, bundle.SafeFailureStage(), processes.Counts(), proxy.SafeSummary())
	}
	cleanup, err := qualificationharness.RunCleanup(ctx, prepared, resources, resources)
	if err != nil || cleanup.Outcome != qualificationharness.CleanupOutcomeSucceeded {
		return RunResult{}, errors.Join(ErrQualificationRun, err)
	}
	emergency = false
	if processes.Emulated() {
		return RunResult{}, qualificationStage("emulated-target-not-qualifying", nil)
	}
	assemblyInput, trustedInputs, err := finalAssemblyInput(configuration, transcript, executor, digests, static, frozen)
	if err != nil {
		return RunResult{}, qualificationStage("evidence-assembly-input", err)
	}
	finalization, err := qualificationharness.FinalizeEvidence(ctx, prepared, qualificationreport.RootAssembler{
		SourceRoot: configuration.SourceRoot, EvidenceRoot: paths.supervisorEvidence, Input: assemblyInput,
	})
	if err != nil || finalization.RunOutcome != qualificationharness.DerivedPassed || finalization.ValidationOutcome != "accepted" {
		return RunResult{}, qualificationStage("evidence-finalization", err)
	}
	retained, err := qualificationreport.VerifyRetained(ctx, paths.supervisorEvidence, configuration.SourceRoot)
	if err != nil || !retainedMatchesFinalization(retained, finalization) {
		return RunResult{}, qualificationStage("retained-evidence-verification", err)
	}
	profileID, profileVersion, profileDigest := frozen.ProfileIdentity()
	checkpoint := ExecutionCheckpoint{
		FormatVersion: 1, CheckpointType: "sandbox-runtime-external-caller-execution-checkpoint-v1",
		ProfileID: profileID, ProfileVersion: profileVersion, ProfileDigest: profileDigest,
		StaticConfiguration: frozen.Digest(), RuntimeCommitment: prepared.Digest(), Initial: initial,
		Reconstruction: reconstruction, Observation: observed, Cleanup: cleanup, EvidenceFinalization: finalization,
		AdapterTranscriptDigest: transcript.Digest, CompletedAt: time.Now().UTC(),
	}
	checkpointPath := filepath.Join(configuration.RunRoot, "execution-checkpoint.json")
	document, err := json.MarshalIndent(checkpoint, "", "  ")
	checkpointBytes := append(document, '\n')
	if err != nil || writeExclusive(checkpointPath, checkpointBytes) != nil {
		return RunResult{}, ErrQualificationRun
	}
	checkpointDigest := rawSHA256(checkpointBytes)
	archivePath := filepath.Join(configuration.RunRoot, "qualification-evidence.tar")
	archive, err := qualificationarchive.Create(ctx, paths.supervisorEvidence, archivePath)
	if err != nil {
		return RunResult{}, qualificationStage("evidence-archive", err)
	}
	envelopePath := filepath.Join(configuration.RunRoot, "qualification-result.json")
	envelopeDigest, err := qualificationarchive.WriteEnvelope(envelopePath, qualificationarchive.EnvelopeInput{
		ProfileID: profileID, ProfileVersion: profileVersion, ProfileDigest: profileDigest,
		ProviderRevision: configuration.ProviderSourceRevision, ExternalRevision: configuration.ExternalSourceRevision,
		CheckpointPath: checkpointPath, CheckpointDigest: checkpointDigest, Archive: archive, Evidence: retained,
		TrustedInputs: trustedInputs, CompletedAt: time.Now().UTC(),
	})
	if err != nil {
		return RunResult{}, qualificationStage("qualification-result-envelope", err)
	}
	verifiedBundle, err := qualificationarchive.VerifyBundle(ctx, configuration.SourceRoot, checkpointPath, archivePath, envelopePath)
	if err != nil || verifiedBundle.EnvelopeDigest != envelopeDigest || verifiedBundle.ArchiveDigest != archive.Digest || verifiedBundle.Evidence != retained {
		return RunResult{}, qualificationStage("qualification-bundle-verification", err)
	}
	return RunResult{
		CheckpointPath: checkpointPath, CheckpointDigest: checkpointDigest, Checkpoint: checkpoint,
		EvidenceRoot: paths.supervisorEvidence, Evidence: finalization, Archive: archive,
		EnvelopePath: envelopePath, EnvelopeDigest: envelopeDigest,
	}, nil
}

type runPaths struct {
	profile, work, supervisorEvidence, supervisorCallerState, harnessState string
	credentials, providerState, runtimeState                               string
}

func prepareRunPaths(root string) (runPaths, error) {
	paths := runPaths{
		profile: filepath.Join(root, "qualification-profile.json"), work: filepath.Join(root, "work"), supervisorEvidence: filepath.Join(root, "supervisor-evidence"),
		supervisorCallerState: filepath.Join(root, "supervisor-state", "caller"), harnessState: filepath.Join(root, "persistent", "stores"),
		credentials: filepath.Join(root, "credentials"), providerState: filepath.Join(root, "persistent", "stores", qualificationharness.ProviderLocalState),
		runtimeState: filepath.Join(root, "persistent", "stores", qualificationharness.RuntimeResourceState),
	}
	for _, path := range []string{paths.work, paths.supervisorEvidence, filepath.Dir(paths.supervisorCallerState), filepath.Dir(paths.harnessState)} {
		if err := os.MkdirAll(path, 0o700); err != nil || os.Chmod(path, 0o700) != nil {
			return runPaths{}, ErrQualificationRun
		}
	}
	return paths, nil
}

func freezeConfiguration(ctx context.Context, sourceRoot, adapterDigest string, digests map[string]string, namespace string) (qualificationharness.Configuration, error) {
	component := func(name string, value any) string {
		return mustCanonicalDigest(map[string]any{"component": name, "configuration": value})
	}
	configuration := qualificationharness.Configuration{
		Architecture:       "linux/amd64",
		TargetDigest:       mustCanonicalDigest(map[string]any{"target": "dedicated-disposable-docker-runner", "architecture": "linux/amd64"}),
		RunNamespaceDigest: mustCanonicalDigest(map[string]any{"namespace": namespace}),
		ComponentConfigurations: qualificationharness.ComponentConfigurationDigests{
			Provider:  component("provider", map[string]any{"revision": ProviderRevision, "runtime_image": CodingShellImage, "protected_admission": true}),
			Caller:    component("external_caller", map[string]any{"executable_digest": digests["external_caller"], "credential_channels": 8}),
			Adapter:   adapterDigest,
			Gateway:   component("caller_gateway", map[string]any{"executable_digest": digests["caller_gateway"], "transport": "mtls-http1-connect"}),
			Observer:  component("observers", map[string]any{"provider": "mtls-reverse-proxy-v1", "gateway": "mtls-connect-proxy-v1"}),
			Inspector: component("resource_inspector", map[string]any{"engine": "docker-unix-api", "selector": "namespace-and-controller-labels"}),
			Teardown:  component("teardown", map[string]any{"engine": "docker-unix-api", "force": true, "selector": "namespace-and-controller-labels"}),
		},
	}
	if _, err := qualificationharness.Freeze(ctx, sourceRoot, configuration); err != nil {
		return qualificationharness.Configuration{}, ErrQualificationRun
	}
	return configuration, nil
}

func runtimeIdentity(configuration RunConfiguration, static qualificationharness.Configuration, digests map[string]string) (*qualificationharness.FrozenConfiguration, qualificationharness.RuntimeObservation, string, string, error) {
	frozen, err := qualificationharness.Freeze(context.Background(), configuration.SourceRoot, static)
	if err != nil {
		return nil, qualificationharness.RuntimeObservation{}, "", "", ErrQualificationRun
	}
	requirements := frozen.ArtifactRequirements()
	artifacts := make([]qualificationharness.ArtifactObservation, len(requirements))
	for index, requirement := range requirements {
		digest := digests["operator"]
		source := &qualificationharness.SourceIdentity{Kind: "source-revision", Value: configuration.ProviderSourceRevision, Immutable: true}
		switch requirement.ArtifactID {
		case "provider":
			digest = digests["provider"]
		case "external_caller", "qualification_adapter", "caller_gateway":
			digest = digests[requirement.ArtifactID]
			source = &qualificationharness.SourceIdentity{Kind: "source-revision", Value: configuration.ExternalSourceRevision, Immutable: true}
		case "runtime_image":
			digest = "sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1"
			source = &qualificationharness.SourceIdentity{Kind: "oci-digest", Value: digest, Immutable: true}
		}
		artifacts[index] = qualificationharness.ArtifactObservation{
			ArtifactID: requirement.ArtifactID, Owner: requirement.Owner, TrustDomain: requirement.TrustDomain,
			DigestSubject: requirement.DigestSubject, Digest: digest, ObservedBy: requirement.ObservedBy, Source: source,
		}
	}
	expectations := frozen.ConfigurationExpectations()
	configs := make([]qualificationharness.ConfigurationObservation, len(expectations))
	for index, expectation := range expectations {
		configs[index] = qualificationharness.ConfigurationObservation{
			ID: expectation.ID, Digest: expectation.Digest, DigestProfile: expectation.DigestProfile, Sanitized: true, ObservedBy: "process_supervisor",
		}
	}
	observation := qualificationharness.RuntimeObservation{
		DedicatedDisposableTarget: true, RunUniqueNamespace: true, Target: frozen.TargetIdentity(), Artifacts: artifacts, Configurations: configs,
	}
	teardownDigest := ""
	for _, artifact := range artifacts {
		if artifact.ArtifactID == "teardown" {
			teardownDigest = artifact.Digest
		}
	}
	teardownConfig := ""
	for _, config := range configs {
		if config.ID == "teardown_configuration" {
			teardownConfig = config.Digest
		}
	}
	return frozen, observation, teardownDigest, teardownConfig, nil
}

func finalizeTranscript(preflight *qualificationsupervisor.FrozenPreflight, executor *PhaseExecutor, digests map[string]string, static qualificationharness.Configuration) (protocol.TranscriptProjection, error) {
	phase := func(id string) (protocol.TranscriptSupervisorPhase, error) {
		evidence, ok := executor.Evidence(id)
		labels := executor.PlannedProcesses(id)
		if !ok || len(labels) != 4 {
			return protocol.TranscriptSupervisorPhase{}, ErrQualificationRun
		}
		return protocol.TranscriptSupervisorPhase{
			ProcessIdentities: protocol.TranscriptComponents{
				Provider: labels["provider"], ExternalCaller: labels["external_caller"], QualificationAdapter: labels["qualification_adapter"], CallerGateway: labels["caller_gateway"],
			},
			ExecutableDigests: protocol.TranscriptComponents{
				Provider: digests["provider"], ExternalCaller: digests["external_caller"], QualificationAdapter: digests["qualification_adapter"], CallerGateway: digests["caller_gateway"],
			},
			ConfigurationDigests: protocol.TranscriptComponents{
				Provider: static.ComponentConfigurations.Provider, ExternalCaller: static.ComponentConfigurations.Caller,
				QualificationAdapter: static.ComponentConfigurations.Adapter, CallerGateway: static.ComponentConfigurations.Gateway,
			},
			StderrWireBytes: evidence.AdapterStderrWireBytes, CredentialPayloadTotalBytes: evidence.Delivery.CredentialPayloadBytes,
		}, nil
	}
	initial, err := phase("initial")
	if err != nil {
		return protocol.TranscriptProjection{}, err
	}
	reconstruction, err := phase("reconstruction")
	if err != nil {
		return protocol.TranscriptProjection{}, err
	}
	return preflight.FinalizeTranscript(initial, reconstruction)
}

func finalAssemblyInput(configuration RunConfiguration, transcript protocol.TranscriptProjection, executor *PhaseExecutor, digests map[string]string, static qualificationharness.Configuration, frozen *qualificationharness.FrozenConfiguration) (qualificationreport.AssemblyInput, []qualificationarchive.TrustedInputSubject, error) {
	if executor == nil || frozen == nil || len(transcript.Document) == 0 {
		return qualificationreport.AssemblyInput{}, nil, ErrQualificationRun
	}
	timings := make([]qualificationreport.ScenarioTimingInput, 0, 20)
	assertions := make([]qualificationreport.CallerAssertionInput, 0, 29)
	for _, phase := range []struct {
		id    string
		count int
	}{{id: "initial", count: 15}, {id: "reconstruction", count: 5}} {
		evidence := executor.ScenarioEvidence(phase.id)
		if len(evidence) != phase.count {
			return qualificationreport.AssemblyInput{}, nil, ErrQualificationRun
		}
		for _, scenario := range evidence {
			if scenario.Disposition != "completed" || scenario.StartedAt.IsZero() || scenario.FinishedAt.Before(scenario.StartedAt) {
				return qualificationreport.AssemblyInput{}, nil, ErrQualificationRun
			}
			timings = append(timings, qualificationreport.ScenarioTimingInput{
				CaseID: scenario.CaseID, PhaseID: phase.id,
				StartedAt: scenario.StartedAt.UTC(), FinishedAt: scenario.FinishedAt.UTC(),
			})
			for _, assertion := range scenario.CallerAssertions {
				assertions = append(assertions, qualificationreport.CallerAssertionInput{
					AssertionID: assertion.AssertionID, Result: assertion.Result,
				})
			}
		}
	}
	if len(assertions) != 29 {
		return qualificationreport.AssemblyInput{}, nil, ErrQualificationRun
	}
	target := frozen.TargetIdentity()
	topologyDigest, err := canonicalSHA256(frozen.Topology())
	if err != nil {
		return qualificationreport.AssemblyInput{}, nil, ErrQualificationRun
	}
	statements := []struct {
		id        string
		source    string
		statement map[string]any
	}{
		{id: "external-caller-ownership", source: "external_caller_owner", statement: map[string]any{
			"repository": "github.com/shell-echo/sandbox-runtime-external-caller", "source_revision": configuration.ExternalSourceRevision,
			"external_caller_digest": digests["external_caller"], "qualification_adapter_digest": digests["qualification_adapter"], "caller_gateway_digest": digests["caller_gateway"],
		}},
		{id: "source-hosting", source: "external_caller_owner", statement: map[string]any{
			"repository": "github.com/shell-echo/sandbox-runtime-external-caller", "source_revision": configuration.ExternalSourceRevision,
			"source_archive_digest": digests["candidate_source"],
		}},
		{id: "build-system", source: "external_caller_owner", statement: map[string]any{
			"release_manifest_digest": digests["candidate_manifest"], "source_archive_digest": digests["candidate_source"],
			"qualification_adapter_digest": digests["qualification_adapter"], "external_caller_digest": digests["external_caller"], "caller_gateway_digest": digests["caller_gateway"],
		}},
		{id: "operating-system", source: "qualification_operator", statement: map[string]any{
			"goos": runtime.GOOS, "goarch": runtime.GOARCH, "target_digest": target.TargetDigest,
			"provider_source_revision": configuration.ProviderSourceRevision,
		}},
		{id: "network-path", source: "qualification_operator", statement: map[string]any{
			"observer_configuration_digest": static.ComponentConfigurations.Observer,
			"gateway_configuration_digest":  static.ComponentConfigurations.Gateway,
			"topology_configuration_digest": topologyDigest,
		}},
	}
	trusted := make([]qualificationreport.TrustedInputStatementInput, len(statements))
	subjects := make([]qualificationarchive.TrustedInputSubject, len(statements))
	for index, statement := range statements {
		digest, err := canonicalSHA256(statement.statement)
		if err != nil {
			return qualificationreport.AssemblyInput{}, nil, ErrQualificationRun
		}
		trusted[index] = qualificationreport.TrustedInputStatementInput{
			InputID: statement.id, Source: statement.source, SubjectDigest: digest,
		}
		subjects[index] = qualificationarchive.TrustedInputSubject{
			InputID: statement.id, Source: statement.source, SubjectDigest: digest,
			Statement: statement.statement,
		}
	}
	return qualificationreport.AssemblyInput{
		AdapterTranscriptProjection: append([]byte(nil), transcript.Document...),
		ScenarioTimings:             timings, CallerAssertions: assertions, TrustedInputs: trusted,
	}, subjects, nil
}

func retainedMatchesFinalization(retained qualificationreport.Result, final qualificationharness.EvidenceFinalizationResult) bool {
	return retained.ReportID == final.ReportID && retained.InvocationID == final.InvocationID &&
		retained.RuntimeCommitment == final.RuntimeCommitmentDigest && retained.ReportDigest == final.ReportDigest &&
		retained.PayloadInventory == final.PayloadInventoryDigest && retained.ReceiptFile == final.ReceiptFile &&
		retained.RunOutcome == final.RunOutcome && retained.ValidationOutcome == final.ValidationOutcome &&
		retained.FileCount == final.FileCount && retained.TotalBytes == final.TotalBytes
}

func writeExclusive(path string, document []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(document)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(document) {
		_ = os.Remove(path)
		return ErrQualificationRun
	}
	return nil
}

func digestFile(path string, limit int64) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil || n < 1 || n > limit {
		return "", 0, ErrQualificationRun
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), n, nil
}

func availablePort(host string) (int, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func mustCanonicalDigest(value any) string {
	digest, err := canonicalSHA256(value)
	if err != nil {
		panic(err)
	}
	return digest
}

func validRunConfiguration(value RunConfiguration) bool {
	for _, path := range []string{value.SourceRoot, value.RunRoot, value.ProviderExecutable, value.OperatorExecutable, value.CandidateDirectory, value.DockerSocket} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return false
		}
	}
	return len(value.ProviderSourceRevision) == 40 && (len(value.ExternalSourceRevision) == 40 || len(value.ExternalSourceRevision) == 64)
}

func qualificationStage(stage string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", ErrQualificationRun, stage)
	}
	return fmt.Errorf("%w: %s: %v", ErrQualificationRun, stage, err)
}
