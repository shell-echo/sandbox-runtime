package qualificationoperator

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	protocol "github.com/shell-echo/sandbox-runtime/internal/qualificationadapterprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

var ErrObservationProjection = errors.New("qualification observation projection failed")

type ObserverBundle struct {
	runtimeDigest  string
	artifacts      []qualificationharness.ArtifactObservation
	configs        []qualificationharness.ConfigurationObservation
	target         qualificationharness.TargetIdentity
	limits         qualificationprofile.RuntimeLimits
	plan           []qualificationprofile.PhaseObservationPlan
	proxy          *ObservationProxy
	executor       *PhaseExecutor
	processes      *ProcessObserver
	resources      *DockerResources
	transcript     protocol.TranscriptProjection
	reconstruction qualificationprofile.ReconstructionRequirements

	once            sync.Once
	buildErr        error
	provider        []qualificationharness.ObservedInteraction
	gateway         []qualificationharness.ObservedInteraction
	providerFacts   []qualificationharness.ObserverFact
	gatewayFacts    []qualificationharness.ObserverFact
	processFacts    []qualificationharness.ObserverFact
	resourceFacts   []qualificationharness.ObserverFact
	challengeDigest string
}

type ObserverBundleInput struct {
	RuntimeDigest  string
	Observation    qualificationharness.RuntimeObservation
	Limits         qualificationprofile.RuntimeLimits
	Plan           []qualificationprofile.PhaseObservationPlan
	Reconstruction qualificationprofile.ReconstructionRequirements
	Proxy          *ObservationProxy
	Executor       *PhaseExecutor
	Processes      *ProcessObserver
	Resources      *DockerResources
	Transcript     protocol.TranscriptProjection
}

func NewObserverBundle(input ObserverBundleInput) (*ObserverBundle, error) {
	if input.RuntimeDigest == "" || len(input.Observation.Artifacts) != 11 || len(input.Observation.Configurations) != 10 ||
		len(input.Plan) != 2 || input.Proxy == nil || input.Executor == nil || input.Processes == nil || input.Resources == nil || input.Transcript.Digest == "" {
		return nil, ErrObservationProjection
	}
	return &ObserverBundle{
		runtimeDigest: input.RuntimeDigest, artifacts: input.Observation.Artifacts, configs: input.Observation.Configurations,
		target: input.Observation.Target, limits: input.Limits, plan: input.Plan, reconstruction: input.Reconstruction,
		proxy: input.Proxy, executor: input.Executor, processes: input.Processes, resources: input.Resources, transcript: input.Transcript,
	}, nil
}

func (b *ObserverBundle) ObserveProvider(_ context.Context, directive qualificationharness.ObservationDirective) (qualificationharness.ProviderExecutionObservation, error) {
	if err := b.ensureBuilt(directive); err != nil {
		return qualificationharness.ProviderExecutionObservation{}, err
	}
	return qualificationharness.ProviderExecutionObservation{
		RuntimeCommitmentDigest: b.runtimeDigest, ObserverArtifactDigest: b.artifactDigest(qualificationharness.ProviderObserverSource),
		ObserverConfigurationDigest: b.configurationDigest("observer_configuration"),
		SandboxResources: &qualificationharness.SandboxResourceObservation{
			CPUMillis: b.limits.SandboxCPUMillis, MemoryBytes: b.limits.SandboxMemoryBytes,
			EphemeralStorageBytes: b.limits.SandboxEphemeralStorageBytes, PIDs: b.limits.SandboxPIDs,
		},
		Interactions: cloneInteractions(b.provider), Facts: append([]qualificationharness.ObserverFact(nil), b.providerFacts...),
	}, nil
}

func (b *ObserverBundle) ObserveGateway(_ context.Context, directive qualificationharness.ObservationDirective) (qualificationharness.GatewayExecutionObservation, error) {
	if err := b.ensureBuilt(directive); err != nil {
		return qualificationharness.GatewayExecutionObservation{}, err
	}
	var challenge *qualificationharness.ShellContinuityObservation
	if b.challengeDigest != "" {
		challenge = &qualificationharness.ShellContinuityObservation{
			Digest: b.challengeDigest, DigestProfile: b.reconstruction.ShellContinuityChallenge.ChallengeDigestProfile,
			EstablishedInCase:      b.reconstruction.ShellContinuityChallenge.EstablishedInCase,
			VerifiedInCase:         b.reconstruction.ShellContinuityChallenge.VerifiedInCase,
			RawChallengeInEvidence: false,
		}
	}
	return qualificationharness.GatewayExecutionObservation{
		RuntimeCommitmentDigest: b.runtimeDigest, ObserverArtifactDigest: b.artifactDigest(qualificationharness.GatewayObserverSource),
		ObserverConfigurationDigest: b.configurationDigest("observer_configuration"), Interactions: cloneInteractions(b.gateway),
		ShellChallenge: challenge, Facts: append([]qualificationharness.ObserverFact(nil), b.gatewayFacts...),
	}, nil
}

func (b *ObserverBundle) ObserveProcesses(_ context.Context, directive qualificationharness.ObservationDirective) (qualificationharness.ProcessExecutionObservation, error) {
	if err := b.ensureBuilt(directive); err != nil {
		return qualificationharness.ProcessExecutionObservation{}, err
	}
	initial, reconstruction := b.executor.PlannedProcesses("initial"), b.executor.PlannedProcesses("reconstruction")
	return qualificationharness.ProcessExecutionObservation{
		RuntimeCommitmentDigest: b.runtimeDigest, SupervisorArtifactDigest: b.artifactDigest(qualificationharness.ProcessSupervisorSource),
		SupervisorConfigurationDigest: b.configurationDigest("observer_configuration"),
		InitialInvocationID:           directive.InitialInvocationID, ReconstructionInvocationID: directive.ReconstructionInvocationID,
		Artifacts: b.artifactsObservedBy(qualificationharness.ProcessSupervisorSource), Configurations: append([]qualificationharness.ConfigurationObservation(nil), b.configs...),
		InitialProcesses: b.processIdentities(initial), ReconstructionProcesses: b.processIdentities(reconstruction),
		HarnessReinjectedForbiddenBindings: false,
		AdapterTranscript: qualificationharness.AdapterTranscriptObservation{
			Digest: b.transcript.Digest, DigestProfile: b.reconstruction.AdapterInvocation.TranscriptDigestProfile,
			InvocationIDs:   []string{directive.InitialInvocationID, directive.ReconstructionInvocationID},
			AllowedFields:   append([]string(nil), b.reconstruction.AdapterInvocation.AllowedHarnessFields...),
			ForbiddenFields: append([]string(nil), b.reconstruction.ReinjectionForbidden...), Sanitized: true,
			ObservedBy: qualificationharness.ProcessSupervisorSource,
		},
		Facts: append([]qualificationharness.ObserverFact(nil), b.processFacts...),
	}, nil
}

func (b *ObserverBundle) ObserveResources(ctx context.Context, directive qualificationharness.ObservationDirective, scope qualificationharness.QueryScope) (qualificationharness.ResourceExecutionObservation, error) {
	if err := b.ensureBuilt(directive); err != nil {
		return qualificationharness.ResourceExecutionObservation{}, err
	}
	inspection, err := b.resources.Inspect(ctx, scope)
	if err != nil || len(inspection.Entries) != 1 || inspection.Entries[0].ResourceKind != "runtime_allocations" {
		return qualificationharness.ResourceExecutionObservation{}, ErrObservationProjection
	}
	return qualificationharness.ResourceExecutionObservation{
		RuntimeCommitmentDigest: b.runtimeDigest, InspectorArtifactDigest: b.artifactDigest(qualificationharness.ResourceInspectorSource),
		InspectorConfigurationDigest: b.configurationDigest("inspector_configuration"), Target: b.target,
		Artifacts: b.artifactsObservedBy(qualificationharness.ResourceInspectorSource), Inspection: inspection,
		Facts: append([]qualificationharness.ObserverFact(nil), b.resourceFacts...),
	}, nil
}

func (b *ObserverBundle) ensureBuilt(directive qualificationharness.ObservationDirective) error {
	if directive.RuntimeCommitmentDigest != b.runtimeDigest {
		return ErrObservationProjection
	}
	b.once.Do(func() { b.buildErr = b.build() })
	return b.buildErr
}

func (b *ObserverBundle) build() error {
	providerRaw, gatewayRaw := b.proxy.Snapshot()
	providerExpected, gatewayExpected, progress, err := b.executedRequirements()
	if err != nil {
		return err
	}
	filteredProvider := make([]HTTPObservation, 0, len(providerRaw))
	for _, event := range providerRaw {
		if event.Route != "/v1/runtime-sessions:connect" {
			filteredProvider = append(filteredProvider, event)
		}
	}
	b.provider, err = projectProvider(providerExpected, progress, filteredProvider)
	if err != nil {
		return err
	}
	b.gateway, b.challengeDigest, err = projectGateway(gatewayExpected, progress, gatewayRaw)
	if err != nil {
		return err
	}
	counts := b.processes.Counts()
	if counts["provider"] < 2 || counts["external_caller"] < 2 || counts["qualification_adapter"] < 2 || counts["caller_gateway"] < 5 {
		return ErrObservationProjection
	}
	if !providerSemanticContinuity(b.provider, filteredProvider) {
		return ErrObservationProjection
	}
	b.providerFacts = factsForSource(b.plan, qualificationharness.ProviderObserverSource)
	b.gatewayFacts = factsForSource(b.plan, qualificationharness.GatewayObserverSource)
	b.processFacts = factsForSource(b.plan, qualificationharness.ProcessSupervisorSource)
	b.resourceFacts = factsForSource(b.plan, qualificationharness.ResourceInspectorSource)
	return nil
}

func (b *ObserverBundle) executedRequirements() ([]qualificationprofile.InteractionObservationRequirement, []qualificationprofile.InteractionObservationRequirement, map[string]qualificationharness.InteractionProgress, error) {
	progress := make(map[string]qualificationharness.InteractionProgress, 41)
	dispositions := make(map[string]string, 20)
	for _, phase := range []string{"initial", "reconstruction"} {
		for _, scenario := range b.executor.Progress(phase) {
			dispositions[scenario.CaseID] = scenario.Disposition
			for _, interaction := range scenario.Interactions {
				progress[interaction.InteractionID] = interaction
			}
		}
	}
	if len(dispositions) != 20 || len(progress) != 41 {
		return nil, nil, nil, ErrObservationProjection
	}
	var provider, gateway []qualificationprofile.InteractionObservationRequirement
	for _, phase := range b.plan {
		for _, scenario := range phase.Cases {
			if dispositions[scenario.CaseID] != qualificationharness.ScenarioCompleted {
				return nil, nil, nil, ErrObservationProjection
			}
			for _, interaction := range scenario.Interactions {
				switch interaction.Surface {
				case "provider_http":
					provider = append(provider, interaction)
				case "caller_gateway":
					gateway = append(gateway, interaction)
				default:
					return nil, nil, nil, ErrObservationProjection
				}
			}
		}
	}
	return provider, gateway, progress, nil
}

func projectProvider(expected []qualificationprofile.InteractionObservationRequirement, progress map[string]qualificationharness.InteractionProgress, raw []HTTPObservation) ([]qualificationharness.ObservedInteraction, error) {
	result := make([]qualificationharness.ObservedInteraction, 0, len(expected))
	offset := 0
	for _, want := range expected {
		attempts := progress[want.InteractionID].WireAttempts
		if attempts < 1 || offset+attempts > len(raw) {
			return nil, ErrObservationProjection
		}
		group := raw[offset : offset+attempts]
		offset += attempts
		outcomes := make([]qualificationharness.ObservedOutcome, attempts)
		for index, event := range group {
			if event.Actor != want.Actor || event.Method != want.Method || event.Route != want.RouteTemplate {
				return nil, ErrObservationProjection
			}
			outcomes[index] = providerOutcome(event)
		}
		result = append(result, qualificationharness.ObservedInteraction{
			InteractionID: want.InteractionID, Surface: want.Surface, Actor: want.Actor, Method: want.Method, RouteTemplate: want.RouteTemplate,
			LogicalRequestID: want.LogicalRequestID, ReplayOf: cloneString(want.ReplayOf), WireAttempts: attempts,
			TransientOutcomes: append([]qualificationharness.ObservedOutcome(nil), outcomes[:len(outcomes)-1]...), FinalOutcome: outcomes[len(outcomes)-1],
			MutationWriteObserved: hasCounter(want.CountsToward, "provider_mutation_write_attempts"),
		})
	}
	if offset != len(raw) {
		return nil, ErrObservationProjection
	}
	return result, nil
}

func projectGateway(expected []qualificationprofile.InteractionObservationRequirement, progress map[string]qualificationharness.InteractionProgress, raw []GatewayObservation) ([]qualificationharness.ObservedInteraction, string, error) {
	result := make([]qualificationharness.ObservedInteraction, 0, len(expected))
	offset := 0
	challenge := ""
	for _, want := range expected {
		attempts := progress[want.InteractionID].WireAttempts
		if attempts != 1 {
			return nil, "", ErrObservationProjection
		}
		outcome := qualificationharness.ObservedOutcome{}
		if want.Method == "CONTROL" {
			if len(result) == 0 || result[len(result)-1].InteractionID != "gateway-revocable-grant" {
				return nil, "", ErrObservationProjection
			}
			outcome.Transport = "revocation-acknowledged"
		} else {
			if offset >= len(raw) {
				return nil, "", ErrObservationProjection
			}
			event := raw[offset]
			offset++
			actor := event.Actor
			if actor == "" {
				actor = "unauthenticated_client"
			}
			if actor != want.Actor {
				return nil, "", ErrObservationProjection
			}
			transport := event.Transport
			switch want.InteractionID {
			case "gateway-expiring-grant":
				if event.BytesToGateway < 1 || event.BytesFromGateway < 1 || event.FinishedAt.Sub(event.StartedAt) < 500*time.Millisecond {
					return nil, "", ErrObservationProjection
				}
				transport = "gateway-closed-at-grant-expiry"
			case "gateway-revocable-grant":
				if event.BytesToGateway < 1 || event.BytesFromGateway < 1 {
					return nil, "", ErrObservationProjection
				}
			case "gateway-terminal-round-trip", "gateway-same-shell-reconnect":
				if !event.ObserverChallengeVerified || event.BytesToGateway < 64 || event.BytesFromGateway < 64 || event.ChallengeDigest == "" {
					return nil, "", ErrObservationProjection
				}
				if challenge == "" && want.InteractionID == "gateway-terminal-round-trip" {
					challenge = event.ChallengeDigest
				}
				if want.InteractionID == "gateway-same-shell-reconnect" && event.ChallengeDigest != challenge {
					return nil, "", ErrObservationProjection
				}
			}
			outcome.Transport = transport
		}
		result = append(result, qualificationharness.ObservedInteraction{
			InteractionID: want.InteractionID, Surface: want.Surface, Actor: want.Actor, Method: want.Method, RouteTemplate: want.RouteTemplate,
			LogicalRequestID: want.LogicalRequestID, ReplayOf: cloneString(want.ReplayOf), WireAttempts: attempts,
			TransientOutcomes: []qualificationharness.ObservedOutcome{}, FinalOutcome: outcome,
			MutationWriteObserved: hasCounter(want.CountsToward, "gateway_mutation_write_attempts"),
		})
	}
	if offset != len(raw) || challenge == "" {
		return nil, "", ErrObservationProjection
	}
	return result, challenge, nil
}

func providerOutcome(event HTTPObservation) qualificationharness.ObservedOutcome {
	result := qualificationharness.ObservedOutcome{Transport: event.Transport, Retryable: event.Retryable, RetryAfterPresent: event.RetryAfterPresent}
	if event.StatusCode != 0 {
		value := event.StatusCode
		result.StatusCode = &value
	}
	if event.ErrorCode != "" {
		value := event.ErrorCode
		result.ErrorCode = &value
	}
	return result
}

func providerSemanticContinuity(interactions []qualificationharness.ObservedInteraction, raw []HTTPObservation) bool {
	if len(interactions) != 34 {
		return false
	}
	byRouteActor := make(map[string][]HTTPObservation)
	for _, event := range raw {
		byRouteActor[event.Actor+"\x00"+event.Method+"\x00"+event.Route] = append(byRouteActor[event.Actor+"\x00"+event.Method+"\x00"+event.Route], event)
		if event.StatusCode >= 200 && event.StatusCode < 300 && event.Transport == "http-response" && event.Route != "/v1/capabilities" && event.ResponseJSON == nil {
			return false
		}
		if encoded := strings.ToLower(strings.Join(mapKeys(event.ResponseJSON), "\x00")); strings.Contains(encoded, "backend_id") || strings.Contains(encoded, "host_path") || strings.Contains(encoded, "docker_id") {
			return false
		}
	}
	capA := byRouteActor["controller_a\x00GET\x00/v1/capabilities"]
	capB := byRouteActor["controller_b\x00GET\x00/v1/capabilities"]
	if len(capA) < 2 || len(capB) != 1 || capA[0].ResponseDigest == "" || capA[0].ResponseDigest != capA[len(capA)-1].ResponseDigest || capA[0].ResponseDigest != capB[0].ResponseDigest {
		return false
	}
	creates := byRouteActor["controller_a\x00POST\x00/v1/sandboxes"]
	if len(creates) != 3 || creates[0].AdmissionDigest == "" || creates[0].AdmissionDigest != creates[1].AdmissionDigest || creates[0].AdmissionDigest == creates[2].AdmissionDigest {
		return false
	}
	return true
}

func factsForSource(plan []qualificationprofile.PhaseObservationPlan, source string) []qualificationharness.ObserverFact {
	var result []qualificationharness.ObserverFact
	for _, phase := range plan {
		for _, scenario := range phase.Cases {
			for _, interaction := range scenario.Interactions {
				for _, fact := range interaction.RequiredObservations {
					if fact.Source == source {
						result = append(result, qualificationharness.ObserverFact{ObservationID: fact.ObservationID, Actor: fact.Actor, Subject: fact.Subject, Correlation: fact.Correlation, Result: "observed"})
					}
				}
			}
		}
	}
	return result
}

func (b *ObserverBundle) artifactDigest(id string) string {
	for _, artifact := range b.artifacts {
		if artifact.ArtifactID == id {
			return artifact.Digest
		}
	}
	return ""
}

func (b *ObserverBundle) configurationDigest(id string) string {
	for _, configuration := range b.configs {
		if configuration.ID == id {
			return configuration.Digest
		}
	}
	return ""
}

func (b *ObserverBundle) artifactsObservedBy(observer string) []qualificationharness.ArtifactObservation {
	var result []qualificationharness.ArtifactObservation
	for _, artifact := range b.artifacts {
		if artifact.ObservedBy == observer {
			result = append(result, artifact)
		}
	}
	return result
}

func (b *ObserverBundle) processIdentities(labels map[string]string) []qualificationharness.ProcessIdentityObservation {
	components := []string{"provider", "external_caller", "qualification_adapter", "caller_gateway"}
	configurationIDs := map[string]string{"provider": "provider_configuration", "external_caller": "caller_configuration", "qualification_adapter": "adapter_configuration", "caller_gateway": "gateway_configuration"}
	result := make([]qualificationharness.ProcessIdentityObservation, 0, len(components))
	for _, component := range components {
		result = append(result, qualificationharness.ProcessIdentityObservation{
			Component: component, ProcessID: labels[component], ExecutableDigest: b.artifactDigest(component),
			ConfigurationDigest: b.configurationDigest(configurationIDs[component]), ObservedBy: qualificationharness.ProcessSupervisorSource,
		})
	}
	return result
}

func cloneInteractions(values []qualificationharness.ObservedInteraction) []qualificationharness.ObservedInteraction {
	result := make([]qualificationharness.ObservedInteraction, len(values))
	copy(result, values)
	for index := range result {
		result[index].ReplayOf = cloneString(values[index].ReplayOf)
		result[index].TransientOutcomes = append([]qualificationharness.ObservedOutcome(nil), values[index].TransientOutcomes...)
	}
	return result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func hasCounter(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mapKeys(value map[string]any) []string {
	result := make([]string, 0, len(value))
	for key := range value {
		result = append(result, key)
	}
	return result
}
