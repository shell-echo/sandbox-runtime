// Package qualificationharness freezes the repository-owned disposable
// qualification harness configuration before runtime setup. It does not start
// a process, create a credential, access a network, or claim a qualification
// result.
package qualificationharness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const (
	ConfigurationDigestProfile = "rfc8785-full-document-v1"
	TargetDigestProfile        = "sha256-canonical-target-description-v1"
	RunNamespaceDigestProfile  = "sha256-run-namespace-v1"
)

var (
	ErrConfiguration    = errors.New("qualification harness configuration rejected")
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	architecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,63}$`)
)

// ComponentConfigurationDigests contains the seven runtime-specific canonical
// configuration identities. It contains digests only; raw paths, endpoints,
// credentials, and caller correlations are deliberately outside this frozen
// sanitized projection. Architecture, topology, and scenario_inventory are
// derived by Freeze from typed input and the verified profile.
type ComponentConfigurationDigests struct {
	Provider  string `json:"provider_configuration"`
	Caller    string `json:"caller_configuration"`
	Adapter   string `json:"adapter_configuration"`
	Gateway   string `json:"gateway_configuration"`
	Observer  string `json:"observer_configuration"`
	Inspector string `json:"inspector_configuration"`
	Teardown  string `json:"teardown_configuration"`
}

// Configuration is sanitized static operator input. The target and namespace
// digests must be computed from their separately controlled canonical
// descriptions; Freeze never accepts their raw values.
type Configuration struct {
	Architecture            string                        `json:"architecture"`
	TargetDigest            string                        `json:"target_digest"`
	RunNamespaceDigest      string                        `json:"run_namespace_digest"`
	ComponentConfigurations ComponentConfigurationDigests `json:"component_configurations"`
}

// TargetIdentity is the report-compatible sanitized target projection.
type TargetIdentity struct {
	TargetDigest              string `json:"target_digest"`
	TargetDigestProfile       string `json:"target_digest_profile"`
	Architecture              string `json:"architecture"`
	RunNamespaceDigest        string `json:"run_namespace_digest"`
	RunNamespaceDigestProfile string `json:"run_namespace_digest_profile"`
}

// Topology is the report-compatible profile topology plus the concrete frozen
// target identity. All slices returned to callers are defensive copies.
type Topology struct {
	DedicatedDisposableTarget     bool                                  `json:"dedicated_disposable_target"`
	RunUniqueNamespace            bool                                  `json:"run_unique_namespace"`
	AdmittedControllers           int                                   `json:"admitted_controllers"`
	DistinctTenants               bool                                  `json:"distinct_tenants"`
	SameCAUnadmittedIdentityCount int                                   `json:"same_ca_unadmitted_identity_count"`
	Actors                        []qualificationprofile.ActorInventory `json:"actors"`
	CallerProcessSeparate         bool                                  `json:"caller_process_separate_from_provider"`
	CallerGatewayOwnedByCaller    bool                                  `json:"caller_gateway_owned_by_caller"`
	ObserverControlDomain         string                                `json:"observer_control_domain"`
	ObserverControlDomainDisjoint []string                              `json:"observer_control_domain_disjoint_from"`
	ProcessIsolationGroups        [][]string                            `json:"process_isolation_groups"`
	TargetIdentity                TargetIdentity                        `json:"target_identity"`
}

// ConfigurationExpectation is one exact ordered sanitized digest that a later
// process-supervisor observation must match. It deliberately has no observed_by
// or evidence status: d1 does not produce runtime evidence.
type ConfigurationExpectation struct {
	ID            string `json:"configuration_id"`
	Digest        string `json:"digest"`
	DigestProfile string `json:"digest_profile"`
}

type architectureDocument struct {
	FormatVersion int    `json:"format_version"`
	Architecture  string `json:"architecture"`
}

type scenarioInventoryDocument struct {
	FormatVersion  int                                   `json:"format_version"`
	ProfileID      string                                `json:"profile_id"`
	ProfileVersion string                                `json:"profile_version"`
	ProfileDigest  string                                `json:"profile_digest"`
	Phases         []qualificationprofile.PhaseInventory `json:"phases"`
}

type commitmentDocument struct {
	FormatVersion             int                                        `json:"format_version"`
	ProfileID                 string                                     `json:"profile_id"`
	ProfileVersion            string                                     `json:"profile_version"`
	ProfileDigest             string                                     `json:"profile_digest"`
	ProfileSchemaDigest       string                                     `json:"profile_schema_digest"`
	TargetIdentity            TargetIdentity                             `json:"target_identity"`
	Topology                  Topology                                   `json:"topology"`
	ArtifactRequirements      []qualificationprofile.ArtifactRequirement `json:"artifact_requirements"`
	ConfigurationExpectations []ConfigurationExpectation                 `json:"configuration_expectations"`
	RuntimeLimits             qualificationprofile.RuntimeLimits         `json:"runtime_limits"`
	CleanupRequirements       qualificationprofile.CleanupRequirements   `json:"cleanup_requirements"`
	ScenarioInventory         []qualificationprofile.PhaseInventory      `json:"scenario_inventory"`
}

type frozenCore struct {
	input           Configuration
	digest          string
	profileID       string
	profileVersion  string
	profileDigest   string
	target          TargetIdentity
	topology        Topology
	artifacts       []qualificationprofile.ArtifactRequirement
	configurations  []ConfigurationExpectation
	limits          qualificationprofile.RuntimeLimits
	cleanup         qualificationprofile.CleanupRequirements
	phases          []qualificationprofile.PhaseInventory
	orchestration   map[string]qualificationprofile.PhaseOrchestration
	reconstruction  qualificationprofile.ReconstructionRequirements
	observationPlan []qualificationprofile.PhaseObservationPlan
}

// FrozenConfiguration is an immutable pre-runtime snapshot. It proves only
// that the locked definition and supplied sanitized digests were committed;
// later steps must observe actual artifacts, configurations, topology and
// runtime behavior independently.
type FrozenConfiguration struct{ core *frozenCore }

// Freeze verifies the content-addressed profile, derives the exact topology and
// scenario identities, and commits every static field under RFC 8785/SHA-256.
// It performs repository reads only: no runtime, network, secret, directory, or
// process operation occurs here.
func Freeze(ctx context.Context, sourceRoot string, input Configuration) (*FrozenConfiguration, error) {
	if ctx == nil || !validConfiguration(input) {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report, err := qualificationprofile.VerifyCodingShellV1(ctx, sourceRoot)
	if err != nil {
		return nil, errors.Join(ErrConfiguration, err)
	}
	inventory := report.Inventory()
	reconstruction := report.Reconstruction()
	target := TargetIdentity{
		TargetDigest: input.TargetDigest, TargetDigestProfile: TargetDigestProfile,
		Architecture: input.Architecture, RunNamespaceDigest: input.RunNamespaceDigest,
		RunNamespaceDigestProfile: RunNamespaceDigestProfile,
	}
	topology := projectTopology(inventory.Topology, target)
	architectureDigest, err := canonicalDigest(architectureDocument{FormatVersion: 1, Architecture: input.Architecture})
	if err != nil {
		return nil, ErrConfiguration
	}
	topologyDigest, err := canonicalDigest(topology)
	if err != nil {
		return nil, ErrConfiguration
	}
	scenarioDigest, err := canonicalDigest(scenarioInventoryDocument{
		FormatVersion: 1, ProfileID: report.ProfileID, ProfileVersion: report.ProfileVersion,
		ProfileDigest: report.ProfileDigest, Phases: inventory.Phases,
	})
	if err != nil {
		return nil, ErrConfiguration
	}
	digestByID := map[string]string{
		"architecture":            architectureDigest,
		"provider_configuration":  input.ComponentConfigurations.Provider,
		"caller_configuration":    input.ComponentConfigurations.Caller,
		"adapter_configuration":   input.ComponentConfigurations.Adapter,
		"gateway_configuration":   input.ComponentConfigurations.Gateway,
		"observer_configuration":  input.ComponentConfigurations.Observer,
		"inspector_configuration": input.ComponentConfigurations.Inspector,
		"teardown_configuration":  input.ComponentConfigurations.Teardown,
		"topology":                topologyDigest,
		"scenario_inventory":      scenarioDigest,
	}
	configurations := make([]ConfigurationExpectation, len(inventory.ConfigurationIDs))
	for index, id := range inventory.ConfigurationIDs {
		digest, ok := digestByID[id]
		if !ok || !digestPattern.MatchString(digest) {
			return nil, ErrConfiguration
		}
		configurations[index] = ConfigurationExpectation{ID: id, Digest: digest, DigestProfile: ConfigurationDigestProfile}
		delete(digestByID, id)
	}
	if len(digestByID) != 0 || len(configurations) != 10 || len(inventory.Artifacts) != 11 || len(inventory.Phases) != 2 {
		return nil, ErrConfiguration
	}
	orchestration := make(map[string]qualificationprofile.PhaseOrchestration, len(inventory.Phases))
	for _, phase := range inventory.Phases {
		plan, ok := report.Orchestration(phase.PhaseID)
		if !ok {
			return nil, ErrConfiguration
		}
		orchestration[phase.PhaseID] = plan
	}
	document := commitmentDocument{
		FormatVersion: 1, ProfileID: report.ProfileID, ProfileVersion: report.ProfileVersion,
		ProfileDigest: report.ProfileDigest, ProfileSchemaDigest: report.SchemaDigest,
		TargetIdentity: target, Topology: topology, ArtifactRequirements: inventory.Artifacts,
		ConfigurationExpectations: configurations, RuntimeLimits: inventory.Limits,
		CleanupRequirements: inventory.Cleanup, ScenarioInventory: inventory.Phases,
	}
	digest, err := canonicalDigest(document)
	if err != nil {
		return nil, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &FrozenConfiguration{core: &frozenCore{
		input: input, digest: digest, profileID: report.ProfileID, profileVersion: report.ProfileVersion,
		profileDigest: report.ProfileDigest, target: target, topology: cloneTopology(topology),
		artifacts:      append([]qualificationprofile.ArtifactRequirement(nil), inventory.Artifacts...),
		configurations: append([]ConfigurationExpectation(nil), configurations...), limits: inventory.Limits,
		cleanup: cloneCleanupRequirements(inventory.Cleanup), phases: clonePhases(inventory.Phases),
		orchestration: cloneOrchestration(orchestration), reconstruction: cloneReconstructionRequirements(reconstruction),
		observationPlan: cloneObservationPlan(report.ObservationPlan()),
	}}, nil
}

func validConfiguration(input Configuration) bool {
	if !validArchitecture(input.Architecture) || !digestPattern.MatchString(input.TargetDigest) || !digestPattern.MatchString(input.RunNamespaceDigest) {
		return false
	}
	for _, digest := range []string{
		input.ComponentConfigurations.Provider, input.ComponentConfigurations.Caller,
		input.ComponentConfigurations.Adapter, input.ComponentConfigurations.Gateway,
		input.ComponentConfigurations.Observer, input.ComponentConfigurations.Inspector,
		input.ComponentConfigurations.Teardown,
	} {
		if !digestPattern.MatchString(digest) {
			return false
		}
	}
	return true
}

func validArchitecture(value string) bool {
	if !architecturePattern.MatchString(value) || strings.HasSuffix(value, "/") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func projectTopology(source qualificationprofile.TopologyInventory, target TargetIdentity) Topology {
	return Topology{
		DedicatedDisposableTarget: source.DedicatedDisposableTarget, RunUniqueNamespace: source.RunUniqueNamespace,
		AdmittedControllers: source.AdmittedControllers, DistinctTenants: source.DistinctTenantsRequired,
		SameCAUnadmittedIdentityCount: source.SameCAUnadmittedIdentityCount, Actors: cloneActors(source.Actors),
		CallerProcessSeparate: source.CallerProcessSeparate, CallerGatewayOwnedByCaller: source.CallerGatewayOwnedByCaller,
		ObserverControlDomain:         source.ObserverControlDomain,
		ObserverControlDomainDisjoint: append([]string(nil), source.ObserverControlDomainDisjoint...),
		ProcessIsolationGroups:        cloneStringMatrix(source.ProcessIsolationGroups), TargetIdentity: target,
	}
}

func canonicalDigest(value any) (string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Digest returns the sanitized full harness-configuration commitment.
func (f *FrozenConfiguration) Digest() string {
	if f == nil || f.core == nil {
		return ""
	}
	return f.core.digest
}

// ProfileIdentity returns the verified profile identity bound into Digest.
func (f *FrozenConfiguration) ProfileIdentity() (id, version, digest string) {
	if f == nil || f.core == nil {
		return "", "", ""
	}
	return f.core.profileID, f.core.profileVersion, f.core.profileDigest
}

// Matches requires byte-identical static input. It does not re-observe runtime
// state and therefore cannot replace the later d2 preflight.
func (f *FrozenConfiguration) Matches(input Configuration) bool {
	return f != nil && f.core != nil && f.core.digest != "" && f.core.input == input
}

// TargetIdentity returns a copy of the sanitized target identity.
func (f *FrozenConfiguration) TargetIdentity() TargetIdentity {
	if f == nil || f.core == nil {
		return TargetIdentity{}
	}
	return f.core.target
}

// Topology returns a deep copy of the exact report-compatible topology.
func (f *FrozenConfiguration) Topology() Topology {
	if f == nil || f.core == nil {
		return Topology{}
	}
	return cloneTopology(f.core.topology)
}

// ArtifactRequirements returns the exact ordered artifact-role inventory from
// the verified profile. It does not claim that any artifact was observed.
func (f *FrozenConfiguration) ArtifactRequirements() []qualificationprofile.ArtifactRequirement {
	if f == nil || f.core == nil {
		return nil
	}
	return append([]qualificationprofile.ArtifactRequirement(nil), f.core.artifacts...)
}

// ConfigurationExpectations returns all ten ordered sanitized digests. They are
// not report evidence until a later process supervisor independently observes
// and matches the actual configurations.
func (f *FrozenConfiguration) ConfigurationExpectations() []ConfigurationExpectation {
	if f == nil || f.core == nil {
		return nil
	}
	return append([]ConfigurationExpectation(nil), f.core.configurations...)
}

// RuntimeLimits returns the exact numeric budget from the verified profile.
// Later orchestration must account at the profile's transport boundaries; this
// getter alone does not enforce a runtime limit.
func (f *FrozenConfiguration) RuntimeLimits() qualificationprofile.RuntimeLimits {
	if f == nil || f.core == nil {
		return qualificationprofile.RuntimeLimits{}
	}
	return f.core.limits
}

// CleanupRequirements returns the exact verified inspection and teardown
// policy. It is a defensive copy and is not cleanup evidence.
func (f *FrozenConfiguration) CleanupRequirements() qualificationprofile.CleanupRequirements {
	if f == nil || f.core == nil {
		return qualificationprofile.CleanupRequirements{}
	}
	return cloneCleanupRequirements(f.core.cleanup)
}

// ScenarioInventory returns a defensive copy of the exact 15+5 phase order.
func (f *FrozenConfiguration) ScenarioInventory() []qualificationprofile.PhaseInventory {
	if f == nil || f.core == nil {
		return nil
	}
	return clonePhases(f.core.phases)
}

func (f *FrozenConfiguration) orchestrationPlan(phaseID string) (qualificationprofile.PhaseOrchestration, bool) {
	if f == nil || f.core == nil {
		return qualificationprofile.PhaseOrchestration{}, false
	}
	phase, ok := f.core.orchestration[phaseID]
	if !ok {
		return qualificationprofile.PhaseOrchestration{}, false
	}
	return clonePhaseOrchestration(phase), true
}

func cloneActors(source []qualificationprofile.ActorInventory) []qualificationprofile.ActorInventory {
	result := make([]qualificationprofile.ActorInventory, len(source))
	for index, actor := range source {
		result[index] = actor
		if actor.TenantBinding != nil {
			value := *actor.TenantBinding
			result[index].TenantBinding = &value
		}
	}
	return result
}

func cloneTopology(source Topology) Topology {
	result := source
	result.Actors = cloneActors(source.Actors)
	result.ObserverControlDomainDisjoint = append([]string(nil), source.ObserverControlDomainDisjoint...)
	result.ProcessIsolationGroups = cloneStringMatrix(source.ProcessIsolationGroups)
	return result
}

func clonePhases(source []qualificationprofile.PhaseInventory) []qualificationprofile.PhaseInventory {
	result := make([]qualificationprofile.PhaseInventory, len(source))
	for index, phase := range source {
		result[index] = phase
		if phase.DependsOnPhase != nil {
			value := *phase.DependsOnPhase
			result[index].DependsOnPhase = &value
		}
		result[index].CaseIDs = append([]string(nil), phase.CaseIDs...)
	}
	return result
}

func cloneCleanupRequirements(source qualificationprofile.CleanupRequirements) qualificationprofile.CleanupRequirements {
	result := source
	result.InspectorScope = append([]string(nil), source.InspectorScope...)
	return result
}

func cloneReconstructionRequirements(source qualificationprofile.ReconstructionRequirements) qualificationprofile.ReconstructionRequirements {
	result := source
	result.RestartComponents = append([]string(nil), source.RestartComponents...)
	result.PreserveStores = append([]string(nil), source.PreserveStores...)
	result.ReinjectionForbidden = append([]string(nil), source.ReinjectionForbidden...)
	result.AdapterInvocation.AllowedHarnessFields = append([]string(nil), source.AdapterInvocation.AllowedHarnessFields...)
	return result
}

func cloneObservationPlan(source []qualificationprofile.PhaseObservationPlan) []qualificationprofile.PhaseObservationPlan {
	result := make([]qualificationprofile.PhaseObservationPlan, len(source))
	for phaseIndex, sourcePhase := range source {
		result[phaseIndex] = qualificationprofile.PhaseObservationPlan{PhaseID: sourcePhase.PhaseID, Cases: make([]qualificationprofile.CaseObservationPlan, len(sourcePhase.Cases))}
		for caseIndex, sourceCase := range sourcePhase.Cases {
			result[phaseIndex].Cases[caseIndex] = qualificationprofile.CaseObservationPlan{CaseID: sourceCase.CaseID, DependsOn: append([]string(nil), sourceCase.DependsOn...), Interactions: make([]qualificationprofile.InteractionObservationRequirement, len(sourceCase.Interactions))}
			for interactionIndex, sourceInteraction := range sourceCase.Interactions {
				projected := sourceInteraction
				if sourceInteraction.ReplayOf != nil {
					value := *sourceInteraction.ReplayOf
					projected.ReplayOf = &value
				}
				projected.CountsToward = append([]string(nil), sourceInteraction.CountsToward...)
				projected.Outcomes = cloneOutcomeRequirements(sourceInteraction.Outcomes)
				projected.TransientOutcomes = cloneOutcomeRequirements(sourceInteraction.TransientOutcomes)
				projected.RequiredObservations = append([]qualificationprofile.ObservationRequirement(nil), sourceInteraction.RequiredObservations...)
				result[phaseIndex].Cases[caseIndex].Interactions[interactionIndex] = projected
			}
		}
	}
	return result
}

func cloneOutcomeRequirements(source []qualificationprofile.OutcomeRequirement) []qualificationprofile.OutcomeRequirement {
	result := make([]qualificationprofile.OutcomeRequirement, len(source))
	for index, candidate := range source {
		result[index] = candidate
		if candidate.StatusCode != nil {
			value := *candidate.StatusCode
			result[index].StatusCode = &value
		}
		result[index].ErrorCodes = append([]string(nil), candidate.ErrorCodes...)
		if candidate.Retryable != nil {
			value := *candidate.Retryable
			result[index].Retryable = &value
		}
		if candidate.RetryAfterRequired != nil {
			value := *candidate.RetryAfterRequired
			result[index].RetryAfterRequired = &value
		}
	}
	return result
}

func clonePhaseOrchestration(source qualificationprofile.PhaseOrchestration) qualificationprofile.PhaseOrchestration {
	result := source
	if source.DependsOnPhase != nil {
		value := *source.DependsOnPhase
		result.DependsOnPhase = &value
	}
	result.Cases = make([]qualificationprofile.CaseOrchestration, len(source.Cases))
	for caseIndex, sourceCase := range source.Cases {
		result.Cases[caseIndex] = sourceCase
		result.Cases[caseIndex].DependsOn = append([]string(nil), sourceCase.DependsOn...)
		result.Cases[caseIndex].Interactions = make([]qualificationprofile.InteractionAccountingRequirement, len(sourceCase.Interactions))
		for interactionIndex, sourceInteraction := range sourceCase.Interactions {
			result.Cases[caseIndex].Interactions[interactionIndex] = sourceInteraction
			result.Cases[caseIndex].Interactions[interactionIndex].CountsToward = append([]string(nil), sourceInteraction.CountsToward...)
		}
	}
	return result
}

func cloneOrchestration(source map[string]qualificationprofile.PhaseOrchestration) map[string]qualificationprofile.PhaseOrchestration {
	result := make(map[string]qualificationprofile.PhaseOrchestration, len(source))
	for phaseID, phase := range source {
		result[phaseID] = clonePhaseOrchestration(phase)
	}
	return result
}

func cloneStringMatrix(source [][]string) [][]string {
	result := make([][]string, len(source))
	for index, row := range source {
		result[index] = append([]string(nil), row...)
	}
	return result
}
