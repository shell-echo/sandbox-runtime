package qualificationharness

import (
	"context"
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const (
	InventoryDigestProfile = "rfc8785-full-document-v1"
	CleanupAuthority       = "operator-owned-run-namespace-teardown-within-disposable-target"
)

var (
	ErrRuntimePreflight        = errors.New("qualification runtime preflight failed")
	ErrPersistentStateRetained = errors.New("qualification persistent state retained for operator teardown")

	sourceRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	releaseIDPattern      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$`)
	observerIDPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
)

// SourceIdentity is a report-compatible immutable source or release identity.
// A caller-owner value remains an assertion until the P2.7e provenance gate.
type SourceIdentity struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Immutable bool   `json:"immutable"`
}

// ArtifactObservation is one claimed runtime artifact observation. PrepareRuntime
// requires the exact profile order and bindings. Independence of the observer is
// deliberately a later d5/e1 evidence obligation.
type ArtifactObservation struct {
	ArtifactID    string          `json:"artifact_id"`
	Owner         string          `json:"owner"`
	TrustDomain   string          `json:"trust_domain"`
	DigestSubject string          `json:"digest_subject"`
	Digest        string          `json:"digest"`
	ObservedBy    string          `json:"observed_by"`
	Source        *SourceIdentity `json:"source_identity"`
}

// ConfigurationObservation is one observed sanitized configuration identity.
type ConfigurationObservation struct {
	ID            string `json:"configuration_id"`
	Digest        string `json:"digest"`
	DigestProfile string `json:"digest_profile"`
	Sanitized     bool   `json:"sanitized"`
	ObservedBy    string `json:"observed_by"`
}

// RuntimeObservation is the complete pre-mutation identity snapshot supplied
// by the runtime composition layer. It contains no endpoint, credential, host
// path, daemon diagnostic, or caller correlation value.
type RuntimeObservation struct {
	DedicatedDisposableTarget bool                       `json:"dedicated_disposable_target"`
	RunUniqueNamespace        bool                       `json:"run_unique_namespace"`
	Target                    TargetIdentity             `json:"target_identity"`
	Artifacts                 []ArtifactObservation      `json:"artifact_identities"`
	Configurations            []ConfigurationObservation `json:"configuration_identities"`
}

// RuntimeInput contains the only local-only path and the sanitized ownership
// selector identity. PersistentStateRoot must be absolute and clean, every
// existing path component must be a real directory rather than a symlink, its
// immediate parent must be trusted and non-group/world-writable, and the root
// must not already exist. Its raw path is never included in a sanitized digest
// or returned evidence projection.
type RuntimeInput struct {
	OwnershipSelectorDigest string
	PersistentStateRoot     string
}

// IdentityObserver obtains the actual pre-mutation target, artifact, and
// configuration snapshot. It has no mutation method. PrepareRuntime validates
// the returned roles against d1 instead of accepting them as configuration.
type IdentityObserver interface {
	Observe(context.Context) (RuntimeObservation, error)
}

// QueryScope is the closed report-compatible authoritative inspector scope.
type QueryScope struct {
	Digest                       string   `json:"scope_digest"`
	DigestProfile                string   `json:"scope_digest_profile"`
	TargetDigest                 string   `json:"target_digest"`
	RunNamespaceDigest           string   `json:"run_namespace_digest"`
	OwnershipSelectorDigest      string   `json:"ownership_selector_digest"`
	ResourceKinds                []string `json:"resource_kinds"`
	InspectorArtifactDigest      string   `json:"inspector_artifact_digest"`
	InspectorConfigurationDigest string   `json:"inspector_configuration_digest"`
	ExcludesHarnessControlPlane  bool     `json:"excludes_harness_control_plane"`
}

// ResourceEntry contains only a sanitized observer identity and its canonical
// identity digest. Backend IDs and raw runtime descriptions are forbidden.
type ResourceEntry struct {
	ResourceKind     string `json:"resource_kind"`
	StableObserverID string `json:"stable_observer_id"`
	IdentityDigest   string `json:"identity_digest"`
}

// Inspection is one complete response from the out-of-band inspector. The
// harness derives count, ordering, digest, stability, and sample time; it does
// not trust caller-supplied summaries.
type Inspection struct {
	QueryScopeDigest string
	Complete         bool
	Entries          []ResourceEntry
}

// ResourceInspector has no mutation method. Keeping preflight read-only makes
// it impossible for d2 to accidentally execute a profile scenario.
type ResourceInspector interface {
	Inspect(context.Context, QueryScope) (Inspection, error)
}

// ResourceBaseline is the report-compatible pre-mutation summary. SampledAt
// is stamped by the harness after the inspector returns successfully.
type ResourceBaseline struct {
	QueryScopeDigest string    `json:"query_scope_digest"`
	InventoryDigest  string    `json:"inventory_digest"`
	DigestProfile    string    `json:"inventory_digest_profile"`
	RunOwnedCount    int       `json:"run_owned_resource_count"`
	Stable           bool      `json:"stable"`
	SampledAt        time.Time `json:"sampled_at"`
}

type inventoryDocument struct {
	FormatVersion    int             `json:"format_version"`
	QueryScopeDigest string          `json:"query_scope_digest"`
	Entries          []ResourceEntry `json:"entries"`
}

type runtimeCommitmentDocument struct {
	FormatVersion          int                                      `json:"format_version"`
	StaticConfiguration    string                                   `json:"static_configuration_digest"`
	Target                 TargetIdentity                           `json:"target_identity"`
	Artifacts              []ArtifactObservation                    `json:"artifact_identities"`
	Configurations         []ConfigurationObservation               `json:"configuration_identities"`
	Limits                 qualificationprofile.RuntimeLimits       `json:"runtime_limits"`
	Cleanup                qualificationprofile.CleanupRequirements `json:"cleanup_requirements"`
	QueryScope             QueryScope                               `json:"query_scope"`
	Baseline               ResourceBaseline                         `json:"baseline"`
	PersistentStoreIDs     []string                                 `json:"persistent_store_ids"`
	ExecutionStartedAt     string                                   `json:"execution_started_at"`
	ExecutionDeadlineAt    string                                   `json:"execution_deadline_at"`
	TotalWallClockDeadline string                                   `json:"total_wall_clock_deadline_at"`
}

// PreparedRuntime is an immutable sanitized runtime snapshot plus descriptor-
// backed local persistent stores. Close releases descriptors only; the state
// root remains for the later operator-owned d6 teardown.
type PreparedRuntime struct {
	mu                      sync.Mutex
	closed                  bool
	initialAttempted        bool
	initialActive           bool
	reconstructionAttempted bool
	reconstructionActive    bool
	observationAttempted    bool
	observationActive       bool
	cleanupAttempted        bool
	cleanupActive           bool
	evidenceAttempted       bool
	evidenceActive          bool
	cleanupRequired         bool
	initialResult           *InitialPhaseResult
	reconstructionResult    *ReconstructionPhaseResult
	executionObservation    *ExecutionObservationResult
	cleanupResult           *CleanupResult
	evidenceResult          *EvidenceFinalizationResult
	digest                  string
	profileID               string
	profileVersion          string
	profileDigest           string
	orchestration           map[string]qualificationprofile.PhaseOrchestration
	reconstruction          qualificationprofile.ReconstructionRequirements
	observationPlan         []qualificationprofile.PhaseObservationPlan
	observation             RuntimeObservation
	limits                  qualificationprofile.RuntimeLimits
	cleanup                 qualificationprofile.CleanupRequirements
	queryScope              QueryScope
	baseline                ResourceBaseline
	executionStarted        time.Time
	executionDeadline       time.Time
	totalDeadline           time.Time
	state                   *persistentState
}

// PrepareRuntime binds the d1 expectations to a complete runtime identity
// snapshot, exclusively creates the three reconstruction stores, and captures
// one complete zero-resource baseline. It exposes no mutation operation and
// therefore cannot execute any of the 15+5 qualification scenarios.
func PrepareRuntime(ctx context.Context, frozen *FrozenConfiguration, input RuntimeInput, identityObserver IdentityObserver, inspector ResourceInspector) (_ *PreparedRuntime, resultErr error) {
	if ctx == nil || frozen == nil || frozen.core == nil || nilPort(identityObserver) || nilPort(inspector) ||
		!digestPattern.MatchString(input.OwnershipSelectorDigest) || !validPersistentStateRoot(input.PersistentStateRoot) {
		return nil, ErrRuntimePreflight
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	limits := frozen.RuntimeLimits()
	cleanup := frozen.CleanupRequirements()
	if !validRuntimeRequirements(limits, cleanup) {
		return nil, ErrRuntimePreflight
	}
	executionDeadline := started.Add(time.Duration(limits.MaxExecutionSeconds) * time.Second)
	totalDeadline := started.Add(time.Duration(limits.MaxTotalWallClockSeconds) * time.Second)
	operationContext, cancel := context.WithDeadline(ctx, executionDeadline)
	defer cancel()

	suppliedObservation, observeErr := identityObserver.Observe(operationContext)
	if observeErr != nil || operationContext.Err() != nil {
		return nil, runtimeContextError(operationContext)
	}
	observation, inspectorArtifactDigest, inspectorConfigurationDigest, err := validateRuntimeObservation(frozen, suppliedObservation)
	if err != nil {
		return nil, err
	}
	scope := QueryScope{
		DigestProfile: InventoryDigestProfile, TargetDigest: observation.Target.TargetDigest,
		RunNamespaceDigest: observation.Target.RunNamespaceDigest, OwnershipSelectorDigest: input.OwnershipSelectorDigest,
		ResourceKinds: append([]string(nil), cleanup.InspectorScope...), InspectorArtifactDigest: inspectorArtifactDigest,
		InspectorConfigurationDigest: inspectorConfigurationDigest, ExcludesHarnessControlPlane: true,
	}
	scope.Digest, err = canonicalDigest(map[string]any{
		"target_digest": scope.TargetDigest, "run_namespace_digest": scope.RunNamespaceDigest,
		"ownership_selector_digest": scope.OwnershipSelectorDigest, "resource_kinds": scope.ResourceKinds,
		"inspector_artifact_digest":      scope.InspectorArtifactDigest,
		"inspector_configuration_digest": scope.InspectorConfigurationDigest,
		"excludes_harness_control_plane": scope.ExcludesHarnessControlPlane,
	})
	if err != nil {
		return nil, ErrRuntimePreflight
	}

	state, err := createPersistentState(operationContext, input.PersistentStateRoot)
	if err != nil {
		result := runtimeContextError(operationContext)
		if errors.Is(err, ErrPersistentStateRetained) {
			result = errors.Join(result, ErrPersistentStateRetained)
		}
		return nil, result
	}
	defer func() {
		if resultErr != nil {
			_ = state.close()
			resultErr = errors.Join(resultErr, ErrPersistentStateRetained)
		}
	}()
	inspection, inspectErr := inspector.Inspect(operationContext, cloneQueryScope(scope))
	sampledAt := time.Now().UTC()
	if inspectErr != nil || operationContext.Err() != nil || !validInspection(scope, cleanup, inspection) {
		return nil, runtimeContextError(operationContext)
	}
	entries := make([]ResourceEntry, len(inspection.Entries))
	copy(entries, inspection.Entries)
	inventoryDigest, err := canonicalDigest(inventoryDocument{
		FormatVersion: 1, QueryScopeDigest: scope.Digest, Entries: entries,
	})
	if err != nil {
		return nil, ErrRuntimePreflight
	}
	baseline := ResourceBaseline{
		QueryScopeDigest: scope.Digest, InventoryDigest: inventoryDigest, DigestProfile: cleanup.InventoryDigestProfile,
		RunOwnedCount: len(inspection.Entries), Stable: true, SampledAt: sampledAt,
	}
	if baseline.RunOwnedCount != cleanup.PreRunRunOwnedResourceCount || sampledAt.Before(started) {
		return nil, ErrRuntimePreflight
	}
	if err := state.recheck(operationContext); err != nil {
		return nil, runtimeContextError(operationContext)
	}
	commitment, err := canonicalDigest(runtimeCommitmentDocument{
		FormatVersion: 1, StaticConfiguration: frozen.Digest(), Target: observation.Target,
		Artifacts: observation.Artifacts, Configurations: observation.Configurations, Limits: limits,
		Cleanup: cleanup, QueryScope: scope, Baseline: baseline, PersistentStoreIDs: persistentStoreIDs(),
		ExecutionStartedAt: started.Format(time.RFC3339Nano), ExecutionDeadlineAt: executionDeadline.Format(time.RFC3339Nano),
		TotalWallClockDeadline: totalDeadline.Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, ErrRuntimePreflight
	}
	return &PreparedRuntime{
		digest: commitment, profileID: frozen.core.profileID, profileVersion: frozen.core.profileVersion,
		profileDigest: frozen.core.profileDigest, orchestration: cloneOrchestration(frozen.core.orchestration),
		reconstruction:  cloneReconstructionRequirements(frozen.core.reconstruction),
		observationPlan: cloneObservationPlan(frozen.core.observationPlan),
		observation:     observation, limits: limits, cleanup: cleanup, queryScope: scope, baseline: baseline,
		executionStarted: started, executionDeadline: executionDeadline, totalDeadline: totalDeadline, state: state,
	}, nil
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validateRuntimeObservation(frozen *FrozenConfiguration, supplied RuntimeObservation) (RuntimeObservation, string, string, error) {
	if !supplied.DedicatedDisposableTarget || !supplied.RunUniqueNamespace || supplied.Target != frozen.TargetIdentity() {
		return RuntimeObservation{}, "", "", ErrRuntimePreflight
	}
	requirements := frozen.ArtifactRequirements()
	if len(supplied.Artifacts) != len(requirements) {
		return RuntimeObservation{}, "", "", ErrRuntimePreflight
	}
	artifacts := make([]ArtifactObservation, len(supplied.Artifacts))
	inspectorArtifactDigest := ""
	for index, actual := range supplied.Artifacts {
		expected := requirements[index]
		if actual.ArtifactID != expected.ArtifactID || actual.Owner != expected.Owner || actual.TrustDomain != expected.TrustDomain ||
			actual.DigestSubject != expected.DigestSubject || actual.ObservedBy != expected.ObservedBy || !digestPattern.MatchString(actual.Digest) ||
			(expected.SourceIdentityRequired && !validSourceIdentity(actual.Source)) {
			return RuntimeObservation{}, "", "", ErrRuntimePreflight
		}
		artifacts[index] = cloneArtifactObservation(actual)
		if actual.ArtifactID == "resource_inspector" {
			inspectorArtifactDigest = actual.Digest
		}
	}
	expectations := frozen.ConfigurationExpectations()
	if len(supplied.Configurations) != len(expectations) {
		return RuntimeObservation{}, "", "", ErrRuntimePreflight
	}
	configurations := append([]ConfigurationObservation(nil), supplied.Configurations...)
	inspectorConfigurationDigest := ""
	for index, actual := range configurations {
		expected := expectations[index]
		if actual.ID != expected.ID || actual.Digest != expected.Digest || actual.DigestProfile != expected.DigestProfile || !actual.Sanitized || actual.ObservedBy != "process_supervisor" {
			return RuntimeObservation{}, "", "", ErrRuntimePreflight
		}
		if actual.ID == "inspector_configuration" {
			inspectorConfigurationDigest = actual.Digest
		}
	}
	if inspectorArtifactDigest == "" || inspectorConfigurationDigest == "" {
		return RuntimeObservation{}, "", "", ErrRuntimePreflight
	}
	return RuntimeObservation{
		DedicatedDisposableTarget: true, RunUniqueNamespace: true, Target: supplied.Target,
		Artifacts: artifacts, Configurations: configurations,
	}, inspectorArtifactDigest, inspectorConfigurationDigest, nil
}

func validSourceIdentity(identity *SourceIdentity) bool {
	if identity == nil || !identity.Immutable {
		return false
	}
	switch identity.Kind {
	case "source-revision":
		return sourceRevisionPattern.MatchString(identity.Value)
	case "oci-digest", "build-attestation":
		return digestPattern.MatchString(identity.Value)
	case "release-id", "operator-release":
		return releaseIDPattern.MatchString(identity.Value)
	default:
		return false
	}
}

func validRuntimeRequirements(limits qualificationprofile.RuntimeLimits, cleanup qualificationprofile.CleanupRequirements) bool {
	for _, value := range []int{
		limits.MaxSandboxes, limits.MaxExecRequests, limits.MaxAdmittedExecOperations, limits.MaxTerminalSessions,
		limits.MaxArtifactRequests, limits.MaxAdmittedArtifactOperations, limits.MaxDistinctProviderMutations,
		limits.MaxProviderMutationWriteAttempts, limits.MaxGatewayMutationWriteAttempts, limits.MaxProviderHTTPRequests,
		limits.MaxGatewayConnectionAttempts, limits.MaxCaseSeconds, limits.MaxExecutionSeconds, limits.MaxCleanupSeconds,
		limits.MaxTotalWallClockSeconds, limits.SandboxCPUMillis, limits.SandboxMemoryBytes,
		limits.SandboxEphemeralStorageBytes, limits.SandboxPIDs, limits.MaxEvidenceFiles,
		limits.MaxEvidenceFileBytes, limits.MaxEvidenceTotalBytes,
	} {
		if value <= 0 {
			return false
		}
	}
	return limits.MaxExecutionSeconds+limits.MaxCleanupSeconds == limits.MaxTotalWallClockSeconds &&
		cleanup.Authority == CleanupAuthority && cleanup.PreRunBaselineRequired && cleanup.QueryScopeIdentityRequired &&
		cleanup.QueryScopeDigestProfile == InventoryDigestProfile && cleanup.QueryScopeExcludesHarnessControl &&
		cleanup.InventoryDigestProfile == InventoryDigestProfile && cleanup.InventoryOrder == "resource-type-then-stable-observer-id-lexicographic" &&
		cleanup.PreRunRunOwnedResourceCount == 0 && cleanup.PostTeardownRunOwnedResourceCount == 0 &&
		cleanup.PostTeardownStabilitySamples == 3 && cleanup.PostTeardownStabilityIntervalMS == 1000 &&
		reflect.DeepEqual(cleanup.InspectorScope, []string{
			"runtime_allocations", "compute_resources", "network_resources", "storage_resources", "run_owned_processes",
		})
}

func validInspection(scope QueryScope, cleanup qualificationprofile.CleanupRequirements, inspection Inspection) bool {
	if !inspection.Complete || inspection.QueryScopeDigest != scope.Digest || inspection.Entries == nil || len(inspection.Entries) > 512 {
		return false
	}
	allowedKinds := make(map[string]struct{}, len(cleanup.InspectorScope))
	for _, kind := range cleanup.InspectorScope {
		allowedKinds[kind] = struct{}{}
	}
	for index, entry := range inspection.Entries {
		if _, ok := allowedKinds[entry.ResourceKind]; !ok || !observerIDPattern.MatchString(entry.StableObserverID) || !digestPattern.MatchString(entry.IdentityDigest) ||
			strings.ContainsAny(entry.StableObserverID, `/\\`) {
			return false
		}
		if index > 0 {
			previous := inspection.Entries[index-1]
			if previous.ResourceKind > entry.ResourceKind || (previous.ResourceKind == entry.ResourceKind && previous.StableObserverID >= entry.StableObserverID) {
				return false
			}
		}
	}
	return sort.SliceIsSorted(inspection.Entries, func(i, j int) bool {
		if inspection.Entries[i].ResourceKind == inspection.Entries[j].ResourceKind {
			return inspection.Entries[i].StableObserverID < inspection.Entries[j].StableObserverID
		}
		return inspection.Entries[i].ResourceKind < inspection.Entries[j].ResourceKind
	})
}

func runtimeContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrRuntimePreflight
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrRuntimePreflight, err)
	}
	return ErrRuntimePreflight
}

func cloneArtifactObservation(source ArtifactObservation) ArtifactObservation {
	result := source
	if source.Source != nil {
		identity := *source.Source
		result.Source = &identity
	}
	return result
}

func cloneRuntimeObservation(source RuntimeObservation) RuntimeObservation {
	result := source
	result.Artifacts = make([]ArtifactObservation, len(source.Artifacts))
	for index, artifact := range source.Artifacts {
		result.Artifacts[index] = cloneArtifactObservation(artifact)
	}
	result.Configurations = append([]ConfigurationObservation(nil), source.Configurations...)
	return result
}

func cloneQueryScope(source QueryScope) QueryScope {
	result := source
	result.ResourceKinds = append([]string(nil), source.ResourceKinds...)
	return result
}

// Digest returns the sanitized d2 commitment. It excludes all local paths.
func (r *PreparedRuntime) Digest() string {
	if r == nil {
		return ""
	}
	return r.digest
}

// Observation returns a defensive copy of the matched identity snapshot.
func (r *PreparedRuntime) Observation() RuntimeObservation {
	if r == nil {
		return RuntimeObservation{}
	}
	return cloneRuntimeObservation(r.observation)
}

func (r *PreparedRuntime) RuntimeLimits() qualificationprofile.RuntimeLimits {
	if r == nil {
		return qualificationprofile.RuntimeLimits{}
	}
	return r.limits
}

func (r *PreparedRuntime) CleanupRequirements() qualificationprofile.CleanupRequirements {
	if r == nil {
		return qualificationprofile.CleanupRequirements{}
	}
	return cloneCleanupRequirements(r.cleanup)
}

func (r *PreparedRuntime) QueryScope() QueryScope {
	if r == nil {
		return QueryScope{}
	}
	return cloneQueryScope(r.queryScope)
}

func (r *PreparedRuntime) Baseline() ResourceBaseline {
	if r == nil {
		return ResourceBaseline{}
	}
	return r.baseline
}

func (r *PreparedRuntime) Deadlines() (executionStarted, executionDeadline, totalDeadline time.Time) {
	if r == nil {
		return time.Time{}, time.Time{}, time.Time{}
	}
	return r.executionStarted, r.executionDeadline, r.totalDeadline
}

// PersistentStatePath returns a local-only path needed to compose a component.
// Callers must never place it in qualification evidence or logs.
func (r *PreparedRuntime) PersistentStatePath(storeID string) (string, bool) {
	if r == nil || r.state == nil {
		return "", false
	}
	return r.state.path(storeID)
}

// RecheckPersistentState verifies descriptor and pathname identity without
// opening or enumerating any store entry.
func (r *PreparedRuntime) RecheckPersistentState(ctx context.Context) error {
	if r == nil || r.state == nil {
		return ErrRuntimePreflight
	}
	if err := r.state.recheck(ctx); err != nil {
		return runtimeContextError(ctx)
	}
	return nil
}

// Close releases local descriptors. It never removes the persistent state.
func (r *PreparedRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.initialActive || r.reconstructionActive || r.observationActive || r.cleanupActive {
		return ErrRuntimePreflight
	}
	if r.closed {
		return nil
	}
	r.closed = true
	if r.state == nil {
		return nil
	}
	if err := r.state.close(); err != nil {
		return ErrRuntimePreflight
	}
	return nil
}
