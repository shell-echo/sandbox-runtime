package qualificationharness

import (
	"context"
	"errors"
	"time"
)

const (
	MaxTeardownAttempts       = 32
	CleanupOutcomeSucceeded   = "succeeded"
	CleanupOutcomeFailed      = "failed"
	CleanupOutcomeUnknown     = "unknown"
	CleanupOutcomeNotRequired = "not_required"
	CleanupOutcomeIncomplete  = "incomplete"
)

var ErrCleanup = errors.New("qualification cleanup failed")

// TeardownDirective is the complete harness-to-teardown input. The operator's
// separately frozen configuration owns the concrete target, namespace, state
// locations, and credentials; the harness supplies only sanitized identities.
type TeardownDirective struct {
	RuntimeCommitmentDigest string `json:"runtime_commitment_digest"`
	ProfileID               string `json:"profile_id"`
	ProfileVersion          string `json:"profile_version"`
	ProfileDigest           string `json:"profile_digest"`
	Authority               string `json:"authority"`
	QueryScopeDigest        string `json:"query_scope_digest"`
}

// TeardownReceipt is the operator-owned, sanitized completion projection. One
// Teardown call may perform bounded internal retries, whose exact count must be
// between one and the report Schema's maximum of 32.
type TeardownReceipt struct {
	RuntimeCommitmentDigest     string `json:"runtime_commitment_digest"`
	Authority                   string `json:"authority"`
	QueryScopeDigest            string `json:"query_scope_digest"`
	TeardownArtifactDigest      string `json:"teardown_artifact_digest"`
	TeardownConfigurationDigest string `json:"teardown_configuration_digest"`
	Attempts                    int    `json:"attempts"`
	Completed                   bool   `json:"completed"`
}

// TeardownOperator owns the out-of-band run-namespace teardown. Its concrete
// endpoint, credentials, host paths, backend IDs, and selection mechanism never
// cross this interface.
type TeardownOperator interface {
	Teardown(context.Context, TeardownDirective) (TeardownReceipt, error)
}

// CleanupInventory is the report-compatible normalized inventory summary. It
// contains one baseline timestamp or exactly three post-teardown timestamps.
type CleanupInventory struct {
	QueryScopeDigest string      `json:"query_scope_digest"`
	InventoryDigest  string      `json:"inventory_digest"`
	DigestProfile    string      `json:"inventory_digest_profile"`
	RunOwnedCount    int         `json:"run_owned_resource_count"`
	Stable           bool        `json:"stable"`
	SampledAt        []time.Time `json:"sampled_at"`
}

// CleanupResult is a sanitized d6 result. It records the original conservative
// obligation separately from independently observed mutation writes. It is not
// a final run outcome and does not write an evidence root.
type CleanupResult struct {
	Authority                     string            `json:"authority"`
	MutationWriteObserved         bool              `json:"mutation_write_observed"`
	CleanupRequired               bool              `json:"cleanup_required"`
	QueryScope                    QueryScope        `json:"query_scope"`
	Baseline                      CleanupInventory  `json:"baseline"`
	TeardownAttempts              int               `json:"teardown_attempts"`
	TeardownCompleted             bool              `json:"teardown_completed"`
	PostTeardown                  *CleanupInventory `json:"post_teardown"`
	StabilitySamples              int               `json:"stability_samples"`
	StabilityIntervalMilliseconds int               `json:"stability_interval_milliseconds"`
	Outcome                       string            `json:"outcome"`
	CleanupStartedAt              time.Time         `json:"cleanup_started_at"`
	CleanupFinishedAt             time.Time         `json:"cleanup_finished_at"`
}

type cleanupClock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}

type systemCleanupClock struct{}

func (systemCleanupClock) Now() time.Time { return time.Now().UTC() }

func (systemCleanupClock) Wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RunCleanup consumes the persistent cleanup obligation once. Cancellation of
// the execution caller does not cancel cleanup or leak its context values: the
// operation receives a fresh context bounded by both the 300-second cleanup
// budget and the original total wall-clock deadline.
func RunCleanup(ctx context.Context, prepared *PreparedRuntime, teardown TeardownOperator, inspector ResourceInspector) (CleanupResult, error) {
	return runCleanup(ctx, prepared, teardown, inspector, systemCleanupClock{})
}

func runCleanup(ctx context.Context, prepared *PreparedRuntime, teardown TeardownOperator, inspector ResourceInspector, clock cleanupClock) (result CleanupResult, resultErr error) {
	if ctx == nil || prepared == nil || nilPort(clock) {
		return CleanupResult{}, ErrCleanup
	}
	observation, cleanupRequired, ok := prepared.beginCleanup(!nilPort(teardown))
	if !ok {
		return CleanupResult{}, ErrCleanup
	}
	result = CleanupResult{
		Authority: cleanupAuthority(prepared), MutationWriteObserved: observedMutationWrite(observation),
		CleanupRequired: cleanupRequired, QueryScope: cloneQueryScope(prepared.queryScope),
		Baseline: cleanupBaseline(prepared.baseline), CleanupStartedAt: clock.Now().UTC(),
	}
	cleanupDeadline := time.Time{}
	defer func() {
		result.CleanupFinishedAt = clock.Now().UTC()
		if result.CleanupFinishedAt.Before(result.CleanupStartedAt) || (!cleanupDeadline.IsZero() && result.CleanupFinishedAt.After(cleanupDeadline)) {
			if result.Outcome == CleanupOutcomeSucceeded || result.Outcome == CleanupOutcomeNotRequired {
				result.Outcome = CleanupOutcomeIncomplete
			} else if result.Outcome == "" {
				result.Outcome = CleanupOutcomeUnknown
			}
			resultErr = errors.Join(resultErr, ErrCleanup)
		}
		prepared.finishCleanup(result)
	}()

	stateReleased := true
	if prepared.state != nil {
		stateReleased = prepared.state.close() == nil
	}
	if !cleanupRequired {
		result.Outcome = CleanupOutcomeNotRequired
		if !stateReleased {
			result.Outcome = CleanupOutcomeIncomplete
			return result, ErrCleanup
		}
		return result, nil
	}

	cleanupDeadline = result.CleanupStartedAt.Add(time.Duration(prepared.limits.MaxCleanupSeconds) * time.Second)
	if prepared.totalDeadline.Before(cleanupDeadline) {
		cleanupDeadline = prepared.totalDeadline
	}
	if !cleanupDeadline.After(result.CleanupStartedAt) {
		result.Outcome = CleanupOutcomeUnknown
		return result, errors.Join(ErrCleanup, context.DeadlineExceeded)
	}
	cleanupContext, cancel := context.WithDeadline(context.Background(), cleanupDeadline)
	defer cancel()
	directive := TeardownDirective{
		RuntimeCommitmentDigest: prepared.digest, ProfileID: prepared.profileID, ProfileVersion: prepared.profileVersion,
		ProfileDigest: prepared.profileDigest, Authority: result.Authority, QueryScopeDigest: prepared.queryScope.Digest,
	}
	receipt, err := teardown.Teardown(cleanupContext, directive)
	observedAt := clock.Now().UTC()
	if err != nil || cleanupContext.Err() != nil || observedAt.Before(result.CleanupStartedAt) || observedAt.After(cleanupDeadline) {
		result.Outcome = CleanupOutcomeUnknown
		return result, cleanupContextError(cleanupContext)
	}
	if !validTeardownReceipt(prepared, directive, receipt) {
		result.Outcome = CleanupOutcomeUnknown
		return result, ErrCleanup
	}
	result.TeardownAttempts = receipt.Attempts
	result.TeardownCompleted = receipt.Completed
	if !receipt.Completed {
		result.Outcome = CleanupOutcomeFailed
		return result, nil
	}
	if nilPort(inspector) {
		result.Outcome = CleanupOutcomeUnknown
		return result, nil
	}

	samples := make([]CleanupInventory, 0, prepared.cleanup.PostTeardownStabilitySamples)
	interval := time.Duration(prepared.cleanup.PostTeardownStabilityIntervalMS) * time.Millisecond
	for index := 0; index < prepared.cleanup.PostTeardownStabilitySamples; index++ {
		if index > 0 {
			if err := clock.Wait(cleanupContext, interval); err != nil || cleanupContext.Err() != nil || clock.Now().After(cleanupDeadline) {
				result.Outcome = CleanupOutcomeIncomplete
				return result, cleanupContextError(cleanupContext)
			}
		}
		inspection, inspectErr := inspector.Inspect(cleanupContext, cloneQueryScope(prepared.queryScope))
		sampledAt := clock.Now().UTC()
		if inspectErr != nil || cleanupContext.Err() != nil || sampledAt.Before(result.CleanupStartedAt) || sampledAt.After(cleanupDeadline) || !validInspection(prepared.queryScope, prepared.cleanup, inspection) {
			result.Outcome = CleanupOutcomeIncomplete
			return result, cleanupContextError(cleanupContext)
		}
		digest, digestErr := canonicalDigest(inventoryDocument{FormatVersion: 1, QueryScopeDigest: prepared.queryScope.Digest, Entries: inspection.Entries})
		if digestErr != nil {
			result.Outcome = CleanupOutcomeIncomplete
			return result, ErrCleanup
		}
		samples = append(samples, CleanupInventory{
			QueryScopeDigest: prepared.queryScope.Digest, InventoryDigest: digest,
			DigestProfile: prepared.cleanup.InventoryDigestProfile, RunOwnedCount: len(inspection.Entries),
			Stable: true, SampledAt: []time.Time{sampledAt},
		})
	}
	post := combineCleanupSamples(samples, interval)
	result.PostTeardown = &post
	result.StabilitySamples = len(samples)
	result.StabilityIntervalMilliseconds = prepared.cleanup.PostTeardownStabilityIntervalMS
	if stateReleased && post.Stable && post.QueryScopeDigest == result.Baseline.QueryScopeDigest &&
		post.InventoryDigest == result.Baseline.InventoryDigest && post.RunOwnedCount == prepared.cleanup.PostTeardownRunOwnedResourceCount {
		result.Outcome = CleanupOutcomeSucceeded
		return result, nil
	}
	result.Outcome = CleanupOutcomeIncomplete
	return result, nil
}

func validTeardownReceipt(prepared *PreparedRuntime, directive TeardownDirective, receipt TeardownReceipt) bool {
	artifactDigest, configurationDigest := teardownIdentities(prepared.observation)
	return receipt.RuntimeCommitmentDigest == directive.RuntimeCommitmentDigest && receipt.Authority == directive.Authority &&
		receipt.QueryScopeDigest == directive.QueryScopeDigest && receipt.TeardownArtifactDigest == artifactDigest &&
		receipt.TeardownConfigurationDigest == configurationDigest && receipt.Attempts >= 1 && receipt.Attempts <= MaxTeardownAttempts
}

func teardownIdentities(observation RuntimeObservation) (string, string) {
	artifactDigest, configurationDigest := "", ""
	for _, artifact := range observation.Artifacts {
		if artifact.ArtifactID == "teardown" {
			artifactDigest = artifact.Digest
		}
	}
	for _, configuration := range observation.Configurations {
		if configuration.ID == "teardown_configuration" {
			configurationDigest = configuration.Digest
		}
	}
	return artifactDigest, configurationDigest
}

func cleanupAuthority(prepared *PreparedRuntime) string {
	if prepared == nil {
		return ""
	}
	return prepared.cleanup.Authority
}

func cleanupBaseline(source ResourceBaseline) CleanupInventory {
	return CleanupInventory{
		QueryScopeDigest: source.QueryScopeDigest, InventoryDigest: source.InventoryDigest,
		DigestProfile: source.DigestProfile, RunOwnedCount: source.RunOwnedCount,
		Stable: source.Stable, SampledAt: []time.Time{source.SampledAt},
	}
}

func observedMutationWrite(observation *ExecutionObservationResult) bool {
	if observation == nil {
		return false
	}
	for _, group := range [][]ObservedInteraction{observation.Provider.Interactions, observation.Gateway.Interactions} {
		for _, interaction := range group {
			if interaction.MutationWriteObserved {
				return true
			}
		}
	}
	return false
}

func combineCleanupSamples(samples []CleanupInventory, interval time.Duration) CleanupInventory {
	if len(samples) == 0 {
		return CleanupInventory{}
	}
	result := samples[len(samples)-1]
	result.SampledAt = make([]time.Time, len(samples))
	result.Stable = true
	for index, sample := range samples {
		result.SampledAt[index] = sample.SampledAt[0]
		if sample.QueryScopeDigest != result.QueryScopeDigest || sample.InventoryDigest != result.InventoryDigest ||
			sample.DigestProfile != result.DigestProfile || sample.RunOwnedCount != result.RunOwnedCount ||
			(index > 0 && result.SampledAt[index].Sub(result.SampledAt[index-1]) < interval) {
			result.Stable = false
		}
	}
	return result
}

func cleanupContextError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrCleanup, ctx.Err())
	}
	return ErrCleanup
}

func cloneCleanupInventory(source CleanupInventory) CleanupInventory {
	result := source
	result.SampledAt = append([]time.Time(nil), source.SampledAt...)
	return result
}

func cloneCleanupResult(source CleanupResult) CleanupResult {
	result := source
	result.QueryScope = cloneQueryScope(source.QueryScope)
	result.Baseline = cloneCleanupInventory(source.Baseline)
	if source.PostTeardown != nil {
		post := cloneCleanupInventory(*source.PostTeardown)
		result.PostTeardown = &post
	}
	return result
}

func (r *PreparedRuntime) beginCleanup(teardownAvailable bool) (*ExecutionObservationResult, bool, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleanupAttempted || r.cleanupActive || r.initialActive || r.reconstructionActive || r.observationActive ||
		(r.cleanupRequired && !teardownAvailable) {
		return nil, false, false
	}
	r.cleanupAttempted = true
	r.cleanupActive = true
	var observation *ExecutionObservationResult
	if r.executionObservation != nil {
		copy := cloneExecutionObservationResult(*r.executionObservation)
		observation = &copy
	}
	return observation, r.cleanupRequired, true
}

func (r *PreparedRuntime) finishCleanup(result CleanupResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copy := cloneCleanupResult(result)
	r.cleanupResult = &copy
	r.cleanupActive = false
	r.closed = true
}

// CleanupResult returns the immutable d6 snapshot after its one-shot attempt.
// A failed, incomplete, or unknown outcome preserves the cleanup uncertainty.
func (r *PreparedRuntime) CleanupResult() (CleanupResult, bool) {
	if r == nil {
		return CleanupResult{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cleanupActive || r.cleanupResult == nil {
		return CleanupResult{}, false
	}
	return cloneCleanupResult(*r.cleanupResult), true
}
