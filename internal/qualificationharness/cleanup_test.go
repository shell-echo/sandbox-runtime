package qualificationharness

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type teardownOperatorFunc func(context.Context, TeardownDirective) (TeardownReceipt, error)

func (f teardownOperatorFunc) Teardown(ctx context.Context, directive TeardownDirective) (TeardownReceipt, error) {
	return f(ctx, directive)
}

type fakeCleanupClock struct {
	now       time.Time
	waits     []time.Duration
	waitError error
}

func (c *fakeCleanupClock) Now() time.Time { return c.now }

func (c *fakeCleanupClock) Wait(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.waits = append(c.waits, duration)
	c.now = c.now.Add(duration)
	return c.waitError
}

func successfulTeardown(prepared *PreparedRuntime, inspectDirective func(context.Context, TeardownDirective)) TeardownOperator {
	artifactDigest, configurationDigest := teardownIdentities(prepared.Observation())
	return teardownOperatorFunc(func(ctx context.Context, directive TeardownDirective) (TeardownReceipt, error) {
		if inspectDirective != nil {
			inspectDirective(ctx, directive)
		}
		return TeardownReceipt{
			RuntimeCommitmentDigest: directive.RuntimeCommitmentDigest, Authority: directive.Authority,
			QueryScopeDigest: directive.QueryScopeDigest, TeardownArtifactDigest: artifactDigest,
			TeardownConfigurationDigest: configurationDigest, Attempts: 2, Completed: true,
		}, nil
	})
}

func triggerUnknownInitialOutcome(t *testing.T, prepared *PreparedRuntime) {
	t.Helper()
	_, err := RunInitial(context.Background(), prepared, initialExecutorFunc(func(context.Context, InitialPhaseDirective) (InitialPhaseSession, error) {
		return nil, errors.New("private endpoint and credential")
	}))
	if !errors.Is(err, ErrInitialPhase) || !prepared.CleanupRequired() {
		t.Fatalf("RunInitial() error = %v, cleanup=%t", err, prepared.CleanupRequired())
	}
}

func TestRunCleanupUsesDetachedBoundedContextAndStableZeroSamples(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	runObservationPhases(t, prepared, false)
	fixture := observationFixture(t, prepared)
	directives := []ObservationDirective{}
	if _, err := ObserveExecution(context.Background(), prepared, fixedExecutionObservers(fixture, &directives)); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	clock := &fakeCleanupClock{now: prepared.executionStarted.Add(10 * time.Minute)}
	inspections := 0
	inspector := inspectorFunc(func(ctx context.Context, scope QueryScope) (Inspection, error) {
		inspections++
		if ctx.Err() != nil || scope.Digest != prepared.QueryScope().Digest {
			return Inspection{}, errors.New("cleanup context or scope mismatch")
		}
		return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: []ResourceEntry{}}, nil
	})
	type privateContextKey struct{}
	parent, cancel := context.WithCancel(context.WithValue(context.Background(), privateContextKey{}, "must-not-cross-cleanup-boundary"))
	cancel()
	teardownCalls := 0
	teardown := successfulTeardown(prepared, func(ctx context.Context, directive TeardownDirective) {
		teardownCalls++
		deadline, ok := ctx.Deadline()
		if ctx.Err() != nil || !ok || !deadline.Equal(clock.now.Add(300*time.Second)) || ctx.Value(privateContextKey{}) != nil {
			t.Fatalf("teardown context = err %v, deadline %v, %t", ctx.Err(), deadline, ok)
		}
		if directive.RuntimeCommitmentDigest != prepared.Digest() || directive.ProfileID == "" || directive.ProfileVersion == "" || directive.ProfileDigest == "" ||
			directive.Authority != CleanupAuthority || directive.QueryScopeDigest != prepared.QueryScope().Digest {
			t.Fatalf("unexpected teardown directive: %+v", directive)
		}
		if _, ok := prepared.PersistentStatePath(CallerOwnedCorrelationState); ok {
			t.Fatal("cleanup exposed persistent state after descriptor release")
		}
	})
	result, err := runCleanup(parent, prepared, teardown, inspector, clock)
	if err != nil {
		t.Fatal(err)
	}
	if teardownCalls != 1 || inspections != 3 || result.Outcome != CleanupOutcomeSucceeded || !result.CleanupRequired || !result.MutationWriteObserved ||
		result.TeardownAttempts != 2 || !result.TeardownCompleted || result.PostTeardown == nil || !result.PostTeardown.Stable ||
		result.PostTeardown.RunOwnedCount != 0 || result.PostTeardown.InventoryDigest != result.Baseline.InventoryDigest ||
		result.StabilitySamples != 3 || result.StabilityIntervalMilliseconds != 1000 || len(result.PostTeardown.SampledAt) != 3 ||
		!reflect.DeepEqual(clock.waits, []time.Duration{time.Second, time.Second}) {
		t.Fatalf("unexpected cleanup result: %+v; calls=%d inspections=%d waits=%v", result, teardownCalls, inspections, clock.waits)
	}
	for index := 1; index < len(result.PostTeardown.SampledAt); index++ {
		if result.PostTeardown.SampledAt[index].Sub(result.PostTeardown.SampledAt[index-1]) < time.Second {
			t.Fatalf("sample interval %d is too short", index)
		}
	}
	if result.CleanupFinishedAt.Sub(result.CleanupStartedAt) != 2*time.Second {
		t.Fatalf("cleanup window = %v", result.CleanupFinishedAt.Sub(result.CleanupStartedAt))
	}

	result.QueryScope.ResourceKinds[0] = "changed"
	result.Baseline.SampledAt[0] = time.Time{}
	result.PostTeardown.SampledAt[0] = time.Time{}
	stored, ok := prepared.CleanupResult()
	if !ok || stored.QueryScope.ResourceKinds[0] == "changed" || stored.Baseline.SampledAt[0].IsZero() || stored.PostTeardown.SampledAt[0].IsZero() {
		t.Fatal("stored cleanup result was mutable")
	}
	if _, err := runCleanup(context.Background(), prepared, teardown, inspector, clock); !errors.Is(err, ErrCleanup) {
		t.Fatalf("second RunCleanup() error = %v", err)
	}
}

func TestRunCleanupRetainsObligationAfterUnknownInitialStart(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	triggerUnknownInitialOutcome(t, prepared)
	clock := &fakeCleanupClock{now: time.Now().UTC()}
	called := 0
	artifactDigest, configurationDigest := teardownIdentities(prepared.Observation())
	result, err := runCleanup(context.Background(), prepared, teardownOperatorFunc(func(_ context.Context, directive TeardownDirective) (TeardownReceipt, error) {
		called++
		return TeardownReceipt{
			RuntimeCommitmentDigest: directive.RuntimeCommitmentDigest, Authority: directive.Authority,
			QueryScopeDigest: directive.QueryScopeDigest, TeardownArtifactDigest: artifactDigest,
			TeardownConfigurationDigest: configurationDigest, Attempts: 1, Completed: false,
		}, nil
	}), nil, clock)
	if err != nil || called != 1 || !result.CleanupRequired || result.MutationWriteObserved || result.Outcome != CleanupOutcomeFailed ||
		result.TeardownAttempts != 1 || result.TeardownCompleted || result.PostTeardown != nil {
		t.Fatalf("cleanup after unknown start = %+v, %v; calls=%d", result, err, called)
	}
}

func TestRunCleanupDistinguishesUnknownAndIncompleteEvidence(t *testing.T) {
	tests := map[string]struct {
		teardown  func(*PreparedRuntime) TeardownOperator
		inspector func(*PreparedRuntime) ResourceInspector
		want      string
		wantError bool
	}{
		"teardown_error": {
			teardown: func(*PreparedRuntime) TeardownOperator {
				return teardownOperatorFunc(func(context.Context, TeardownDirective) (TeardownReceipt, error) {
					return TeardownReceipt{}, errors.New("credential at /private/path")
				})
			},
			want: CleanupOutcomeUnknown, wantError: true,
		},
		"inspector_unavailable": {
			teardown: func(prepared *PreparedRuntime) TeardownOperator { return successfulTeardown(prepared, nil) },
			want:     CleanupOutcomeUnknown,
		},
		"invalid_inspection_scope": {
			teardown: func(prepared *PreparedRuntime) TeardownOperator { return successfulTeardown(prepared, nil) },
			inspector: func(*PreparedRuntime) ResourceInspector {
				return inspectorFunc(func(context.Context, QueryScope) (Inspection, error) {
					return Inspection{QueryScopeDigest: digestOf("f"), Complete: true, Entries: []ResourceEntry{}}, nil
				})
			},
			want: CleanupOutcomeIncomplete, wantError: true,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			triggerUnknownInitialOutcome(t, prepared)
			clock := &fakeCleanupClock{now: time.Now().UTC()}
			var inspector ResourceInspector
			if test.inspector != nil {
				inspector = test.inspector(prepared)
			}
			teardown := test.teardown(prepared)
			result, err := runCleanup(context.Background(), prepared, teardown, inspector, clock)
			if (err != nil) != test.wantError || result.Outcome != test.want {
				t.Fatalf("RunCleanup() = %+v, %v", result, err)
			}
			if err != nil && (strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "/private")) {
				t.Fatalf("cleanup error leaked diagnostics: %v", err)
			}
		})
	}
}

func TestRunCleanupRejectsResidualOrUnstablePostTeardownInventory(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries func(int) []ResourceEntry
		stable  bool
	}{
		{name: "stable_residual", stable: true, entries: func(int) []ResourceEntry {
			return []ResourceEntry{{ResourceKind: "runtime_allocations", StableObserverID: "remaining-sandbox", IdentityDigest: digestOf("a")}}
		}},
		{name: "changing_inventory", stable: false, entries: func(index int) []ResourceEntry {
			if index == 1 {
				return []ResourceEntry{{ResourceKind: "compute_resources", StableObserverID: "remaining-compute", IdentityDigest: digestOf("b")}}
			}
			return []ResourceEntry{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			triggerUnknownInitialOutcome(t, prepared)
			clock := &fakeCleanupClock{now: time.Now().UTC()}
			calls := 0
			inspector := inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
				entries := test.entries(calls)
				calls++
				return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: entries}, nil
			})
			result, err := runCleanup(context.Background(), prepared, successfulTeardown(prepared, nil), inspector, clock)
			if err != nil || result.Outcome != CleanupOutcomeIncomplete || result.PostTeardown == nil || result.PostTeardown.Stable != test.stable ||
				result.StabilitySamples != 3 || len(result.PostTeardown.SampledAt) != 3 || calls != 3 {
				t.Fatalf("RunCleanup() = %+v, %v; calls=%d", result, err, calls)
			}
		})
	}
}

func TestRunCleanupValidatesTeardownIdentityAttemptsAndDeadline(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*PreparedRuntime, *TeardownReceipt, *fakeCleanupClock)
	}{
		{name: "wrong_runtime", mutate: func(_ *PreparedRuntime, receipt *TeardownReceipt, _ *fakeCleanupClock) {
			receipt.RuntimeCommitmentDigest = digestOf("f")
		}},
		{name: "wrong_scope", mutate: func(_ *PreparedRuntime, receipt *TeardownReceipt, _ *fakeCleanupClock) {
			receipt.QueryScopeDigest = digestOf("f")
		}},
		{name: "wrong_artifact", mutate: func(_ *PreparedRuntime, receipt *TeardownReceipt, _ *fakeCleanupClock) {
			receipt.TeardownArtifactDigest = digestOf("f")
		}},
		{name: "wrong_configuration", mutate: func(_ *PreparedRuntime, receipt *TeardownReceipt, _ *fakeCleanupClock) {
			receipt.TeardownConfigurationDigest = digestOf("f")
		}},
		{name: "zero_attempts", mutate: func(_ *PreparedRuntime, receipt *TeardownReceipt, _ *fakeCleanupClock) { receipt.Attempts = 0 }},
		{name: "too_many_attempts", mutate: func(_ *PreparedRuntime, receipt *TeardownReceipt, _ *fakeCleanupClock) { receipt.Attempts = 33 }},
		{name: "past_deadline", mutate: func(prepared *PreparedRuntime, _ *TeardownReceipt, clock *fakeCleanupClock) {
			prepared.totalDeadline = clock.now
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, prepared := prepareRuntimeFixture(t)
			triggerUnknownInitialOutcome(t, prepared)
			clock := &fakeCleanupClock{now: time.Now().UTC()}
			artifactDigest, configurationDigest := teardownIdentities(prepared.Observation())
			called := 0
			operator := teardownOperatorFunc(func(_ context.Context, directive TeardownDirective) (TeardownReceipt, error) {
				called++
				receipt := TeardownReceipt{
					RuntimeCommitmentDigest: directive.RuntimeCommitmentDigest, Authority: directive.Authority,
					QueryScopeDigest: directive.QueryScopeDigest, TeardownArtifactDigest: artifactDigest,
					TeardownConfigurationDigest: configurationDigest, Attempts: 1, Completed: true,
				}
				if test.name != "past_deadline" {
					test.mutate(prepared, &receipt, clock)
				}
				return receipt, nil
			})
			if test.name == "past_deadline" {
				test.mutate(prepared, nil, clock)
			}
			result, err := runCleanup(context.Background(), prepared, operator, zeroInspector(), clock)
			if !errors.Is(err, ErrCleanup) || result.Outcome != CleanupOutcomeUnknown || (test.name == "past_deadline" && called != 0) {
				t.Fatalf("RunCleanup() = %+v, %v; calls=%d", result, err, called)
			}
		})
	}
}

func TestRunCleanupNotRequiredClosesRuntimeAndPreventsExecution(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	result, err := RunCleanup(context.Background(), prepared, nil, nil)
	if err != nil || result.Outcome != CleanupOutcomeNotRequired || result.CleanupRequired || result.MutationWriteObserved ||
		result.TeardownAttempts != 0 || result.TeardownCompleted || result.PostTeardown != nil || result.StabilitySamples != 0 || result.StabilityIntervalMilliseconds != 0 {
		t.Fatalf("RunCleanup(no mutation) = %+v, %v", result, err)
	}
	if _, ok := prepared.PersistentStatePath(ProviderLocalState); ok {
		t.Fatal("no-mutation cleanup left state descriptors open")
	}
	if _, err := RunInitial(context.Background(), prepared, nil); !errors.Is(err, ErrInitialPhase) {
		t.Fatalf("RunInitial() after cleanup error = %v", err)
	}
}

func TestRunCleanupRejectsInvalidPortsAndActiveExecutionWithoutConsumingAttempt(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	triggerUnknownInitialOutcome(t, prepared)
	var typedNil teardownOperatorFunc
	if _, err := RunCleanup(context.Background(), prepared, typedNil, zeroInspector()); !errors.Is(err, ErrCleanup) {
		t.Fatalf("typed nil teardown error = %v", err)
	}
	prepared.mu.Lock()
	prepared.reconstructionActive = true
	prepared.mu.Unlock()
	if _, err := RunCleanup(context.Background(), prepared, successfulTeardown(prepared, nil), zeroInspector()); !errors.Is(err, ErrCleanup) {
		t.Fatalf("active cleanup error = %v", err)
	}
	prepared.mu.Lock()
	prepared.reconstructionActive = false
	prepared.mu.Unlock()
	clock := &fakeCleanupClock{now: time.Now().UTC()}
	result, err := runCleanup(context.Background(), prepared, successfulTeardown(prepared, nil), zeroInspector(), clock)
	if err != nil || result.Outcome != CleanupOutcomeSucceeded {
		t.Fatalf("retry after rejected input = %+v, %v", result, err)
	}
}

func TestTeardownDirectiveHasOnlySanitizedIdentityFields(t *testing.T) {
	typeOf := reflect.TypeOf(TeardownDirective{})
	want := []string{"runtime_commitment_digest", "profile_id", "profile_version", "profile_digest", "authority", "query_scope_digest"}
	got := make([]string, typeOf.NumField())
	for index := 0; index < typeOf.NumField(); index++ {
		got[index] = typeOf.Field(index).Tag.Get("json")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("teardown directive fields = %v", got)
	}
	for _, field := range got {
		for _, forbidden := range []string{"path", "endpoint", "credential", "request", "sandbox_id", "operation_id", "idempotency", "fencing", "handoff"} {
			if strings.Contains(field, forbidden) {
				t.Fatalf("teardown directive exposes %q", field)
			}
		}
	}
}
