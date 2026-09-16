package qualificationharness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type inspectorFunc func(context.Context, QueryScope) (Inspection, error)

func (f inspectorFunc) Inspect(ctx context.Context, scope QueryScope) (Inspection, error) {
	return f(ctx, scope)
}

type identityObserverFunc func(context.Context) (RuntimeObservation, error)

func (f identityObserverFunc) Observe(ctx context.Context) (RuntimeObservation, error) {
	return f(ctx)
}

func fixedIdentityObserver(observation RuntimeObservation) IdentityObserver {
	return identityObserverFunc(func(context.Context) (RuntimeObservation, error) {
		return cloneRuntimeObservation(observation), nil
	})
}

func realTempDir(t *testing.T) string {
	t.Helper()
	value, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(value, 0700); err != nil {
		t.Fatal(err)
	}
	return value
}

func runtimeObservationFixture(frozen *FrozenConfiguration) RuntimeObservation {
	requirements := frozen.ArtifactRequirements()
	artifacts := make([]ArtifactObservation, len(requirements))
	for index, requirement := range requirements {
		character := fmt.Sprintf("%x", (index%15)+1)
		artifacts[index] = ArtifactObservation{
			ArtifactID: requirement.ArtifactID, Owner: requirement.Owner, TrustDomain: requirement.TrustDomain,
			DigestSubject: requirement.DigestSubject, Digest: digestOf(character), ObservedBy: requirement.ObservedBy,
			Source: &SourceIdentity{Kind: "source-revision", Value: strings.Repeat(character, 40), Immutable: true},
		}
	}
	expectations := frozen.ConfigurationExpectations()
	configurations := make([]ConfigurationObservation, len(expectations))
	for index, expectation := range expectations {
		configurations[index] = ConfigurationObservation{
			ID: expectation.ID, Digest: expectation.Digest, DigestProfile: expectation.DigestProfile,
			Sanitized: true, ObservedBy: "process_supervisor",
		}
	}
	return RuntimeObservation{
		DedicatedDisposableTarget: true, RunUniqueNamespace: true, Target: frozen.TargetIdentity(),
		Artifacts: artifacts, Configurations: configurations,
	}
}

func zeroInspector() ResourceInspector {
	return inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
		return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: []ResourceEntry{}}, nil
	})
}

func prepareRuntimeFixture(t *testing.T) (*FrozenConfiguration, RuntimeInput, RuntimeObservation, *PreparedRuntime) {
	t.Helper()
	frozen := freezeFixture(t)
	observation := runtimeObservationFixture(frozen)
	input := RuntimeInput{
		OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: filepath.Join(realTempDir(t), "qualification-state"),
	}
	if !validRuntimeRequirements(frozen.RuntimeLimits(), frozen.CleanupRequirements()) {
		t.Fatal("fixture runtime requirements are invalid")
	}
	if _, _, _, err := validateRuntimeObservation(frozen, observation); err != nil {
		t.Fatalf("fixture observation is invalid: %v", err)
	}
	prepared, err := PrepareRuntime(context.Background(), frozen, input, fixedIdentityObserver(observation), zeroInspector())
	if err != nil {
		t.Fatalf("%v; limits=%+v cleanup=%+v", err, frozen.RuntimeLimits(), frozen.CleanupRequirements())
	}
	t.Cleanup(func() { _ = prepared.Close() })
	return frozen, input, observation, prepared
}

func TestPrepareRuntimeBindsIdentitiesLimitsStateAndZeroBaseline(t *testing.T) {
	frozen, input, observation, prepared := prepareRuntimeFixture(t)
	if prepared.Digest() == "" || !digestPattern.MatchString(prepared.Digest()) {
		t.Fatalf("invalid runtime commitment %q", prepared.Digest())
	}
	if got := prepared.Observation(); !reflect.DeepEqual(got, observation) {
		t.Fatalf("observation changed: %+v", got)
	}
	limits := prepared.RuntimeLimits()
	if limits.MaxSandboxes != 1 || limits.MaxCaseSeconds != 120 || limits.MaxExecutionSeconds != 1800 ||
		limits.MaxCleanupSeconds != 300 || limits.MaxTotalWallClockSeconds != 2100 || limits.SandboxCPUMillis != 500 ||
		limits.SandboxMemoryBytes != 268435456 || limits.SandboxEphemeralStorageBytes != 268435456 || limits.SandboxPIDs != 64 {
		t.Fatalf("unexpected runtime limits: %+v", limits)
	}
	cleanup := prepared.CleanupRequirements()
	if cleanup.Authority != CleanupAuthority || len(cleanup.InspectorScope) != 5 || cleanup.PostTeardownStabilitySamples != 3 || cleanup.PostTeardownStabilityIntervalMS != 1000 {
		t.Fatalf("unexpected cleanup requirements: %+v", cleanup)
	}
	scope := prepared.QueryScope()
	if scope.TargetDigest != frozen.TargetIdentity().TargetDigest || scope.RunNamespaceDigest != frozen.TargetIdentity().RunNamespaceDigest ||
		scope.OwnershipSelectorDigest != input.OwnershipSelectorDigest || scope.DigestProfile != InventoryDigestProfile ||
		!scope.ExcludesHarnessControlPlane || len(scope.ResourceKinds) != 5 {
		t.Fatalf("unexpected query scope: %+v", scope)
	}
	wantScopeDigest, err := canonicalDigest(map[string]any{
		"target_digest": scope.TargetDigest, "run_namespace_digest": scope.RunNamespaceDigest,
		"ownership_selector_digest": scope.OwnershipSelectorDigest, "resource_kinds": scope.ResourceKinds,
		"inspector_artifact_digest":      scope.InspectorArtifactDigest,
		"inspector_configuration_digest": scope.InspectorConfigurationDigest,
		"excludes_harness_control_plane": true,
	})
	if err != nil || scope.Digest != wantScopeDigest {
		t.Fatalf("query scope digest = %q, want %q: %v", scope.Digest, wantScopeDigest, err)
	}
	baseline := prepared.Baseline()
	wantInventoryDigest, err := canonicalDigest(inventoryDocument{FormatVersion: 1, QueryScopeDigest: scope.Digest, Entries: []ResourceEntry{}})
	if err != nil || baseline.QueryScopeDigest != scope.Digest || baseline.InventoryDigest != wantInventoryDigest ||
		baseline.DigestProfile != InventoryDigestProfile || baseline.RunOwnedCount != 0 || !baseline.Stable || baseline.SampledAt.IsZero() {
		t.Fatalf("unexpected baseline: %+v, want digest %q: %v", baseline, wantInventoryDigest, err)
	}
	started, executionDeadline, totalDeadline := prepared.Deadlines()
	if baseline.SampledAt.Before(started) || executionDeadline.Sub(started) != 1800*time.Second || totalDeadline.Sub(started) != 2100*time.Second {
		t.Fatalf("unexpected clock anchors: %v %v %v baseline=%v", started, executionDeadline, totalDeadline, baseline.SampledAt)
	}
	for _, storeID := range persistentStoreIDs() {
		path, ok := prepared.PersistentStatePath(storeID)
		if !ok || !strings.HasPrefix(path, input.PersistentStateRoot+string(filepath.Separator)) {
			t.Fatalf("store %q path = %q, %t", storeID, path, ok)
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("store %q is not private: %v %+v", storeID, err, info)
		}
	}
	callerPath, _ := prepared.PersistentStatePath(CallerOwnedCorrelationState)
	if err := os.WriteFile(filepath.Join(callerPath, "opaque-state"), []byte("not-read-by-harness"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := prepared.RecheckPersistentState(context.Background()); err != nil {
		t.Fatalf("metadata-only recheck rejected caller contents: %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := prepared.PersistentStatePath(CallerOwnedCorrelationState); ok {
		t.Fatal("closed runtime exposed a state path")
	}
	if _, err := os.Stat(input.PersistentStateRoot); err != nil {
		t.Fatalf("Close removed persistent state: %v", err)
	}
}

func TestPrepareRuntimeDefensiveCopies(t *testing.T) {
	_, _, _, prepared := prepareRuntimeFixture(t)
	observation := prepared.Observation()
	observation.Artifacts[0].ArtifactID = "changed"
	observation.Artifacts[0].Source.Value = "changed"
	observation.Configurations[0].ID = "changed"
	scope := prepared.QueryScope()
	scope.ResourceKinds[0] = "changed"
	cleanup := prepared.CleanupRequirements()
	cleanup.InspectorScope[0] = "changed"
	if got := prepared.Observation(); got.Artifacts[0].ArtifactID != "provider" || got.Artifacts[0].Source.Value == "changed" || got.Configurations[0].ID != "architecture" {
		t.Fatal("identity mutation escaped")
	}
	if prepared.QueryScope().ResourceKinds[0] != "runtime_allocations" || prepared.CleanupRequirements().InspectorScope[0] != "runtime_allocations" {
		t.Fatal("scope mutation escaped")
	}
}

func TestPrepareRuntimeReadsIdentityBeforeCreatingStateAndBaselinesAfter(t *testing.T) {
	frozen := freezeFixture(t)
	root := filepath.Join(realTempDir(t), "ordered-state")
	observation := runtimeObservationFixture(frozen)
	identityCalled := false
	identityObserver := identityObserverFunc(func(ctx context.Context) (RuntimeObservation, error) {
		identityCalled = true
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			return RuntimeObservation{}, errors.New("state created before identity observation")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) < 1790*time.Second || time.Until(deadline) > 1800*time.Second {
			return RuntimeObservation{}, errors.New("identity observation did not receive execution deadline")
		}
		return observation, nil
	})
	inspector := inspectorFunc(func(ctx context.Context, scope QueryScope) (Inspection, error) {
		if !identityCalled {
			return Inspection{}, errors.New("resource baseline preceded identity observation")
		}
		for _, leaf := range persistentStoreIDs() {
			info, err := os.Stat(filepath.Join(root, leaf))
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
				return Inspection{}, errors.New("persistent stores unavailable before baseline")
			}
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 1800*time.Second {
			return Inspection{}, errors.New("resource inspector did not receive execution deadline")
		}
		return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: []ResourceEntry{}}, nil
	})
	prepared, err := PrepareRuntime(context.Background(), frozen, RuntimeInput{
		OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: root,
	}, identityObserver, inspector)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
}

func TestPrepareRuntimeSuppressesIdentityObserverDiagnostics(t *testing.T) {
	frozen := freezeFixture(t)
	root := filepath.Join(realTempDir(t), "must-not-exist")
	observer := identityObserverFunc(func(context.Context) (RuntimeObservation, error) {
		return RuntimeObservation{}, errors.New("credential and /private/identity-path")
	})
	got, err := PrepareRuntime(context.Background(), frozen, RuntimeInput{
		OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: root,
	}, observer, zeroInspector())
	if got != nil || !errors.Is(err, ErrRuntimePreflight) || strings.Contains(err.Error(), "credential") || strings.Contains(err.Error(), "/private") {
		t.Fatalf("PrepareRuntime = %v, %v", got, err)
	}
	if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("identity observer failure created state: %v", statErr)
	}
}

func TestPrepareRuntimeRejectsIdentityMismatchBeforeStateCreation(t *testing.T) {
	frozen := freezeFixture(t)
	base := runtimeObservationFixture(frozen)
	changes := map[string]func(*RuntimeObservation){
		"not_disposable":       func(value *RuntimeObservation) { value.DedicatedDisposableTarget = false },
		"namespace_not_unique": func(value *RuntimeObservation) { value.RunUniqueNamespace = false },
		"target":               func(value *RuntimeObservation) { value.Target.TargetDigest = digestOf("f") },
		"missing_artifact":     func(value *RuntimeObservation) { value.Artifacts = value.Artifacts[:10] },
		"artifact_order": func(value *RuntimeObservation) {
			value.Artifacts[0], value.Artifacts[1] = value.Artifacts[1], value.Artifacts[0]
		},
		"artifact_owner":  func(value *RuntimeObservation) { value.Artifacts[0].Owner = "external_caller_owner" },
		"artifact_digest": func(value *RuntimeObservation) { value.Artifacts[0].Digest = "sha256:bad" },
		"artifact_source": func(value *RuntimeObservation) { value.Artifacts[0].Source.Immutable = false },
		"self_observed_supervisor": func(value *RuntimeObservation) {
			value.Artifacts[8].ObservedBy = "process_supervisor"
		},
		"missing_configuration": func(value *RuntimeObservation) { value.Configurations = value.Configurations[:9] },
		"configuration_order": func(value *RuntimeObservation) {
			value.Configurations[0], value.Configurations[1] = value.Configurations[1], value.Configurations[0]
		},
		"configuration_digest":      func(value *RuntimeObservation) { value.Configurations[0].Digest = digestOf("f") },
		"configuration_unsanitized": func(value *RuntimeObservation) { value.Configurations[0].Sanitized = false },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			observation := cloneRuntimeObservation(base)
			change(&observation)
			root := filepath.Join(t.TempDir(), "must-not-exist")
			got, err := PrepareRuntime(context.Background(), frozen, RuntimeInput{
				OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: root,
			}, fixedIdentityObserver(observation), zeroInspector())
			if got != nil || !errors.Is(err, ErrRuntimePreflight) {
				t.Fatalf("PrepareRuntime = %v, %v", got, err)
			}
			if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("identity failure created state: %v", statErr)
			}
		})
	}
}

func TestPrepareRuntimeRejectsInvalidInspectionAndRetainsState(t *testing.T) {
	frozen := freezeFixture(t)
	tests := map[string]ResourceInspector{
		"inspector_error": inspectorFunc(func(context.Context, QueryScope) (Inspection, error) {
			return Inspection{}, errors.New("raw daemon diagnostic and /private/path")
		}),
		"incomplete": inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
			return Inspection{QueryScopeDigest: scope.Digest}, nil
		}),
		"wrong_scope": inspectorFunc(func(context.Context, QueryScope) (Inspection, error) {
			return Inspection{QueryScopeDigest: digestOf("f"), Complete: true}, nil
		}),
		"vacuous_nil_inventory": inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
			return Inspection{QueryScopeDigest: scope.Digest, Complete: true}, nil
		}),
		"residual_resource": inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
			return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: []ResourceEntry{{
				ResourceKind: "runtime_allocations", StableObserverID: "resource-1", IdentityDigest: digestOf("a"),
			}}}, nil
		}),
		"unsorted": inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
			return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: []ResourceEntry{
				{ResourceKind: "storage_resources", StableObserverID: "resource-2", IdentityDigest: digestOf("a")},
				{ResourceKind: "compute_resources", StableObserverID: "resource-1", IdentityDigest: digestOf("b")},
			}}, nil
		}),
		"backend_like_id": inspectorFunc(func(_ context.Context, scope QueryScope) (Inspection, error) {
			return Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: []ResourceEntry{{
				ResourceKind: "compute_resources", StableObserverID: "runtime/container-id", IdentityDigest: digestOf("a"),
			}}}, nil
		}),
	}
	for name, inspector := range tests {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(realTempDir(t), "retained-state")
			got, err := PrepareRuntime(context.Background(), frozen, RuntimeInput{
				OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: root,
			}, fixedIdentityObserver(runtimeObservationFixture(frozen)), inspector)
			if got != nil || !errors.Is(err, ErrRuntimePreflight) || !errors.Is(err, ErrPersistentStateRetained) {
				t.Fatalf("PrepareRuntime = %v, %v", got, err)
			}
			if strings.Contains(err.Error(), "daemon") || strings.Contains(err.Error(), "/private/path") || strings.Contains(err.Error(), root) {
				t.Fatalf("error leaked private detail: %v", err)
			}
			for _, leaf := range persistentStoreIDs() {
				if info, statErr := os.Stat(filepath.Join(root, leaf)); statErr != nil || !info.IsDir() {
					t.Fatalf("failed preflight did not retain %q: %v", leaf, statErr)
				}
			}
		})
	}
}

func TestPrepareRuntimeRejectsInvalidInputAndPreexistingState(t *testing.T) {
	frozen := freezeFixture(t)
	observer := fixedIdentityObserver(runtimeObservationFixture(frozen))
	var typedNilObserver identityObserverFunc
	var typedNilInspector inspectorFunc
	root := filepath.Join(realTempDir(t), "existing")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		ctx       context.Context
		input     RuntimeInput
		observer  IdentityObserver
		inspector ResourceInspector
	}{
		"nil_context":                   {ctx: nil, observer: observer, inspector: zeroInspector()},
		"nil_frozen_covered_separately": {ctx: context.Background(), observer: observer, inspector: zeroInspector()},
		"invalid_selector": {ctx: context.Background(), input: RuntimeInput{
			OwnershipSelectorDigest: "bad", PersistentStateRoot: filepath.Join(t.TempDir(), "state"),
		}, observer: observer, inspector: zeroInspector()},
		"relative_state": {ctx: context.Background(), input: RuntimeInput{
			OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: "relative",
		}, observer: observer, inspector: zeroInspector()},
		"preexisting_state": {ctx: context.Background(), input: RuntimeInput{
			OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: root,
		}, observer: observer, inspector: zeroInspector()},
		"nil_observer": {ctx: context.Background(), input: RuntimeInput{
			OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: filepath.Join(t.TempDir(), "state"),
		}, inspector: zeroInspector()},
		"typed_nil_observer": {ctx: context.Background(), input: RuntimeInput{
			OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: filepath.Join(t.TempDir(), "state"),
		}, observer: typedNilObserver, inspector: zeroInspector()},
		"nil_inspector": {ctx: context.Background(), input: RuntimeInput{
			OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: filepath.Join(t.TempDir(), "state"),
		}, observer: observer},
		"typed_nil_inspector": {ctx: context.Background(), input: RuntimeInput{
			OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: filepath.Join(t.TempDir(), "state"),
		}, observer: observer, inspector: typedNilInspector},
	} {
		t.Run(name, func(t *testing.T) {
			candidateFrozen := frozen
			if name == "nil_frozen_covered_separately" {
				candidateFrozen = nil
			}
			got, err := PrepareRuntime(test.ctx, candidateFrozen, test.input, test.observer, test.inspector)
			if got != nil || !errors.Is(err, ErrRuntimePreflight) {
				t.Fatalf("PrepareRuntime = %v, %v", got, err)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := PrepareRuntime(cancelled, frozen, RuntimeInput{
		OwnershipSelectorDigest: digestOf("e"), PersistentStateRoot: filepath.Join(t.TempDir(), "state"),
	}, observer, zeroInspector())
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled PrepareRuntime = %v, %v", got, err)
	}
}

func TestPreparedRuntimeDetectsStateReplacementWithoutReadingEntries(t *testing.T) {
	_, input, _, prepared := prepareRuntimeFixture(t)
	original := input.PersistentStateRoot + "-original"
	if err := os.Rename(input.PersistentStateRoot, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(input.PersistentStateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepared.RecheckPersistentState(context.Background()); !errors.Is(err, ErrRuntimePreflight) {
		t.Fatalf("replacement recheck = %v", err)
	}
}

func TestRuntimeCommitmentShapeContainsNoPathField(t *testing.T) {
	typeOf := reflect.TypeOf(runtimeCommitmentDocument{})
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		if strings.Contains(strings.ToLower(field.Name), "path") || strings.Contains(field.Tag.Get("json"), "path") {
			t.Fatalf("runtime commitment exposes a path field: %s", field.Name)
		}
	}
}

func TestPersistentStateCreatesExactPrivateEmptyStores(t *testing.T) {
	root := filepath.Join(realTempDir(t), "state")
	state, err := createPersistentState(context.Background(), root)
	if err != nil {
		parentInfo, _ := os.Stat(filepath.Dir(root))
		t.Fatalf("%v; parent=%+v", err, parentInfo)
	}
	defer state.close()
	for _, storeID := range persistentStoreIDs() {
		path, ok := state.path(storeID)
		if !ok {
			t.Fatalf("missing store %q", storeID)
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatalf("store %q is not empty: %v, %d", storeID, err, len(entries))
		}
	}
}

func TestPersistentStateRejectsSymlinkedOrWritableParent(t *testing.T) {
	base := realTempDir(t)
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if state, err := createPersistentState(context.Background(), filepath.Join(link, "state")); state != nil || !errors.Is(err, errPersistentState) {
		t.Fatalf("symlinked parent = %v, %v", state, err)
	}
	writable := filepath.Join(base, "writable")
	if err := os.Mkdir(writable, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0777); err != nil {
		t.Fatal(err)
	}
	if state, err := createPersistentState(context.Background(), filepath.Join(writable, "state")); state != nil || !errors.Is(err, errPersistentState) {
		t.Fatalf("writable parent = %v, %v", state, err)
	}
}

func TestPersistentStateRejectsUnsafeRootNames(t *testing.T) {
	parent := realTempDir(t)
	for name, root := range map[string]string{
		"root":             string(filepath.Separator),
		"trailing_slash":   parent + string(filepath.Separator),
		"dot_prefix":       filepath.Join(parent, ".state"),
		"unsupported_byte": filepath.Join(parent, "state:name"),
		"too_long":         filepath.Join(parent, strings.Repeat("a", 129)),
	} {
		t.Run(name, func(t *testing.T) {
			if state, err := createPersistentState(context.Background(), root); state != nil || !errors.Is(err, errPersistentState) {
				t.Fatalf("unsafe root = %v, %v", state, err)
			}
		})
	}
}
