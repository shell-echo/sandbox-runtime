package migration

import (
	"context"
	"errors"
	"testing"
	"time"
)

var migrationTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func revision(id, image byte) Revision {
	return Revision{ID: idString(id), CapabilityProfileID: "terminal-v1", RuntimeProfileID: "sandbox-runtime-terminal-v1", ContractNamespace: "urn:shell-echo:sandbox-runtime:provider-v1", ContractVersion: "1.0.0", ImageDigest: digest(image), SecurityPolicyDigest: digest(image + 1)}
}

func idString(value byte) string { return string([]byte{'r', 'e', 'v', '-', value}) }
func digest(value byte) string   { return "sha256:" + string(repeat(value, 64)) }
func repeat(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = valueForHex(value, index)
	}
	return result
}
func valueForHex(value byte, index int) byte {
	const hex = "0123456789abcdef"
	return hex[int(value+byte(index))%len(hex)]
}

func TestRouterBindsCanaryDeterministicallyAndRollsBackOnlyNewRuns(t *testing.T) {
	stable, canary := revision('a', 'a'), revision('b', 'c')
	router, err := NewRouter(Policy{Stable: stable, Canary: &canary, CanaryPercent: 100}, func() time.Time { return migrationTestNow })
	if err != nil {
		t.Fatal(err)
	}
	old, err := router.Bind("run-old")
	if err != nil || old.ProviderRevision.ID != canary.ID {
		t.Fatalf("old binding = %#v, %v", old, err)
	}
	if err := router.Rollback(stable); err != nil {
		t.Fatal(err)
	}
	newBinding, err := router.Bind("run-new")
	if err != nil || newBinding.ProviderRevision.ID != stable.ID {
		t.Fatalf("new binding after rollback = %#v, %v", newBinding, err)
	}
	replay, err := router.Bind("run-old")
	if err != nil || replay.ProviderRevision.ID != canary.ID {
		t.Fatalf("old replay moved revision = %#v, %v", replay, err)
	}
	if err := router.SetState("run-old", RunDraining); err != nil {
		t.Fatal(err)
	}
	if binding, err := router.Get("run-old"); err != nil || binding.State != RunDraining {
		t.Fatalf("draining binding = %#v, %v", binding, err)
	}
}

func TestRouterRejectsProfileChangingCanaryAndCompletedReopen(t *testing.T) {
	stable := revision('a', 'a')
	bad := stable
	bad.ID = "rev-bad"
	bad.RuntimeProfileID = "other-profile"
	if _, err := NewRouter(Policy{Stable: stable, Canary: &bad, CanaryPercent: 1}, func() time.Time { return migrationTestNow }); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("profile-changing policy error = %v", err)
	}
	router, err := NewRouter(Policy{Stable: stable}, func() time.Time { return migrationTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.Bind("run-1"); err != nil {
		t.Fatal(err)
	}
	if err := router.SetState("run-1", RunCompleted); err != nil {
		t.Fatal(err)
	}
	if err := router.SetState("run-1", RunActive); !errors.Is(err, ErrRunConflict) {
		t.Fatalf("completed reopen error = %v", err)
	}
}

func TestShadowValidateDoesNotExposeDocumentOrDispatch(t *testing.T) {
	revision := revision('a', 'a')
	called := false
	result, err := ShadowValidate(context.Background(), revision, ShadowRequest, []byte(`{"operation":"exec"}`), func(_ context.Context, got Revision, kind string, document []byte) error {
		called = true
		if got.ID != revision.ID || kind != ShadowRequest || string(document) != `{"operation":"exec"}` {
			t.Fatalf("shadow callback input mismatch")
		}
		return errors.New("rejected")
	}, migrationTestNow)
	if err != nil || result.Accepted || !called || result.RevisionID != revision.ID {
		t.Fatalf("shadow result = %#v, %v", result, err)
	}
}

func TestMetricsRejectsInconsistentSamplesAndAggregates(t *testing.T) {
	var metrics Metrics
	if err := metrics.Record(Sample{ExecSucceeded: true}); !errors.Is(err, ErrInvalidMetric) {
		t.Fatalf("inconsistent metric error = %v", err)
	}
	if err := metrics.Record(Sample{LifecycleLatency: 10 * time.Millisecond, ExecAttempted: true, ExecSucceeded: true, Orphaned: true, SessionObserved: true, SessionStable: true, ResourceObserved: true, ResourceEvidence: true, ReconciliationBacklog: 2}); err != nil {
		t.Fatal(err)
	}
	snapshot := metrics.Snapshot()
	if snapshot.LifecycleSamples != 1 || snapshot.ExecSuccesses != 1 || snapshot.OrphanCount != 1 || snapshot.StableSessions != 1 || snapshot.ResourceEvidence != 1 || snapshot.ReconciliationBacklog != 2 {
		t.Fatalf("metric snapshot = %#v", snapshot)
	}
}
