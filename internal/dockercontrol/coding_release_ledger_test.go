package dockercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/volume"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type testCodingExactDeletion struct {
	scope       string
	runtimeID   string
	runtimeGone bool
	volumeGone  map[string]bool
	order       []string
	failAt      string
}

func (d *testCodingExactDeletion) ScopeDigest() string { return d.scope }
func (d *testCodingExactDeletion) RemoveRuntime(ctx context.Context, id string) error {
	d.order = append(d.order, "runtime:"+id)
	if ctx.Err() != nil || id != d.runtimeID || d.failAt == "runtime" {
		return ErrInvalidCodingInventory
	}
	d.runtimeGone = true
	return nil
}
func (d *testCodingExactDeletion) RemoveVolume(ctx context.Context, name string) error {
	d.order = append(d.order, "volume:"+name)
	if ctx.Err() != nil || !d.runtimeGone || d.failAt == name || d.volumeGone[name] {
		return ErrInvalidCodingInventory
	}
	d.volumeGone[name] = true
	return nil
}

func testCodingReleaseIntent(t *testing.T, fixture codingCompletionFixture) CodingCleanupAuthority {
	t.Helper()
	ticket := fixture.ticket
	ticket.Status = codingidentity.Cleaning
	sandbox := fixture.sandbox
	sandbox.DesiredState = lifecycle.DesiredTerminated
	sandbox.Generation++
	now := time.Now().UTC()
	sandbox.UpdatedAt = now
	operation := lifecycle.Operation{ID: "cleanup-operation-1", AttemptID: "cleanup-attempt-1",
		FencingToken: fixture.receipt.Authority.Fence, SandboxID: sandbox.ID,
		Type: lifecycle.OperationTerminate, State: lifecycle.OperationRunning,
		Deadline: now.Add(time.Minute), ObservedAt: now,
		IdempotencyKey: "cleanup-key-1", RequestDigest: testControlDigest("b")}
	intent, err := NewCodingCleanupAuthority(t.Context(), fixture.receipt.Authority, ticket,
		operation, sandbox, fixture.observer.binding.Plan,
		fixture.observer.binding.ControlPolicyDigest,
		fixture.observer.binding.PeerPrincipalDigest, now)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func testCodingReleaseSetup(t *testing.T, runningInspectRewrite ...func(string) string) (codingCompletionFixture, *CodingReceiptLedger,
	CodingCleanupAuthority, *testCodingExactDeletion) {
	t.Helper()
	fixture := testCodingCompletionFixture(t)
	if len(runningInspectRewrite) > 1 {
		t.Fatal("at most one running inspect rewrite")
	}
	if len(runningInspectRewrite) == 1 {
		base := fixture.observer.bounded.base
		runtimeName, _ := fixture.set.ContainerName(CodingRuntimeRole)
		fixture.observer.bounded.base = codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			response, err := base.RoundTrip(request)
			if err != nil || request.URL.Path != "/v1.55/containers/"+runtimeName+"/json" {
				return response, err
			}
			return codingRewriteJSONResponse(t, response, runningInspectRewrite[0]), nil
		})
	}
	ledger, _ := testLiveCodingCompletionLedger(t, fixture)
	if _, err := ledger.completeCodingCreate(t.Context(), fixture.receipt.Authority.RequestID,
		fixture.observer); err != nil {
		t.Fatalf("prepare sealed Completed receipt: %v", err)
	}
	intent := testCodingReleaseIntent(t, fixture)
	deletion := &testCodingExactDeletion{scope: fixture.observer.binding.EndpointScopeDigest,
		runtimeID: strings.Repeat("a", 64), volumeGone: make(map[string]bool)}
	original := fixture.respond
	runtimeName, _ := fixture.set.ContainerName(CodingRuntimeRole)
	fixture.observer.bounded.base = codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		path := request.URL.Path
		if deletion.runtimeGone {
			switch path {
			case "/v1.55/containers/" + runtimeName + "/json":
				return codingSDKResponse(http.StatusNotFound, `{"message":"No such container"}`, "application/json"), nil
			case "/v1.55/containers/json":
				return codingSDKResponse(http.StatusOK, `[]`, "application/json"), nil
			}
		}
		for _, role := range [3]CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
			name, _ := fixture.set.VolumeName(role)
			if path == "/v1.55/volumes/"+name && deletion.volumeGone[name] {
				return codingSDKResponse(http.StatusNotFound, `{"message":"No such volume"}`, "application/json"), nil
			}
		}
		if path == "/v1.55/volumes" && len(deletion.volumeGone) != 0 {
			remaining := make([]volume.Volume, 0, 3)
			for _, role := range [3]CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
				name, _ := fixture.set.VolumeName(role)
				if !deletion.volumeGone[name] {
					labels, _ := fixture.set.Labels(role)
					remaining = append(remaining, volume.Volume{Name: name,
						Driver: "local", Scope: "local", Labels: labels})
				}
			}
			document, err := json.Marshal(struct {
				Volumes  []volume.Volume `json:"Volumes"`
				Warnings []string        `json:"Warnings"`
			}{remaining, []string{}})
			if err != nil {
				return nil, err
			}
			return codingSDKResponse(http.StatusOK, string(document), "application/json"), nil
		}
		return original(request)
	})
	return fixture, ledger, intent, deletion
}

func TestCodingExactCleanupPersistsReleasedAndReopens(t *testing.T) {
	fixture, ledger, intent, deletion := testCodingReleaseSetup(t)
	requestID := fixture.receipt.Authority.RequestID
	released, err := ledger.completeCodingCleanup(t.Context(), requestID, intent,
		fixture.observer, deletion)
	if err != nil || released.Status != ReceiptReleased ||
		!controlDigest.MatchString(released.AbsenceDigest) ||
		!controlDigest.MatchString(released.AbsenceEvidenceDigest) {
		t.Fatalf("exact cleanup release: %#v, %v", released, err)
	}
	wantOrder := []string{"runtime:" + deletion.runtimeID}
	for _, role := range [3]CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := fixture.set.VolumeName(role)
		wantOrder = append(wantOrder, "volume:"+name)
	}
	if !reflect.DeepEqual(deletion.order, wantOrder) {
		t.Fatalf("exact delete order: %#v", deletion.order)
	}
	path, err := releaseEvidencePath(ledger.path, fixture.receipt.Authority.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := readReleaseEvidence(path)
	if err != nil || evidence.ProofDigest != released.AbsenceDigest ||
		evidence.digest() != released.AbsenceEvidenceDigest ||
		evidence.AfterFirst != evidence.AfterSecond || evidence.Before == evidence.AfterFirst {
		t.Fatalf("private exact cleanup evidence: %#v, %v", evidence, err)
	}
	if _, err := ledger.completeCodingCleanup(t.Context(), requestID, intent,
		fixture.observer, deletion); !errors.Is(err, ErrReceiptReplay) ||
		!reflect.DeepEqual(deletion.order, wantOrder) {
		t.Fatalf("cleanup replay re-deleted: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCodingReceiptLedger(ledger.path, fixture.observer.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, err := reopened.ReadReleasedSnapshot(requestID)
	if err != nil || snapshot.Validate(fixture.receipt.Authority, intent) != nil ||
		snapshot.Receipt() != released {
		t.Fatalf("reopened exact Released tombstone: %#v, %v", snapshot, err)
	}
	wrong := intent
	wrong.CleanupFence++
	if snapshot.Validate(fixture.receipt.Authority, wrong) == nil {
		t.Fatal("Released snapshot accepted a different current PG retirement")
	}
}

func TestCodingExactCleanupFailureKeepsAllocationOccupied(t *testing.T) {
	for name, change := range map[string]func(*testCodingExactDeletion){
		"wrong scope":  func(d *testCodingExactDeletion) { d.scope = testControlDigest("0") },
		"delete fails": func(d *testCodingExactDeletion) { d.failAt = "runtime" },
		"volume fails": func(d *testCodingExactDeletion) { d.failAt = "coding-0000-inputs" },
	} {
		t.Run(name, func(t *testing.T) {
			fixture, ledger, intent, deletion := testCodingReleaseSetup(t)
			change(deletion)
			if name == "volume fails" {
				deletion.failAt, _ = fixture.set.VolumeName(CodingInputsRole)
			}
			if _, err := ledger.completeCodingCleanup(t.Context(), fixture.receipt.Authority.RequestID,
				intent, fixture.observer, deletion); err == nil {
				t.Fatal("failed or unbound mutation released allocation")
			}
			receipt, err := ledger.Lookup(fixture.receipt.Authority.RequestID)
			if err != nil || receipt.Status != ReceiptCompleted || receipt.AbsenceDigest != "" {
				t.Fatalf("failure changed occupancy: %#v, %v", receipt, err)
			}
			if _, err := ledger.completeCodingCleanup(t.Context(), fixture.receipt.Authority.RequestID,
				intent, fixture.observer, deletion); !errors.Is(err, ErrReceiptReplay) {
				t.Fatalf("failed cleanup intent retried deletion: %v", err)
			}
		})
	}
}

func TestCodingCleanupPredeleteConfigDriftMakesZeroDeletes(t *testing.T) {
	fixture, ledger, intent, deletion := testCodingReleaseSetup(t)
	base := fixture.observer.bounded.base
	runtimeName, _ := fixture.set.ContainerName(CodingRuntimeRole)
	fixture.observer.bounded.base = codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(request)
		if err != nil || request.URL.Path != "/v1.55/containers/"+runtimeName+"/json" {
			return response, err
		}
		return codingRewriteJSONResponse(t, response, func(body string) string {
			changed := strings.Replace(body, `"NetworkMode":"none"`, `"NetworkMode":"host"`, 1)
			if changed == body {
				t.Fatal("runtime config fixture did not contain network mode")
			}
			return changed
		}), nil
	})
	if _, err := ledger.completeCodingCleanup(t.Context(), fixture.receipt.Authority.RequestID,
		intent, fixture.observer, deletion); err == nil || len(deletion.order) != 0 {
		t.Fatalf("drifted runtime config reached DELETE: %v, %#v", err, deletion.order)
	}
	receipt, err := ledger.Lookup(fixture.receipt.Authority.RequestID)
	if err != nil || receipt.Status != ReceiptCompleted || receipt.AbsenceDigest != "" {
		t.Fatalf("config drift released allocation: %#v, %v", receipt, err)
	}
}

func TestCodingDeletePreflightCloseWinsQueuedAdmission(t *testing.T) {
	fixture, _, _, deletion := testCodingReleaseSetup(t)
	observer := fixture.observer
	requests := 0
	observer.bounded.base = codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		return fixture.respond(request)
	})
	if !observer.acquire(t.Context()) {
		t.Fatal("cannot hold observer gate")
	}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(started)
		_, _, err := observer.readDeletePreflight(t.Context(), deletion.runtimeID)
		result <- err
	}()
	<-started
	// Keep the gate held while the preflight joins its admission queue.
	time.Sleep(10 * time.Millisecond)
	if err := observer.api.Close(); err != nil {
		observer.release()
		t.Fatal(err)
	}
	observer.api = nil
	observer.release()
	if err := <-result; !errors.Is(err, ErrInvalidCodingInventory) || requests != 0 {
		t.Fatalf("closed observer reached Docker or panicked: %v, requests=%d", err, requests)
	}
	if err := observer.CloseContext(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCodingCleanupAcceptsStoppedRuntimeWithSameFrozenConfig(t *testing.T) {
	fixture, ledger, intent, deletion := testCodingReleaseSetup(t, func(body string) string {
		var document map[string]any
		if json.Unmarshal([]byte(body), &document) != nil {
			t.Fatal("invalid running inspect fixture")
		}
		// Completion sees the private /tmp tmpfs. Docker may omit it from
		// the realized Mounts view after the same runtime exits.
		document["Mounts"] = append(document["Mounts"].([]any), map[string]any{
			"Type": "tmpfs", "Destination": "/tmp", "RW": true,
		})
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	})
	base := fixture.observer.bounded.base
	runtimeName, _ := fixture.set.ContainerName(CodingRuntimeRole)
	fixture.observer.bounded.base = codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(request)
		if err != nil || request.URL.Path != "/v1.55/containers/"+runtimeName+"/json" ||
			deletion.runtimeGone {
			return response, err
		}
		return codingRewriteJSONResponse(t, response, func(body string) string {
			var document map[string]any
			if json.Unmarshal([]byte(body), &document) != nil {
				t.Fatal("invalid runtime inspect fixture")
			}
			state := document["State"].(map[string]any)
			state["Status"] = "exited"
			state["Running"] = false
			state["Pid"] = 0
			state["Error"] = "/private/host-path/sentinel"
			encoded, marshalErr := json.Marshal(document)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			return string(encoded)
		}), nil
	})
	released, err := ledger.completeCodingCleanup(t.Context(), fixture.receipt.Authority.RequestID,
		intent, fixture.observer, deletion)
	if err != nil || released.Status != ReceiptReleased || len(deletion.order) != 4 {
		t.Fatalf("stopped runtime with unchanged config could not retire: %#v, %v", released, err)
	}
	path, err := releaseEvidencePath(ledger.path, fixture.receipt.Authority.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(stored), "/private/host-path/sentinel") {
		t.Fatalf("daemon diagnostic persisted in private evidence: %v", err)
	}
}

func TestCodingCleanupRejectsUnknownOrDuplicateRealizedMountsBeforeDelete(t *testing.T) {
	for name, mutate := range map[string]func([]any) []any{
		"duplicate tmpfs": func(mounts []any) []any {
			entry := map[string]any{"Type": "tmpfs", "Destination": "/tmp", "RW": true}
			return append(mounts, entry, entry)
		},
		"wrong tmpfs": func(mounts []any) []any {
			return append(mounts, map[string]any{"Type": "tmpfs", "Destination": "/tmp", "RW": false})
		},
		"foreign volume": func(mounts []any) []any {
			return append(mounts, map[string]any{"Type": "volume", "Name": "foreign",
				"Destination": "/tmp", "RW": true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture, ledger, intent, deletion := testCodingReleaseSetup(t)
			base := fixture.observer.bounded.base
			runtimeName, _ := fixture.set.ContainerName(CodingRuntimeRole)
			fixture.observer.bounded.base = codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				response, err := base.RoundTrip(request)
				if err != nil || request.URL.Path != "/v1.55/containers/"+runtimeName+"/json" {
					return response, err
				}
				return codingRewriteJSONResponse(t, response, func(body string) string {
					var document map[string]any
					if json.Unmarshal([]byte(body), &document) != nil {
						t.Fatal("invalid runtime inspect fixture")
					}
					document["Mounts"] = mutate(document["Mounts"].([]any))
					encoded, marshalErr := json.Marshal(document)
					if marshalErr != nil {
						t.Fatal(marshalErr)
					}
					return string(encoded)
				}), nil
			})
			if _, err := ledger.completeCodingCleanup(t.Context(), fixture.receipt.Authority.RequestID,
				intent, fixture.observer, deletion); err == nil || len(deletion.order) != 0 {
				t.Fatalf("invalid realized mounts reached DELETE: %v, %#v", err, deletion.order)
			}
		})
	}
}

func TestCodingExactCleanupEvidenceAndCommitFaultsFailClosed(t *testing.T) {
	for _, stage := range []string{"after-evidence", "after-commit", "before-write", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			fixture, ledger, intent, deletion := testCodingReleaseSetup(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if stage == "after-evidence" || stage == "after-commit" {
				ledger.cleanupStage = func(observed string) {
					if stage == observed {
						cancel()
					}
				}
			} else {
				ledger.cleanupStage = func(observed string) {
					if observed == "after-evidence" {
						ledger.writeFault = func(writeStage string) error {
							if writeStage == stage {
								return errors.New("injected release persistence fault")
							}
							return nil
						}
					}
				}
			}
			if _, err := ledger.completeCodingCleanup(ctx, fixture.receipt.Authority.RequestID,
				intent, fixture.observer, deletion); err == nil {
				t.Fatal("uncertain release returned success")
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenCodingReceiptLedger(ledger.path, fixture.observer.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			receipt, err := reopened.Lookup(fixture.receipt.Authority.RequestID)
			wantReleased := stage == "after-commit" || stage == "after-rename"
			if err != nil || (receipt.Status == ReceiptReleased) != wantReleased {
				t.Fatalf("ambiguous release must be read-only reconciled: %#v, %v", receipt, err)
			}
		})
	}
}

func TestCodingReleasedEvidenceTamperRejectsReopen(t *testing.T) {
	fixture, ledger, intent, deletion := testCodingReleaseSetup(t)
	if _, err := ledger.completeCodingCleanup(t.Context(), fixture.receipt.Authority.RequestID,
		intent, fixture.observer, deletion); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	path, err := releaseEvidencePath(ledger.path, fixture.receipt.Authority.EffectID)
	if err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(document, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCodingReceiptLedger(ledger.path, fixture.observer.binding); !errors.Is(err, ErrInvalidReceiptState) {
		t.Fatalf("noncanonical/tampered Released evidence reopened: %v", err)
	}
	if filepath.Dir(path) != filepath.Dir(ledger.path) {
		t.Fatal("private release evidence escaped ledger directory")
	}
}

func TestCodingReleasedEvidenceCheckedOnTargetButNotUnrelatedHotRead(t *testing.T) {
	for _, target := range []string{"release", "completion"} {
		t.Run(target, func(t *testing.T) {
			fixture, ledger, intent, deletion := testCodingReleaseSetup(t)
			if _, err := ledger.completeCodingCleanup(t.Context(), fixture.receipt.Authority.RequestID,
				intent, fixture.observer, deletion); err != nil {
				t.Fatal(err)
			}
			var path string
			var err error
			if target == "release" {
				path, err = releaseEvidencePath(ledger.path, fixture.receipt.Authority.EffectID)
			} else {
				path, err = completionEvidencePath(ledger.path, fixture.receipt.Authority.EffectID)
			}
			if err != nil {
				t.Fatal(err)
			}
			document, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(document, ' '), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ledger.Lookup(testControlDigest("0")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unrelated read scanned historical evidence: %v", err)
			}
			if _, err := ledger.Lookup(fixture.receipt.Authority.RequestID); !errors.Is(err, ErrInvalidReceiptState) {
				t.Fatalf("targeted released evidence drift admitted: %v", err)
			}
			if _, err := ledger.ReadReleasedSnapshot(fixture.receipt.Authority.RequestID); !errors.Is(err, ErrInvalidReceiptState) {
				t.Fatalf("targeted released snapshot drift admitted: %v", err)
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenCodingReceiptLedger(ledger.path, fixture.observer.binding); !errors.Is(err, ErrInvalidReceiptState) {
				t.Fatalf("reopen ignored unrelated-history drift: %v", err)
			}
		})
	}
}
