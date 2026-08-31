package platform

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
)

var testStable = Revision{
	ID: "provider-revision-test-v1", CapabilityProfileID: capabilityProfile, RuntimeProfileID: runtimeProfile,
	ContractNamespace: contractNamespace, ContractVersion: contractVersion,
	ImageDigest:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	SecurityPolicyDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
}

func TestRouterRollbackPreservesOldRunAndChangesOnlyNewRun(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	canary := testStable
	canary.ID = "provider-revision-test-canary"
	router, err := newRouter(testStable, &canary, 100, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	old, err := router.bind("old-run")
	if err != nil || old.ProviderRevision.ID != canary.ID {
		t.Fatalf("old binding = %#v, err = %v", old, err)
	}
	if err := router.setState(old.RunID, runDraining); err != nil {
		t.Fatal(err)
	}
	if err := router.rollback(testStable); err != nil {
		t.Fatal(err)
	}
	newRun, err := router.bind("new-run")
	if err != nil || newRun.ProviderRevision.ID != testStable.ID {
		t.Fatalf("new binding = %#v, err = %v", newRun, err)
	}
	retained, err := router.get(old.RunID)
	if err != nil || retained.ProviderRevision.ID != canary.ID || retained.State != runDraining {
		t.Fatalf("retained binding = %#v, err = %v", retained, err)
	}
	if err := router.setState(old.RunID, runCompleted); err != nil {
		t.Fatal(err)
	}
}

func TestRouterRejectsProfileChangingCanaryAndReopeningCompletedRun(t *testing.T) {
	canary := testStable
	canary.ID = "provider-revision-test-canary"
	canary.RuntimeProfileID = "different-profile"
	if _, err := newRouter(testStable, &canary, 100, time.Now); err == nil {
		t.Fatal("profile-changing canary was accepted")
	}
	canary.RuntimeProfileID = testStable.RuntimeProfileID
	router, err := newRouter(testStable, &canary, 0, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.bind("completed-run"); err != nil {
		t.Fatal(err)
	}
	if err := router.setState("completed-run", runCompleted); err != nil {
		t.Fatal(err)
	}
	if err := router.setState("completed-run", runActive); !errors.Is(err, errCompletedRun) {
		t.Fatal("completed run was reopened")
	}
}

func TestShadowRequestRejectsUnknownField(t *testing.T) {
	document := []byte(`{"unknown":true}`)
	if err := shadowRequest(document, callerCapabilities(), testStable); err == nil {
		t.Fatal("unknown shadow field was accepted")
	}
}

func TestShadowRequestAcceptsCandidateCreateShape(t *testing.T) {
	config := caller.Config{
		ProviderRevisionID:    testStable.ID,
		RuntimeImageReference: "registry.invalid/runtime",
		RuntimeImageDigest:    testStable.ImageDigest,
		ControllerA:           caller.IdentityConfig{TenantID: "tenant-a", WorkOrderID: "work-order-a"},
	}
	document, err := buildCreateRequest(config, testStable)
	if err != nil {
		t.Fatal(err)
	}
	if err := shadowRequest(document, candidateCapabilities(), testStable); err != nil {
		t.Fatal(err)
	}
}

func TestShadowRequestRejectsMissingAndNestedUnknownFields(t *testing.T) {
	config := caller.Config{
		ProviderRevisionID:    testStable.ID,
		RuntimeImageReference: "registry.invalid/runtime",
		RuntimeImageDigest:    testStable.ImageDigest,
		ControllerA:           caller.IdentityConfig{TenantID: "tenant-a", WorkOrderID: "work-order-a"},
	}
	document, err := buildCreateRequest(config, testStable)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(document, &root); err != nil {
		t.Fatal(err)
	}
	delete(root, "request_digest")
	missing, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := shadowRequest(missing, candidateCapabilities(), testStable); err == nil {
		t.Fatal("missing required top-level field was accepted")
	}

	root, err = decodeMap(document)
	if err != nil {
		t.Fatal(err)
	}
	spec := root["spec"].(map[string]any)
	image := spec["image"].(map[string]any)
	image["unexpected"] = true
	nested, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := shadowRequest(nested, candidateCapabilities(), testStable); err == nil {
		t.Fatal("unknown nested field was accepted")
	}
}

func callerCapabilities() caller.Capabilities {
	return caller.Capabilities{}
}

func candidateCapabilities() caller.Capabilities {
	return caller.Capabilities{
		ProviderRevisionID: testStable.ID,
		APIVersion:         "v1",
		Capabilities: []caller.Capability{
			{ID: capabilityIDExec, Versions: []string{contractVersion}, Profiles: []string{"exec-v1"}},
			{ID: capabilityIDTTY, Versions: []string{contractVersion}, Profiles: []string{"terminal-v1"}},
		},
		RuntimeProfiles: []caller.RuntimeProfile{{ID: runtimeProfile, IsolationClass: "container", Architecture: []string{"amd64"}, CapabilityProfileIDs: []string{"exec-v1", "terminal-v1"}}},
	}
}

func decodeMap(document []byte) (map[string]any, error) {
	var value map[string]any
	if err := json.Unmarshal(document, &value); err != nil {
		return nil, err
	}
	return value, nil
}
