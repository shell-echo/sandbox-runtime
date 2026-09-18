package caller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const (
	ReferenceSandboxID = "e2e-sandbox-1"
	sandboxID          = ReferenceSandboxID
	workspaceID        = "e2e-workspace-1"
	createOperation    = "e2e-operation-create-1"
	createAttempt      = "e2e-attempt-create-1"
	execOperation      = "e2e-operation-exec-output-1"
	execAttempt        = "e2e-attempt-exec-output-1"
	cancelTargetOp     = "e2e-operation-exec-cancel-target-1"
	cancelTargetAtt    = "e2e-attempt-exec-cancel-target-1"
	cancelOperation    = "e2e-operation-cancel-exec-1"
	cancelAttempt      = "e2e-attempt-cancel-exec-1"
	sessionOperation   = "e2e-operation-session-1"
	sessionAttempt     = "e2e-attempt-session-1"
	runtimeSessionID   = "e2e-session-1"
	artifactOperation  = "e2e-operation-artifact-1"
	artifactAttempt    = "e2e-attempt-artifact-1"
	suspendOperation   = "e2e-operation-suspend-1"
	suspendAttempt     = "e2e-attempt-suspend-1"
	resumeOperation    = "e2e-operation-resume-1"
	resumeAttempt      = "e2e-attempt-resume-1"
	leaseOperation     = "e2e-operation-lease-1"
	leaseAttempt       = "e2e-attempt-lease-1"
	closeOperation     = "e2e-operation-session-close-1"
	closeAttempt       = "e2e-attempt-session-close-1"
	terminateOperation = "e2e-operation-terminate-1"
	terminateAttempt   = "e2e-attempt-terminate-1"
)

var artifactContent = []byte("{\"ok\":true}\n")

type ScenarioResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Report struct {
	Phase       string           `json:"phase"`
	Scenarios   []ScenarioResult `json:"scenarios"`
	CompletedAt string           `json:"completed_at"`
}

type runner struct {
	config Config
	a      *providerClient
	b      *providerClient
	wrong  *providerClient
	report Report
}

type operationReference struct {
	SandboxID    string
	OperationID  string
	AttemptID    string
	FencingToken int64
	TenantID     string
	WorkOrderID  string
}

func Run(ctx context.Context, config Config) (Report, error) {
	primary, err := newProviderClient(config, config.ControllerA, config.ControllerA)
	if err != nil {
		return Report{}, err
	}
	defer primary.Close()
	secondary, err := newProviderClient(config, config.ControllerB, config.ControllerB)
	if err != nil {
		return Report{}, err
	}
	defer secondary.Close()
	wrongCaller, err := newProviderClient(config, config.ControllerB, config.ControllerA)
	if err != nil {
		return Report{}, err
	}
	defer wrongCaller.Close()
	r := &runner{config: config, a: primary, b: secondary, wrong: wrongCaller, report: Report{Phase: config.Phase, Scenarios: []ScenarioResult{}}}
	if err := r.step(ctx, "locked capability discovery", r.verifyCapabilities); err != nil {
		return r.report, err
	}
	if config.Profile == ProfileBrowser {
		if err := r.runBrowser(ctx); err != nil {
			return r.report, err
		}
	} else {
		if config.Phase == PhaseLifecycle {
			if err := r.runLifecycle(ctx); err != nil {
				return r.report, err
			}
		} else if config.Phase == PhaseResume {
			if err := r.runResume(ctx); err != nil {
				return r.report, err
			}
		} else if err := r.runInitial(ctx); err != nil {
			return r.report, err
		}
	}
	r.report.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return r.report, nil
}

func (r *runner) step(ctx context.Context, name string, scenario func(context.Context) error) error {
	if err := scenario(ctx); err != nil {
		return fmt.Errorf("scenario %q: %w", name, err)
	}
	r.report.Scenarios = append(r.report.Scenarios, ScenarioResult{Name: name, Status: "passed"})
	return nil
}

func (r *runner) runInitial(ctx context.Context) error {
	var create preparedRequest
	if err := r.step(ctx, "protected lifecycle create", func(ctx context.Context) error {
		var err error
		create, err = r.prepareCreate()
		if err != nil {
			return err
		}
		operation, err := r.sendOperation(ctx, r.a, create, http.StatusAccepted)
		return errors.Join(err, validateOperation(operation, createRef(), "create", "accepted"))
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "mutation replay rejection", func(ctx context.Context) error {
		result, err := r.a.send(ctx, create)
		if err != nil {
			return err
		}
		if result.Status != http.StatusConflict {
			return unexpectedStatus("create replay", result, http.StatusConflict)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "lifecycle completion and status", func(ctx context.Context) error {
		operation, err := r.waitOperation(ctx, createRef())
		if err != nil || operation.Status != "succeeded" {
			failure := ProviderError{}
			if operation.Error != nil {
				failure = *operation.Error
			}
			return errors.Join(err, fmt.Errorf("create operation status=%q error_code=%q outcome=%q retryable=%t", operation.Status, failure.Code, failure.Outcome, failure.Retryable))
		}
		status, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		if status.ObservedState != "ready" || status.Generation != 1 || status.ObservedGeneration != 1 || status.TenantID != r.config.ControllerA.TenantID {
			return fmt.Errorf("sandbox status = %#v", status)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "exec result and usage evidence", r.runOutputExec); err != nil {
		return err
	}
	if err := r.step(ctx, "stale fencing rejection", r.verifyStaleFencing); err != nil {
		return err
	}
	if err := r.step(ctx, "exec cancellation", r.runCancellation); err != nil {
		return err
	}
	var handoff RuntimeSessionHandoff
	if err := r.step(ctx, "terminal session and opaque handoff", func(ctx context.Context) error {
		var err error
		handoff, err = r.openSession(ctx)
		return err
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Gateway terminal byte round trip", func(ctx context.Context) error {
		return terminalRoundTrip(ctx, r.a.http, r.config, handoff, "grant-initial-terminal-1", "export E2E_RESTART_MARKER=survived; printf 'initial:%s\\n' \"$E2E_RESTART_MARKER\"\n", "initial:survived")
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Gateway wrong caller and cross-tenant rejection", func(ctx context.Context) error {
		return verifyGatewayDenials(ctx, r.a.http, r.config, handoff)
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Gateway grant expiry", func(ctx context.Context) error {
		return verifyGatewayExpiry(ctx, r.a.http, r.config, handoff)
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Gateway revocation", func(ctx context.Context) error {
		return verifyGatewayRevocation(ctx, r.a.http, r.config, handoff)
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "artifact staging and evidence", r.runArtifact); err != nil {
		return err
	}
	if err := r.step(ctx, "Provider cross-tenant staging rejection", r.runCrossTenantArtifact); err != nil {
		return err
	}
	return r.step(ctx, "Provider mTLS caller binding rejection", r.verifyWrongCaller)
}

func (r *runner) runResume(ctx context.Context) error {
	if err := r.step(ctx, "durable lifecycle after stack reconstruction", func(ctx context.Context) error {
		status, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		if status.ObservedState != "ready" || status.ObservedGeneration != 1 {
			return fmt.Errorf("reconstructed sandbox status = %#v", status)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "retained exec usage and artifact evidence", func(ctx context.Context) error {
		var result ExecResult
		if err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/operations/"+execOperation+"/exec-result", "read_result", execRef(), &result); err != nil {
			return err
		}
		if result.Status != "completed" {
			return fmt.Errorf("retained exec status = %q", result.Status)
		}
		var usage UsageEvidence
		if err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/operations/"+execOperation+"/usage-evidence", "read_usage_evidence", execRef(), &usage); err != nil {
			return err
		}
		var artifact ArtifactStagingEvidence
		if err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/operations/"+artifactOperation+"/artifact-staging-evidence", "read_artifact_staging_evidence", artifactRef(), &artifact); err != nil {
			return err
		}
		if usage.ReconciliationStatus == "" || artifact.Status != "staged" {
			return errors.New("retained evidence is incomplete")
		}
		return nil
	}); err != nil {
		return err
	}
	var handoff RuntimeSessionHandoff
	if err := r.step(ctx, "durable opaque handoff after stack reconstruction", func(ctx context.Context) error {
		var err error
		handoff, err = r.readHandoff(ctx)
		return err
	}); err != nil {
		return err
	}
	return r.step(ctx, "same-shell reconnect after stack reconstruction", func(ctx context.Context) error {
		return terminalRoundTrip(ctx, r.a.http, r.config, handoff, "grant-resume-terminal-1", "printf 'resume:%s\\n' \"$E2E_RESTART_MARKER\"\n", "resume:survived")
	})
}

func (r *runner) runLifecycle(ctx context.Context) error {
	var baseline LifecycleEventPage
	if err := r.step(ctx, "retained lifecycle events after stack reconstruction", func(ctx context.Context) error {
		status, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		if status.DesiredState != "ready" || status.ObservedState != "ready" || status.Generation != 1 || status.ObservedGeneration != 1 {
			return fmt.Errorf("pre-control sandbox status = %#v", status)
		}
		baseline, err = r.readLifecycleEvents(ctx, 0)
		if err != nil {
			return err
		}
		return validateEventPage(baseline, 0, createOperation)
	}); err != nil {
		return err
	}

	if err := r.step(ctx, "suspend reconciliation and runtime observation", func(ctx context.Context) error {
		ref := suspendRef()
		deadline := time.Now().UTC().Add(2 * time.Minute)
		body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-suspend-idempotency-1", deadline)
		body["expected_generation"] = 1
		body["desired_state"] = "suspended"
		body["reason"] = "phase_2_black_box"
		prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/desired-state", body, r.binding("set_desired_state", ref, deadline))
		if err != nil {
			return err
		}
		operation, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted)
		if err != nil {
			return err
		}
		if err := validateOperation(operation, ref, "suspend", "accepted"); err != nil {
			return err
		}
		operation, err = r.waitOperation(ctx, ref)
		if err != nil || operation.Status != "succeeded" {
			return errors.Join(err, fmt.Errorf("suspend operation = %#v", operation))
		}
		status, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		if status.DesiredState != "suspended" || status.ObservedState != "suspended" || status.Generation != 2 || status.ObservedGeneration != 2 {
			return fmt.Errorf("suspended sandbox status = %#v", status)
		}
		return nil
	}); err != nil {
		return err
	}

	var suspendedEvents LifecycleEventPage
	if err := r.step(ctx, "lifecycle event cursor continuation", func(ctx context.Context) error {
		var err error
		suspendedEvents, err = r.readLifecycleEvents(ctx, baseline.NextSequence)
		if err != nil {
			return err
		}
		if err := validateEventPage(suspendedEvents, baseline.NextSequence, suspendOperation); err != nil {
			return err
		}
		return requireEventKinds(suspendedEvents, "desired-state-requested", "suspending", "suspended")
	}); err != nil {
		return err
	}

	if err := r.step(ctx, "resume reconciliation and runtime observation", func(ctx context.Context) error {
		ref := resumeRef()
		deadline := time.Now().UTC().Add(2 * time.Minute)
		body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-resume-idempotency-1", deadline)
		body["expected_generation"] = 2
		body["desired_state"] = "ready"
		body["reason"] = "phase_2_black_box"
		prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/desired-state", body, r.binding("set_desired_state", ref, deadline))
		if err != nil {
			return err
		}
		operation, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted)
		if err != nil {
			return err
		}
		if err := validateOperation(operation, ref, "resume", "accepted"); err != nil {
			return err
		}
		operation, err = r.waitOperation(ctx, ref)
		if err != nil || operation.Status != "succeeded" {
			return errors.Join(err, fmt.Errorf("resume operation = %#v", operation))
		}
		status, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		if status.DesiredState != "ready" || status.ObservedState != "ready" || status.Generation != 3 || status.ObservedGeneration != 3 {
			return fmt.Errorf("resumed sandbox status = %#v", status)
		}
		return nil
	}); err != nil {
		return err
	}

	if err := r.step(ctx, "lease extension without generation drift", func(ctx context.Context) error {
		before, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		beforeExpiry, err := time.Parse(time.RFC3339Nano, before.LeaseExpiresAt)
		if err != nil {
			return err
		}
		ref := leaseRef()
		deadline := time.Now().UTC().Add(2 * time.Minute)
		body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-lease-idempotency-1", deadline)
		body["expected_generation"] = 3
		body["extend_seconds"] = 60
		prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/lease", body, r.binding("extend_lease", ref, deadline))
		if err != nil {
			return err
		}
		if _, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted); err != nil {
			return err
		}
		operation, err := r.waitOperation(ctx, ref)
		if err != nil || operation.Status != "succeeded" || operation.Type != "extend_lease" {
			return errors.Join(err, fmt.Errorf("lease operation = %#v", operation))
		}
		after, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		afterExpiry, err := time.Parse(time.RFC3339Nano, after.LeaseExpiresAt)
		if err != nil {
			return err
		}
		if after.Generation != 3 || after.ObservedGeneration != 3 || !afterExpiry.Equal(beforeExpiry.Add(time.Minute)) {
			return fmt.Errorf("lease extension status before=%#v after=%#v", before, after)
		}
		return nil
	}); err != nil {
		return err
	}

	var closedHandoff RuntimeSessionHandoff
	if err := r.step(ctx, "durable terminal session close", func(ctx context.Context) error {
		var err error
		closedHandoff, err = r.readHandoff(ctx)
		if err != nil {
			return err
		}
		ref := closeRef()
		deadline := time.Now().UTC().Add(2 * time.Minute)
		body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-session-close-idempotency-1", deadline)
		body["expected_generation"] = 3
		body["runtime_session_id"] = runtimeSessionID
		body["connection_generation"] = closedHandoff.ConnectionGeneration
		body["reason"] = "caller_complete"
		path := "/v1/sandboxes/" + sandboxID + "/runtime-sessions/" + runtimeSessionID + ":close"
		prepared, err := r.a.prepare(http.MethodPost, path, body, r.binding("close_runtime_session", ref, deadline))
		if err != nil {
			return err
		}
		operation, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted)
		if err != nil || operation.Type != "close_runtime_session" || (operation.Status != "accepted" && operation.Status != "succeeded") {
			return errors.Join(err, fmt.Errorf("close operation acceptance = %#v", operation))
		}
		operation, err = r.waitOperation(ctx, ref)
		if err != nil || operation.Status != "succeeded" {
			return errors.Join(err, fmt.Errorf("close operation = %#v", operation))
		}
		return nil
	}); err != nil {
		return err
	}

	if err := r.step(ctx, "Gateway reconnect denied after terminal close", func(ctx context.Context) error {
		return verifyClosedSessionReconnectDenied(ctx, r.a.http, r.config, closedHandoff)
	}); err != nil {
		return err
	}

	return r.step(ctx, "termination cleanup and final lifecycle events", func(ctx context.Context) error {
		ref := terminateRef()
		deadline := time.Now().UTC().Add(2 * time.Minute)
		body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-terminate-idempotency-1", deadline)
		body["expected_generation"] = 3
		body["reason"] = "work_order_complete"
		body["preserve_workspace_snapshot"] = false
		prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+":terminate", body, r.binding("terminate", ref, deadline))
		if err != nil {
			return err
		}
		operation, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted)
		if err != nil {
			return err
		}
		if err := validateOperation(operation, ref, "terminate", "accepted"); err != nil {
			return err
		}
		operation, err = r.waitOperation(ctx, ref)
		if err != nil || operation.Status != "succeeded" {
			return errors.Join(err, fmt.Errorf("terminate operation = %#v error=%#v", operation, operation.Error))
		}
		status, err := r.readSandbox(ctx)
		if err != nil {
			return err
		}
		if status.DesiredState != "terminated" || status.ObservedState != "terminated" || status.Generation != 4 || status.ObservedGeneration != 4 {
			return fmt.Errorf("terminated sandbox status = %#v", status)
		}
		finalEvents, err := r.readLifecycleEvents(ctx, suspendedEvents.NextSequence)
		if err != nil {
			return err
		}
		if err := validateEventPage(finalEvents, suspendedEvents.NextSequence, resumeOperation, leaseOperation, terminateOperation); err != nil {
			return err
		}
		return requireEventKinds(finalEvents, "resuming", "ready", "lease-extended", "terminating", "terminated")
	})
}

func (r *runner) verifyCapabilities(ctx context.Context) error {
	capabilities, _, err := r.a.capabilities(ctx)
	if err != nil {
		return err
	}
	if r.config.Profile == ProfileBrowser {
		wantCapabilities := []Capability{{ID: "sandbox.browser", Versions: []string{"1.0.0"}, Profiles: []string{"browser-v1"}}}
		wantRuntimeProfiles := []RuntimeProfile{{
			ID: "sandbox-runtime-browser-v1", IsolationClass: "container", RuntimeClassName: "sandbox-runtime-browser",
			Architecture: []string{r.config.RuntimeArchitecture}, CapabilityProfileIDs: []string{"browser-v1"},
		}}
		wantSnapshotProfiles := []SnapshotRestoreProfile{{
			ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider",
			SuiteVersion: "1.0.0", SuiteDigest: "sha256:" + strings.Repeat("a", 64),
		}}
		if capabilities.ProviderRevisionID != r.config.ProviderRevisionID || capabilities.APIVersion != "v1" ||
			!reflect.DeepEqual(capabilities.Capabilities, wantCapabilities) ||
			!reflect.DeepEqual(capabilities.RuntimeProfiles, wantRuntimeProfiles) ||
			!reflect.DeepEqual(capabilities.SnapshotRestoreProfiles, wantSnapshotProfiles) {
			return fmt.Errorf("Browser reference capability snapshot differs from lock: %#v", capabilities)
		}
		return nil
	}
	wantCapabilities := []Capability{
		{ID: "sandbox.exec", Versions: []string{"1.0.0"}, Profiles: []string{"exec-v1"}},
		{ID: "sandbox.terminal", Versions: []string{"1.0.0"}, Profiles: []string{"terminal-v1"}},
		{ID: "sandbox.lifecycle-control", Versions: []string{"1.0.0"}, Profiles: []string{"lifecycle-control-v1"}},
		{ID: "sandbox.terminal-control", Versions: []string{"1.0.0"}, Profiles: []string{"terminal-control-v1"}},
		{ID: "sandbox.terminal-connect", Versions: []string{"1.0.0"}, Profiles: []string{"terminal-connect-v1"}},
	}
	wantSnapshotProfiles := []SnapshotRestoreProfile{{
		ProfileID: "sandbox-snapshot-workspace-v1", Level: "workspace", SuiteID: "sandbox-provider",
		SuiteVersion: "1.0.0", SuiteDigest: "sha256:7db1d28d35ca193632c395247cc71eeaaff48b027964b9ea9da247eaad5e3991",
	}}
	if capabilities.ProviderRevisionID != r.config.ProviderRevisionID || capabilities.APIVersion != "v1" || !reflect.DeepEqual(capabilities.Capabilities, wantCapabilities) || len(capabilities.RuntimeProfiles) != 1 || !reflect.DeepEqual(capabilities.SnapshotRestoreProfiles, wantSnapshotProfiles) {
		return fmt.Errorf("capability snapshot differs from lock: %#v", capabilities)
	}
	profile := capabilities.RuntimeProfiles[0]
	if profile.ID != "sandbox-runtime-coding-shell-v1" || !reflect.DeepEqual(profile.Architecture, []string{"amd64"}) || !reflect.DeepEqual(profile.CapabilityProfileIDs, []string{"exec-v1", "terminal-v1", "lifecycle-control-v1", "terminal-control-v1", "terminal-connect-v1"}) {
		return fmt.Errorf("runtime profile differs from lock: %#v", profile)
	}
	return nil
}

func (r *runner) readLifecycleEvents(ctx context.Context, after int64) (LifecycleEventPage, error) {
	path := "/v1/sandboxes/" + sandboxID + "/events"
	if after > 0 {
		path += "?after_sequence=" + strconv.FormatInt(after, 10)
	}
	var page LifecycleEventPage
	err := r.readJSON(ctx, r.a, http.MethodGet, path, "read_events", createRef(), &page)
	return page, err
}

func validateEventPage(page LifecycleEventPage, after int64, operationIDs ...string) error {
	if len(page.Events) == 0 || page.FirstAvailableSequence < 1 || page.LatestSequence < page.FirstAvailableSequence || page.NextSequence != page.Events[len(page.Events)-1].Sequence || page.NextSequence > page.LatestSequence {
		return fmt.Errorf("invalid lifecycle event page = %#v", page)
	}
	found := make(map[string]bool, len(operationIDs))
	previous := after
	for _, event := range page.Events {
		if event.Sequence != previous+1 || event.SandboxID != sandboxID || event.Generation < 1 || event.FencingToken < 1 || event.Kind == "" || event.OccurredAt == "" {
			return fmt.Errorf("invalid lifecycle event after %d = %#v", previous, event)
		}
		if event.DataDigest != "" && !isDigest(event.DataDigest) {
			return fmt.Errorf("invalid lifecycle event digest = %#v", event)
		}
		found[event.OperationID] = true
		previous = event.Sequence
	}
	for _, operationID := range operationIDs {
		if !found[operationID] {
			return fmt.Errorf("lifecycle event page lacks operation %q", operationID)
		}
	}
	return nil
}

func requireEventKinds(page LifecycleEventPage, kinds ...string) error {
	found := make(map[string]bool, len(page.Events))
	for _, event := range page.Events {
		found[event.Kind] = true
	}
	for _, kind := range kinds {
		if !found[kind] {
			return fmt.Errorf("lifecycle event page lacks kind %q", kind)
		}
	}
	return nil
}

func (r *runner) prepareCreate() (preparedRequest, error) {
	deadline := time.Now().UTC().Add(2 * time.Minute)
	body := mutationEnvelope(createOperation, createAttempt, 1, "e2e-create-idempotency-1", deadline)
	body["protocol_version"] = "v1"
	body["spec"] = map[string]any{
		"sandbox_id": sandboxID, "tenant_id": r.config.ControllerA.TenantID,
		"work_order_id": r.config.ControllerA.WorkOrderID, "workspace_id": workspaceID,
		"branch_id": "e2e-branch-1", "provider_resolution_id": "e2e-provider-resolution-1",
		"provider_revision_id": r.config.ProviderRevisionID,
		"image":                map[string]any{"reference": r.config.RuntimeImageReference, "digest": r.config.RuntimeImageDigest, "architecture": r.config.RuntimeArchitecture},
		"runtime_profile":      "sandbox-runtime-coding-shell-v1",
		"resources":            map[string]any{"cpu_millis": 500, "memory_bytes": 268435456, "ephemeral_storage_bytes": 268435456, "pids_limit": 64},
		"required_capabilities": []any{
			map[string]any{"id": "sandbox.exec", "version": "1.0.0", "profile": "exec-v1"},
			map[string]any{"id": "sandbox.terminal", "version": "1.0.0", "profile": "terminal-v1"},
			map[string]any{"id": "sandbox.lifecycle-control", "version": "1.0.0", "profile": "lifecycle-control-v1"},
			map[string]any{"id": "sandbox.terminal-control", "version": "1.0.0", "profile": "terminal-control-v1"},
			map[string]any{"id": "sandbox.terminal-connect", "version": "1.0.0", "profile": "terminal-connect-v1"},
		},
		"network": map[string]any{"mode": "none"},
		"workspace": map[string]any{
			"mode": "ephemeral", "base_revision_id": "e2e-workspace-revision-1",
			"base_revision_digest": "sha256:" + strings.Repeat("e", 64), "base_workspace_head_version": 0,
			"commit_mode": "read_only", "mount_path": "/workspace",
		},
		"lease": map[string]any{"expires_at": time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano), "max_extension_seconds": 3600},
		"security": map[string]any{
			"privilege_level": "unprivileged", "root_filesystem": "read_only", "service_account_mode": "none",
			"allow_privilege_escalation": false, "host_namespace_access": false, "seccomp_profile": "runtime-default",
		},
		"sandbox_slot_key": "primary-code",
	}
	return r.a.prepare(http.MethodPost, "/v1/sandboxes", body, r.binding("create", createRef(), deadline))
}

func (r *runner) runOutputExec(ctx context.Context) error {
	deadline := time.Now().UTC().Add(2 * time.Minute)
	body := mutationEnvelope(execOperation, execAttempt, 2, "e2e-exec-output-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["command"] = []string{"/bin/e2e-workload", "write-output"}
	body["working_directory"] = "/workspace"
	body["result_retention_seconds"] = 600
	body["capture"] = map[string]any{"stdout": true, "stderr": true, "max_bytes": 65536}
	prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/exec", body, r.binding("exec", execRef(), deadline))
	if err != nil {
		return err
	}
	operation, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted)
	if err != nil || operation.OperationID != execOperation {
		return errors.Join(err, errors.New("exec operation correlation failed"))
	}
	operation, err = r.waitOperation(ctx, execRef())
	if err != nil || operation.Status != "succeeded" {
		return errors.Join(err, fmt.Errorf("exec operation status = %q", operation.Status))
	}
	var result ExecResult
	if err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/operations/"+execOperation+"/exec-result", "read_result", execRef(), &result); err != nil {
		return err
	}
	if result.Status != "completed" || result.ExitCode == nil || *result.ExitCode != 0 || !strings.HasPrefix(result.StdoutReference, "ref:exec/") {
		return fmt.Errorf("exec result = %#v", result)
	}
	var usage UsageEvidence
	if err := r.pollJSON(ctx, r.a, "/v1/operations/"+execOperation+"/usage-evidence", "read_usage_evidence", execRef(), &usage); err != nil {
		return err
	}
	if usage.OperationID != execOperation || len(usage.Entries) == 0 || usage.ReconciliationStatus == "" {
		return fmt.Errorf("usage evidence = %#v", usage)
	}
	return nil
}

func (r *runner) verifyStaleFencing(ctx context.Context) error {
	ref := staleExecRef()
	deadline := time.Now().UTC().Add(time.Minute)
	body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-stale-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["command"] = []string{"/bin/e2e-workload", "true"}
	body["working_directory"] = "/workspace"
	body["result_retention_seconds"] = 60
	prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/exec", body, r.binding("exec", ref, deadline))
	if err != nil {
		return err
	}
	result, err := r.a.send(ctx, prepared)
	if err != nil {
		return err
	}
	if result.Status != http.StatusConflict {
		return unexpectedStatus("stale fencing", result, http.StatusConflict)
	}
	return nil
}

func (r *runner) runCancellation(ctx context.Context) error {
	target := cancelTargetRef()
	deadline := time.Now().UTC().Add(2 * time.Minute)
	body := mutationEnvelope(target.OperationID, target.AttemptID, target.FencingToken, "e2e-cancel-target-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["command"] = []string{"/bin/e2e-workload", "sleep", "30"}
	body["working_directory"] = "/workspace"
	body["result_retention_seconds"] = 600
	prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/exec", body, r.binding("exec", target, deadline))
	if err != nil {
		return err
	}
	if _, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted); err != nil {
		return err
	}
	time.Sleep(150 * time.Millisecond)
	cancelRef := cancellationRef()
	cancelDeadline := time.Now().UTC().Add(time.Minute)
	cancelBody := mutationEnvelope(cancelRef.OperationID, cancelRef.AttemptID, cancelRef.FencingToken, "e2e-cancel-idempotency-1", cancelDeadline)
	cancelBody["expected_generation"] = 1
	cancelBody["target_operation_id"] = target.OperationID
	cancelBody["target_attempt_id"] = target.AttemptID
	cancelBody["reason"] = "caller_requested"
	prepared, err = r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/exec:cancel", cancelBody, r.binding("cancel_exec", cancelRef, cancelDeadline))
	if err != nil {
		return err
	}
	operation, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted)
	if err != nil || operation.Status != "succeeded" {
		return errors.Join(err, fmt.Errorf("cancellation operation = %#v", operation))
	}
	operation, err = r.waitOperation(ctx, target)
	if err != nil || operation.Status != "cancelled" {
		return errors.Join(err, fmt.Errorf("cancelled target operation = %#v", operation))
	}
	var result ExecResult
	if err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/operations/"+target.OperationID+"/exec-result", "read_result", target, &result); err != nil {
		return err
	}
	if result.Status != "cancelled" {
		return fmt.Errorf("cancelled exec result = %#v", result)
	}
	return nil
}

func (r *runner) openSession(ctx context.Context) (RuntimeSessionHandoff, error) {
	ref := sessionRef()
	deadline, expiresAt := sessionWindow(time.Now().UTC())
	body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-session-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["runtime_session_id"] = runtimeSessionID
	body["runtime_type"] = "terminal"
	body["capability_profile_id"] = "terminal-v1"
	body["expires_at"] = expiresAt.Format(time.RFC3339Nano)
	prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/runtime-sessions", body, r.binding("open_runtime_session", ref, deadline))
	if err != nil {
		return RuntimeSessionHandoff{}, err
	}
	if _, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted); err != nil {
		return RuntimeSessionHandoff{}, err
	}
	operation, err := r.waitOperation(ctx, ref)
	if err != nil || operation.Status != "succeeded" {
		return RuntimeSessionHandoff{}, errors.Join(err, fmt.Errorf("session operation = %#v", operation))
	}
	return r.readHandoff(ctx)
}

func (r *runner) readHandoff(ctx context.Context) (RuntimeSessionHandoff, error) {
	var handoff RuntimeSessionHandoff
	if err := r.pollJSON(ctx, r.a, "/v1/operations/"+sessionOperation+"/runtime-session", "read_runtime_session", sessionRef(), &handoff); err != nil {
		return RuntimeSessionHandoff{}, err
	}
	if handoff.Protocol != "websocket" || handoff.InternalEndpointReference == "" || !strings.HasPrefix(handoff.InternalEndpointReference, "ref:session:") ||
		strings.Contains(handoff.InternalEndpointReference, "://") || handoff.ConnectionGeneration < 1 {
		return RuntimeSessionHandoff{}, fmt.Errorf("runtime handoff is not opaque: %#v", handoff)
	}
	return handoff, nil
}

func (r *runner) runArtifact(ctx context.Context) error {
	ref := artifactRef()
	deadline, retentionSeconds := artifactWindow(time.Now().UTC())
	body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-artifact-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["artifact_reference"] = "artifact-ref:platform/e2e-report-1"
	body["source_path"] = "/outputs/report.json"
	body["expected_digest"] = sha256Digest(artifactContent)
	body["expected_media_type"] = "application/json"
	body["max_bytes"] = 4096
	body["retention_seconds"] = retentionSeconds
	prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/artifacts:stage", body, r.binding("stage_artifact", ref, deadline))
	if err != nil {
		return err
	}
	if _, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted); err != nil {
		return err
	}
	operation, err := r.waitOperation(ctx, ref)
	if err != nil || operation.Status != "succeeded" {
		return errors.Join(err, fmt.Errorf("artifact operation = %#v", operation))
	}
	var evidence ArtifactStagingEvidence
	if err := r.pollJSON(ctx, r.a, "/v1/operations/"+ref.OperationID+"/artifact-staging-evidence", "read_artifact_staging_evidence", ref, &evidence); err != nil {
		return err
	}
	if evidence.Status != "staged" || evidence.ContentDigest != sha256Digest(artifactContent) || evidence.SizeBytes != int64(len(artifactContent)) || !strings.HasPrefix(evidence.StagingReference, "ref:staging/") {
		return fmt.Errorf("artifact evidence = %#v", evidence)
	}
	return nil
}

func (r *runner) runCrossTenantArtifact(ctx context.Context) error {
	ref := operationReference{SandboxID: sandboxID, OperationID: "e2e-operation-artifact-cross-tenant-1", AttemptID: "e2e-attempt-artifact-cross-tenant-1", FencingToken: 7, TenantID: r.config.ControllerB.TenantID, WorkOrderID: r.config.ControllerB.WorkOrderID}
	deadline, retentionSeconds := artifactWindow(time.Now().UTC())
	body := mutationEnvelope(ref.OperationID, ref.AttemptID, ref.FencingToken, "e2e-artifact-cross-tenant-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["artifact_reference"] = "artifact-ref:platform/cross-tenant-1"
	body["source_path"] = "/outputs/report.json"
	body["expected_digest"] = sha256Digest(artifactContent)
	body["expected_media_type"] = "application/json"
	body["max_bytes"] = 4096
	body["retention_seconds"] = retentionSeconds
	prepared, err := r.b.prepare(http.MethodPost, "/v1/sandboxes/"+sandboxID+"/artifacts:stage", body, r.binding("stage_artifact", ref, deadline))
	if err != nil {
		return err
	}
	result, err := r.b.send(ctx, prepared)
	if err != nil {
		return err
	}
	if result.Status != http.StatusForbidden {
		return unexpectedStatus("cross-tenant artifact staging", result, http.StatusForbidden)
	}
	var forbidden StandardError
	if err := decodeStrict(result.Body, &forbidden); err != nil || forbidden.Code != "SANDBOX_FORBIDDEN" || forbidden.Retryable {
		return errors.Join(err, fmt.Errorf("cross-tenant artifact error = %#v", forbidden))
	}
	if err := checkNoBackendDisclosure(result.Body); err != nil {
		return err
	}

	readDeadline := time.Now().UTC().Add(time.Minute)
	read, err := r.b.prepare(http.MethodGet, "/v1/operations/"+ref.OperationID, nil, r.binding("read_operation", ref, readDeadline))
	if err != nil {
		return err
	}
	result, err = r.b.send(ctx, read)
	if err != nil {
		return err
	}
	if result.Status != http.StatusNotFound {
		return unexpectedStatus("cross-tenant artifact operation", result, http.StatusNotFound)
	}
	var notFound StandardError
	if err := decodeStrict(result.Body, &notFound); err != nil || notFound.Code != "SANDBOX_NOT_FOUND" || notFound.Retryable {
		return errors.Join(err, fmt.Errorf("cross-tenant artifact operation error = %#v", notFound))
	}
	return checkNoBackendDisclosure(result.Body)
}

func artifactWindow(now time.Time) (time.Time, int64) {
	retention := 10 * time.Minute
	return now.Add(retention + 2*time.Minute), int64(retention / time.Second)
}

func (r *runner) verifyWrongCaller(ctx context.Context) error {
	ref := createRef()
	prepared, err := r.wrong.prepare(http.MethodGet, "/v1/sandboxes/"+sandboxID, nil, r.binding("read_sandbox", ref, time.Now().UTC().Add(time.Minute)))
	if err != nil {
		return err
	}
	result, err := r.wrong.send(ctx, prepared)
	if err != nil {
		return err
	}
	if result.Status != http.StatusForbidden {
		return unexpectedStatus("wrong mTLS caller", result, http.StatusForbidden)
	}
	return nil
}

func (r *runner) readSandbox(ctx context.Context) (SandboxStatus, error) {
	var status SandboxStatus
	err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/sandboxes/"+sandboxID, "read_sandbox", createRef(), &status)
	return status, err
}

func (r *runner) waitOperation(ctx context.Context, reference operationReference) (Operation, error) {
	deadline := time.Now().Add(operationPollWindow(r.config.Profile))
	var last Operation
	for {
		var operation Operation
		err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/operations/"+reference.OperationID, "read_operation", reference, &operation)
		if err == nil {
			last = operation
			switch operation.Status {
			case "succeeded", "failed", "cancelled", "outcome_unknown":
				return operation, nil
			}
		}
		if time.Now().After(deadline) {
			return last, errors.Join(fmt.Errorf("operation polling timed out at status %q", last.Status), err)
		}
		select {
		case <-ctx.Done():
			return Operation{}, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func operationPollWindow(profile string) time.Duration {
	if profile == ProfileBrowser {
		return 330 * time.Second
	}
	return 30 * time.Second
}

func (r *runner) readJSON(ctx context.Context, client *providerClient, method, path, operation string, reference operationReference, target any) error {
	prepared, err := client.prepare(method, path, nil, r.binding(operation, reference, time.Now().UTC().Add(time.Minute)))
	if err != nil {
		return err
	}
	result, err := client.send(ctx, prepared)
	if err != nil {
		return err
	}
	if result.Status != http.StatusOK {
		return unexpectedStatus(operation, result, http.StatusOK)
	}
	if err := checkNoBackendDisclosure(result.Body); err != nil {
		return err
	}
	return decodeStrict(result.Body, target)
}

func (r *runner) pollJSON(ctx context.Context, client *providerClient, path, operation string, reference operationReference, target any) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		prepared, err := client.prepare(http.MethodGet, path, nil, r.binding(operation, reference, time.Now().UTC().Add(time.Minute)))
		if err != nil {
			return err
		}
		result, err := client.send(ctx, prepared)
		if err == nil && result.Status == http.StatusOK {
			if err := checkNoBackendDisclosure(result.Body); err != nil {
				return err
			}
			return decodeStrict(result.Body, target)
		}
		if err == nil && result.Status != http.StatusNotFound && result.Status != http.StatusServiceUnavailable {
			return unexpectedStatus(operation, result, http.StatusOK, http.StatusNotFound, http.StatusServiceUnavailable)
		}
		if time.Now().After(deadline) {
			return errors.Join(errors.New("evidence polling timed out"), err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (r *runner) sendOperation(ctx context.Context, client *providerClient, prepared preparedRequest, expected int) (Operation, error) {
	result, err := client.send(ctx, prepared)
	if err != nil {
		return Operation{}, err
	}
	if result.Status != expected {
		return Operation{}, unexpectedStatus("mutation", result, expected)
	}
	if err := checkNoBackendDisclosure(result.Body); err != nil {
		return Operation{}, err
	}
	var operation Operation
	if err := decodeStrict(result.Body, &operation); err != nil {
		return Operation{}, err
	}
	return operation, nil
}

func (r *runner) binding(operation string, reference operationReference, deadline time.Time) admissionBinding {
	reference = r.fillAuthority(reference)
	return admissionBinding{
		Operation: operation, SandboxID: reference.SandboxID, OperationID: reference.OperationID,
		AttemptID: reference.AttemptID, FencingToken: reference.FencingToken,
		TenantID: reference.TenantID, WorkOrderID: reference.WorkOrderID, Deadline: deadline,
	}
}

func mutationEnvelope(operationID, attemptID string, fencing int64, idempotency string, deadline time.Time) map[string]any {
	return map[string]any{
		"operation_id": operationID, "attempt_id": attemptID, "fencing_token": fencing,
		"idempotency_key": idempotency, "deadline_at": deadline.UTC().Format(time.RFC3339Nano),
	}
}

func createRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: createOperation, AttemptID: createAttempt, FencingToken: 1, TenantID: "", WorkOrderID: ""}
}

func execRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: execOperation, AttemptID: execAttempt, FencingToken: 2}
}

func staleExecRef() operationReference {
	reference := execRef()
	reference.AttemptID = "e2e-attempt-exec-stale-1"
	reference.FencingToken = 1
	return reference
}

func sessionWindow(now time.Time) (time.Time, time.Time) {
	deadline := now.UTC().Add(4 * time.Minute)
	return deadline, deadline.Add(-time.Minute)
}

func cancelTargetRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: cancelTargetOp, AttemptID: cancelTargetAtt, FencingToken: 3}
}

func cancellationRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: cancelOperation, AttemptID: cancelAttempt, FencingToken: 4}
}

func sessionRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: sessionOperation, AttemptID: sessionAttempt, FencingToken: 5}
}

func artifactRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: artifactOperation, AttemptID: artifactAttempt, FencingToken: 6}
}

func suspendRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: suspendOperation, AttemptID: suspendAttempt, FencingToken: 7}
}

func resumeRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: resumeOperation, AttemptID: resumeAttempt, FencingToken: 8}
}

func leaseRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: leaseOperation, AttemptID: leaseAttempt, FencingToken: 9}
}

func closeRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: closeOperation, AttemptID: closeAttempt, FencingToken: 10}
}

func terminateRef() operationReference {
	return operationReference{SandboxID: sandboxID, OperationID: terminateOperation, AttemptID: terminateAttempt, FencingToken: 11}
}

func (r *runner) fillAuthority(reference operationReference) operationReference {
	if reference.TenantID == "" {
		reference.TenantID = r.config.ControllerA.TenantID
	}
	if reference.WorkOrderID == "" {
		reference.WorkOrderID = r.config.ControllerA.WorkOrderID
	}
	return reference
}

func validateOperation(operation Operation, reference operationReference, operationType, status string) error {
	if operation.OperationID != reference.OperationID || operation.AttemptID != reference.AttemptID || operation.FencingToken != reference.FencingToken ||
		operation.SandboxID != reference.SandboxID || operation.Type != operationType || operation.Status != status {
		return fmt.Errorf("operation correlation = %#v", operation)
	}
	return nil
}
