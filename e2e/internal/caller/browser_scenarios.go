package caller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	BrowserSandboxID       = "e2e-browser-sandbox-1"
	browserWorkspaceID     = "e2e-browser-workspace-1"
	browserCreateOperation = "e2e-browser-operation-create-1"
	browserCreateAttempt   = "e2e-browser-attempt-create-1"
	browserOpenOperation   = "e2e-browser-operation-session-1"
	browserOpenAttempt     = "e2e-browser-attempt-session-1"
	browserSessionID       = "e2e-browser-session-1"
)

func (r *runner) runBrowser(ctx context.Context) error {
	if r.config.Phase == PhaseResume {
		return r.runBrowserResume(ctx)
	}
	return r.runBrowserInitial(ctx)
}

func (r *runner) runBrowserInitial(ctx context.Context) error {
	if err := r.step(ctx, "protected Browser lifecycle create", func(ctx context.Context) error {
		prepared, err := r.prepareBrowserCreate()
		if err != nil {
			return err
		}
		operation, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted)
		return errors.Join(err, validateOperation(operation, browserCreateRef(), "create", "accepted"))
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Browser lifecycle completion and status", r.waitBrowserSandbox); err != nil {
		return err
	}
	var handoff BrowserSessionHandoff
	if err := r.step(ctx, "Browser session and opaque handoff", func(ctx context.Context) error {
		var err error
		handoff, err = r.openBrowserSession(ctx)
		return err
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Browser Gateway CDP and restricted egress", func(ctx context.Context) error {
		return browserRoundTrip(ctx, r.a.http, r.config, handoff, "grant-browser-initial-1")
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Browser Gateway concurrent capacity and release", func(ctx context.Context) error {
		return verifyBrowserGatewayCapacity(ctx, r.a.http, r.config, handoff)
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Browser Gateway wrong caller and cross-tenant rejection", func(ctx context.Context) error {
		return verifyBrowserGatewayDenials(ctx, r.a.http, r.config, handoff)
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Browser Gateway grant expiry", func(ctx context.Context) error {
		return verifyBrowserGatewayExpiry(ctx, r.a.http, r.config, handoff)
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Browser Gateway active revocation", func(ctx context.Context) error {
		return verifyBrowserGatewayRevocation(ctx, r.a.http, r.config, handoff)
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "partial Browser duration usage evidence", func(ctx context.Context) error {
		return r.readBrowserUsage(ctx, "partial")
	}); err != nil {
		return err
	}
	return r.step(ctx, "Browser Provider mTLS caller binding rejection", r.verifyBrowserWrongCaller)
}

func (r *runner) runBrowserResume(ctx context.Context) error {
	if err := r.step(ctx, "durable Browser lifecycle after stack reconstruction", r.waitBrowserSandbox); err != nil {
		return err
	}
	var handoff BrowserSessionHandoff
	if err := r.step(ctx, "durable Browser handoff after stack reconstruction", func(ctx context.Context) error {
		var err error
		handoff, err = r.readBrowserHandoff(ctx)
		return err
	}); err != nil {
		return err
	}
	if err := r.step(ctx, "Browser Gateway CDP after stack reconstruction", func(ctx context.Context) error {
		return browserRoundTrip(ctx, r.a.http, r.config, handoff, "grant-browser-resume-1")
	}); err != nil {
		return err
	}
	return r.step(ctx, "complete Browser duration usage at handoff expiry", func(ctx context.Context) error {
		expiresAt, err := time.Parse(time.RFC3339Nano, handoff.ExpiresAt)
		if err != nil {
			return err
		}
		if wait := time.Until(expiresAt.Add(150 * time.Millisecond)); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return r.readBrowserUsage(ctx, "complete")
	})
}

func (r *runner) prepareBrowserCreate() (preparedRequest, error) {
	deadline := time.Now().UTC().Add(5 * time.Minute)
	body := mutationEnvelope(browserCreateOperation, browserCreateAttempt, 1, "e2e-browser-create-idempotency-1", deadline)
	body["protocol_version"] = "v1"
	body["spec"] = map[string]any{
		"sandbox_id": BrowserSandboxID, "tenant_id": r.config.ControllerA.TenantID,
		"work_order_id": r.config.ControllerA.WorkOrderID, "workspace_id": browserWorkspaceID,
		"branch_id": "e2e-browser-branch-1", "provider_resolution_id": "e2e-browser-provider-resolution-1",
		"provider_revision_id": r.config.ProviderRevisionID,
		"image": map[string]any{
			"reference": r.config.RuntimeImageReference, "digest": r.config.RuntimeImageDigest,
			"architecture": r.config.RuntimeArchitecture,
		},
		"runtime_profile": "sandbox-runtime-browser-v1",
		"resources": map[string]any{
			"cpu_millis": 1000, "memory_bytes": 1073741824, "ephemeral_storage_bytes": 1073741824,
			"workspace_bytes": 268435456, "pids_limit": 256,
		},
		"required_capabilities": []any{
			map[string]any{"id": "sandbox.browser", "version": "1.0.0", "profile": "browser-v1"},
		},
		"network": map[string]any{
			"mode": "restricted", "policy_reference": "browser-egress-policy-1", "egress_gateway_required": true,
		},
		"workspace": map[string]any{
			"mode": "ephemeral", "base_revision_id": "e2e-browser-workspace-revision-1",
			"base_revision_digest": "sha256:" + strings.Repeat("e", 64), "base_workspace_head_version": 0,
			"commit_mode": "read_only", "mount_path": "/workspace",
		},
		"lease": map[string]any{
			"expires_at": time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339Nano), "max_extension_seconds": 3600,
		},
		"placement_constraints": map[string]any{"resource_class": "browser", "architecture": r.config.RuntimeArchitecture},
		"security": map[string]any{
			"privilege_level": "unprivileged", "root_filesystem": "read_only", "service_account_mode": "none",
			"allow_privilege_escalation": false, "host_namespace_access": false, "seccomp_profile": "runtime-default",
		},
		"sandbox_slot_key": "browser",
	}
	return r.a.prepare(http.MethodPost, "/v1/sandboxes", body, r.binding("create", browserCreateRef(), deadline))
}

func (r *runner) waitBrowserSandbox(ctx context.Context) error {
	operation, err := r.waitOperation(ctx, browserCreateRef())
	if err != nil || operation.Status != "succeeded" {
		return errors.Join(err, fmt.Errorf("Browser create operation = %#v", operation))
	}
	var status SandboxStatus
	if err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/sandboxes/"+BrowserSandboxID, "read_sandbox", browserCreateRef(), &status); err != nil {
		return err
	}
	if status.RuntimeProfile != "sandbox-runtime-browser-v1" || status.ObservedState != "ready" ||
		status.Generation != 1 || status.ObservedGeneration != 1 || status.TenantID != r.config.ControllerA.TenantID {
		return fmt.Errorf("Browser sandbox status = %#v", status)
	}
	return nil
}

func (r *runner) openBrowserSession(ctx context.Context) (BrowserSessionHandoff, error) {
	deadline := time.Now().UTC().Add(5 * time.Minute)
	expiresAt := time.Now().UTC().Add(4 * time.Minute)
	body := mutationEnvelope(browserOpenOperation, browserOpenAttempt, 2, "e2e-browser-session-idempotency-1", deadline)
	body["expected_generation"] = 1
	body["browser_session_id"] = browserSessionID
	body["capability_profile_id"] = "browser-v1"
	body["expires_at"] = expiresAt.Format(time.RFC3339Nano)
	prepared, err := r.a.prepare(http.MethodPost, "/v1/sandboxes/"+BrowserSandboxID+"/browser-sessions", body, r.binding("open_browser_session", browserOpenRef(), deadline))
	if err != nil {
		return BrowserSessionHandoff{}, err
	}
	if _, err := r.sendOperation(ctx, r.a, prepared, http.StatusAccepted); err != nil {
		return BrowserSessionHandoff{}, err
	}
	operation, err := r.waitOperation(ctx, browserOpenRef())
	if err != nil || operation.Status != "succeeded" {
		return BrowserSessionHandoff{}, errors.Join(err, fmt.Errorf("Browser session operation = %#v", operation))
	}
	return r.readBrowserHandoff(ctx)
}

func (r *runner) readBrowserHandoff(ctx context.Context) (BrowserSessionHandoff, error) {
	var handoff BrowserSessionHandoff
	if err := r.pollJSON(ctx, r.a, "/v1/operations/"+browserOpenOperation+"/browser-session", "read_browser_session", browserOpenRef(), &handoff); err != nil {
		return BrowserSessionHandoff{}, err
	}
	if handoff.Protocol != "websocket" || handoff.BrowserSessionID != browserSessionID ||
		!strings.HasPrefix(handoff.InternalEndpointReference, "ref:browser-session:") ||
		strings.Contains(handoff.InternalEndpointReference, "://") || handoff.ConnectionGeneration < 1 {
		return BrowserSessionHandoff{}, fmt.Errorf("Browser handoff is not opaque: %#v", handoff)
	}
	return handoff, nil
}

func (r *runner) readBrowserUsage(ctx context.Context, reconciliation string) error {
	var evidence UsageEvidence
	if err := r.readJSON(ctx, r.a, http.MethodGet, "/v1/operations/"+browserOpenOperation+"/usage-evidence", "read_usage_evidence", browserOpenRef(), &evidence); err != nil {
		return err
	}
	if evidence.OperationID != browserOpenOperation || evidence.ReconciliationStatus != reconciliation || len(evidence.Entries) != 1 ||
		evidence.Entries[0].Meter != "sandbox.browser_session_milliseconds" || evidence.Entries[0].Unit != "milliseconds" ||
		evidence.Entries[0].Quantity < 0 {
		return fmt.Errorf("Browser usage evidence = %#v", evidence)
	}
	if reconciliation == "complete" && evidence.Entries[0].Quantity == 0 {
		return fmt.Errorf("complete Browser usage duration is zero: %#v", evidence)
	}
	return nil
}

func (r *runner) verifyBrowserWrongCaller(ctx context.Context) error {
	prepared, err := r.wrong.prepare(http.MethodGet, "/v1/sandboxes/"+BrowserSandboxID, nil, r.binding("read_sandbox", browserCreateRef(), time.Now().UTC().Add(time.Minute)))
	if err != nil {
		return err
	}
	result, err := r.wrong.send(ctx, prepared)
	if err != nil {
		return err
	}
	if result.Status != http.StatusForbidden {
		return unexpectedStatus("wrong Browser mTLS caller", result, http.StatusForbidden)
	}
	return nil
}

func browserCreateRef() operationReference {
	return operationReference{
		SandboxID: BrowserSandboxID, OperationID: browserCreateOperation, AttemptID: browserCreateAttempt, FencingToken: 1,
	}
}

func browserOpenRef() operationReference {
	return operationReference{
		SandboxID: BrowserSandboxID, OperationID: browserOpenOperation, AttemptID: browserOpenAttempt, FencingToken: 2,
	}
}
