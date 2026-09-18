package productprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/product"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func (c *Client) ControlBrowserSlot(ctx context.Context, work product.ReconcileWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || work.ProviderRevisionID != c.revisionID || work.SandboxID == "" ||
		work.PreviousGeneration < 1 || work.SlotGeneration <= work.PreviousGeneration || work.ProviderGeneration < 1 ||
		work.FencingToken != work.SlotGeneration || work.Slot.Kind != product.BrowserSlotKind ||
		work.Slot.ProfileID != product.BrowserSlotProfile {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	profile, ok := c.profileForRuntime(work.Slot.ProfileID)
	if !ok {
		return product.ProviderOperationEvidence{}, product.ErrCapabilityUnsupported
	}
	snapshot, err := c.discover(ctx)
	if err != nil {
		return product.ProviderOperationEvidence{}, err
	}
	if !exactBrowserReady(snapshot, profile) {
		return product.ProviderOperationEvidence{ErrorCode: "capability_unsupported"}, product.ErrDispatchRejected
	}
	desired := providerv1.RequestedStateSuspended
	operation, contractID := "set_desired_state", "urn:shell-echo:sandbox-runtime:request:set-desired-state:v1"
	path := "/v1/sandboxes/" + url.PathEscape(work.SandboxID) + "/desired-state"
	deadline := c.clock.Now().UTC().Add(2 * time.Minute)
	var request any
	switch work.Action {
	case "suspend", "resume":
		if work.Action == "resume" {
			desired = providerv1.RequestedStateReady
		}
		request = &providerv1.DesiredStateRequest{MutationEnvelope: providerv1.MutationEnvelope{
			OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.FencingToken,
			IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
			ExpectedGeneration: work.ProviderGeneration, DesiredState: desired, Reason: "product_browser_" + work.Action}
	case "terminate", "replace":
		operation, contractID = "terminate", "urn:shell-echo:sandbox-runtime:request:terminate:v1"
		path = "/v1/sandboxes/" + url.PathEscape(work.SandboxID) + ":terminate"
		request = &providerv1.TerminateRequest{MutationEnvelope: providerv1.MutationEnvelope{
			OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.FencingToken,
			IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
			ExpectedGeneration: work.ProviderGeneration, Reason: "product_browser_" + work.Action, PreserveWorkspaceSnapshot: false}
	default:
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	return c.dispatchLifecycleMutation(ctx, profile, work.TenantID, work.OperationID, work.AttemptID,
		work.SandboxID, work.FencingToken, operation, contractID, path, deadline, request, lifecycleExpectedType(work.Action))
}

func (c *Client) terminateBrowserSession(ctx context.Context, work product.SessionControlWork) (product.ProviderOperationEvidence, error) {
	if work.FencingToken <= work.SlotGeneration || work.ProviderGeneration < 1 {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	profile, ok := c.profileForRuntime(work.RuntimeProfileID)
	if !ok {
		return product.ProviderOperationEvidence{}, product.ErrCapabilityUnsupported
	}
	snapshot, err := c.discover(ctx)
	if err != nil {
		return product.ProviderOperationEvidence{}, err
	}
	if !exactBrowserReady(snapshot, profile) {
		return product.ProviderOperationEvidence{ErrorCode: "capability_unsupported"}, product.ErrDispatchRejected
	}
	deadline := c.clock.Now().UTC().Add(2 * time.Minute)
	path := "/v1/sandboxes/" + url.PathEscape(work.SandboxID) + ":terminate"
	request := &providerv1.TerminateRequest{MutationEnvelope: providerv1.MutationEnvelope{
		OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.FencingToken,
		IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
		ExpectedGeneration: work.ProviderGeneration, Reason: work.Reason, PreserveWorkspaceSnapshot: false}
	return c.dispatchLifecycleMutation(ctx, profile, work.TenantID, work.OperationID, work.AttemptID, work.SandboxID,
		work.FencingToken, "terminate", "urn:shell-echo:sandbox-runtime:request:terminate:v1", path, deadline, request, providerv1.OperationTerminate)
}

func lifecycleExpectedType(action string) providerv1.OperationType {
	switch action {
	case "suspend":
		return providerv1.OperationSuspend
	case "resume":
		return providerv1.OperationResume
	default:
		return providerv1.OperationTerminate
	}
}

func (c *Client) dispatchLifecycleMutation(ctx context.Context, profile Profile, tenantID, operationID, attemptID,
	sandboxID string, fencingToken int64, operation, contractID, path string, deadline time.Time, request any,
	expected providerv1.OperationType) (product.ProviderOperationEvidence, error) {
	digest, err := mutationDigest(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	switch value := request.(type) {
	case *providerv1.DesiredStateRequest:
		value.RequestDigest = providerv1.SHA256Digest(digest)
	case *providerv1.TerminateRequest:
		value.RequestDigest = providerv1.SHA256Digest(digest)
	default:
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	body, err := json.Marshal(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	now := c.clock.Now().UTC()
	headers, err := c.signAdmission(now, admissionSigningInput{PolicyDigest: profile.PolicyDigest, TenantID: tenantID,
		WorkOrderID: operationID, Operation: operation, SandboxID: sandboxID, OperationID: operationID, AttemptID: attemptID,
		FencingToken: fencingToken, Deadline: deadline, RequestContractID: contractID,
		RequestDigestProfile: "rfc8785-request-excluding-request-digest-v1", RequestDigest: digest, Method: http.MethodPost, Path: path})
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrStoreUnavailable
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.origin.String()+path, bytes.NewReader(body))
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Authorization", "Bearer "+headers.Bearer)
	httpRequest.Header.Set("X-Sandbox-Runtime-Admission-Context", headers.Context)
	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID, RequestDigest: digest,
			State: "outcome_unknown", ErrorCode: "transport_unknown", OutcomeUnknown: true, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		var standard providerv1.StandardError
		_ = decodeBounded(response.Body, &standard)
		code := "provider_rejected"
		if standard.Code != "" {
			code = strings.ToLower(strings.ReplaceAll(standard.Code, "_", "-"))
		}
		retryable := response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID, RequestDigest: digest,
			State: "failed", ErrorCode: code, Retryable: retryable, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchRejected
	}
	var providerOperation providerv1.Operation
	if err := decodeBounded(response.Body, &providerOperation); err != nil || providerOperation.OperationID != operationID ||
		providerOperation.AttemptID != attemptID || providerOperation.SandboxID != sandboxID ||
		providerOperation.FencingToken != fencingToken || providerOperation.Type != expected {
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID, RequestDigest: digest,
			State: "outcome_unknown", ErrorCode: "invalid_provider_response", OutcomeUnknown: true, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	observed, err := time.Parse(time.RFC3339Nano, providerOperation.ObservedAt)
	if err != nil {
		observed = c.clock.Now().UTC()
	}
	evidence := product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID,
		ProviderOperationID: providerOperation.ProviderOperationID, RequestDigest: digest, State: string(providerOperation.Status), ObservedAt: observed}
	if providerOperation.Error != nil {
		evidence.ErrorCode = strings.ToLower(strings.ReplaceAll(providerOperation.Error.Code, "_", "-"))
		evidence.Retryable = providerOperation.Error.Retryable
		evidence.OutcomeUnknown = providerOperation.Error.Outcome == providerv1.OutcomeUnknownFailure
	}
	return evidence, nil
}
