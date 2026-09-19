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

// ControlDesktopSlot sends only Provider lifecycle mutations. Product slot
// generation remains the fencing authority while ProviderGeneration is the
// independently observed Provider sandbox generation.
func (c *Client) ControlDesktopSlot(ctx context.Context, work product.ReconcileWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || work.ProviderRevisionID != c.revisionID || work.SandboxID == "" ||
		work.PreviousGeneration < 1 || work.SlotGeneration <= work.PreviousGeneration || work.ProviderGeneration < 1 ||
		work.FencingToken != work.SlotGeneration || work.Slot.Kind != product.DesktopSlotKind ||
		work.Slot.ProfileID != product.DesktopSlotProfile || len(work.Slot.RequiredCapabilities) != 1 ||
		work.Slot.RequiredCapabilities[0] != (product.CapabilityRequirement{CapabilityID: product.DesktopCapabilityID,
			Version: product.DesktopCapabilityVersion, ProfileID: product.DesktopCapabilityProfile}) {
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
	if !exactDesktopReady(snapshot, profile) {
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
			ExpectedGeneration: work.ProviderGeneration, DesiredState: desired, Reason: "product_desktop_" + work.Action}
	case "terminate", "replace":
		operation, contractID = "terminate", "urn:shell-echo:sandbox-runtime:request:terminate:v1"
		path = "/v1/sandboxes/" + url.PathEscape(work.SandboxID) + ":terminate"
		request = &providerv1.TerminateRequest{MutationEnvelope: providerv1.MutationEnvelope{
			OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.FencingToken,
			IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
			ExpectedGeneration: work.ProviderGeneration, Reason: "product_desktop_" + work.Action, PreserveWorkspaceSnapshot: false}
	default:
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	return c.dispatchLifecycleMutation(ctx, profile, work.TenantID, work.OperationID, work.AttemptID,
		work.SandboxID, work.FencingToken, operation, contractID, path, deadline, request, lifecycleExpectedType(work.Action))
}

// ExecuteDesktopSessionControl dispatches the separate Desktop open/close
// family. It never sends end-user grants, media negotiation, input, clipboard,
// transfer content, credentials, or private runtime coordinates.
func (c *Client) ExecuteDesktopSessionControl(ctx context.Context, work product.SessionControlWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || (work.Action != "open" && work.Action != "close") || work.ProviderRevisionID != c.revisionID ||
		work.SandboxID == "" || work.SessionID == "" || work.SlotGeneration < 1 || work.ProviderGeneration < 1 ||
		work.RuntimeProfileID != product.DesktopSlotProfile || work.Kind != product.SessionKindDesktop ||
		work.ProtocolProfile != product.SessionProfileDesktop {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	if work.FencingToken < 1 {
		work.FencingToken = work.SlotGeneration
	}
	if work.FencingToken != work.SlotGeneration {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	if work.Action == "close" && (work.ConnectionGeneration < 1 || strings.TrimSpace(work.Reason) == "") {
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
	if !exactDesktopReady(snapshot, profile) {
		return product.ProviderOperationEvidence{ErrorCode: "capability_unsupported"}, product.ErrDispatchRejected
	}

	now := c.clock.Now().UTC()
	deadline := now.Add(2 * time.Minute)
	path := "/v1/sandboxes/" + url.PathEscape(work.SandboxID) + "/desktop-sessions"
	operation := "open_desktop_session"
	contractID := "urn:shell-echo:sandbox-runtime:request:open-desktop-session:v1"
	expectedType := providerv1.OperationOpenDesktopSession
	var request any
	if work.Action == "open" {
		if work.ExpiresAt.IsZero() || !work.ExpiresAt.After(now) {
			return product.ProviderOperationEvidence{}, product.ErrInvalid
		}
		if work.ExpiresAt.Before(deadline) {
			deadline = work.ExpiresAt
		}
		request = &providerv1.DesktopSessionOpenRequest{MutationEnvelope: providerv1.MutationEnvelope{
			OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.FencingToken,
			IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
			ExpectedGeneration: work.ProviderGeneration, DesktopSessionID: work.SessionID,
			CapabilityProfileID: product.DesktopCapabilityProfile, ExpiresAt: work.ExpiresAt.UTC().Format(time.RFC3339Nano)}
	} else {
		operation = "close_desktop_session"
		contractID = "urn:shell-echo:sandbox-runtime:request:close-desktop-session:v1"
		expectedType = providerv1.OperationCloseDesktopSession
		path += "/" + url.PathEscape(work.SessionID) + ":close"
		request = &providerv1.DesktopSessionCloseRequest{MutationEnvelope: providerv1.MutationEnvelope{
			OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.FencingToken,
			IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
			ExpectedGeneration: work.ProviderGeneration, DesktopSessionID: work.SessionID,
			ConnectionGeneration: work.ConnectionGeneration, Reason: work.Reason}
	}

	digest, err := mutationDigest(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	switch value := request.(type) {
	case *providerv1.DesktopSessionOpenRequest:
		value.RequestDigest = providerv1.SHA256Digest(digest)
	case *providerv1.DesktopSessionCloseRequest:
		value.RequestDigest = providerv1.SHA256Digest(digest)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	headers, err := c.signAdmission(now, admissionSigningInput{PolicyDigest: profile.PolicyDigest, TenantID: work.TenantID,
		WorkOrderID: work.OperationID, Operation: operation, SandboxID: work.SandboxID, OperationID: work.OperationID,
		AttemptID: work.AttemptID, FencingToken: work.FencingToken, Deadline: deadline, RequestContractID: contractID,
		RequestDigestProfile: "rfc8785-request-excluding-request-digest-v1", RequestDigest: digest,
		Method: http.MethodPost, Path: path})
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
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID,
			RequestDigest: digest, State: "outcome_unknown", ErrorCode: "transport_unknown", OutcomeUnknown: true,
			ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
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
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID,
			RequestDigest: digest, State: "failed", ErrorCode: code, Retryable: retryable,
			ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchRejected
	}
	var providerOperation providerv1.Operation
	if err := decodeBounded(response.Body, &providerOperation); err != nil || providerOperation.OperationID != work.OperationID ||
		providerOperation.AttemptID != work.AttemptID || providerOperation.SandboxID != work.SandboxID ||
		providerOperation.FencingToken != work.FencingToken || providerOperation.Type != expectedType {
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID,
			RequestDigest: digest, State: "outcome_unknown", ErrorCode: "invalid_provider_response", OutcomeUnknown: true,
			ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	observed, err := time.Parse(time.RFC3339Nano, providerOperation.ObservedAt)
	if err != nil {
		observed = c.clock.Now().UTC()
	}
	evidence := product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID,
		ProviderOperationID: providerOperation.ProviderOperationID, RequestDigest: digest,
		State: string(providerOperation.Status), ObservedAt: observed}
	if providerOperation.Error != nil {
		evidence.ErrorCode = strings.ToLower(strings.ReplaceAll(providerOperation.Error.Code, "_", "-"))
		evidence.Retryable = providerOperation.Error.Retryable
		evidence.OutcomeUnknown = providerOperation.Error.Outcome == providerv1.OutcomeUnknownFailure
	}
	return evidence, nil
}
