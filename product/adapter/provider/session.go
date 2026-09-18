package productprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/product"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

func (c *Client) AuthorizeSession(ctx context.Context, kind, protocolProfile string) error {
	if ctx == nil {
		return product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	capability, capabilityProfile := "sandbox.terminal", "terminal-v1"
	switch {
	case kind == product.SessionKindTerminal && protocolProfile == product.SessionProfileTerminal:
	case kind == product.SessionKindBrowserAutomation && protocolProfile == product.SessionProfileBrowserAutomation,
		kind == product.SessionKindBrowserLive && protocolProfile == product.SessionProfileBrowserLive:
		capability, capabilityProfile = product.BrowserCapabilityID, product.BrowserCapabilityProfile
	default:
		return product.ErrCapabilityUnsupported
	}
	snapshot, err := c.discover(ctx)
	if err != nil {
		return err
	}
	for _, profile := range c.profiles {
		if capability == product.BrowserCapabilityID && exactBrowserReady(snapshot, profile) {
			return nil
		}
		if capability == "sandbox.terminal" && providerCapabilityReady(snapshot, profile.RuntimeProfileID, capability, "1.0.0", capabilityProfile) &&
			providerCapabilityReady(snapshot, profile.RuntimeProfileID, "sandbox.terminal-control", "1.0.0", "terminal-control-v1") {
			return nil
		}
	}
	return product.ErrCapabilityUnsupported
}

func (c *Client) ExecuteBrowserSessionControl(ctx context.Context, work product.SessionControlWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || work.Action != "open" || work.ProviderRevisionID != c.revisionID || work.SandboxID == "" ||
		work.SessionID == "" || work.SlotGeneration < 1 || work.RuntimeProfileID != product.BrowserSlotProfile ||
		!((work.Kind == product.SessionKindBrowserAutomation && work.ProtocolProfile == product.SessionProfileBrowserAutomation) ||
			(work.Kind == product.SessionKindBrowserLive && work.ProtocolProfile == product.SessionProfileBrowserLive)) {
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
	if work.ExpiresAt.Before(deadline) {
		deadline = work.ExpiresAt
	}
	request := &providerv1.BrowserSessionOpenRequest{
		MutationEnvelope: providerv1.MutationEnvelope{OperationID: work.OperationID, AttemptID: work.AttemptID,
			FencingToken: work.SlotGeneration, IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
		ExpectedGeneration: work.SlotGeneration, BrowserSessionID: work.SessionID,
		CapabilityProfileID: product.BrowserCapabilityProfile, ExpiresAt: work.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	digest, err := mutationDigest(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	request.RequestDigest = providerv1.SHA256Digest(digest)
	body, err := json.Marshal(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	now := c.clock.Now().UTC()
	path := "/v1/sandboxes/" + url.PathEscape(work.SandboxID) + "/browser-sessions"
	headers, err := c.signAdmission(now, admissionSigningInput{PolicyDigest: profile.PolicyDigest, TenantID: work.TenantID,
		WorkOrderID: work.OperationID, Operation: "open_browser_session", SandboxID: work.SandboxID,
		OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.SlotGeneration, Deadline: deadline,
		RequestContractID:    "urn:shell-echo:sandbox-runtime:request:open-browser-session:v1",
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
			RequestDigest: digest, State: "failed", ErrorCode: code, Retryable: retryable, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchRejected
	}
	var providerOperation providerv1.Operation
	if err := decodeBounded(response.Body, &providerOperation); err != nil || providerOperation.OperationID != work.OperationID ||
		providerOperation.AttemptID != work.AttemptID || providerOperation.SandboxID != work.SandboxID ||
		providerOperation.FencingToken != work.SlotGeneration || providerOperation.Type != providerv1.OperationOpenBrowserSession {
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID,
			RequestDigest: digest, State: "outcome_unknown", ErrorCode: "invalid_provider_response", OutcomeUnknown: true,
			ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	observed, err := time.Parse(time.RFC3339Nano, providerOperation.ObservedAt)
	if err != nil {
		observed = c.clock.Now().UTC()
	}
	return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID,
		ProviderOperationID: providerOperation.ProviderOperationID, RequestDigest: digest,
		State: string(providerOperation.Status), ObservedAt: observed}, nil
}

func (c *Client) ExecuteSessionControl(ctx context.Context, work product.SessionControlWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || work.ProviderRevisionID != c.revisionID || work.SandboxID == "" || work.SessionID == "" || work.SlotGeneration < 1 {
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
	capability, capabilityProfile, operation, contractID, path := "sandbox.terminal", "terminal-v1", "open_runtime_session", "urn:shell-echo:sandbox-runtime:request:open-runtime-session:v1", "/v1/sandboxes/"+url.PathEscape(work.SandboxID)+"/runtime-sessions"
	var request any
	deadline := c.clock.Now().UTC().Add(2 * time.Minute)
	if work.ExpiresAt.Before(deadline) {
		deadline = work.ExpiresAt
	}
	if work.Action == "open" {
		request = &providerv1.RuntimeSessionOpenRequest{MutationEnvelope: providerv1.MutationEnvelope{OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.SlotGeneration, IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)}, ExpectedGeneration: work.SlotGeneration, RuntimeSessionID: work.SessionID, RuntimeType: providerv1.TerminalRuntimeTerminal, CapabilityProfileID: capabilityProfile, ExpiresAt: work.ExpiresAt.UTC().Format(time.RFC3339Nano)}
	} else if work.Action == "close" {
		capability, capabilityProfile, operation, contractID = "sandbox.terminal-control", "terminal-control-v1", "close_runtime_session", "urn:shell-echo:sandbox-runtime:request:close-runtime-session:v1"
		path += "/" + url.PathEscape(work.SessionID) + ":close"
		request = &providerv1.RuntimeSessionCloseRequest{MutationEnvelope: providerv1.MutationEnvelope{OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.SlotGeneration, IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)}, ExpectedGeneration: work.SlotGeneration, RuntimeSessionID: work.SessionID, ConnectionGeneration: work.ConnectionGeneration, Reason: work.Reason}
	} else {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	if !providerCapabilityReady(snapshot, profile.RuntimeProfileID, capability, "1.0.0", capabilityProfile) {
		return product.ProviderOperationEvidence{ErrorCode: "capability_unsupported"}, product.ErrDispatchRejected
	}
	digest, err := mutationDigest(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	switch value := request.(type) {
	case *providerv1.RuntimeSessionOpenRequest:
		value.RequestDigest = providerv1.SHA256Digest(digest)
	case *providerv1.RuntimeSessionCloseRequest:
		value.RequestDigest = providerv1.SHA256Digest(digest)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	now := c.clock.Now().UTC()
	headers, err := c.signAdmission(now, admissionSigningInput{PolicyDigest: profile.PolicyDigest, TenantID: work.TenantID, WorkOrderID: work.OperationID, Operation: operation, SandboxID: work.SandboxID, OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.SlotGeneration, Deadline: deadline, RequestContractID: contractID, RequestDigestProfile: "rfc8785-request-excluding-request-digest-v1", RequestDigest: digest, Method: http.MethodPost, Path: path})
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
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID, RequestDigest: digest, State: "outcome_unknown", ErrorCode: "transport_unknown", OutcomeUnknown: true, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		var standard providerv1.StandardError
		_ = decodeBounded(response.Body, &standard)
		retryable := response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable
		code := "provider_rejected"
		if standard.Code != "" {
			code = strings.ToLower(strings.ReplaceAll(standard.Code, "_", "-"))
		}
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID, RequestDigest: digest, State: "failed", ErrorCode: code, Retryable: retryable, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchRejected
	}
	var providerOperation providerv1.Operation
	if err := decodeBounded(response.Body, &providerOperation); err != nil || providerOperation.OperationID != work.OperationID || providerOperation.AttemptID != work.AttemptID || providerOperation.SandboxID != work.SandboxID || providerOperation.FencingToken != work.SlotGeneration {
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID, RequestDigest: digest, State: "outcome_unknown", ErrorCode: "invalid_provider_response", OutcomeUnknown: true, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	observed, err := time.Parse(time.RFC3339Nano, providerOperation.ObservedAt)
	if err != nil {
		observed = c.clock.Now().UTC()
	}
	return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID, ProviderOperationID: providerOperation.ProviderOperationID, RequestDigest: digest, State: string(providerOperation.Status), ObservedAt: observed}, nil
}

func (c *Client) profileForRuntime(runtimeID string) (Profile, bool) {
	for _, profile := range c.profiles {
		if profile.RuntimeProfileID == runtimeID {
			return profile, true
		}
	}
	return Profile{}, false
}

func (c *Client) readRuntimeSessionHandoff(ctx context.Context, work product.ProviderObservationWork, profile Profile) (providerv1.RuntimeSessionHandoff, error) {
	descriptor := map[string]any{"operation": "read_runtime_session", "sandbox_id": work.SandboxID, "operation_id": work.OperationID, "attempt_id": work.AttemptID, "fencing_token": work.SlotGeneration}
	digest, err := canonicalFullDigest(descriptor)
	if err != nil {
		return providerv1.RuntimeSessionHandoff{}, product.ErrInvalid
	}
	now := c.clock.Now().UTC()
	deadline := now.Add(time.Minute)
	path := "/v1/operations/" + url.PathEscape(work.OperationID) + "/runtime-session"
	headers, err := c.signAdmission(now, admissionSigningInput{PolicyDigest: profile.PolicyDigest, TenantID: work.TenantID, WorkOrderID: work.OperationID,
		Operation: "read_runtime_session", SandboxID: work.SandboxID, OperationID: work.OperationID, AttemptID: work.AttemptID,
		FencingToken: work.SlotGeneration, Deadline: deadline, RequestContractID: "urn:shell-echo:sandbox-runtime:descriptor:runtime-session:v1",
		RequestDigestProfile: "rfc8785-full-document-v1", RequestDigest: digest, Method: http.MethodGet, Path: path})
	if err != nil {
		return providerv1.RuntimeSessionHandoff{}, product.ErrStoreUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin.String()+path, nil)
	if err != nil {
		return providerv1.RuntimeSessionHandoff{}, product.ErrInvalid
	}
	request.Header.Set("Authorization", "Bearer "+headers.Bearer)
	request.Header.Set("X-Sandbox-Runtime-Admission-Context", headers.Context)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return providerv1.RuntimeSessionHandoff{}, product.ErrStoreUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return providerv1.RuntimeSessionHandoff{}, product.ErrStoreUnavailable
	}
	var handoff providerv1.RuntimeSessionHandoff
	if err := decodeBounded(response.Body, &handoff); err != nil || handoff.OperationID != work.OperationID || handoff.AttemptID != work.AttemptID ||
		handoff.SandboxID != work.SandboxID || handoff.RuntimeSessionID != work.SessionID || handoff.FencingToken != work.SlotGeneration ||
		handoff.ConnectionGeneration < 1 || handoff.InternalEndpointReference == "" {
		return providerv1.RuntimeSessionHandoff{}, product.ErrStoreUnavailable
	}
	return handoff, nil
}

func (c *Client) readBrowserSessionHandoff(ctx context.Context, work product.ProviderObservationWork, profile Profile) (providerv1.BrowserSessionHandoff, error) {
	descriptor := map[string]any{"operation": "read_browser_session", "sandbox_id": work.SandboxID,
		"operation_id": work.OperationID, "attempt_id": work.AttemptID, "fencing_token": work.SlotGeneration}
	digest, err := canonicalFullDigest(descriptor)
	if err != nil {
		return providerv1.BrowserSessionHandoff{}, product.ErrInvalid
	}
	now := c.clock.Now().UTC()
	deadline := now.Add(time.Minute)
	path := "/v1/operations/" + url.PathEscape(work.OperationID) + "/browser-session"
	headers, err := c.signAdmission(now, admissionSigningInput{PolicyDigest: profile.PolicyDigest, TenantID: work.TenantID,
		WorkOrderID: work.OperationID, Operation: "read_browser_session", SandboxID: work.SandboxID,
		OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.SlotGeneration, Deadline: deadline,
		RequestContractID:    "urn:shell-echo:sandbox-runtime:descriptor:browser-session:v1",
		RequestDigestProfile: "rfc8785-full-document-v1", RequestDigest: digest, Method: http.MethodGet, Path: path})
	if err != nil {
		return providerv1.BrowserSessionHandoff{}, product.ErrStoreUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin.String()+path, nil)
	if err != nil {
		return providerv1.BrowserSessionHandoff{}, product.ErrInvalid
	}
	request.Header.Set("Authorization", "Bearer "+headers.Bearer)
	request.Header.Set("X-Sandbox-Runtime-Admission-Context", headers.Context)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return providerv1.BrowserSessionHandoff{}, product.ErrStoreUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return providerv1.BrowserSessionHandoff{}, product.ErrStoreUnavailable
	}
	var handoff providerv1.BrowserSessionHandoff
	if err := decodeBounded(response.Body, &handoff); err != nil || handoff.OperationID != work.OperationID ||
		handoff.AttemptID != work.AttemptID || handoff.SandboxID != work.SandboxID || handoff.BrowserSessionID != work.SessionID ||
		handoff.FencingToken != work.SlotGeneration || handoff.CapabilityProfileID != product.BrowserCapabilityProfile ||
		handoff.Protocol != providerv1.BrowserProtocolWebSocket || handoff.ConnectionGeneration < 1 ||
		!browserEndpointReference(handoff.InternalEndpointReference) {
		return providerv1.BrowserSessionHandoff{}, product.ErrStoreUnavailable
	}
	return handoff, nil
}

func browserEndpointReference(value string) bool {
	const prefix = "ref:browser-session:"
	if !strings.HasPrefix(value, prefix) || len(value) > len(prefix)+200 {
		return false
	}
	suffix := strings.TrimPrefix(value, prefix)
	if len(suffix) < 1 || !asciiAlphaNumeric(suffix[0]) {
		return false
	}
	for index := 1; index < len(suffix); index++ {
		character := suffix[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func providerCapabilityReady(snapshot providerv1.Capabilities, runtimeID, capabilityID, version, profileID string) bool {
	profileMapped := false
	for _, runtimeProfile := range snapshot.RuntimeProfiles {
		if runtimeProfile.ID == runtimeID && contains(runtimeProfile.CapabilityProfileIDs, profileID) {
			profileMapped = true
		}
	}
	if !profileMapped {
		return false
	}
	for _, capability := range snapshot.Capabilities {
		if string(capability.ID) == capabilityID && contains(capability.Versions, version) && contains(capability.Profiles, profileID) {
			return true
		}
	}
	return false
}
func mutationDigest(request any) (string, error) {
	document, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	var members map[string]any
	if err := json.Unmarshal(document, &members); err != nil {
		return "", err
	}
	delete(members, "request_digest")
	return canonicalFullDigest(members)
}
func canonicalFullDigest(value any) (string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
