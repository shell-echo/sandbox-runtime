package productprovider

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/product"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const (
	LockedProviderRevision = "98995384c60a924f25ca58d3b7e561207bfa5be8"
	LockedProviderTree     = "0a627baed11c8a6ddbe8a24bbc1869e4f85edc16"
	maxProviderBody        = 1 << 20
)

type Clock interface{ Now() time.Time }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type Profile struct {
	ProductProfileID       string
	RuntimeProfileID       string
	ImageReference         string
	ImageDigest            string
	Architecture           providerv1.Architecture
	CPUMillis              int64
	MemoryBytes            int64
	EphemeralBytes         int64
	PIDsLimit              int64
	BaseRevisionID         string
	BaseRevisionDigest     string
	PolicyDigest           string
	NetworkPolicyReference string
}

type Authority struct {
	Issuer     string
	Subject    string
	Audience   string
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

type Config struct {
	Origin               string
	HTTPClient           *http.Client
	ExpectedRevisionID   string
	ExpectedTree         string
	ProviderResolutionID string
	Profiles             []Profile
	Authority            Authority
	Clock                Clock
	AllowHTTPForTests    bool
}

type Client struct {
	origin       *url.URL
	httpClient   *http.Client
	revisionID   string
	tree         string
	resolutionID string
	profiles     map[string]Profile
	authority    Authority
	clock        Clock
}

func New(config Config) (*Client, error) {
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Host == "" || origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" ||
		(origin.Scheme != "https" && !(config.AllowHTTPForTests && origin.Scheme == "http")) || config.HTTPClient == nil ||
		config.ExpectedRevisionID != LockedProviderRevision || config.ExpectedTree != LockedProviderTree ||
		config.ProviderResolutionID == "" || config.Authority.Issuer == "" || config.Authority.Subject == "" ||
		config.Authority.Audience == "" || config.Authority.KeyID == "" || len(config.Authority.PrivateKey) != ed25519.PrivateKeySize {
		return nil, product.ErrInvalid
	}
	profiles := make(map[string]Profile, len(config.Profiles))
	for _, profile := range config.Profiles {
		if profile.ProductProfileID == "" || profile.RuntimeProfileID == "" || profile.ImageReference == "" ||
			!strings.HasPrefix(profile.ImageDigest, "sha256:") || !strings.HasPrefix(profile.BaseRevisionDigest, "sha256:") ||
			!strings.HasPrefix(profile.PolicyDigest, "sha256:") || profile.CPUMillis < 1 || profile.MemoryBytes < 1 ||
			profile.EphemeralBytes < 1 || profile.PIDsLimit < 1 {
			return nil, product.ErrInvalid
		}
		if profile.RuntimeProfileID == product.BrowserSlotProfile && !providerIdentifier(profile.NetworkPolicyReference) {
			return nil, product.ErrInvalid
		}
		if _, exists := profiles[profile.ProductProfileID]; exists {
			return nil, product.ErrInvalid
		}
		profiles[profile.ProductProfileID] = profile
	}
	if len(profiles) == 0 {
		return nil, product.ErrInvalid
	}
	clientCopy := *config.HTTPClient
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	clock := config.Clock
	if clock == nil {
		clock = systemClock{}
	}
	return &Client{origin: origin, httpClient: &clientCopy, revisionID: config.ExpectedRevisionID, tree: config.ExpectedTree,
		resolutionID: config.ProviderResolutionID, profiles: profiles, authority: config.Authority, clock: clock}, nil
}

func (c *Client) AuthorizePrimarySlot(ctx context.Context, slot product.SlotSpec) error {
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	profile, ok := c.profiles[slot.ProfileID]
	if !ok {
		return product.ErrCapabilityUnsupported
	}
	snapshot, err := c.discover(ctx)
	if err != nil {
		return err
	}
	if !profileReady(snapshot, profile, slot.RequiredCapabilities) {
		return product.ErrCapabilityUnsupported
	}
	return nil
}

func (c *Client) AuthorizeSlot(ctx context.Context, slot product.SlotSpec) error {
	if ctx == nil {
		return product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if slot.SlotKey == product.PrimarySlotKey || slot.Kind != "browser" || slot.ProfileID != product.BrowserSlotProfile ||
		len(slot.RequiredCapabilities) != 1 || slot.RequiredCapabilities[0] != (product.CapabilityRequirement{
		CapabilityID: product.BrowserCapabilityID, Version: product.BrowserCapabilityVersion, ProfileID: product.BrowserCapabilityProfile,
	}) {
		return product.ErrCapabilityUnsupported
	}
	profile, ok := c.profiles[slot.ProfileID]
	if !ok || profile.RuntimeProfileID != product.BrowserSlotProfile || !providerIdentifier(profile.NetworkPolicyReference) {
		return product.ErrCapabilityUnsupported
	}
	snapshot, err := c.discover(ctx)
	if err != nil {
		return err
	}
	if !exactBrowserReady(snapshot, profile) {
		return product.ErrCapabilityUnsupported
	}
	return nil
}

func (c *Client) discover(ctx context.Context) (providerv1.Capabilities, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin.String()+"/v1/capabilities", nil)
	if err != nil {
		return providerv1.Capabilities{}, product.ErrStoreUnavailable
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return providerv1.Capabilities{}, errors.Join(product.ErrStoreUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProviderBody))
		return providerv1.Capabilities{}, product.ErrStoreUnavailable
	}
	var snapshot providerv1.Capabilities
	if err := decodeBounded(resp.Body, &snapshot); err != nil || snapshot.ProviderRevisionID != c.revisionID || snapshot.APIVersion != providerv1.APIVersionV1 {
		return providerv1.Capabilities{}, product.ErrStoreUnavailable
	}
	return snapshot, nil
}

func exactBrowserReady(snapshot providerv1.Capabilities, profile Profile) bool {
	if profile.RuntimeProfileID != product.BrowserSlotProfile || len(snapshot.Capabilities) != 1 || len(snapshot.RuntimeProfiles) != 1 {
		return false
	}
	capability := snapshot.Capabilities[0]
	runtimeProfile := snapshot.RuntimeProfiles[0]
	return capability.ID == providerv1.CapabilityBrowser && len(capability.Versions) == 1 &&
		capability.Versions[0] == product.BrowserCapabilityVersion && len(capability.Profiles) == 1 &&
		capability.Profiles[0] == product.BrowserCapabilityProfile && runtimeProfile.ID == product.BrowserSlotProfile &&
		runtimeProfile.IsolationClass == providerv1.IsolationContainer && len(runtimeProfile.Architecture) == 1 &&
		len(runtimeProfile.CapabilityProfileIDs) == 1 && runtimeProfile.CapabilityProfileIDs[0] == product.BrowserCapabilityProfile &&
		containsArchitecture(runtimeProfile.Architecture, profile.Architecture)
}

func containsArchitecture(values []providerv1.Architecture, wanted providerv1.Architecture) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func profileReady(snapshot providerv1.Capabilities, profile Profile, required []product.CapabilityRequirement) bool {
	foundRuntime := false
	profileIDs := map[string]bool{}
	for _, runtimeProfile := range snapshot.RuntimeProfiles {
		if runtimeProfile.ID == profile.RuntimeProfileID {
			foundRuntime = true
			for _, id := range runtimeProfile.CapabilityProfileIDs {
				profileIDs[id] = true
			}
		}
	}
	if !foundRuntime {
		return false
	}
	for _, need := range required {
		found := false
		for _, capability := range snapshot.Capabilities {
			if string(capability.ID) != need.CapabilityID || !contains(capability.Versions, need.Version) || !contains(capability.Profiles, need.ProfileID) {
				continue
			}
			if profileIDs[need.ProfileID] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func (c *Client) ProvisionPrimarySlot(ctx context.Context, work product.ReconcileWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || work.SlotKey != product.PrimarySlotKey || work.SlotGeneration < 1 {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	if err := c.AuthorizePrimarySlot(ctx, work.Slot); err != nil {
		return product.ProviderOperationEvidence{ErrorCode: "capability_unsupported"}, product.ErrDispatchRejected
	}
	return c.provisionSlot(ctx, work, false)
}

func (c *Client) ProvisionBrowserSlot(ctx context.Context, work product.ReconcileWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || work.SlotKey == product.PrimarySlotKey || work.SlotGeneration < 1 || work.Slot.SlotKey != work.SlotKey {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	if err := c.AuthorizeSlot(ctx, work.Slot); err != nil {
		return product.ProviderOperationEvidence{ErrorCode: "capability_unsupported"}, product.ErrDispatchRejected
	}
	return c.provisionSlot(ctx, work, true)
}

func (c *Client) provisionSlot(ctx context.Context, work product.ReconcileWork, browser bool) (product.ProviderOperationEvidence, error) {
	profile := c.profiles[work.Slot.ProfileID]
	now := c.clock.Now().UTC()
	deadline := now.Add(2 * time.Minute)
	if work.WorkspaceExpiry.Before(deadline) {
		deadline = work.WorkspaceExpiry
	}
	sandboxID := deterministicSandboxID(work)
	network := providerv1.NetworkPolicy{Mode: providerv1.NetworkNone}
	var placement *providerv1.PlacementConstraints
	if browser {
		required := true
		network = providerv1.NetworkPolicy{Mode: providerv1.NetworkRestricted, PolicyReference: profile.NetworkPolicyReference, EgressGatewayRequired: &required}
		placement = &providerv1.PlacementConstraints{ResourceClass: providerv1.ResourceBrowser, Architecture: profile.Architecture}
	}
	request := providerv1.CreateRequest{
		MutationEnvelope: providerv1.MutationEnvelope{OperationID: work.OperationID, AttemptID: work.AttemptID,
			FencingToken: work.SlotGeneration, IdempotencyKey: "product-" + work.AttemptID, DeadlineAt: deadline.Format(time.RFC3339Nano)},
		ProtocolVersion: providerv1.APIVersionV1,
		Spec: providerv1.SandboxSpec{
			SandboxID: sandboxID, TenantID: work.TenantID, WorkOrderID: work.OperationID, WorkspaceID: work.WorkspaceID,
			BranchID: "main", ProviderResolutionID: c.resolutionID, ProviderRevisionID: c.revisionID,
			Image:                providerv1.SandboxImage{Reference: profile.ImageReference, Digest: providerv1.SHA256Digest(profile.ImageDigest), Architecture: profile.Architecture},
			RuntimeProfile:       profile.RuntimeProfileID,
			Resources:            providerv1.SandboxResources{CPUMillis: profile.CPUMillis, MemoryBytes: profile.MemoryBytes, EphemeralStorageBytes: profile.EphemeralBytes, PIDsLimit: profile.PIDsLimit},
			RequiredCapabilities: providerRequirements(work.Slot.RequiredCapabilities),
			Network:              network,
			Workspace: providerv1.WorkspacePolicy{Mode: providerv1.WorkspaceEphemeral, BaseRevisionID: profile.BaseRevisionID,
				BaseRevisionDigest: providerv1.SHA256Digest(profile.BaseRevisionDigest), BaseWorkspaceHeadVersion: 0,
				CommitMode: providerv1.WorkspaceReadOnly, MountPath: providerv1.WorkspaceMount},
			Lease:                providerv1.LeasePolicy{ExpiresAt: work.WorkspaceExpiry.UTC().Format(time.RFC3339Nano), MaxExtensionSeconds: 3600},
			PlacementConstraints: placement,
			Security: providerv1.SecurityPolicy{PrivilegeLevel: providerv1.PrivilegeUnprivileged, RootFilesystem: providerv1.RootFilesystemReadOnly,
				ServiceAccountMode: providerv1.ServiceAccountNone, SeccompProfile: providerv1.SeccompRuntimeDefault},
			SandboxSlotKey: providerv1.SandboxSlotKey(work.SlotKey),
		}, TraceContext: json.RawMessage(`{}`),
	}
	digest, err := requestDigest(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	request.RequestDigest = providerv1.SHA256Digest(digest)
	body, err := json.Marshal(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	path := "/v1/sandboxes"
	headers, err := c.sign(now, profile.PolicyDigest, work, sandboxID, deadline, path, digest)
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
	resp, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID, RequestDigest: digest,
			State: "outcome_unknown", ErrorCode: "transport_unknown", OutcomeUnknown: true, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		var standard providerv1.StandardError
		_ = decodeBounded(resp.Body, &standard)
		code := "provider_rejected"
		if standard.Code != "" {
			code = strings.ToLower(strings.ReplaceAll(standard.Code, "_", "-"))
		}
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID, RequestDigest: digest,
			State: "failed", ErrorCode: code, Retryable: retryable, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchRejected
	}
	var operation providerv1.Operation
	if err := decodeBounded(resp.Body, &operation); err != nil || operation.OperationID != work.OperationID || operation.AttemptID != work.AttemptID ||
		operation.SandboxID != sandboxID || operation.FencingToken != work.SlotGeneration || operation.Type != providerv1.OperationCreate {
		return product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID, RequestDigest: digest,
			State: "outcome_unknown", ErrorCode: "invalid_provider_response", OutcomeUnknown: true, ObservedAt: c.clock.Now().UTC()}, product.ErrDispatchOutcomeUnknown
	}
	observed, err := time.Parse(time.RFC3339Nano, operation.ObservedAt)
	if err != nil {
		observed = c.clock.Now().UTC()
	}
	evidence := product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: sandboxID,
		ProviderOperationID: operation.ProviderOperationID, RequestDigest: digest, State: string(operation.Status), ObservedAt: observed}
	if operation.Error != nil {
		evidence.ErrorCode = strings.ToLower(strings.ReplaceAll(operation.Error.Code, "_", "-"))
		evidence.Retryable = operation.Error.Retryable
		evidence.OutcomeUnknown = operation.Error.Outcome == providerv1.OutcomeUnknownFailure
	}
	return evidence, nil
}

func providerIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 200 || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func (c *Client) ObserveOperation(ctx context.Context, work product.ProviderObservationWork) (product.ProviderOperationEvidence, error) {
	if ctx == nil || work.ProviderRevisionID != c.revisionID || work.SandboxID == "" || work.OperationID == "" || work.AttemptID == "" || work.SlotGeneration < 1 {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	if work.FencingToken < 1 {
		work.FencingToken = work.SlotGeneration
	}
	var profile Profile
	found := false
	for _, candidate := range c.profiles {
		if candidate.RuntimeProfileID == work.RuntimeProfileID {
			profile, found = candidate, true
			break
		}
	}
	if !found {
		return product.ProviderOperationEvidence{}, product.ErrCapabilityUnsupported
	}
	descriptor := map[string]any{"operation": "read_operation", "sandbox_id": work.SandboxID, "operation_id": work.OperationID,
		"attempt_id": work.AttemptID, "fencing_token": work.FencingToken}
	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	canonical, err := jcs.Transform(descriptorJSON)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	digestBytes := sha256.Sum256(canonical)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	now := c.clock.Now().UTC()
	deadline := now.Add(time.Minute)
	path := "/v1/operations/" + url.PathEscape(work.OperationID)
	headers, err := c.signAdmission(now, admissionSigningInput{PolicyDigest: profile.PolicyDigest, TenantID: work.TenantID,
		WorkOrderID: work.OperationID, Operation: "read_operation", SandboxID: work.SandboxID, OperationID: work.OperationID,
		AttemptID: work.AttemptID, FencingToken: work.FencingToken, Deadline: deadline,
		RequestContractID: "urn:shell-echo:sandbox-runtime:descriptor:operation:v1", RequestDigestProfile: "rfc8785-full-document-v1",
		RequestDigest: digest, Method: http.MethodGet, Path: path})
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrStoreUnavailable
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin.String()+path, nil)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrInvalid
	}
	request.Header.Set("Authorization", "Bearer "+headers.Bearer)
	request.Header.Set("X-Sandbox-Runtime-Admission-Context", headers.Context)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return product.ProviderOperationEvidence{}, errors.Join(product.ErrStoreUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProviderBody))
		return product.ProviderOperationEvidence{}, product.ErrStoreUnavailable
	}
	var operation providerv1.Operation
	if err := decodeBounded(response.Body, &operation); err != nil || operation.OperationID != work.OperationID || operation.AttemptID != work.AttemptID ||
		operation.FencingToken != work.FencingToken || operation.SandboxID != work.SandboxID || operation.Type != expectedProviderOperationType(work) {
		return product.ProviderOperationEvidence{}, product.ErrStoreUnavailable
	}
	observed, err := time.Parse(time.RFC3339Nano, operation.ObservedAt)
	if err != nil {
		return product.ProviderOperationEvidence{}, product.ErrStoreUnavailable
	}
	evidence := product.ProviderOperationEvidence{ProviderRevisionID: c.revisionID, SandboxID: work.SandboxID,
		ProviderOperationID: operation.ProviderOperationID, State: string(operation.Status), ObservedAt: observed}
	if operation.Error != nil {
		evidence.ErrorCode = strings.ToLower(strings.ReplaceAll(operation.Error.Code, "_", "-"))
		evidence.Retryable = operation.Error.Retryable
		evidence.OutcomeUnknown = operation.Error.Outcome == providerv1.OutcomeUnknownFailure
	}
	if evidence.State == "succeeded" && work.SessionID != "" && work.OperationType == "create_session" {
		var expiresAt string
		if work.SessionKind == product.SessionKindBrowserAutomation || work.SessionKind == product.SessionKindBrowserLive {
			handoff, handoffErr := c.readBrowserSessionHandoff(ctx, work, profile)
			if handoffErr != nil {
				return product.ProviderOperationEvidence{}, handoffErr
			}
			evidence.HandoffReference = handoff.InternalEndpointReference
			evidence.ConnectionGeneration = handoff.ConnectionGeneration
			expiresAt = handoff.ExpiresAt
		} else {
			handoff, handoffErr := c.readRuntimeSessionHandoff(ctx, work, profile)
			if handoffErr != nil {
				return product.ProviderOperationEvidence{}, handoffErr
			}
			evidence.HandoffReference = handoff.InternalEndpointReference
			evidence.ConnectionGeneration = handoff.ConnectionGeneration
			expiresAt = handoff.ExpiresAt
		}
		evidence.HandoffExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
		if err != nil || !evidence.HandoffExpiresAt.After(now) || work.SessionExpiresAt.IsZero() || evidence.HandoffExpiresAt.After(work.SessionExpiresAt) {
			return product.ProviderOperationEvidence{}, product.ErrStoreUnavailable
		}
	}
	return evidence, nil
}

func expectedProviderOperationType(work product.ProviderObservationWork) providerv1.OperationType {
	switch work.ProviderAction {
	case "create":
		return providerv1.OperationCreate
	case "suspend":
		return providerv1.OperationSuspend
	case "resume":
		return providerv1.OperationResume
	case "terminate", "terminate_browser_session":
		return providerv1.OperationTerminate
	case "open_runtime_session":
		return providerv1.OperationOpenRuntimeSession
	case "close_runtime_session":
		return providerv1.OperationCloseRuntimeSession
	case "open_browser_session":
		return providerv1.OperationOpenBrowserSession
	}
	switch {
	case work.OperationType == "create_session" && (work.SessionKind == product.SessionKindBrowserAutomation || work.SessionKind == product.SessionKindBrowserLive):
		return providerv1.OperationOpenBrowserSession
	case work.OperationType == "create_session":
		return providerv1.OperationOpenRuntimeSession
	case work.OperationType == "close_session":
		return providerv1.OperationCloseRuntimeSession
	default:
		return providerv1.OperationCreate
	}
}

func providerRequirements(input []product.CapabilityRequirement) []providerv1.CapabilityRequirement {
	result := make([]providerv1.CapabilityRequirement, 0, len(input))
	for _, value := range input {
		result = append(result, providerv1.CapabilityRequirement{ID: value.CapabilityID, Version: value.Version, Profile: value.ProfileID})
	}
	return result
}

func deterministicSandboxID(work product.ReconcileWork) string {
	sum := sha256.Sum256([]byte(work.TenantID + "\x00" + work.WorkspaceID + "\x00" + work.SlotKey + fmt.Sprint("\x00", work.SlotGeneration)))
	return "psb-" + hex.EncodeToString(sum[:16])
}

func requestDigest(request providerv1.CreateRequest) (string, error) {
	request.RequestDigest = ""
	document, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	var members map[string]any
	if err := json.Unmarshal(document, &members); err != nil {
		return "", err
	}
	delete(members, "request_digest")
	without, err := json.Marshal(members)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(without)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

type signedHeaders struct{ Bearer, Context string }

type admissionTarget struct {
	Method          string   `json:"method"`
	Path            string   `json:"path"`
	NormalizedQuery []string `json:"normalized_query"`
}
type admissionContext struct {
	ContextContractID        string          `json:"context_contract_id"`
	ContextDigestProfile     string          `json:"context_digest_profile"`
	ContextDigest            string          `json:"context_digest"`
	ControllerSubject        string          `json:"controller_subject"`
	ProviderRevisionID       string          `json:"provider_revision_id"`
	ProviderInstanceAudience string          `json:"provider_instance_audience"`
	TenantID                 string          `json:"tenant_id"`
	WorkOrderID              string          `json:"work_order_id"`
	PolicyDigest             string          `json:"policy_digest"`
	PolicyDecidedAt          string          `json:"policy_decided_at"`
	Operation                string          `json:"operation"`
	SandboxID                string          `json:"sandbox_id"`
	OperationID              string          `json:"operation_id"`
	AttemptID                string          `json:"attempt_id"`
	FencingToken             int64           `json:"fencing_token"`
	DeadlineAt               string          `json:"deadline_at"`
	RequestContractID        string          `json:"request_contract_id"`
	RequestDigestProfile     string          `json:"request_digest_profile"`
	RequestDigest            string          `json:"request_digest"`
	HTTPTarget               admissionTarget `json:"http_target"`
}

func (c *Client) sign(now time.Time, policyDigest string, work product.ReconcileWork, sandboxID string, deadline time.Time, path, requestDigest string) (signedHeaders, error) {
	return c.signAdmission(now, admissionSigningInput{PolicyDigest: policyDigest, TenantID: work.TenantID, WorkOrderID: work.OperationID,
		Operation: "create", SandboxID: sandboxID, OperationID: work.OperationID, AttemptID: work.AttemptID, FencingToken: work.SlotGeneration,
		Deadline: deadline, RequestContractID: "urn:shell-echo:sandbox-runtime:request:create-sandbox:v1",
		RequestDigestProfile: "rfc8785-request-excluding-request-digest-v1", RequestDigest: requestDigest,
		Method: http.MethodPost, Path: path})
}

type admissionSigningInput struct {
	PolicyDigest, TenantID, WorkOrderID                    string
	Operation, SandboxID, OperationID, AttemptID           string
	FencingToken                                           int64
	Deadline                                               time.Time
	RequestContractID, RequestDigestProfile, RequestDigest string
	Method, Path                                           string
}

func (c *Client) signAdmission(now time.Time, input admissionSigningInput) (signedHeaders, error) {
	contextValue := admissionContext{ContextContractID: "urn:shell-echo:sandbox-runtime:admission-context:v1", ContextDigestProfile: "rfc8785-full-document-excluding-context-digest-v1",
		ControllerSubject: c.authority.Subject, ProviderRevisionID: c.revisionID, ProviderInstanceAudience: c.authority.Audience,
		TenantID: input.TenantID, WorkOrderID: input.WorkOrderID, PolicyDigest: input.PolicyDigest, PolicyDecidedAt: now.Format(time.RFC3339Nano),
		Operation: input.Operation, SandboxID: input.SandboxID, OperationID: input.OperationID, AttemptID: input.AttemptID, FencingToken: input.FencingToken,
		DeadlineAt: input.Deadline.Format(time.RFC3339Nano), RequestContractID: input.RequestContractID,
		RequestDigestProfile: input.RequestDigestProfile, RequestDigest: input.RequestDigest,
		HTTPTarget: admissionTarget{Method: input.Method, Path: input.Path, NormalizedQuery: []string{}}}
	digest, err := canonicalDigestExcluding(contextValue, "context_digest")
	if err != nil {
		return signedHeaders{}, err
	}
	contextValue.ContextDigest = digest
	contextJSON, err := json.Marshal(contextValue)
	if err != nil {
		return signedHeaders{}, err
	}
	jtiBytes := make([]byte, 18)
	if _, err := rand.Read(jtiBytes); err != nil {
		return signedHeaders{}, err
	}
	claims := struct {
		JTI                           string `json:"jti"`
		Issuer                        string `json:"iss"`
		Subject                       string `json:"sub"`
		Audience                      string `json:"aud"`
		IssuedAt                      int64  `json:"iat"`
		NotBefore                     int64  `json:"nbf"`
		ExpiresAt                     int64  `json:"exp"`
		Operation                     string `json:"operation"`
		ProviderRevisionID            string `json:"provider_revision_id"`
		SandboxID                     string `json:"sandbox_id"`
		OperationID                   string `json:"operation_id"`
		AttemptID                     string `json:"attempt_id"`
		FencingToken                  int64  `json:"fencing_token"`
		TenantID                      string `json:"tenant_id"`
		WorkOrderID                   string `json:"work_order_id"`
		PolicyDigest                  string `json:"policy_digest"`
		PolicyDecidedAt               string `json:"policy_decided_at"`
		RequestContractID             string `json:"request_contract_id"`
		RequestDigestProfile          string `json:"request_digest_profile"`
		RequestDigest                 string `json:"request_digest"`
		DeadlineAt                    string `json:"deadline_at"`
		AdmissionContextContractID    string `json:"admission_context_contract_id"`
		AdmissionContextDigestProfile string `json:"admission_context_digest_profile"`
		AdmissionContextDigest        string `json:"admission_context_digest"`
	}{base64.RawURLEncoding.EncodeToString(jtiBytes), c.authority.Issuer, c.authority.Subject, c.authority.Audience, now.Unix(), now.Unix(), minTime(input.Deadline, now.Add(time.Minute)).Unix(),
		input.Operation, c.revisionID, input.SandboxID, input.OperationID, input.AttemptID, input.FencingToken, input.TenantID, input.WorkOrderID, input.PolicyDigest, now.Format(time.RFC3339Nano),
		input.RequestContractID, input.RequestDigestProfile, input.RequestDigest, input.Deadline.Format(time.RFC3339Nano),
		contextValue.ContextContractID, contextValue.ContextDigestProfile, digest}
	header := struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}{"EdDSA", c.authority.KeyID, "agent-sandbox-operation-admission+jwt"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := encodedHeader + "." + encodedClaims
	signature := ed25519.Sign(c.authority.PrivateKey, []byte(signingInput))
	return signedHeaders{Bearer: signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), Context: base64.RawURLEncoding.EncodeToString(contextJSON)}, nil
}

func canonicalDigestExcluding(value any, member string) (string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var members map[string]any
	if err := json.Unmarshal(document, &members); err != nil {
		return "", err
	}
	delete(members, member)
	document, err = json.Marshal(members)
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

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}

func decodeBounded(reader io.Reader, destination any) error {
	limited := &io.LimitedReader{R: reader, N: maxProviderBody + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if limited.N <= 0 {
		return errors.New("provider response too large")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("provider response contains trailing data")
	}
	return nil
}
