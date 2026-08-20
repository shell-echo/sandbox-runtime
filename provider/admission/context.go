package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	AdmissionContextContractID    = "urn:shell-echo:sandbox-runtime:admission-context:v1"
	AdmissionContextDigestProfile = "rfc8785-full-document-excluding-context-digest-v1"
	AdmissionContextHeader        = "X-Sandbox-Runtime-Admission-Context"
	MaxAdmissionContextBytes      = 16384
)

var contextPathPattern = regexp.MustCompile(`^/v1(?:/[A-Za-z0-9._:-]+)+$`)

// AdmissionContext is the independently admitted caller snapshot carried by
// every protected Sandbox Provider request. It is never derived from bearer
// claims; the transport compares those claims to this value.
type AdmissionContext struct {
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
	Operation                Operation       `json:"operation"`
	SandboxID                string          `json:"sandbox_id"`
	OperationID              string          `json:"operation_id"`
	AttemptID                string          `json:"attempt_id"`
	FencingToken             int64           `json:"fencing_token"`
	DeadlineAt               string          `json:"deadline_at"`
	RequestContractID        string          `json:"request_contract_id"`
	RequestDigestProfile     DigestProfile   `json:"request_digest_profile"`
	RequestDigest            string          `json:"request_digest"`
	HTTPTarget               AdmissionTarget `json:"http_target"`
}

type AdmissionTarget struct {
	Method          string           `json:"method"`
	Path            string           `json:"path"`
	NormalizedQuery []AdmissionQuery `json:"normalized_query"`
}

type AdmissionQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

var (
	ErrInvalidAdmissionContext        = errors.New("provider admission context is invalid")
	ErrAdmissionContextTargetMismatch = errors.New("provider admission context target does not match request")
)

// DecodeAdmissionContextCarrier validates and decodes the unpadded base64url
// carrier declared by the local Provider Contract. It rejects padding,
// whitespace, duplicate members, unknown members, trailing JSON, and a digest
// that does not cover the complete document excluding context_digest.
func DecodeAdmissionContextCarrier(carrier string) (AdmissionContext, error) {
	if len(carrier) == 0 || len(carrier) > MaxAdmissionContextBytes || strings.ContainsAny(carrier, "= \t\r\n") || !utf8.ValidString(carrier) {
		return AdmissionContext{}, ErrInvalidAdmissionContext
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(carrier)
	if err != nil || len(raw) == 0 || len(raw) > MaxAdmissionContextBytes || !utf8.Valid(raw) {
		return AdmissionContext{}, ErrInvalidAdmissionContext
	}
	var context AdmissionContext
	if !decodeClosedJSON(raw, &context) || !validAdmissionContext(context) {
		return AdmissionContext{}, ErrInvalidAdmissionContext
	}
	digest, err := admissionContextDigest(raw)
	if err != nil || digest != context.ContextDigest {
		return AdmissionContext{}, ErrInvalidAdmissionContext
	}
	return context, nil
}

func validAdmissionContext(context AdmissionContext) bool {
	if context.ContextContractID != AdmissionContextContractID || context.ContextDigestProfile != AdmissionContextDigestProfile || !digestPattern.MatchString(context.ContextDigest) || !digestPattern.MatchString(context.PolicyDigest) || !digestPattern.MatchString(context.RequestDigest) || !context.Operation.Supported() || !context.RequestDigestProfile.Supported() || !context.HTTPTarget.validForOperation(context.Operation) || context.FencingToken < 1 || context.FencingToken > maxSafeJSONInteger {
		return false
	}
	if !audiencePattern.MatchString(context.ProviderInstanceAudience) || !validBoundedText(context.ControllerSubject, 1, 200) || !validBoundedText(context.ProviderRevisionID, 1, 200) || !validBoundedText(context.TenantID, 1, 200) || !validBoundedText(context.WorkOrderID, 1, 200) || !validBoundedText(context.SandboxID, 1, 200) || !validBoundedText(context.OperationID, 1, 200) || !validBoundedText(context.AttemptID, 1, 200) || !validBoundedText(context.RequestContractID, 1, 200) {
		return false
	}
	if !validRequestBinding(TokenClaims{Operation: context.Operation, RequestContractID: context.RequestContractID, RequestDigestProfile: context.RequestDigestProfile}) {
		return false
	}
	for _, value := range []string{context.PolicyDecidedAt, context.DeadlineAt} {
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return false
		}
	}
	return true
}

func (target AdmissionTarget) validForOperation(operation Operation) bool {
	if target.Method != http.MethodGet && target.Method != http.MethodPost || len(target.Path) < 4 || len(target.Path) > 600 || !contextPathPattern.MatchString(target.Path) || target.NormalizedQuery == nil || len(target.NormalizedQuery) > 4 {
		return false
	}
	if operation != OperationReadEvents {
		return len(target.NormalizedQuery) == 0
	}
	if target.Method != http.MethodGet {
		return false
	}
	if len(target.NormalizedQuery) == 0 {
		return true
	}
	if len(target.NormalizedQuery) != 1 || target.NormalizedQuery[0].Name != "after_sequence" {
		return false
	}
	return validAfterSequence(target.NormalizedQuery[0].Value)
}

func validAfterSequence(value string) bool {
	sequence, err := strconv.ParseInt(value, 10, 64)
	return err == nil && sequence >= 0 && sequence <= maxSafeJSONInteger && strconv.FormatInt(sequence, 10) == value
}

func admissionContextDigest(raw []byte) (string, error) {
	var document map[string]json.RawMessage
	if !decodeClosedJSON(raw, &document) {
		return "", ErrInvalidAdmissionContext
	}
	delete(document, "context_digest")
	withoutDigest, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(withoutDigest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// DigestForDocument creates the carrier digest for a context document. It is
// intended for test-local and Platform-side fixture construction; callers must
// set context_digest to the returned value before encoding the carrier.
func DigestForAdmissionContext(document AdmissionContext) (string, error) {
	document.ContextDigest = ""
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	return admissionContextDigest(encoded)
}

// ValidateTarget binds the independently admitted HTTP target to the actual
// parsed request, including a canonical sorted query representation.
func (context AdmissionContext) ValidateTarget(request *http.Request) error {
	if request == nil || context.HTTPTarget.Method != request.Method || context.HTTPTarget.Path != request.URL.Path {
		return ErrAdmissionContextTargetMismatch
	}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return ErrAdmissionContextTargetMismatch
	}
	if request.URL.ForceQuery && len(query) == 0 {
		return ErrAdmissionContextTargetMismatch
	}
	items := make([]AdmissionQuery, 0, len(query))
	for name, values := range query {
		if len(values) != 1 || values[0] == "" {
			return ErrAdmissionContextTargetMismatch
		}
		items = append(items, AdmissionQuery{Name: name, Value: values[0]})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	if !bytes.Equal(mustJSON(items), mustJSON(context.HTTPTarget.NormalizedQuery)) {
		return ErrAdmissionContextTargetMismatch
	}
	return nil
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

// TokenBinding returns the independent context facts consumed by the pure
// admission gate. The bearer is never used to populate these values.
func (context AdmissionContext) TokenBinding(caller string) TokenBinding {
	return TokenBinding{
		Caller: caller, ProviderRevisionID: context.ProviderRevisionID,
		Audience: context.ProviderInstanceAudience, Operation: context.Operation,
		SandboxID: context.SandboxID, OperationID: context.OperationID,
		AttemptID: context.AttemptID, FencingToken: context.FencingToken,
		TenantID: context.TenantID, WorkOrderID: context.WorkOrderID,
		PolicyDigest: context.PolicyDigest, RequestContractID: context.RequestContractID,
		RequestDigestProfile: context.RequestDigestProfile, RequestDigest: context.RequestDigest,
		PolicyDecisionAt: parseTime(context.PolicyDecidedAt), DeadlineAt: parseTime(context.DeadlineAt),
		AdmissionContextContractID:    context.ContextContractID,
		AdmissionContextDigestProfile: context.ContextDigestProfile,
		AdmissionContextDigest:        context.ContextDigest,
	}
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}
