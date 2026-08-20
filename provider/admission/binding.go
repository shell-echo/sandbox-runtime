package admission

import (
	"errors"
	"time"
)

var ErrUnauthorizedTokenBinding = errors.New("provider admission token binding is not authorized")

// TokenBinding contains only transport-verified and request-normalized facts
// that must exactly match a verified protected-operation token. Caller is the
// unique allowlisted URI SAN selected from a TLS-verified client leaf, never a
// caller-provided header value.
type TokenBinding struct {
	Caller                        string
	ProviderRevisionID            string
	Audience                      string
	Operation                     Operation
	SandboxID                     string
	OperationID                   string
	AttemptID                     string
	FencingToken                  int64
	TenantID                      string
	WorkOrderID                   string
	PolicyDigest                  string
	RequestContractID             string
	RequestDigestProfile          DigestProfile
	RequestDigest                 string
	PolicyDecisionAt              time.Time
	DeadlineAt                    time.Time
	AdmissionContextContractID    string
	AdmissionContextDigestProfile string
	AdmissionContextDigest        string
}

// ValidateTokenBinding rejects a verified token unless every contextual value
// and its short-lived validity window match the admitted Provider operation.
// It neither parses TLS state nor dispatches a Provider request.
func ValidateTokenBinding(token VerifiedToken, binding TokenBinding, clock Clock) error {
	if clock == nil || !validateClaimsShape(token.Claims) || !validTokenBinding(binding) {
		return ErrUnauthorizedTokenBinding
	}
	claims := token.Claims
	if claims.Subject != binding.Caller ||
		claims.ProviderRevisionID != binding.ProviderRevisionID ||
		claims.Audience != binding.Audience ||
		claims.Operation != binding.Operation ||
		claims.SandboxID != binding.SandboxID ||
		claims.OperationID != binding.OperationID ||
		claims.AttemptID != binding.AttemptID ||
		claims.FencingToken != binding.FencingToken ||
		claims.TenantID != binding.TenantID ||
		claims.WorkOrderID != binding.WorkOrderID ||
		claims.PolicyDigest != binding.PolicyDigest ||
		claims.RequestContractID != binding.RequestContractID ||
		claims.RequestDigestProfile != binding.RequestDigestProfile ||
		claims.RequestDigest != binding.RequestDigest ||
		(binding.AdmissionContextContractID != "" && !sameRFC3339Time(claims.PolicyDecidedAt, binding.PolicyDecisionAt)) ||
		claims.AdmissionContextContractID != binding.AdmissionContextContractID ||
		claims.AdmissionContextDigestProfile != binding.AdmissionContextDigestProfile ||
		claims.AdmissionContextDigest != binding.AdmissionContextDigest {
		return ErrUnauthorizedTokenBinding
	}

	deadline, err := time.Parse(time.RFC3339Nano, claims.DeadlineAt)
	if err != nil || !deadline.Equal(binding.DeadlineAt) {
		return ErrUnauthorizedTokenBinding
	}
	now := clock.Now()
	if now.IsZero() || !validTokenLifetime(claims, binding.PolicyDecisionAt, deadline, now) {
		return ErrUnauthorizedTokenBinding
	}
	return nil
}

func sameRFC3339Time(value string, expected time.Time) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Equal(expected)
}

func validTokenBinding(binding TokenBinding) bool {
	if !validBoundedText(binding.Caller, 1, 200) || !validRequiredText(binding.ProviderRevisionID) || !audiencePattern.MatchString(binding.Audience) || !binding.Operation.Supported() || binding.FencingToken < 1 || !digestPattern.MatchString(binding.PolicyDigest) || !digestPattern.MatchString(binding.RequestDigest) || !binding.RequestDigestProfile.Supported() || binding.PolicyDecisionAt.IsZero() || binding.DeadlineAt.IsZero() {
		return false
	}
	if !validRequestBinding(TokenClaims{
		Operation:            binding.Operation,
		RequestContractID:    binding.RequestContractID,
		RequestDigestProfile: binding.RequestDigestProfile,
	}) {
		return false
	}
	for _, value := range []string{binding.SandboxID, binding.OperationID, binding.AttemptID, binding.TenantID, binding.WorkOrderID} {
		if !validRequiredText(value) {
			return false
		}
	}
	return true
}

func validTokenLifetime(claims TokenClaims, policyDecisionAt, deadlineAt, now time.Time) bool {
	if claims.IssuedAt > claims.NotBefore || claims.NotBefore >= claims.ExpiresAt || claims.ExpiresAt-claims.IssuedAt > 300 {
		return false
	}
	notBefore := time.Unix(claims.NotBefore, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if notBefore.Before(policyDecisionAt) || expiresAt.After(deadlineAt) {
		return false
	}
	return !now.Before(notBefore) && now.Before(expiresAt)
}
