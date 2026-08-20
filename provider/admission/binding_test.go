package admission

import (
	"errors"
	"testing"
	"time"
)

func TestValidateTokenBindingAcceptsExactVerifiedContext(t *testing.T) {
	token, binding, clock := validTokenBindingForTest()
	if err := ValidateTokenBinding(token, binding, clock); err != nil {
		t.Fatalf("ValidateTokenBinding() error = %v", err)
	}
}

func TestValidateTokenBindingRejectsMismatchedContext(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TokenBinding)
	}{
		{name: "caller", mutate: func(binding *TokenBinding) { binding.Caller = "spiffe://provider/other-controller" }},
		{name: "provider revision", mutate: func(binding *TokenBinding) { binding.ProviderRevisionID = "provider-revision-other" }},
		{name: "audience", mutate: func(binding *TokenBinding) {
			binding.Audience = "urn:shell-echo:sandbox-runtime:provider-instance:other"
		}},
		{name: "operation", mutate: func(binding *TokenBinding) {
			binding.Operation = OperationCreate
			binding.RequestContractID = "urn:shell-echo:sandbox-runtime:request:create:v1"
		}},
		{name: "sandbox", mutate: func(binding *TokenBinding) { binding.SandboxID = "sandbox-other" }},
		{name: "operation id", mutate: func(binding *TokenBinding) { binding.OperationID = "operation-other" }},
		{name: "attempt", mutate: func(binding *TokenBinding) { binding.AttemptID = "attempt-other" }},
		{name: "fencing", mutate: func(binding *TokenBinding) { binding.FencingToken = 2 }},
		{name: "tenant", mutate: func(binding *TokenBinding) { binding.TenantID = "tenant-other" }},
		{name: "work order", mutate: func(binding *TokenBinding) { binding.WorkOrderID = "work-order-other" }},
		{name: "policy", mutate: func(binding *TokenBinding) { binding.PolicyDigest = validDigest('c') }},
		{name: "request digest", mutate: func(binding *TokenBinding) { binding.RequestDigest = validDigest('d') }},
		{name: "deadline", mutate: func(binding *TokenBinding) { binding.DeadlineAt = binding.DeadlineAt.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, binding, clock := validTokenBindingForTest()
			test.mutate(&binding)
			if err := ValidateTokenBinding(token, binding, clock); !errors.Is(err, ErrUnauthorizedTokenBinding) {
				t.Fatalf("ValidateTokenBinding() error = %v, want %v", err, ErrUnauthorizedTokenBinding)
			}
		})
	}
}

func TestValidateTokenBindingRejectsInvalidTokenLifetime(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*VerifiedToken, *TokenBinding, *fixedClock)
	}{
		{name: "issued after not before", mutate: func(token *VerifiedToken, _ *TokenBinding, _ *fixedClock) {
			token.Claims.IssuedAt = token.Claims.NotBefore + 1
		}},
		{name: "long lifetime", mutate: func(token *VerifiedToken, _ *TokenBinding, _ *fixedClock) {
			token.Claims.ExpiresAt = token.Claims.IssuedAt + 301
		}},
		{name: "before policy decision", mutate: func(token *VerifiedToken, binding *TokenBinding, _ *fixedClock) {
			binding.PolicyDecisionAt = time.Unix(token.Claims.NotBefore+1, 0)
		}},
		{name: "after deadline", mutate: func(token *VerifiedToken, binding *TokenBinding, _ *fixedClock) {
			binding.DeadlineAt = time.Unix(token.Claims.ExpiresAt-1, 0)
		}},
		{name: "not yet valid", mutate: func(token *VerifiedToken, _ *TokenBinding, clock *fixedClock) {
			clock.now = time.Unix(token.Claims.NotBefore-1, 0)
		}},
		{name: "expired", mutate: func(token *VerifiedToken, _ *TokenBinding, clock *fixedClock) {
			clock.now = time.Unix(token.Claims.ExpiresAt, 0)
		}},
		{name: "zero clock", mutate: func(_ *VerifiedToken, _ *TokenBinding, clock *fixedClock) { clock.now = time.Time{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, binding, clock := validTokenBindingForTest()
			test.mutate(&token, &binding, &clock)
			if err := ValidateTokenBinding(token, binding, clock); !errors.Is(err, ErrUnauthorizedTokenBinding) {
				t.Fatalf("ValidateTokenBinding() error = %v, want %v", err, ErrUnauthorizedTokenBinding)
			}
		})
	}

	token, binding, _ := validTokenBindingForTest()
	if err := ValidateTokenBinding(token, binding, nil); !errors.Is(err, ErrUnauthorizedTokenBinding) {
		t.Fatalf("nil clock error = %v, want %v", err, ErrUnauthorizedTokenBinding)
	}
}

type fixedClock struct {
	now time.Time
}

func (clock fixedClock) Now() time.Time {
	return clock.now
}

func validTokenBindingForTest() (VerifiedToken, TokenBinding, fixedClock) {
	deadline := time.Unix(200, 0).UTC()
	claims := validTokenClaims()
	claims.IssuedAt = 100
	claims.NotBefore = 110
	claims.ExpiresAt = 180
	claims.DeadlineAt = deadline.Format(time.RFC3339Nano)
	token := VerifiedToken{Claims: claims}
	binding := TokenBinding{
		Caller:               claims.Subject,
		ProviderRevisionID:   claims.ProviderRevisionID,
		Audience:             claims.Audience,
		Operation:            claims.Operation,
		SandboxID:            claims.SandboxID,
		OperationID:          claims.OperationID,
		AttemptID:            claims.AttemptID,
		FencingToken:         claims.FencingToken,
		TenantID:             claims.TenantID,
		WorkOrderID:          claims.WorkOrderID,
		PolicyDigest:         claims.PolicyDigest,
		RequestContractID:    claims.RequestContractID,
		RequestDigestProfile: claims.RequestDigestProfile,
		RequestDigest:        claims.RequestDigest,
		PolicyDecisionAt:     time.Unix(105, 0).UTC(),
		DeadlineAt:           deadline,
	}
	return token, binding, fixedClock{now: time.Unix(150, 0).UTC()}
}
