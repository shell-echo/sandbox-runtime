package productguest

import (
	"context"
	"errors"
	"testing"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/product"
)

func TestAuthenticationErrorSeparatesDefiniteDependencyFailureFromUnknownCommit(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input, want error
	}{
		{"pre-commit dependency", product.ErrStoreUnavailable, guestagent.ErrAuthDependencyUnavailable},
		{"unknown commit", product.ErrStoreOutcomeUnknown, guestagent.ErrAuthOutcomeUnknown},
		{"revoked or invalid", product.ErrForbidden, guestagent.ErrUnauthorized},
		{"cancelled", context.Canceled, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapAuthenticationError(tc.input); !errors.Is(got, tc.want) ||
				(tc.want != guestagent.ErrAuthDependencyUnavailable && errors.Is(got, guestagent.ErrAuthDependencyUnavailable)) {
				t.Fatalf("mapped error = %v, want only %v", got, tc.want)
			}
		})
	}
}

type retirementStoreFunc func(context.Context, product.GuestBinding) (product.GuestRetirementDisposition, error)

func (f retirementStoreFunc) RetireGuestConnection(ctx context.Context, binding product.GuestBinding) (product.GuestRetirementDisposition, error) {
	return f(ctx, binding)
}

func (f retirementStoreFunc) ReadGuestRetirement(ctx context.Context, binding product.GuestBinding) (product.GuestRetirementDisposition, error) {
	return f(ctx, binding)
}

func TestRetirementPolicyMapsExactProductDispositions(t *testing.T) {
	for _, tc := range []struct {
		input product.GuestRetirementDisposition
		want  guestagent.RetirementDisposition
		ok    bool
	}{
		{product.GuestRetireReleased, guestagent.RetirementReleased, true},
		{product.GuestRetireInactive, guestagent.RetirementInactive, true},
		{product.GuestRetireSuperseded, guestagent.RetirementSuperseded, true},
		{product.GuestRetireStillOwned, guestagent.RetirementStillOwned, true},
		{"unexpected", "", false},
	} {
		policy, err := NewRetirementPolicy(retirementStoreFunc(func(_ context.Context, binding product.GuestBinding) (product.GuestRetirementDisposition, error) {
			if binding.GuestID != "guest" || binding.ClientNonce != "nonce" {
				t.Fatal("retirement lost exact owner identity")
			}
			return tc.input, nil
		}), 3)
		if err != nil || policy.Capacity != 3 {
			t.Fatalf("policy = %+v, %v", policy, err)
		}
		got, err := policy.Retire(context.Background(), guestagent.Identity{GuestID: "guest", ClientNonce: "nonce"})
		if got != tc.want || (err == nil) != tc.ok {
			t.Fatalf("disposition %q = %q, %v", tc.input, got, err)
		}
	}
}
