package phase6security

import (
	"strings"
	"testing"
)

func TestSlice6DesiredAuthorizationPrincipalsBindExactFreshRun(t *testing.T) {
	environment := testDigest("environment")
	profile := testDigest("principal-profile")
	first, err := Slice6DesiredAuthorizationPrincipals(strings.Repeat("a", 32), environment, profile)
	if err != nil || len(first) != 80 {
		t.Fatalf("reviewed run-bound identity inventory = %d, %v", len(first), err)
	}
	second, err := Slice6DesiredAuthorizationPrincipals(strings.Repeat("b", 32), environment, profile)
	if err != nil || len(second) != len(first) {
		t.Fatalf("fresh run identity inventory = %d, %v", len(second), err)
	}
	for _, name := range slice6ApprovedDeploymentNames() {
		if _, sandbox := requiredResourceControllers[name]; sandbox {
			if _, found := first[name]; found {
				t.Fatalf("sandbox template %s acquired static workload identity", name)
			}
			continue
		}
		one, found := first[name]
		if !found || one.InstanceDigest == second[name].InstanceDigest || one.PrincipalDigest == second[name].PrincipalDigest ||
			one.EnvironmentDigest != environment || one.ProfileDigest != profile {
			t.Fatalf("deployment %s lost per-run identity binding", name)
		}
	}
	for _, bad := range []string{"", strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 31)} {
		if _, err := Slice6DesiredAuthorizationPrincipals(bad, environment, profile); err == nil {
			t.Fatalf("invalid run ID %q admitted", bad)
		}
	}
}

func TestSlice6DesiredTLSIdentityHasNoOperatorSelectedSANOrLifetime(t *testing.T) {
	digest := testDigest("principal")
	for _, deployment := range slice6ApprovedDeploymentNames() {
		kind, err := Slice6DesiredDeploymentKind(deployment)
		if err != nil {
			t.Fatal(err)
		}
		input := digest
		if kind == "sandbox" {
			input = ""
		}
		identity, err := Slice6DesiredTLSIdentity(deployment, input)
		if err != nil {
			t.Fatalf("reviewed TLS identity %s: %v", deployment, err)
		}
		if kind == "sandbox" || kind == "ingress_relay" {
			if identity != nil {
				t.Fatalf("non-leaf deployment %s acquired TLS policy", deployment)
			}
			continue
		}
		if identity == nil || identity.PrincipalDigest != digest || identity.TTLSeconds != 900 ||
			identity.URI != "spiffe://sandbox-runtime.test/"+deployment {
			t.Fatalf("reviewed TLS identity %s drifted", deployment)
		}
	}
	if _, err := Slice6DesiredTLSIdentity("unreviewed-runtime", digest); err == nil {
		t.Fatal("unreviewed TLS identity admitted")
	}
}
