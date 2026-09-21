package docker

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/browser/network/gateway"
)

func TestBrowserWrapperPreservesClosedPolicyType(t *testing.T) {
	options := Options{Policies: []gateway.Policy{{Reference: "browser-egress-policy-1", AllowedHosts: []string{"allowed.example"}}}}
	if len(options.Policies) != 1 || options.Policies[0].Reference != "browser-egress-policy-1" {
		t.Fatalf("policies = %#v", options.Policies)
	}
}
