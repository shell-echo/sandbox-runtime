package docker

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/network/restricted"
)

func TestDesktopWrapperAcceptsOnlyNeutralPolicyDocuments(t *testing.T) {
	options := Options{Policies: []restricted.Policy{{Reference: "desktop-egress-policy-1", AllowedHosts: []string{"allowed.example"}}}}
	if len(options.Policies) != 1 || options.Policies[0].Reference != "desktop-egress-policy-1" {
		t.Fatalf("policies = %#v", options.Policies)
	}
}
