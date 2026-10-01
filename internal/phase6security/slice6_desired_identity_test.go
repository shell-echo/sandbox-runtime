package phase6security

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestSlice6DesiredAuthorizationPrincipalsBindExactFreshRun(t *testing.T) {
	environment := testDigest("environment")
	profile := testDigest("principal-profile")
	first, err := Slice6DesiredAuthorizationPrincipals(strings.Repeat("a", 32), environment, profile)
	if err != nil || len(first) != 76 {
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

func TestSlice6RetiredMaterialAgentSlotsPreserveEverySurvivor(t *testing.T) {
	// These hashes were independently captured from the prior reviewed
	// 82-principal desired inventory with only the four retired names omitted.
	// They cover all surviving UID/GID and dedicated/shared network CIDRs.
	pairs := Slice6DesiredUIDGID()
	if len(pairs) != 78 {
		t.Fatalf("active identity count = %d", len(pairs))
	}
	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)
	var identities strings.Builder
	for _, name := range names {
		fmt.Fprintf(&identities, "%s\x00%d\x00%d\n", name, pairs[name][0], pairs[name][1])
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(identities.String()))); got != "17aa13219358f0c1d1a3d7a86a74ffad312a8f755ca1172fef370e6d53b50647" {
		t.Fatalf("surviving UID/GID allocation changed: %s", got)
	}
	networks := Slice6DesiredNetworks()
	if len(networks) != 92 {
		t.Fatalf("active role network count = %d", len(networks))
	}
	var addresses strings.Builder
	for _, network := range networks {
		fmt.Fprintf(&addresses, "%s\x00%s\n", network.Name, network.IPv4Subnet)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(addresses.String()))); got != "b8a8c42d0103b739b8dac9fda8cd0327c946fe23ed59dda02e24468a156d1dad" {
		t.Fatalf("surviving network CIDRs changed: %s", got)
	}
	finalNetworks := Slice6DesiredFinalNetworks()
	if len(finalNetworks) != 121 {
		t.Fatalf("active final network count = %d", len(finalNetworks))
	}
	addresses.Reset()
	for _, network := range finalNetworks {
		fmt.Fprintf(&addresses, "%s\x00%s\n", network.Name, network.IPv4Subnet)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(addresses.String()))); got != "b6d363ed83a6e0fe3280a064b79df33005c5b3d2dfec8dc23d199f3724d9d951" {
		t.Fatalf("surviving final network CIDRs changed: %s", got)
	}
	for _, retired := range []string{"browser-agent", "browser-agent-tls-agent", "desktop-agent", "desktop-agent-tls-agent"} {
		if _, present := pairs[retired]; present {
			t.Fatalf("retired identity %s reintroduced", retired)
		}
		for _, network := range finalNetworks {
			if network.Name == "network-"+retired || network.Name == "service-"+retired+"-vault" {
				t.Fatalf("retired network %s reintroduced", network.Name)
			}
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
