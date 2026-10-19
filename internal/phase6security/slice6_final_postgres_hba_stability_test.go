package phase6security

import (
	"net/netip"
	"slices"
	"testing"
)

// These bytes precede the per-call planning optimization. They pin all nine
// SQL identities and /32 sources, including the two broker-owned dialers.
func TestSlice6FinalSharedPostgresHBAStableBytesAndOwnedResults(t *testing.T) {
	const want = `local all postgres peer
hostssl product product_gateway 172.31.137.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl product product_migrator 172.31.140.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl product product_runtime 172.31.142.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl provider_browser browser_provider_migrator 172.31.156.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl provider_browser browser_provider_runtime 172.31.145.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl provider_desktop desktop_provider_migrator 172.31.158.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl provider_desktop desktop_provider_runtime 172.31.148.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl provider provider_migrator 172.31.151.2/32 scram-sha-256 clientcert=verify-full clientname=CN
hostssl provider provider_runtime 172.31.152.2/32 scram-sha-256 clientcert=verify-full clientname=CN
host all all 0.0.0.0/0 reject
host all all ::/0 reject
`
	for i := 0; i < 2; i++ {
		document, err := RenderSlice6DesiredFinalSharedPostgresHBA()
		if err != nil || string(document) != want {
			t.Fatalf("fixed HBA changed: %v\n%s", err, document)
		}
		rules, err := Slice6DesiredFinalSharedPostgresHBARules()
		if err != nil || len(rules) != 9 {
			t.Fatal("missing fixed rules", err)
		}
		// Neither returned rules nor rendered bytes may poison another call.
		rules[0].SourceCIDR, rules[0].SQLRole = "0.0.0.0/0", "postgres"
		document[0] = 'X'
		if VerifySlice6DesiredFinalSharedPostgresHBARules(rules) == nil {
			t.Fatal("modified rule admitted")
		}
	}
}

func TestSlice6FinalServiceEndpointsRemainOwnedAndClosed(t *testing.T) {
	bridges := Slice6DesiredFinalServiceBridges()
	if len(bridges) != 30 {
		t.Fatal("changed desired bridge set")
	}
	for _, bridge := range bridges {
		if len(bridge.Principals) != 1 || len(bridge.ExternalServices) != 1 {
			t.Fatal("changed desired bridge membership")
		}
		for _, member := range []string{bridge.Principals[0], bridge.ExternalServices[0]} {
			address := netip.MustParsePrefix(bridge.IPv4Subnet).Addr().As4()
			address[3] = 3
			if member == bridge.Principals[0] {
				address[3] = 2
			}
			got, err := Slice6DesiredFinalServiceEndpointAddress(bridge.Name, member)
			if err != nil || got != netip.AddrFrom4(address).String() {
				t.Fatal("changed desired endpoint", bridge.Name, member, got, err)
			}
		}
		for _, member := range []string{"", "unapproved", bridge.Name} {
			if _, err := Slice6DesiredFinalServiceEndpointAddress(bridge.Name, member); err == nil {
				t.Fatal("unapproved endpoint member admitted")
			}
		}
	}
	if _, err := Slice6DesiredFinalServiceEndpointAddress("unknown", "postgres"); err == nil {
		t.Fatal("unknown bridge admitted")
	}
	first := bridges[0]
	member := first.Principals[0]
	want, err := Slice6DesiredFinalServiceEndpointAddress(first.Name, member)
	if err != nil {
		t.Fatal(err)
	}
	bridges[0].IPv4Subnet = "192.0.2.0/24"
	bridges[0].Principals[0] = "substituted"
	bridges[0].ExternalServices[0] = "substituted"
	got, err := Slice6DesiredFinalServiceEndpointAddress(first.Name, member)
	if err != nil || got != want || slices.Contains(Slice6DesiredFinalServiceBridges()[0].Principals, "substituted") {
		t.Fatal("caller-owned plan mutation changed later lookup", err)
	}
}
