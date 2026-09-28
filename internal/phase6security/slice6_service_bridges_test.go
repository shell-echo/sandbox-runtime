package phase6security

import (
	"net/netip"
	"slices"
	"testing"
)

func TestSlice6DesiredServiceBridgesHaveExactDedicatedMembersAndStableCIDRs(t *testing.T) {
	bridges := Slice6DesiredServiceBridges()
	if err := VerifySlice6DesiredServiceBridges(bridges); err != nil {
		t.Fatalf("28 service bridges rejected: %v", err)
	}
	old := Slice6DesiredNetworks()
	oldSubnets := make(map[string]bool, len(old))
	for _, network := range old {
		oldSubnets[network.IPv4Subnet] = true
	}
	seen := make(map[string]bool, len(bridges))
	for _, bridge := range bridges {
		if len(bridge.Principals) != 1 || len(bridge.ExternalServices) != 1 ||
			!bridge.Internal || bridge.GatewayModeIPv4 != "isolated" || bridge.IPv6Enabled ||
			seen[bridge.IPv4Subnet] {
			t.Fatalf("unsafe dedicated service bridge: %+v", bridge)
		}
		seen[bridge.IPv4Subnet] = true
		if oldSubnets[bridge.IPv4Subnet] && bridge.Name != "network-certificate-controller" {
			t.Fatalf("new service bridge shifted existing CIDR: %+v", bridge)
		}
		dialer, err := Slice6DesiredServiceEndpointAddress(bridge.Name, bridge.Principals[0])
		if err != nil {
			t.Fatal(err)
		}
		service, err := Slice6DesiredServiceEndpointAddress(bridge.Name, bridge.ExternalServices[0])
		if err != nil || dialer == service ||
			!netip.MustParsePrefix(bridge.IPv4Subnet).Contains(netip.MustParseAddr(service)) {
			t.Fatalf("invalid planned service endpoint %s: %v", bridge.Name, err)
		}
	}
	if !slices.ContainsFunc(bridges, func(network Network) bool {
		return network.Name == "service-provider-runtime-postgres" &&
			slices.Equal(network.Principals, []string{"provider-runtime"}) &&
			slices.Equal(network.ExternalServices, []string{"postgres"})
	}) {
		t.Fatal("coding Provider database bridge missing")
	}
	wrong := append([]Network(nil), bridges...)
	wrong[0].Kind = "external_uplink"
	if VerifySlice6DesiredServiceBridges(wrong) == nil {
		t.Fatal("NAT service bridge admitted")
	}
	if _, err := Slice6DesiredServiceEndpointAddress("service-gateway-postgres", "provider-runtime"); err == nil {
		t.Fatal("unapproved principal received service endpoint")
	}
	for _, bridge := range bridges {
		dialerID, serviceID := testDigest("dialer/" + bridge.Name)[7:], testDigest("service/" + bridge.Name)[7:]
		dialerAddress, _ := Slice6DesiredServiceEndpointAddress(bridge.Name, bridge.Principals[0])
		serviceAddress, _ := Slice6DesiredServiceEndpointAddress(bridge.Name, bridge.ExternalServices[0])
		observed := NetworkObservation{Name: bridge.Name, ContainerIDs: []string{dialerID, serviceID},
			Endpoints: []NetworkEndpointObservation{{ContainerID: dialerID, IPv4Address: dialerAddress},
				{ContainerID: serviceID, IPv4Address: serviceAddress}}}
		slices.Sort(observed.ContainerIDs)
		if err := VerifySlice6DesiredServiceBridgeObservation(bridge, observed, dialerID, serviceID); err != nil {
			t.Fatalf("reviewed service endpoint %s rejected: %v", bridge.Name, err)
		}
		observed.ContainerIDs[1] = testDigest("substituted-container")[7:]
		if VerifySlice6DesiredServiceBridgeObservation(bridge, observed, dialerID, serviceID) == nil {
			t.Fatalf("service container identity substitution admitted on %s", bridge.Name)
		}
		observed.ContainerIDs = []string{dialerID, serviceID}
		slices.Sort(observed.ContainerIDs)
		observed.Endpoints[1].IPv4Address = dialerAddress
		if VerifySlice6DesiredServiceBridgeObservation(bridge, observed, dialerID, serviceID) == nil {
			t.Fatalf("service endpoint substitution admitted on %s", bridge.Name)
		}
	}
}
