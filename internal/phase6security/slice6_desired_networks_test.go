package phase6security

import (
	"slices"
	"strings"
	"testing"
)

func TestSlice6ReviewedNetworkGraphMatchesClosedProfileShape(t *testing.T) {
	fixture := validProfile()
	if err := VerifySlice6DesiredPrincipalIDs(fixture); err != nil {
		t.Fatalf("reviewed UID/GID partitions and closed profile fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredNetworkGraph(fixture); err != nil {
		t.Fatalf("reviewed graph and closed profile fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredNetworks(fixture); err == nil {
		t.Fatal("synthetic fixture CIDRs were admitted as the real desired plan")
	}
	planned := Slice6DesiredNetworks()
	if len(planned) != len(fixture.Networks) || len(planned) < 30 {
		t.Fatal("desired network inventory is incomplete")
	}
	for index, network := range planned {
		if network.Name != fixture.Networks[index].Name || network.Kind != fixture.Networks[index].Kind ||
			!slices.Equal(network.Principals, fixture.Networks[index].Principals) {
			t.Fatalf("network %d differs from frozen routing shape", index)
		}
	}
	broadened := fixture
	broadened.Networks = append([]Network(nil), fixture.Networks...)
	for index := range broadened.Networks {
		if broadened.Networks[index].Name == "product-internal" {
			broadened.Networks[index].Kind = "trust_edge"
			break
		}
	}
	broadened.ProfileDigest = broadened.Digest()
	if err := VerifySlice6DesiredNetworkGraph(broadened); err == nil {
		t.Fatal("self-consistent broadened network kind was admitted")
	}
	if err := VerifySlice6DesiredNetworkGraph(Profile{}); err == nil {
		t.Fatal("missing profile was admitted")
	}
	changedID := fixture
	changedID.Principals = append([]Principal(nil), fixture.Principals...)
	changedID.Principals[0].UID = 25000
	changedID.ProfileDigest = changedID.Digest()
	if err := VerifySlice6DesiredPrincipalIDs(changedID); err == nil {
		t.Fatal("changed expected container UID was admitted")
	}
}

func TestSlice6DesiredEndpointPlanIsIndependentOfObservedAddress(t *testing.T) {
	var edge Network
	for _, network := range Slice6DesiredNetworks() {
		if network.Name == "guest-product" {
			edge = network
		}
	}
	if edge.Name == "" || !slices.Equal(edge.Principals, []string{"guest-runtime", "product-runtime"}) {
		t.Fatal("reviewed Guest/Product edge is absent")
	}
	guestAddress, err := Slice6DesiredEndpointAddress(edge.Name, "guest-runtime")
	if err != nil {
		t.Fatal(err)
	}
	productAddress, err := Slice6DesiredEndpointAddress(edge.Name, "product-runtime")
	if err != nil || guestAddress == productAddress {
		t.Fatal("reviewed Guest/Product endpoint allocation is invalid")
	}
	guestID, productID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	observed := NetworkObservation{Name: edge.Name, Endpoints: []NetworkEndpointObservation{
		{ContainerID: guestID, IPv4Address: guestAddress},
		{ContainerID: productID, IPv4Address: productAddress},
	}}
	actualIDs := map[string]string{"guest-runtime": guestID, "product-runtime": productID}
	if err := VerifySlice6DesiredEndpointObservation(edge, observed, actualIDs); err != nil {
		t.Fatalf("exact endpoint projection rejected: %v", err)
	}
	observed.Endpoints[1].IPv4Address = guestAddress
	if err := VerifySlice6DesiredEndpointObservation(edge, observed, actualIDs); err == nil {
		t.Fatal("post hoc observed endpoint substitution was admitted")
	}
	if _, err := Slice6DesiredEndpointAddress(edge.Name, "undeclared-role"); err == nil {
		t.Fatal("undeclared deployment received an endpoint")
	}
}
