//go:build phase6slice6gate

package productphase6gate

import (
	"strings"
	"testing"
)

func TestSlice6GuestRuntimeCreatedNetworksCheckRequestedTwoEdges(t *testing.T) {
	plan, productID, internalID := slice6GuestRuntimeNetworkTestTargets()
	product := slice6MigrationNetworkEndpoint{}
	product.IPAMConfig.IPv4Address = plan.ProductIP
	internal := slice6MigrationNetworkEndpoint{}
	internal.IPAMConfig.IPv4Address = plan.InternalIP
	for _, keys := range [][2]string{
		{plan.ProductNetwork.Name, plan.InternalNetwork.Name},
		{productID, internalID},
		{plan.ProductNetwork.Name, internalID},
		{productID, plan.InternalNetwork.Name},
	} {
		if err := slice6ValidateGuestRuntimeCreatedNetworks(
			map[string]slice6MigrationNetworkEndpoint{keys[0]: product, keys[1]: internal},
			plan, productID, internalID); err != nil {
			t.Fatalf("created network keys %q rejected: %v", keys, err)
		}
	}
	product.NetworkID, internal.NetworkID = productID, internalID
	if err := slice6ValidateGuestRuntimeCreatedNetworks(
		map[string]slice6MigrationNetworkEndpoint{plan.ProductNetwork.Name: product,
			plan.InternalNetwork.Name: internal}, plan, productID, internalID); err != nil {
		t.Fatalf("created endpoints with already assigned effective IDs rejected: %v", err)
	}
	wrongProductID := product
	wrongProductID.NetworkID = internalID
	wrongProductIP := product
	wrongProductIP.IPAMConfig.IPv4Address = plan.InternalIP
	wrongInternalID := internal
	wrongInternalID.NetworkID = productID
	wrongInternalIP := internal
	wrongInternalIP.IPAMConfig.IPv4Address = plan.ProductIP
	for label, networks := range map[string]map[string]slice6MigrationNetworkEndpoint{
		"missing":           {plan.ProductNetwork.Name: product},
		"unknown":           {plan.ProductNetwork.Name: product, "other": internal},
		"duplicate":         {plan.ProductNetwork.Name: product, productID: product},
		"swapped":           {plan.ProductNetwork.Name: internal, plan.InternalNetwork.Name: product},
		"wrong-product-id":  {plan.ProductNetwork.Name: wrongProductID, plan.InternalNetwork.Name: internal},
		"wrong-product-ip":  {plan.ProductNetwork.Name: wrongProductIP, plan.InternalNetwork.Name: internal},
		"wrong-internal-id": {plan.ProductNetwork.Name: product, plan.InternalNetwork.Name: wrongInternalID},
		"wrong-internal-ip": {plan.ProductNetwork.Name: product, plan.InternalNetwork.Name: wrongInternalIP},
	} {
		if err := slice6ValidateGuestRuntimeCreatedNetworks(networks, plan, productID, internalID); err == nil {
			t.Fatalf("created Guest admitted %s network drift", label)
		}
	}
}

func TestSlice6GuestRuntimeRunningNetworksRequireEffectiveTwoEdges(t *testing.T) {
	plan, productID, internalID := slice6GuestRuntimeNetworkTestTargets()
	product := slice6GuestFixtureRunningEndpoint{NetworkID: productID, IPAddress: plan.ProductIP}
	product.IPAMConfig.IPv4Address = plan.ProductIP
	internal := slice6GuestFixtureRunningEndpoint{NetworkID: internalID, IPAddress: plan.InternalIP}
	internal.IPAMConfig.IPv4Address = plan.InternalIP
	for _, keys := range [][2]string{
		{plan.ProductNetwork.Name, plan.InternalNetwork.Name},
		{productID, internalID},
		{plan.ProductNetwork.Name, internalID},
		{productID, plan.InternalNetwork.Name},
	} {
		if err := slice6ValidateGuestRuntimeRunningNetworks(
			map[string]slice6GuestFixtureRunningEndpoint{keys[0]: product, keys[1]: internal},
			plan, productID, internalID); err != nil {
			t.Fatalf("running network keys %q rejected: %v", keys, err)
		}
	}
	missingID := product
	missingID.NetworkID = ""
	missingIP := product
	missingIP.IPAddress = ""
	wrongRequest := product
	wrongRequest.IPAMConfig.IPv4Address = plan.InternalIP
	wrongInternalID := internal
	wrongInternalID.NetworkID = productID
	wrongInternalIP := internal
	wrongInternalIP.IPAddress = plan.ProductIP
	for label, networks := range map[string]map[string]slice6GuestFixtureRunningEndpoint{
		"missing":           {plan.ProductNetwork.Name: product},
		"unknown":           {plan.ProductNetwork.Name: product, "other": internal},
		"duplicate":         {plan.ProductNetwork.Name: product, productID: product},
		"swapped":           {plan.ProductNetwork.Name: internal, plan.InternalNetwork.Name: product},
		"missing-id":        {plan.ProductNetwork.Name: missingID, plan.InternalNetwork.Name: internal},
		"missing-ip":        {plan.ProductNetwork.Name: missingIP, plan.InternalNetwork.Name: internal},
		"wrong-request":     {plan.ProductNetwork.Name: wrongRequest, plan.InternalNetwork.Name: internal},
		"wrong-internal-id": {plan.ProductNetwork.Name: product, plan.InternalNetwork.Name: wrongInternalID},
		"wrong-internal-ip": {plan.ProductNetwork.Name: product, plan.InternalNetwork.Name: wrongInternalIP},
	} {
		if err := slice6ValidateGuestRuntimeRunningNetworks(networks, plan, productID, internalID); err == nil {
			t.Fatalf("running Guest admitted %s network drift", label)
		}
	}
}

func slice6GuestRuntimeNetworkTestTargets() (slice6GuestRuntimeLaunchPlan, string, string) {
	plan := slice6GuestRuntimeLaunchPlan{}
	plan.ProductNetwork.Name = "guest-product"
	plan.InternalNetwork.Name = "network-guest-runtime"
	plan.ProductIP = "172.31.71.3"
	plan.InternalIP = "172.31.72.2"
	return plan, strings.Repeat("a", 64), strings.Repeat("b", 64)
}

func TestSlice6GuestRuntimeTmpfsIsExact(t *testing.T) {
	const options = "rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=20036,gid=30036"
	if !slice6GuestRuntimeTmpfsMatches(options, 20036, 30036) ||
		!slice6GuestRuntimeTmpfsMatches("gid=30036,uid=20036,mode=0700,size=8388608,nodev,nosuid,noexec,rw", 20036, 30036) {
		t.Fatal("Guest exact tmpfs option set rejected")
	}
	for _, value := range []string{
		"rw,noexec,nosuid,nodev,size=8388608,mode=0777,uid=20036,gid=30036",
		"rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=0,gid=30036",
		"rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=20036,gid=30036,exec",
		"rw,noexec,nosuid,nodev,size=8388608,mode=0700,uid=20036",
	} {
		if slice6GuestRuntimeTmpfsMatches(value, 20036, 30036) {
			t.Fatal("Guest unsafe tmpfs option set admitted")
		}
	}
}
