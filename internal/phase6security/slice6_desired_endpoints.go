package phase6security

import (
	"net/netip"
	"slices"
)

// Slice6DesiredEndpointAddress assigns one stable non-gateway IPv4 address
// within the reviewed /24 to a declared member. It never reads a Docker
// allocation and therefore cannot accept a post hoc endpoint as desired.
func Slice6DesiredEndpointAddress(networkName, deployment string) (string, error) {
	for _, network := range Slice6DesiredNetworks() {
		if network.Name != networkName {
			continue
		}
		index := slices.Index(network.Principals, deployment)
		if index < 0 || index > 249 {
			return "", errSlice6DesiredInventory
		}
		prefix, err := netip.ParsePrefix(network.IPv4Subnet)
		if err != nil || prefix.Bits() != 24 || !prefix.Addr().Is4() {
			return "", errSlice6DesiredInventory
		}
		address := prefix.Addr().As4()
		address[3] = byte(index + 2)
		return netip.AddrFrom4(address).String(), nil
	}
	return "", errSlice6DesiredInventory
}

// VerifySlice6DesiredEndpointObservation is an additional independent
// comparison after ObserveDockerNetwork has parsed the original raw inspect.
// The caller supplies actual container IDs from separate container inspection.
func VerifySlice6DesiredEndpointObservation(expected Network, observed NetworkObservation, containerIDs map[string]string) error {
	approved := false
	for _, network := range Slice6DesiredNetworks() {
		if network.Name == expected.Name {
			approved = network.Kind == expected.Kind && network.Internal == expected.Internal &&
				!expected.IPv6Enabled && network.GatewayModeIPv4 == expected.GatewayModeIPv4 &&
				network.IPv4Subnet == expected.IPv4Subnet && slices.Equal(network.Principals, expected.Principals)
			break
		}
	}
	if !approved || expected.Name != observed.Name || len(expected.Principals) != len(containerIDs) ||
		len(observed.Endpoints) != len(expected.Principals) {
		return errSlice6DesiredInventory
	}
	for _, deployment := range expected.Principals {
		address, err := Slice6DesiredEndpointAddress(expected.Name, deployment)
		if err != nil || !networkHasEndpoint(observed, containerIDs[deployment], address) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
