package phase6security

import (
	"net/netip"
	"slices"
	"sort"
	"strconv"
)

// Slice6DesiredServiceBridges allocates the 28 approved dialer/service paths
// without shifting the previously reviewed role-network CIDRs. This is a
// pre-freeze desired plan, not an observed or activated Docker network.
func Slice6DesiredServiceBridges() []Network {
	paths := Slice6DesiredExecutableExternalTransports()
	old := Slice6DesiredNetworks()
	bridges := make([]Network, 0, len(paths))
	ordinal := 0
	for _, path := range paths {
		if path.Network == "network-certificate-controller" {
			for _, network := range old {
				if network.Name == path.Network {
					network.ExternalServices = []string{path.Service}
					bridges = append(bridges, network)
				}
			}
			continue
		}
		bridges = append(bridges, Network{Name: path.Network, Kind: "trust_edge", Internal: true,
			GatewayModeIPv4: "isolated", IPv4Subnet: "172.31." + strconv.Itoa(128+ordinal) + ".0/24",
			Principals: []string{path.Dialer}, ExternalServices: []string{path.Service}})
		ordinal++
	}
	sort.Slice(bridges, func(i, j int) bool { return bridges[i].Name < bridges[j].Name })
	return bridges
}

// Slice6DesiredServiceEndpointAddress fixes .2 for the dialer and .3 for the
// external member; neither address may be copied from a Docker observation.
func Slice6DesiredServiceEndpointAddress(networkName, member string) (string, error) {
	for _, network := range Slice6DesiredServiceBridges() {
		if network.Name != networkName {
			continue
		}
		var offset byte
		switch {
		case slices.Contains(network.Principals, member):
			offset = 2
		case slices.Contains(network.ExternalServices, member):
			offset = 3
		default:
			return "", errSlice6DesiredInventory
		}
		prefix, err := netip.ParsePrefix(network.IPv4Subnet)
		if err != nil || prefix.Bits() != 24 || !prefix.Addr().Is4() {
			return "", errSlice6DesiredInventory
		}
		address := prefix.Addr().As4()
		address[3] = offset
		return netip.AddrFrom4(address).String(), nil
	}
	return "", errSlice6DesiredInventory
}

func VerifySlice6DesiredServiceBridges(bridges []Network) error {
	wanted := Slice6DesiredServiceBridges()
	if VerifySlice6DesiredExecutableExternalTransports(Slice6DesiredExecutableExternalTransports()) != nil ||
		len(bridges) != 28 || !slices.EqualFunc(bridges, wanted, func(left, right Network) bool {
		return left.Name == right.Name && left.Kind == right.Kind && left.Internal == right.Internal &&
			left.GatewayModeIPv4 == right.GatewayModeIPv4 && left.IPv4Subnet == right.IPv4Subnet &&
			!left.IPv6Enabled && slices.Equal(left.Principals, right.Principals) &&
			slices.Equal(left.ExternalServices, right.ExternalServices)
	}) {
		return errSlice6DesiredInventory
	}
	return nil
}

// VerifySlice6DesiredServiceBridgeObservation is an additional comparison
// after the raw Docker inspect is parsed. It never accepts Docker's observed
// addresses as the source of the desired .2/.3 allocation.
func VerifySlice6DesiredServiceBridgeObservation(expected Network, observed NetworkObservation,
	dialerContainerID, serviceContainerID string) error {
	approved := false
	for _, bridge := range Slice6DesiredServiceBridges() {
		if bridge.Name == expected.Name {
			approved = bridge.Name == expected.Name && bridge.Kind == expected.Kind &&
				bridge.Internal == expected.Internal && bridge.GatewayModeIPv4 == expected.GatewayModeIPv4 &&
				bridge.IPv4Subnet == expected.IPv4Subnet && !expected.IPv6Enabled &&
				slices.Equal(bridge.Principals, expected.Principals) &&
				slices.Equal(bridge.ExternalServices, expected.ExternalServices)
			break
		}
	}
	if !approved || observed.Name != expected.Name || len(expected.Principals) != 1 ||
		len(expected.ExternalServices) != 1 || !containerIDPattern.MatchString(dialerContainerID) ||
		!containerIDPattern.MatchString(serviceContainerID) || dialerContainerID == serviceContainerID ||
		len(observed.Endpoints) != 2 || len(observed.ContainerIDs) != 2 {
		return errSlice6DesiredInventory
	}
	wantedIDs := []string{dialerContainerID, serviceContainerID}
	sort.Strings(wantedIDs)
	if !slices.Equal(observed.ContainerIDs, wantedIDs) {
		return errSlice6DesiredInventory
	}
	dialerAddress, dialerErr := Slice6DesiredServiceEndpointAddress(expected.Name, expected.Principals[0])
	serviceAddress, serviceErr := Slice6DesiredServiceEndpointAddress(expected.Name, expected.ExternalServices[0])
	if dialerErr != nil || serviceErr != nil ||
		!networkHasEndpoint(observed, dialerContainerID, dialerAddress) ||
		!networkHasEndpoint(observed, serviceContainerID, serviceAddress) {
		return errSlice6DesiredInventory
	}
	return nil
}
