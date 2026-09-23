package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
)

var ErrInvalidObservation = errors.New("invalid Phase 6 security observation")
var containerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type ObservationSet struct {
	ProfileDigest                          string                 `json:"profile_digest"`
	Containers                             []ContainerObservation `json:"containers"`
	Networks                               []NetworkObservation   `json:"networks"`
	DistinctContainerUIDGIDEstablished     bool                   `json:"distinct_container_uid_gid_established"`
	ContainerNamespaceIsolationEstablished bool                   `json:"container_namespace_isolation_established"`
	HostUserNamespaceMappingEstablished    bool                   `json:"host_user_namespace_mapping_established"`
	PlatformServiceAccountEstablished      bool                   `json:"platform_service_account_established"`
	SameHostLocalContainerGate             bool                   `json:"same_host_local_container_gate"`
}

type NetworkObservation struct {
	Name            string                       `json:"name"`
	NetworkID       string                       `json:"network_id"`
	InspectDigest   string                       `json:"inspect_digest"`
	Driver          string                       `json:"driver"`
	Internal        bool                         `json:"internal"`
	IPv6Enabled     bool                         `json:"ipv6_enabled"`
	GatewayModeIPv4 string                       `json:"gateway_mode_ipv4"`
	Subnet          string                       `json:"subnet"`
	HostGateway     string                       `json:"host_gateway"`
	ContainerIDs    []string                     `json:"container_ids"`
	Endpoints       []NetworkEndpointObservation `json:"endpoints"`
}

type NetworkEndpointObservation struct {
	ContainerID string `json:"container_id"`
	IPv4Address string `json:"ipv4_address"`
}

type PublishedPortObservation struct {
	Protocol      string `json:"protocol"`
	ContainerPort int    `json:"container_port"`
	HostAddress   string `json:"host_address"`
	HostPort      int    `json:"host_port"`
}

type ContainerObservation struct {
	DeploymentName             string                     `json:"deployment_name"`
	PrincipalDigest            string                     `json:"principal_digest"`
	ControllingPrincipalDigest string                     `json:"controlling_principal_digest"`
	ContainerID                string                     `json:"container_id"`
	ImageReference             string                     `json:"image_reference"`
	ImageDigest                string                     `json:"image_digest"`
	ProcessUID                 uint32                     `json:"process_uid"`
	ProcessGID                 uint32                     `json:"process_gid"`
	ReadOnlyRootFilesystem     bool                       `json:"read_only_root_filesystem"`
	NoNewPrivileges            bool                       `json:"no_new_privileges"`
	DroppedCapabilities        []string                   `json:"dropped_capabilities"`
	AddedCapabilities          []string                   `json:"added_capabilities"`
	SeccompDigest              string                     `json:"seccomp_digest"`
	Resources                  Resources                  `json:"resources"`
	Networks                   []string                   `json:"networks"`
	Mounts                     []ObservedMount            `json:"mounts"`
	Listeners                  []Listener                 `json:"listeners"`
	PublishedPorts             []PublishedPortObservation `json:"published_ports"`
	HostNetwork                bool                       `json:"host_network"`
	Privileged                 bool                       `json:"privileged"`
	DockerSocket               bool                       `json:"docker_socket"`
	HostDevices                bool                       `json:"host_devices"`
	ProxyEnvironmentPresent    bool                       `json:"proxy_environment_present"`
	RootWriteDenied            bool                       `json:"root_write_denied"`
	PrivilegeEscalationDenied  bool                       `json:"privilege_escalation_denied"`
	PIDExhaustionDenied        bool                       `json:"pid_exhaustion_denied"`
	MemoryExhaustionDenied     bool                       `json:"memory_exhaustion_denied"`
	CPUQuotaObserved           bool                       `json:"cpu_quota_observed"`
	DirectEgressDenied         bool                       `json:"direct_egress_denied"`
	ExternalUplinkObserved     bool                       `json:"external_uplink_observed"`
	NamespaceIsolated          bool                       `json:"namespace_isolated"`
	ExactCleanupObserved       bool                       `json:"exact_cleanup_observed"`
}

type ObservedMount struct {
	Target    string `json:"target"`
	Kind      string `json:"kind"`
	ReadOnly  bool   `json:"read_only"`
	MaxBytes  int64  `json:"max_bytes"`
	StorageID string `json:"storage_id"`
}

func DecodeObservations(document []byte, profile Profile) (ObservationSet, error) {
	if len(document) < 1 || len(document) > maxBytes || rejectDuplicateMembers(document) != nil {
		return ObservationSet{}, ErrInvalidObservation
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var observations ObservationSet
	if decoder.Decode(&observations) != nil {
		return ObservationSet{}, ErrInvalidObservation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ObservationSet{}, ErrInvalidObservation
	}
	canonical, err := json.Marshal(observations)
	if err != nil || !bytes.Equal(canonical, document) || ValidateObservations(profile, observations) != nil {
		return ObservationSet{}, ErrInvalidObservation
	}
	return observations, nil
}

func ValidateObservations(profile Profile, observations ObservationSet) error { //nolint:gocyclo
	if profile.Validate() != nil || observations.ProfileDigest != profile.ProfileDigest ||
		!observations.DistinctContainerUIDGIDEstablished || !observations.ContainerNamespaceIsolationEstablished ||
		observations.HostUserNamespaceMappingEstablished || observations.PlatformServiceAccountEstablished ||
		!observations.SameHostLocalContainerGate ||
		len(observations.Containers) != len(profile.Principals) || len(observations.Networks) != len(profile.Networks) {
		return ErrInvalidObservation
	}
	profiles := make(map[string]Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		profiles[principal.Name] = principal
	}
	seen := make(map[string]struct{}, len(observations.Containers))
	containerByDeployment := make(map[string]string, len(observations.Containers))
	containerIDs := make(map[string]struct{}, len(observations.Containers))
	uid, gid := make(map[uint32]struct{}), make(map[uint32]struct{})
	previous := ""
	for _, observation := range observations.Containers {
		expected, ok := profiles[observation.DeploymentName]
		if !ok || observation.DeploymentName <= previous || validateContainerObservation(expected, observation) != nil {
			return ErrInvalidObservation
		}
		previous = observation.DeploymentName
		if _, duplicate := seen[observation.DeploymentName]; duplicate {
			return ErrInvalidObservation
		}
		if _, duplicate := containerIDs[observation.ContainerID]; duplicate {
			return ErrInvalidObservation
		}
		if _, duplicate := uid[observation.ProcessUID]; duplicate {
			return ErrInvalidObservation
		}
		if _, duplicate := gid[observation.ProcessGID]; duplicate {
			return ErrInvalidObservation
		}
		seen[observation.DeploymentName], containerIDs[observation.ContainerID] = struct{}{}, struct{}{}
		containerByDeployment[observation.DeploymentName] = observation.ContainerID
		uid[observation.ProcessUID], gid[observation.ProcessGID] = struct{}{}, struct{}{}
	}
	networkIDs := make(map[string]struct{}, len(observations.Networks))
	for index, observation := range observations.Networks {
		expected := profile.Networks[index]
		if observation.Name != expected.Name || !containerIDPattern.MatchString(observation.NetworkID) ||
			!digestPattern.MatchString(observation.InspectDigest) ||
			observation.Driver != "bridge" || observation.Internal != expected.Internal ||
			observation.IPv6Enabled || observation.GatewayModeIPv4 != expected.GatewayModeIPv4 ||
			observation.Subnet != expected.IPv4Subnet ||
			len(observation.ContainerIDs) != len(expected.Principals) {
			return ErrInvalidObservation
		}
		if _, duplicate := networkIDs[observation.NetworkID]; duplicate {
			return ErrInvalidObservation
		}
		networkIDs[observation.NetworkID] = struct{}{}
		expectedIDs := make([]string, len(expected.Principals))
		for memberIndex, name := range expected.Principals {
			expectedIDs[memberIndex] = containerByDeployment[name]
		}
		sort.Strings(expectedIDs)
		if !exactStrings(observation.ContainerIDs, expectedIDs) ||
			!validNetworkEndpoints(observation.Endpoints, expectedIDs, observation.Subnet, observation.HostGateway) ||
			!validObservedSubnet(observation.Subnet, observation.HostGateway) ||
			(expected.GatewayModeIPv4 == "isolated" && observation.HostGateway != "") ||
			(expected.GatewayModeIPv4 == "nat" && (net.ParseIP(observation.HostGateway) == nil || net.ParseIP(observation.HostGateway).To4() == nil)) {
			return ErrInvalidObservation
		}
	}
	if validateIngressObservations(profile, observations, containerByDeployment) != nil {
		return ErrInvalidObservation
	}
	return nil
}

func validNetworkEndpoints(endpoints []NetworkEndpointObservation, ids []string, subnet, gateway string) bool {
	if len(endpoints) != len(ids) {
		return false
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return false
	}
	for index, endpoint := range endpoints {
		address, err := netip.ParseAddr(endpoint.IPv4Address)
		if endpoint.ContainerID != ids[index] || err != nil || !address.Is4() ||
			address.String() != endpoint.IPv4Address || !prefix.Contains(address) ||
			address == prefix.Addr() || address == ipv4Broadcast(prefix) ||
			address.String() == gateway {
			return false
		}
	}
	addresses := make([]string, len(endpoints))
	for index, endpoint := range endpoints {
		addresses[index] = endpoint.IPv4Address
	}
	slices.Sort(addresses)
	for index := 1; index < len(addresses); index++ {
		if addresses[index] == addresses[index-1] {
			return false
		}
	}
	return true
}

func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().As4()
	for bit := prefix.Bits(); bit < 32; bit++ {
		bytes[bit/8] |= byte(1 << (7 - bit%8))
	}
	return netip.AddrFrom4(bytes)
}

func validateIngressObservations(profile Profile, observations ObservationSet, containerIDs map[string]string) error {
	containers := make(map[string]ContainerObservation, len(observations.Containers))
	for _, container := range observations.Containers {
		containers[container.DeploymentName] = container
		if container.DeploymentName != "public-ingress-relay" && len(container.PublishedPorts) != 0 {
			return ErrInvalidObservation
		}
	}
	if len(containers["public-ingress-relay"].PublishedPorts) != len(profile.IngressBindings) {
		return ErrInvalidObservation
	}
	networks := make(map[string]NetworkObservation, len(observations.Networks))
	for _, network := range observations.Networks {
		networks[network.Name] = network
	}
	for index, binding := range profile.IngressBindings {
		frontend, frontendErr := netip.ParseAddrPort(binding.FrontendAddress)
		upstream, upstreamErr := netip.ParseAddrPort(binding.UpstreamAddress)
		host, hostErr := netip.ParseAddrPort(binding.HostBindAddress)
		if frontendErr != nil || upstreamErr != nil || hostErr != nil {
			return ErrInvalidObservation
		}
		publication := containers["public-ingress-relay"].PublishedPorts[index]
		if publication != (PublishedPortObservation{Protocol: "tcp", ContainerPort: int(frontend.Port()),
			HostAddress: host.Addr().String(), HostPort: int(host.Port())}) ||
			!networkHasEndpoint(networks[binding.FrontendNetwork], containerIDs[binding.Relay], frontend.Addr().String()) ||
			!networkHasEndpoint(networks[binding.TrustNetwork], containerIDs[binding.Target], upstream.Addr().String()) {
			return ErrInvalidObservation
		}
	}
	return nil
}

func networkHasEndpoint(network NetworkObservation, containerID, address string) bool {
	for _, endpoint := range network.Endpoints {
		if endpoint.ContainerID == containerID && endpoint.IPv4Address == address {
			return true
		}
	}
	return false
}

func validObservedSubnet(subnet, gateway string) bool {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Masked() != prefix || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return false
	}
	if gateway == "" {
		return true
	}
	address, err := netip.ParseAddr(gateway)
	return err == nil && address.Is4() && prefix.Contains(address) && address != prefix.Addr()
}

func validateContainerObservation(expected Principal, actual ContainerObservation) error { //nolint:gocyclo
	if !containerIDPattern.MatchString(actual.ContainerID) || actual.PrincipalDigest != expected.PrincipalDigest ||
		actual.ControllingPrincipalDigest != expected.ControllingPrincipalDigest ||
		actual.ImageReference != expected.ImageReference || actual.ImageDigest != expected.ImageDigest ||
		actual.ProcessUID != expected.UID || actual.ProcessGID != expected.GID || !actual.ReadOnlyRootFilesystem || !actual.NoNewPrivileges ||
		!exactStrings(actual.DroppedCapabilities, expected.DroppedCapabilities) || len(actual.AddedCapabilities) != 0 ||
		actual.SeccompDigest != expected.SeccompDigest || actual.Resources != expected.Resources ||
		!exactStrings(actual.Networks, expected.Networks) || !equalObservedMounts(actual.Mounts, expected.Mounts) ||
		!equalListeners(actual.Listeners, expected.Listeners) || actual.HostNetwork || actual.Privileged || actual.DockerSocket ||
		actual.HostDevices || actual.ProxyEnvironmentPresent || !actual.RootWriteDenied || !actual.PrivilegeEscalationDenied ||
		!actual.PIDExhaustionDenied || !actual.MemoryExhaustionDenied || !actual.CPUQuotaObserved || !actual.NamespaceIsolated ||
		!actual.ExactCleanupObserved {
		return ErrInvalidObservation
	}
	if expected.Kind == "egress_broker" || expected.Kind == "ingress_relay" {
		if actual.DirectEgressDenied || !actual.ExternalUplinkObserved {
			return ErrInvalidObservation
		}
	} else if !actual.DirectEgressDenied || actual.ExternalUplinkObserved {
		return ErrInvalidObservation
	}
	return nil
}

func equalObservedMounts(actual []ObservedMount, expected []Mount) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != (ObservedMount{Target: expected[index].Target, Kind: expected[index].Kind,
			ReadOnly: expected[index].ReadOnly, MaxBytes: expected[index].MaxBytes, StorageID: expected[index].StorageID}) {
			return false
		}
	}
	return true
}

func equalListeners(actual, expected []Listener) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func SortedObservations(values []ContainerObservation) []ContainerObservation {
	result := append([]ContainerObservation(nil), values...)
	sort.Slice(result, func(first, second int) bool { return result[first].DeploymentName < result[second].DeploymentName })
	return result
}
