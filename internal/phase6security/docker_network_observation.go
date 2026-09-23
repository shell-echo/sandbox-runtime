package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
)

// ObserveDockerNetwork extracts a strict, bounded projection from one raw
// `docker network inspect` response. The caller retains the raw bytes under
// InspectDigest; this projection alone is not proof of active socket denial.
func ObserveDockerNetwork(document []byte, expected Network, containerIDs map[string]string) (NetworkObservation, error) {
	if len(document) < 1 || len(document) > maxBytes || rejectDuplicateMembers(document) != nil ||
		len(containerIDs) != len(expected.Principals) ||
		(expected.GatewayModeIPv4 != "isolated" && expected.GatewayModeIPv4 != "nat") {
		return NetworkObservation{}, ErrInvalidObservation
	}
	var values []struct {
		Name       string
		ID         string `json:"Id"`
		Driver     string
		Scope      string
		Internal   bool
		Attachable bool
		Ingress    bool
		EnableIPv4 bool
		EnableIPv6 bool
		Options    map[string]string
		IPAM       struct {
			Config []struct{ Subnet, Gateway string }
		}
		Containers map[string]struct {
			IPv4Address string
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	if decoder.Decode(&values) != nil || len(values) != 1 {
		return NetworkObservation{}, ErrInvalidObservation
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return NetworkObservation{}, ErrInvalidObservation
	}
	value := values[0]
	if value.Name != expected.Name || !containerIDPattern.MatchString(value.ID) || value.Driver != "bridge" ||
		value.Scope != "local" || value.Internal != expected.Internal || value.Attachable || value.Ingress ||
		!value.EnableIPv4 || value.EnableIPv6 || len(value.IPAM.Config) != 1 ||
		value.Options["com.docker.network.bridge.gateway_mode_ipv4"] != expected.GatewayModeIPv4 ||
		len(value.Containers) != len(expected.Principals) ||
		!validObservedSubnet(value.IPAM.Config[0].Subnet, value.IPAM.Config[0].Gateway) ||
		value.IPAM.Config[0].Subnet != expected.IPv4Subnet ||
		(expected.GatewayModeIPv4 == "isolated" && value.IPAM.Config[0].Gateway != "") ||
		(expected.GatewayModeIPv4 == "nat" && value.IPAM.Config[0].Gateway == "") {
		return NetworkObservation{}, ErrInvalidObservation
	}
	for key, option := range value.Options {
		switch key {
		case "com.docker.network.bridge.gateway_mode_ipv4":
			if option != expected.GatewayModeIPv4 {
				return NetworkObservation{}, ErrInvalidObservation
			}
		case "com.docker.network.enable_ipv4":
			if option != "true" {
				return NetworkObservation{}, ErrInvalidObservation
			}
		case "com.docker.network.enable_ipv6":
			if option != "false" {
				return NetworkObservation{}, ErrInvalidObservation
			}
		default:
			return NetworkObservation{}, ErrInvalidObservation
		}
	}
	memberIDs := make([]string, 0, len(containerIDs))
	endpoints := make([]NetworkEndpointObservation, 0, len(containerIDs))
	subnet, err := netip.ParsePrefix(value.IPAM.Config[0].Subnet)
	if err != nil {
		return NetworkObservation{}, ErrInvalidObservation
	}
	for _, name := range expected.Principals {
		ID, ok := containerIDs[name]
		if !ok || !containerIDPattern.MatchString(ID) {
			return NetworkObservation{}, ErrInvalidObservation
		}
		member, exists := value.Containers[ID]
		if !exists {
			return NetworkObservation{}, ErrInvalidObservation
		}
		address, parseErr := netip.ParsePrefix(member.IPv4Address)
		if parseErr != nil || !address.Addr().Is4() || address.Bits() != subnet.Bits() ||
			!subnet.Contains(address.Addr()) || member.IPv4Address != address.String() {
			return NetworkObservation{}, ErrInvalidObservation
		}
		memberIDs = append(memberIDs, ID)
		endpoints = append(endpoints, NetworkEndpointObservation{ContainerID: ID, IPv4Address: address.Addr().String()})
	}
	sort.Strings(memberIDs)
	sort.Slice(endpoints, func(i, j int) bool { return endpoints[i].ContainerID < endpoints[j].ContainerID })
	if !validNetworkEndpoints(endpoints, memberIDs, value.IPAM.Config[0].Subnet, value.IPAM.Config[0].Gateway) {
		return NetworkObservation{}, ErrInvalidObservation
	}
	digest := sha256.Sum256(document)
	return NetworkObservation{Name: value.Name, NetworkID: value.ID,
		InspectDigest: "sha256:" + hex.EncodeToString(digest[:]), Driver: value.Driver,
		Internal: value.Internal, IPv6Enabled: value.EnableIPv6,
		GatewayModeIPv4: expected.GatewayModeIPv4, Subnet: value.IPAM.Config[0].Subnet,
		HostGateway: value.IPAM.Config[0].Gateway, ContainerIDs: memberIDs, Endpoints: endpoints}, nil
}
