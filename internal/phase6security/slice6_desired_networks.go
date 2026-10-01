package phase6security

import (
	"errors"
	"slices"
	"sort"
	"strconv"
)

// Slice6DesiredNetworkInventoryVersion identifies the reviewed local-gate
// graph. It is desired configuration, never an observation of Docker state.
const Slice6DesiredNetworkInventoryVersion = 2

var errSlice6DesiredInventory = errors.New("Slice 6 desired inventory mismatch")

type slice6DesiredNetwork struct {
	name, kind string
	principals []string
}

func slice6ApprovedDeploymentNames() []string {
	all := make([]string, 0, len(slice6ApprovedDeploymentKinds))
	for name := range slice6ApprovedDeploymentKinds {
		all = append(all, name)
	}
	sort.Strings(all)
	return all
}

// The shared edges are explicitly reviewed; all other approved principals
// receive one dedicated isolated role network. No runtime inspection result
// participates in constructing this inventory.
var slice6SharedNetworks = []slice6DesiredNetwork{
	{"guest-product", "trust_edge", []string{"guest-runtime", "product-runtime"}},
	{"network-guest-runtime", "role_internal", []string{"guest-runtime"}},
	{"gateway-provider", "trust_edge", []string{"gateway-runtime", "provider-runtime"}},
	{"gateway-browser-action-ingress", "trust_edge", []string{"browser-action-ingress-runtime", "gateway-runtime"}},
	{"browser-action-ingress-provider", "trust_edge", []string{"browser-action-ingress-runtime", "provider-browser-runtime"}},
	{"network-browser-action-ingress-runtime", "role_internal", []string{"browser-action-ingress-runtime"}},
	{"gateway-provider-desktop", "trust_edge", []string{"gateway-runtime", "provider-desktop-runtime"}},
	{"network-provider-runtime", "role_internal", []string{"provider-runtime"}},
	{"network-provider-browser-runtime", "role_internal", []string{"provider-browser-runtime"}},
	{"network-provider-desktop-runtime", "role_internal", []string{"provider-desktop-runtime"}},
	{"product-provider", "trust_edge", []string{"product-runtime", "provider-runtime"}},
	{"product-provider-browser", "trust_edge", []string{"product-runtime", "provider-browser-runtime"}},
	{"product-provider-desktop", "trust_edge", []string{"product-runtime", "provider-desktop-runtime"}},
	{"provider-browser", "trust_edge", []string{"browser-runtime-role", "provider-browser-runtime"}},
	{"provider-desktop", "trust_edge", []string{"desktop-runtime-role", "provider-desktop-runtime"}},
	{"network-gateway-runtime", "role_internal", []string{"gateway-runtime"}},
	{"ingress-gateway", "trust_edge", []string{"gateway-runtime", "public-ingress-relay"}},
	{"ingress-product", "trust_edge", []string{"product-runtime", "public-ingress-relay"}},
	{"public-ingress", "public_ingress", []string{"public-ingress-relay"}},
	{"executor-browser", "trust_edge", []string{"browser-executor-backend", "browser-runtime-role"}},
	{"executor-desktop", "trust_edge", []string{"desktop-executor-backend", "desktop-runtime-role"}},
	{"external-uplink", "external_uplink", []string{"egress-broker-product"}},
	{"product-internal", "role_internal", []string{"egress-broker-product", "product-runtime"}},
	{"external-uplink-browser-action-ingress", "external_uplink", []string{"egress-broker-browser-action-ingress"}},
	{"external-uplink-gateway", "external_uplink", []string{"egress-broker-gateway"}},
	{"external-uplink-provider-browser", "external_uplink", []string{"egress-broker-provider-browser"}},
	{"external-uplink-provider-desktop", "external_uplink", []string{"egress-broker-provider-desktop"}},
	{"browser-action-ingress-internal", "role_internal", []string{"browser-action-ingress-runtime", "egress-broker-browser-action-ingress"}},
	{"gateway-internal", "role_internal", []string{"egress-broker-gateway", "gateway-runtime"}},
	{"provider-browser-internal", "role_internal", []string{"egress-broker-provider-browser", "provider-browser-runtime"}},
	{"provider-desktop-internal", "role_internal", []string{"egress-broker-provider-desktop", "provider-desktop-runtime"}},
}

// Slice6DesiredNetworks returns the full frozen graph with deterministic
// /24 CIDRs from its reviewed 172.31.0.0/16 local-gate allocation. A clash
// fails preflight; the gate must not widen an edge or pick a surprise subnet.
func Slice6DesiredNetworks() []Network {
	excluded := map[string]bool{}
	for _, edge := range slice6SharedNetworks {
		for _, name := range edge.principals {
			excluded[name] = true
		}
	}
	all := slice6ApprovedDeploymentNames()
	result := make([]Network, 0, len(all)+len(slice6SharedNetworks))
	materialSigners := make([]string, 0, 11)
	for _, name := range all {
		if _, added := slice6AdditionalDeploymentOrdinals[name]; added {
			continue
		}
		if subject := requiredTLSAgentSubjects[name]; requiredPrincipals[subject] == "material_agent" {
			materialSigners = append(materialSigners, name)
			continue
		}
		if !excluded[name] {
			result = append(result, Network{Name: "network-" + name, Kind: "role_internal", Internal: true,
				GatewayModeIPv4: "isolated", Principals: []string{name}})
		}
	}
	for _, edge := range slice6SharedNetworks {
		participants := append([]string(nil), edge.principals...)
		sort.Strings(participants)
		internal := edge.kind == "role_internal" || edge.kind == "trust_edge"
		mode := "nat"
		if internal {
			mode = "isolated"
		}
		result = append(result, Network{Name: edge.name, Kind: edge.kind, Internal: internal,
			GatewayModeIPv4: mode, Principals: participants})
	}
	// Preserve the old IPAM ordinals of every surviving bridge. These two
	// networks are sorting tombstones only; they are never returned or run.
	for _, name := range []string{"browser-agent", "desktop-agent"} {
		result = append(result, Network{Name: "network-" + name})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	for index := range result {
		result[index].IPv4Subnet = "172.31." + strconv.Itoa(index+1) + ".0/24"
	}
	active := result[:0]
	for _, network := range result {
		if network.Name != "network-browser-agent" && network.Name != "network-desktop-agent" {
			active = append(active, network)
		}
	}
	result = active
	// Material-agent signer principals were added after the first reviewed
	// role IPAM. Keep every old subnet unchanged and reserve 80-90 for their
	// dedicated isolated networks; service bridges start separately at 128.
	materialSigners = append(materialSigners, "browser-agent-tls-agent", "desktop-agent-tls-agent")
	sort.Strings(materialSigners)
	for index, name := range materialSigners {
		if name == "browser-agent-tls-agent" || name == "desktop-agent-tls-agent" {
			continue
		}
		result = append(result, Network{Name: "network-" + name, Kind: "role_internal", Internal: true,
			GatewayModeIPv4: "isolated", IPv4Subnet: "172.31." + strconv.Itoa(80+index) + ".0/24",
			Principals: []string{name}})
	}
	for name, ordinal := range slice6AdditionalDeploymentOrdinals {
		result = append(result, Network{Name: "network-" + name, Kind: "role_internal", Internal: true,
			GatewayModeIPv4: "isolated", IPv4Subnet: "172.31." + strconv.Itoa(91+ordinal) + ".0/24",
			Principals: []string{name}})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// VerifySlice6DesiredNetworkGraph is the preflight complement of
// Profile.Validate: the latter enforces a closed safe shape, while this
// function rejects a self-consistent but broadened expected graph.
func VerifySlice6DesiredNetworkGraph(profile Profile) error {
	if profile.Validate() != nil || len(profile.Principals) != len(slice6ApprovedDeploymentKinds) {
		return errSlice6DesiredInventory
	}
	names := make(map[string]bool, len(profile.Principals))
	for _, principal := range profile.Principals {
		if slice6ApprovedDeploymentKinds[principal.Name] != principal.Kind {
			return errSlice6DesiredInventory
		}
		names[principal.Name] = true
	}
	if len(names) != len(profile.Principals) {
		return errSlice6DesiredInventory
	}
	wanted := Slice6DesiredNetworks()
	if len(profile.Networks) != len(wanted) {
		return errSlice6DesiredInventory
	}
	for index, actual := range profile.Networks {
		expected := wanted[index]
		if actual.Name != expected.Name || actual.Kind != expected.Kind || actual.Internal != expected.Internal ||
			actual.IPv6Enabled || actual.GatewayModeIPv4 != expected.GatewayModeIPv4 ||
			!slices.Equal(actual.Principals, expected.Principals) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}

// VerifySlice6DesiredNetworks additionally freezes the reviewed /24 plan.
// The generator must resolve a real port/IPAM clash before this checkpoint,
// never after the application starts or by silently expanding its policy.
func VerifySlice6DesiredNetworks(profile Profile) error {
	if VerifySlice6DesiredNetworkGraph(profile) != nil {
		return errSlice6DesiredInventory
	}
	wanted := Slice6DesiredNetworks()
	for index, actual := range profile.Networks {
		if actual.IPv4Subnet != wanted[index].IPv4Subnet {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
