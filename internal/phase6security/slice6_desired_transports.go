package phase6security

import (
	"slices"
)

// Slice6ExternalTransportPath distinguishes the authorized logical caller
// from the process that actually dials an external dependency. EdgeIDs names
// every reviewed logical/egress edge covered by that one physical path.
// Network is an internal, isolated service bridge, not a host/NAT bypass.
type Slice6ExternalTransportPath struct {
	LogicalCaller string
	Dialer        string
	Service       string
	Network       string
	EdgeIDs       []string
}

var slice6DesiredExternalTransports = []Slice6ExternalTransportPath{
	{"browser-action-ingress-runtime", "egress-broker-browser-action-ingress", "action-history-postgres",
		"service-browser-action-ingress-action-history-postgres", []string{"browser-action-history-postgres", "egress-browser-action-history-postgres"}},
	{"browser-action-ingress-runtime", "egress-broker-browser-action-ingress", "capacity-valkey",
		"service-browser-action-ingress-capacity-valkey", []string{"browser-capacity-valkey", "egress-browser-capacity-valkey"}},
	{"browser-action-ingress-runtime", "egress-broker-browser-action-ingress", "dns",
		"service-browser-action-ingress-dns", []string{"egress-dns-browser-action-ingress"}},
	{"certificate-controller", "certificate-controller", "vault", "network-certificate-controller",
		[]string{"certificate-vault"}},
	{"gateway-runtime", "egress-broker-gateway", "capacity-valkey", "service-gateway-capacity-valkey",
		[]string{"egress-gateway-capacity-valkey", "gateway-capacity-valkey"}},
	{"gateway-runtime", "egress-broker-gateway", "dns", "service-gateway-dns",
		[]string{"egress-dns-gateway"}},
	{"product-runtime", "egress-broker-product", "dns", "service-product-dns",
		[]string{"egress-dns"}},
	{"product-runtime", "product-runtime", "postgres", "service-product-postgres",
		[]string{"product-postgres"}},
	{"provider-browser-runtime", "egress-broker-provider-browser", "dns", "service-provider-browser-dns",
		[]string{"egress-dns-provider-browser"}},
	{"provider-browser-runtime", "egress-broker-provider-browser", "postgres", "service-provider-browser-postgres",
		[]string{"egress-provider-browser-postgres", "provider-browser-postgres"}},
	{"provider-desktop-runtime", "egress-broker-provider-desktop", "dns", "service-provider-desktop-dns",
		[]string{"egress-dns-provider-desktop"}},
	{"provider-desktop-runtime", "egress-broker-provider-desktop", "postgres", "service-provider-desktop-postgres",
		[]string{"egress-provider-desktop-postgres", "provider-desktop-postgres"}},
}

func Slice6DesiredExternalTransports() []Slice6ExternalTransportPath {
	result := make([]Slice6ExternalTransportPath, len(slice6DesiredExternalTransports))
	for index, path := range slice6DesiredExternalTransports {
		result[index] = path
		result[index].EdgeIDs = append([]string(nil), path.EdgeIDs...)
	}
	return result
}

// VerifySlice6DesiredExternalTransportCoverage rejects an omitted logical
// edge, a direct role bypass of its broker, or two dialers sharing an
// undeclared service bridge before the profile/network builder consumes it.
func VerifySlice6DesiredExternalTransportCoverage(paths []Slice6ExternalTransportPath) error {
	if len(paths) != 12 || len(slice6DesiredExternalEdges) != 17 ||
		!slices.EqualFunc(paths, slice6DesiredExternalTransports, func(left, right Slice6ExternalTransportPath) bool {
			return left.LogicalCaller == right.LogicalCaller && left.Dialer == right.Dialer &&
				left.Service == right.Service && left.Network == right.Network && slices.Equal(left.EdgeIDs, right.EdgeIDs)
		}) {
		return errSlice6DesiredInventory
	}
	brokerOwner := map[string]string{
		"egress-broker-product": "product-runtime", "egress-broker-gateway": "gateway-runtime",
		"egress-broker-browser-action-ingress": "browser-action-ingress-runtime",
		"egress-broker-provider-browser":       "provider-browser-runtime",
		"egress-broker-provider-desktop":       "provider-desktop-runtime",
	}
	edges := make(map[string]slice6ExternalEdge, len(slice6DesiredExternalEdges))
	for _, edge := range slice6DesiredExternalEdges {
		edges[edge.id] = edge
	}
	seenEdges := make(map[string]bool, len(edges))
	seenNetworks := make(map[string]bool, len(paths))
	for _, path := range paths {
		if path.LogicalCaller == "" || path.Dialer == "" || path.Service == "" || path.Network == "" ||
			seenNetworks[path.Network] || len(path.EdgeIDs) < 1 || len(path.EdgeIDs) > 2 {
			return errSlice6DesiredInventory
		}
		seenNetworks[path.Network] = true
		fromCaller, fromDialer := false, false
		for _, id := range path.EdgeIDs {
			edge, found := edges[id]
			if !found || seenEdges[id] || edge.to != path.Service ||
				(edge.from != path.LogicalCaller && edge.from != path.Dialer) {
				return errSlice6DesiredInventory
			}
			seenEdges[id] = true
			fromCaller = fromCaller || edge.from == path.LogicalCaller
			fromDialer = fromDialer || edge.from == path.Dialer
		}
		if !fromDialer || path.LogicalCaller != path.Dialer && !fromCaller &&
			!(len(path.EdgeIDs) == 1 && brokerOwner[path.Dialer] == path.LogicalCaller) ||
			path.LogicalCaller == path.Dialer && len(path.EdgeIDs) != 1 {
			return errSlice6DesiredInventory
		}
		if path.LogicalCaller != path.Dialer && brokerOwner[path.Dialer] != path.LogicalCaller {
			return errSlice6DesiredInventory
		}
	}
	if len(seenEdges) != len(edges) {
		return errSlice6DesiredInventory
	}
	return nil
}
