package phase6security

import (
	"net/netip"
	"slices"
	"sort"
)

// This is the reviewed set of local numeric mTLS targets in the Slice 6
// profile. It fixes the permission graph independently of the addresses
// assigned during local IPAM planning.
type slice6LocalEdge struct {
	id, from, to, protocol, route, scope string
	port                                 int
}

var slice6DesiredLocalEdges = []slice6LocalEdge{
	{"product-provider-contract", "product-runtime", "provider-runtime", "https", "/v1", "bound", 8444},
	{"gateway-provider-private", "gateway-runtime", "provider-runtime", "wss", "/private/terminal", "bound", 8448},
	{"product-provider-browser-contract", "product-runtime", "provider-browser-runtime", "https", "/v1", "bound", 8444},
	{"product-provider-desktop-contract", "product-runtime", "provider-desktop-runtime", "https", "/v1", "bound", 8444},
	{"gateway-browser-action-ingress", "gateway-runtime", "browser-action-ingress-runtime", "wss", "/browser/action", "bound", 8452},
	{"browser-action-ingress-provider-private", "browser-action-ingress-runtime", "provider-browser-runtime", "wss", "/private/browser", "bound", 8448},
	{"gateway-provider-desktop-private", "gateway-runtime", "provider-desktop-runtime", "wss", "/desktop", "bound", 8448},
	{"guest-product", "guest-runtime", "product-runtime", "wss", "/agent", "bound", 8449},
	{"provider-browser-attach", "provider-browser-runtime", "browser-runtime-role", "wss", "/executor", "bound", 8450},
	{"provider-desktop-attach", "provider-desktop-runtime", "desktop-runtime-role", "wss", "/executor", "bound", 8451},
	{"egress-role-product", "product-runtime", "egress-broker-product", "tls", "", "system", 8443},
	{"egress-role-gateway", "gateway-runtime", "egress-broker-gateway", "tls", "", "system", 8443},
	{"egress-role-browser-action-ingress", "browser-action-ingress-runtime", "egress-broker-browser-action-ingress", "tls", "", "system", 8443},
	{"executor-browser", "browser-runtime-role", "browser-executor-backend", "wss", "/executor", "system", 8443},
	{"executor-desktop", "desktop-runtime-role", "desktop-executor-backend", "wss", "/executor", "system", 8443},
	{"egress-role-provider-browser", "provider-browser-runtime", "egress-broker-provider-browser", "tls", "", "system", 8443},
	{"egress-role-provider-desktop", "provider-desktop-runtime", "egress-broker-provider-desktop", "tls", "", "system", 8443},
}

type slice6ExternalEdge struct {
	id, from, to, protocol, scope string
	port                          int
	maxSeconds                    int64
}

var slice6DesiredExternalEdges = []slice6ExternalEdge{
	{"browser-action-history-postgres", "browser-action-ingress-runtime", "action-history-postgres", "postgres", "bound", 5432, 300},
	{"browser-capacity-valkey", "browser-action-ingress-runtime", "capacity-valkey", "tls", "bound", 6379, 300},
	{"certificate-vault", "certificate-controller", "vault", "https", "system", 8200, 60},
	{"egress-browser-action-history-postgres", "egress-broker-browser-action-ingress", "action-history-postgres", "postgres", "bound", 5432, 300},
	{"egress-browser-capacity-valkey", "egress-broker-browser-action-ingress", "capacity-valkey", "tls", "bound", 6379, 300},
	{"egress-dns", "egress-broker-product", "dns", "dns_tcp", "system", 853, 30},
	{"egress-dns-browser-action-ingress", "egress-broker-browser-action-ingress", "dns", "dns_tcp", "system", 853, 30},
	{"egress-dns-gateway", "egress-broker-gateway", "dns", "dns_tcp", "system", 853, 30},
	{"egress-dns-provider-browser", "egress-broker-provider-browser", "dns", "dns_tcp", "system", 853, 30},
	{"egress-dns-provider-desktop", "egress-broker-provider-desktop", "dns", "dns_tcp", "system", 853, 30},
	{"egress-gateway-capacity-valkey", "egress-broker-gateway", "capacity-valkey", "tls", "bound", 6379, 300},
	{"egress-provider-browser-postgres", "egress-broker-provider-browser", "postgres", "postgres", "bound", 5432, 300},
	{"egress-provider-desktop-postgres", "egress-broker-provider-desktop", "postgres", "postgres", "bound", 5432, 300},
	{"gateway-capacity-valkey", "gateway-runtime", "capacity-valkey", "tls", "bound", 6379, 300},
	{"product-postgres", "product-runtime", "postgres", "postgres", "bound", 5432, 300},
	{"provider-browser-postgres", "provider-browser-runtime", "postgres", "postgres", "bound", 5432, 300},
	{"provider-desktop-postgres", "provider-desktop-runtime", "postgres", "postgres", "bound", 5432, 300},
}

type slice6EdgeSpec struct {
	id, from, to, protocol, route, authentication, scope, serverAnchor, clientAnchor string
	port                                                                             int
	maxSeconds                                                                       int64
	crossDomain, numericTarget                                                       bool
}

func slice6DesiredTrustEdges() []slice6EdgeSpec {
	result := make([]slice6EdgeSpec, 0, 118+len(approvedCredentialIssuerClients))
	for _, edge := range slice6DesiredLocalEdges {
		result = append(result, slice6EdgeSpec{id: edge.id, from: edge.from, to: edge.to,
			protocol: edge.protocol, port: edge.port, route: edge.route, authentication: "mtls", scope: edge.scope,
			serverAnchor: "internal-server-ca", clientAnchor: "internal-client-ca", maxSeconds: 300, numericTarget: true})
	}
	for _, edge := range slice6DesiredExternalEdges {
		result = append(result, slice6EdgeSpec{id: edge.id, from: edge.from, to: edge.to,
			protocol: edge.protocol, port: edge.port, authentication: "mtls", scope: edge.scope,
			serverAnchor: "external-server-ca", maxSeconds: edge.maxSeconds, crossDomain: true})
	}
	unix := func(id, from, to string, maxSeconds int64) {
		result = append(result, slice6EdgeSpec{id: id, from: from, to: to, protocol: "unix",
			authentication: "unix_peer_credentials", scope: "system", maxSeconds: maxSeconds})
	}
	for _, role := range []string{"product", "gateway", "browser-action-ingress", "provider-browser", "provider-desktop"} {
		broker := "egress-broker-" + role
		unix("egress-authority-"+role, broker, "egress-policy-authority-"+role, 5)
	}
	for agent, subject := range slice6ApprovedTLSAgentSubjects {
		unix("tls-agent-"+agent, subject, agent, 5)
		unix("certificate-agent-"+agent, agent, "certificate-controller", 5)
	}
	unix("browser-executor-provider-mux", "browser-executor-backend", "provider-browser-runtime", 10)
	unix("certificate-controller-self", "certificate-controller", "certificate-controller", 5)
	unix("certificate-credential-controller", "workload-credential-controller", "certificate-controller", 5)
	for _, client := range approvedCredentialIssuerClients {
		unix(credentialIssuerBinding(client).UnixEdgeID, client, "workload-credential-controller", 5)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].id < result[j].id })
	return result
}

// VerifySlice6DesiredTrustEdges freezes the current exact local-gate graph,
// including external destinations and Unix peers. A rewritten profile digest
// cannot authorize a new edge, downgrade its authentication or extend its
// lifetime. Live transport and endpoint proof remains a separate gate.
func VerifySlice6DesiredTrustEdges(profile Profile) error {
	if profile.Validate() != nil {
		return errSlice6DesiredInventory
	}
	wanted := slice6DesiredTrustEdges()
	if len(profile.TrustEdges) != len(wanted) {
		return errSlice6DesiredInventory
	}
	for index, actual := range profile.TrustEdges {
		expected := wanted[index]
		if actual.ID != expected.id || actual.From != expected.from || actual.To != expected.to ||
			actual.Protocol != expected.protocol || actual.Port != expected.port || actual.RoutePath != expected.route ||
			actual.Authentication != expected.authentication || actual.TenantScope != expected.scope ||
			actual.ServerAnchorID != expected.serverAnchor || actual.ClientAnchorID != expected.clientAnchor ||
			actual.MaxConnectionSeconds != expected.maxSeconds || actual.CrossDomain != expected.crossDomain ||
			(actual.TargetAddress != "") != expected.numericTarget {
			return errSlice6DesiredInventory
		}
	}
	return nil
}

func slice6PlannedLocalTarget(edge TrustEdge) (string, error) {
	if edge.Port < 1 || edge.Port > 65535 {
		return "", errSlice6DesiredInventory
	}
	shared := ""
	for _, network := range Slice6DesiredNetworks() {
		if slices.Contains(network.Principals, edge.From) && slices.Contains(network.Principals, edge.To) {
			if shared != "" {
				return "", errSlice6DesiredInventory
			}
			shared = network.Name
		}
	}
	if shared == "" {
		return "", errSlice6DesiredInventory
	}
	address, err := Slice6DesiredEndpointAddress(shared, edge.To)
	if err != nil {
		return "", errSlice6DesiredInventory
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return "", errSlice6DesiredInventory
	}
	return netip.AddrPortFrom(parsed, uint16(edge.Port)).String(), nil
}

// VerifySlice6DesiredEdgeAddresses closes the remaining profile-level IPAM
// choice: every reviewed numeric local target must be the preplanned address
// of its declared recipient, not merely an arbitrary address in its subnet.
func VerifySlice6DesiredEdgeAddresses(profile Profile) error {
	if VerifySlice6DesiredTrustEdges(profile) != nil || VerifySlice6DesiredNetworks(profile) != nil {
		return errSlice6DesiredInventory
	}
	for _, edge := range profile.TrustEdges {
		if edge.TargetAddress == "" {
			continue
		}
		planned, err := slice6PlannedLocalTarget(edge)
		if err != nil || edge.TargetAddress != planned {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
