package phase6security

import (
	"slices"
	"sort"
)

// Slice6DirectExternalDependency is a command-level dial requirement, kept
// independent of the desired trust-edge table. A matching transport path is
// only coverage of desired configuration; it is not an observed connection.
// The command audit is intentionally explicit so that dropping a deployment
// from the profile inventory cannot silently drop its external dependency.
type Slice6DirectExternalDependency struct {
	Dialer  string
	Service string
	Network string
	EdgeID  string
}

var slice6RequiredDirectExternalDependencies = []Slice6DirectExternalDependency{
	{"browser-action-ingress-agent", "vault", "service-browser-action-ingress-agent-vault", "browser-action-ingress-agent-vault"},
	{"browser-agent", "vault", "service-browser-agent-vault", "browser-agent-vault"},
	{"certificate-controller", "vault", "network-certificate-controller", "certificate-vault"},
	{"desktop-agent", "vault", "service-desktop-agent-vault", "desktop-agent-vault"},
	{"gateway-agent", "vault", "service-gateway-agent-vault", "gateway-agent-vault"},
	{"gateway-runtime", "postgres", "service-gateway-postgres", "gateway-postgres"},
	{"guest-agent", "vault", "service-guest-agent-vault", "guest-agent-vault"},
	{"product-migration-agent", "vault", "service-product-migration-agent-vault", "product-migration-agent-vault"},
	{"product-migration-job", "postgres", "service-product-migration-job-postgres", "product-migration-postgres"},
	{"product-runtime", "postgres", "service-product-postgres", "product-postgres"},
	{"product-runtime-agent", "vault", "service-product-runtime-agent-vault", "product-runtime-agent-vault"},
	{"provider-browser-runtime-agent", "vault", "service-provider-browser-runtime-agent-vault", "provider-browser-runtime-agent-vault"},
	{"provider-desktop-runtime-agent", "vault", "service-provider-desktop-runtime-agent-vault", "provider-desktop-runtime-agent-vault"},
	{"provider-migration-agent", "vault", "service-provider-migration-agent-vault", "provider-migration-agent-vault"},
	{"provider-migration-job", "postgres", "service-provider-migration-job-postgres", "provider-migration-postgres"},
	{"provider-runtime", "postgres", "service-provider-runtime-postgres", "provider-coding-postgres"},
	{"provider-runtime-agent", "vault", "service-provider-runtime-agent-vault", "provider-runtime-agent-vault"},
	{"workload-credential-controller", "vault", "service-workload-credential-controller-vault", "credential-controller-vault"},
}

func Slice6RequiredDirectExternalDependencies() []Slice6DirectExternalDependency {
	return append([]Slice6DirectExternalDependency(nil), slice6RequiredDirectExternalDependencies...)
}

// MissingSlice6DirectExternalDependencies reports every command-level direct
// dial that is absent or incorrectly routed through a broker/shared bridge.
// In particular, the old edge-complete 17/12 table is not a deployable graph.
func MissingSlice6DirectExternalDependencies(paths []Slice6ExternalTransportPath) []Slice6DirectExternalDependency {
	missing := make([]Slice6DirectExternalDependency, 0)
	for _, required := range slice6RequiredDirectExternalDependencies {
		found := false
		for _, path := range paths {
			if path.LogicalCaller == required.Dialer && path.Dialer == required.Dialer &&
				path.Service == required.Service && path.Network == required.Network &&
				slices.Equal(path.EdgeIDs, []string{required.EdgeID}) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, required)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i].Dialer < missing[j].Dialer })
	return missing
}

// Slice6DesiredExecutableExternalTransports is the earlier approved 28-path
// candidate. It does not include the subsequently required Browser/Desktop
// Provider migration instances; MissingSlice6FinalExternalDependencies must
// be empty before a final profile or evidence can be admitted.
func Slice6DesiredExecutableExternalTransports() []Slice6ExternalTransportPath {
	paths := Slice6DesiredExternalTransports()
	for _, dependency := range MissingSlice6DirectExternalDependencies(paths) {
		paths = append(paths, Slice6ExternalTransportPath{LogicalCaller: dependency.Dialer,
			Dialer: dependency.Dialer, Service: dependency.Service, Network: dependency.Network,
			EdgeIDs: []string{dependency.EdgeID}})
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].LogicalCaller != paths[j].LogicalCaller {
			return paths[i].LogicalCaller < paths[j].LogicalCaller
		}
		if paths[i].Service != paths[j].Service {
			return paths[i].Service < paths[j].Service
		}
		return paths[i].Network < paths[j].Network
	})
	return paths
}

// VerifySlice6DesiredExecutableExternalTransports freezes that intermediate
// 28-path candidate; it is not the final migration-complete admission gate.
func VerifySlice6DesiredExecutableExternalTransports(paths []Slice6ExternalTransportPath) error {
	wanted := Slice6DesiredExecutableExternalTransports()
	if len(paths) != 28 || !slices.EqualFunc(paths, wanted, func(left, right Slice6ExternalTransportPath) bool {
		return left.LogicalCaller == right.LogicalCaller && left.Dialer == right.Dialer &&
			left.Service == right.Service && left.Network == right.Network && slices.Equal(left.EdgeIDs, right.EdgeIDs)
	}) || VerifySlice6DesiredExternalTransportCoverage(Slice6DesiredExternalTransports()) != nil ||
		VerifySlice6ExecutableExternalDependencyCoverage(paths) != nil {
		return errSlice6DesiredInventory
	}
	return nil
}

// VerifySlice6ExecutableExternalDependencyCoverage is the command-level
// preflight. It must be used in addition to the reviewed trust-edge coverage
// check before a complete candidate profile can be frozen.
func VerifySlice6ExecutableExternalDependencyCoverage(paths []Slice6ExternalTransportPath) error {
	if len(MissingSlice6DirectExternalDependencies(paths)) != 0 {
		return errSlice6DesiredInventory
	}
	return nil
}

// Slice6DesiredExecutableExternalEdges is the earlier 33-edge candidate,
// not the currently activated 17-edge profile graph or final migration graph.
// Each extra direct dial
// has one independently named edge; a service bridge never confers authority
// to another caller sharing the same external service process.
func Slice6DesiredExecutableExternalEdges() []slice6ExternalEdge {
	edges := append([]slice6ExternalEdge(nil), slice6DesiredExternalEdges...)
	for _, dependency := range MissingSlice6DirectExternalDependencies(Slice6DesiredExternalTransports()) {
		edge := slice6ExternalEdge{id: dependency.EdgeID, from: dependency.Dialer, to: dependency.Service,
			protocol: "https", scope: "system", port: 8200, maxSeconds: 60}
		if dependency.Service == "postgres" {
			edge.protocol, edge.scope, edge.port, edge.maxSeconds = "postgres", "bound", 5432, 300
			if dependency.Dialer == "product-migration-job" || dependency.Dialer == "provider-migration-job" {
				edge.scope, edge.maxSeconds = "system", 60
			}
		}
		edges = append(edges, edge)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].id < edges[j].id })
	return edges
}

// VerifySlice6DesiredExecutableExternalEdges checks exact edge/path ownership
// before the 33-edge target can replace the partial activated graph.
func VerifySlice6DesiredExecutableExternalEdges(edges []slice6ExternalEdge) error {
	wanted := Slice6DesiredExecutableExternalEdges()
	if len(edges) != 33 || !slices.Equal(edges, wanted) ||
		VerifySlice6DesiredExecutableExternalTransports(Slice6DesiredExecutableExternalTransports()) != nil {
		return errSlice6DesiredInventory
	}
	byID := make(map[string]slice6ExternalEdge, len(edges))
	for _, edge := range edges {
		if edge.id == "" || byID[edge.id].id != "" || edge.from == "" || edge.to == "" ||
			edge.port < 1 || edge.maxSeconds < 1 {
			return errSlice6DesiredInventory
		}
		byID[edge.id] = edge
	}
	covered := make(map[string]bool, len(edges))
	for _, path := range Slice6DesiredExecutableExternalTransports() {
		for _, id := range path.EdgeIDs {
			edge, ok := byID[id]
			if !ok || covered[id] || edge.to != path.Service ||
				(edge.from != path.LogicalCaller && edge.from != path.Dialer) {
				return errSlice6DesiredInventory
			}
			covered[id] = true
		}
	}
	if len(covered) != len(edges) {
		return errSlice6DesiredInventory
	}
	return nil
}
