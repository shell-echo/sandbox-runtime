package phase6security

import (
	"net/netip"
	"slices"
	"sort"
	"strconv"
)

// Slice6ProviderMigrationExpansion names the two additional one-shot
// database migrations required by the Browser and Desktop Provider stores.
// Each job owns a separate material agent, Vault-client signer and PG-purpose
// signer. This is an admission target; current 69-deployment profiles omit
// these instances and therefore cannot pass the final Slice 6 gate.
type Slice6ProviderMigrationExpansion struct {
	Job                 string
	MaterialAgent       string
	MaterialVaultSigner string
	PostgresSigner      string
	Database            string
	SQLRole             string
	VaultNetwork        string
	VaultEdgeID         string
	PostgresNetwork     string
	PostgresEdgeID      string
}

var slice6ProviderMigrationExpansions = []Slice6ProviderMigrationExpansion{
	{
		Job: "provider-browser-migration-job", MaterialAgent: "provider-browser-migration-agent",
		MaterialVaultSigner: "provider-browser-migration-agent-tls-agent",
		PostgresSigner:      "provider-browser-migration-postgres-tls-agent",
		Database:            "provider_browser", SQLRole: "browser_provider_migrator",
		VaultNetwork:    "service-provider-browser-migration-agent-vault",
		VaultEdgeID:     "provider-browser-migration-agent-vault",
		PostgresNetwork: "service-provider-browser-migration-job-postgres",
		PostgresEdgeID:  "provider-browser-migration-postgres",
	},
	{
		Job: "provider-desktop-migration-job", MaterialAgent: "provider-desktop-migration-agent",
		MaterialVaultSigner: "provider-desktop-migration-agent-tls-agent",
		PostgresSigner:      "provider-desktop-migration-postgres-tls-agent",
		Database:            "provider_desktop", SQLRole: "desktop_provider_migrator",
		VaultNetwork:    "service-provider-desktop-migration-agent-vault",
		VaultEdgeID:     "provider-desktop-migration-agent-vault",
		PostgresNetwork: "service-provider-desktop-migration-job-postgres",
		PostgresEdgeID:  "provider-desktop-migration-postgres",
	},
}

func Slice6DesiredProviderMigrationExpansions() []Slice6ProviderMigrationExpansion {
	return append([]Slice6ProviderMigrationExpansion(nil), slice6ProviderMigrationExpansions...)
}

func VerifySlice6DesiredProviderMigrationExpansions(values []Slice6ProviderMigrationExpansion) error {
	if len(values) != 2 || !slices.Equal(values, slice6ProviderMigrationExpansions) {
		return errSlice6DesiredInventory
	}
	seen := make(map[string]bool, len(values)*10)
	for _, value := range values {
		for _, name := range []string{value.Job, value.MaterialAgent, value.MaterialVaultSigner, value.PostgresSigner,
			value.VaultNetwork, value.VaultEdgeID, value.PostgresNetwork, value.PostgresEdgeID} {
			if !namePattern.MatchString(name) || seen[name] {
				return errSlice6DesiredInventory
			}
			seen[name] = true
		}
		if !postgresAuthorityID.MatchString(value.Database) || !postgresAuthorityID.MatchString(value.SQLRole) ||
			value.MaterialVaultSigner != value.MaterialAgent+"-tls-agent" ||
			value.PostgresSigner == value.MaterialVaultSigner ||
			value.Job == "provider-migration-job" || value.MaterialAgent == "provider-migration-agent" ||
			value.Database == "provider" || value.SQLRole == "provider_migrator" {
			return errSlice6DesiredInventory
		}
	}
	return nil
}

// Slice6ProviderMigrationExternalDependencies is the four-path delta omitted
// by the earlier 28-path candidate. The final gate must cover these as well
// as the original direct-command inventory before freezing a profile.
func Slice6ProviderMigrationExternalDependencies() []Slice6DirectExternalDependency {
	result := make([]Slice6DirectExternalDependency, 0, 4)
	for _, value := range slice6ProviderMigrationExpansions {
		result = append(result,
			Slice6DirectExternalDependency{Dialer: value.MaterialAgent, Service: "vault",
				Network: value.VaultNetwork, EdgeID: value.VaultEdgeID},
			Slice6DirectExternalDependency{Dialer: value.Job, Service: "postgres",
				Network: value.PostgresNetwork, EdgeID: value.PostgresEdgeID})
	}
	return result
}

// MissingSlice6FinalExternalDependencies is a fail-closed final-inventory
// complement to the older 18-direct-path audit. A green 28/33 candidate is
// insufficient once the two real Provider migration jobs are required.
func MissingSlice6FinalExternalDependencies(paths []Slice6ExternalTransportPath) []Slice6DirectExternalDependency {
	wanted := append(Slice6RequiredDirectExternalDependencies(), Slice6ProviderMigrationExternalDependencies()...)
	missing := make([]Slice6DirectExternalDependency, 0)
	for _, required := range wanted {
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
	return missing
}

// VerifySlice6FinalExternalDependencyClosure is a necessary production
// condition, not sufficient release evidence. It rejects the now-incomplete
// 33/28 candidate until the two additional migration jobs and every reviewed
// physical dial path actually appear in one validated profile.
func VerifySlice6FinalExternalDependencyClosure(profile Profile) error {
	if profile.Validate() != nil || VerifySlice6DesiredProviderMigrationExpansions(Slice6DesiredProviderMigrationExpansions()) != nil {
		return errSlice6DesiredInventory
	}
	paths, expectedEdges := Slice6DesiredFinalExternalTransports(), Slice6DesiredFinalExternalEdges()
	if VerifySlice6DesiredFinalExternalGraph(paths, expectedEdges) != nil {
		return errSlice6DesiredInventory
	}
	wantedEdges := make(map[string]slice6ExternalEdge, len(expectedEdges))
	for _, edge := range expectedEdges {
		wantedEdges[edge.id] = edge
	}
	for _, path := range paths {
		matchedNetwork, matchedService := false, false
		for _, network := range profile.Networks {
			if network.Name == path.Network && network.Internal && network.GatewayModeIPv4 == "isolated" &&
				slices.Equal(network.Principals, []string{path.Dialer}) &&
				slices.Equal(network.ExternalServices, []string{path.Service}) {
				matchedNetwork = true
			}
		}
		for _, service := range profile.External {
			if service.Name == path.Service && slices.Contains(service.Networks, path.Network) {
				matchedService = true
				for _, id := range path.EdgeIDs {
					if !slices.Contains(service.IngressEdges, id) {
						return errSlice6DesiredInventory
					}
				}
			}
		}
		if !matchedNetwork || !matchedService {
			return errSlice6DesiredInventory
		}
		for _, id := range path.EdgeIDs {
			found := false
			spec := wantedEdges[id]
			for _, edge := range profile.TrustEdges {
				if edge.ID == id && edge.From == spec.from && edge.To == spec.to &&
					edge.Protocol == spec.protocol && edge.Port == spec.port &&
					edge.TenantScope == spec.scope && edge.MaxConnectionSeconds == spec.maxSeconds &&
					edge.Authentication == "mtls" &&
					edge.ServerAnchorID == "external-server-ca" && edge.ClientAnchorID == "" && edge.CrossDomain &&
					edge.TargetAddress == "" {
					found = true
				}
			}
			if !found {
				return errSlice6DesiredInventory
			}
		}
	}
	return nil
}

// Slice6DesiredFinalExternalTransports extends the reviewed 28-path
// intermediate graph with the two real Provider migrations' four physical
// dials. It remains desired configuration, never Docker observation.
func Slice6DesiredFinalExternalTransports() []Slice6ExternalTransportPath {
	paths := Slice6DesiredExecutableExternalTransports()
	for _, dependency := range Slice6ProviderMigrationExternalDependencies() {
		paths = append(paths, Slice6ExternalTransportPath{LogicalCaller: dependency.Dialer,
			Dialer: dependency.Dialer, Service: dependency.Service, Network: dependency.Network,
			EdgeIDs: []string{dependency.EdgeID}})
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i].Network < paths[j].Network })
	return paths
}

// Slice6DesiredFinalExternalEdges is the matching finite 37-edge target.
// It cannot be substituted for PKI/SQL/HBA/live connection evidence.
func Slice6DesiredFinalExternalEdges() []slice6ExternalEdge {
	edges := Slice6DesiredExecutableExternalEdges()
	for _, dependency := range Slice6ProviderMigrationExternalDependencies() {
		edge := slice6ExternalEdge{id: dependency.EdgeID, from: dependency.Dialer,
			to: dependency.Service, protocol: "https", scope: "system", port: 8200, maxSeconds: 60}
		if dependency.Service == "postgres" {
			edge.protocol, edge.port = "postgres", 5432
		}
		edges = append(edges, edge)
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].id < edges[j].id })
	return edges
}

func VerifySlice6DesiredFinalExternalGraph(paths []Slice6ExternalTransportPath, edges []slice6ExternalEdge) error {
	wantedPaths, wantedEdges := Slice6DesiredFinalExternalTransports(), Slice6DesiredFinalExternalEdges()
	if len(paths) != 32 || len(edges) != 37 ||
		!slices.EqualFunc(paths, wantedPaths, func(left, right Slice6ExternalTransportPath) bool {
			return left.LogicalCaller == right.LogicalCaller && left.Dialer == right.Dialer &&
				left.Service == right.Service && left.Network == right.Network && slices.Equal(left.EdgeIDs, right.EdgeIDs)
		}) || !slices.Equal(edges, wantedEdges) || len(MissingSlice6FinalExternalDependencies(paths)) != 0 {
		return errSlice6DesiredInventory
	}
	byID, covered, networks := make(map[string]slice6ExternalEdge, len(edges)), map[string]bool{}, map[string]bool{}
	for _, edge := range edges {
		if byID[edge.id].id != "" || edge.id == "" || edge.from == "" || edge.to == "" {
			return errSlice6DesiredInventory
		}
		byID[edge.id] = edge
	}
	for _, path := range paths {
		if networks[path.Network] || path.Network == "" || path.Dialer == "" || path.Service == "" {
			return errSlice6DesiredInventory
		}
		networks[path.Network] = true
		for _, id := range path.EdgeIDs {
			edge, found := byID[id]
			if !found || covered[id] || edge.to != path.Service ||
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

// Slice6DesiredFinalServiceBridges reserves 155-158 after the original 27
// new /24 bridges; the certificate controller retains its old isolated CIDR.
func Slice6DesiredFinalServiceBridges() []Network {
	bridges := Slice6DesiredServiceBridges()
	for index, dependency := range Slice6ProviderMigrationExternalDependencies() {
		bridges = append(bridges, Network{Name: dependency.Network, Kind: "trust_edge", Internal: true,
			GatewayModeIPv4: "isolated", IPv4Subnet: "172.31." + strconv.Itoa(155+index) + ".0/24",
			Principals: []string{dependency.Dialer}, ExternalServices: []string{dependency.Service}})
	}
	sort.Slice(bridges, func(i, j int) bool { return bridges[i].Name < bridges[j].Name })
	return bridges
}

func VerifySlice6DesiredFinalServiceBridges(bridges []Network) error {
	wanted := Slice6DesiredFinalServiceBridges()
	if len(bridges) != 32 || !slices.EqualFunc(bridges, wanted, func(left, right Network) bool {
		return left.Name == right.Name && left.Kind == right.Kind && left.Internal == right.Internal &&
			left.GatewayModeIPv4 == right.GatewayModeIPv4 && left.IPv4Subnet == right.IPv4Subnet &&
			!left.IPv6Enabled && slices.Equal(left.Principals, right.Principals) &&
			slices.Equal(left.ExternalServices, right.ExternalServices)
	}) || VerifySlice6DesiredFinalExternalGraph(Slice6DesiredFinalExternalTransports(), Slice6DesiredFinalExternalEdges()) != nil {
		return errSlice6DesiredInventory
	}
	seen := map[string]bool{}
	for _, bridge := range bridges {
		if seen[bridge.IPv4Subnet] || len(bridge.Principals) != 1 || len(bridge.ExternalServices) != 1 ||
			!bridge.Internal || bridge.GatewayModeIPv4 != "isolated" {
			return errSlice6DesiredInventory
		}
		seen[bridge.IPv4Subnet] = true
	}
	return nil
}

func Slice6DesiredFinalServiceEndpointAddress(networkName, member string) (string, error) {
	for _, network := range Slice6DesiredFinalServiceBridges() {
		if network.Name != networkName {
			continue
		}
		prefix, err := netip.ParsePrefix(network.IPv4Subnet)
		if err != nil || prefix.Bits() != 24 || !prefix.Addr().Is4() {
			return "", errSlice6DesiredInventory
		}
		address := prefix.Addr().As4()
		switch {
		case slices.Contains(network.Principals, member):
			address[3] = 2
		case slices.Contains(network.ExternalServices, member):
			address[3] = 3
		default:
			return "", errSlice6DesiredInventory
		}
		return netip.AddrFrom4(address).String(), nil
	}
	return "", errSlice6DesiredInventory
}

// Slice6DesiredFinalNetworks is the full role-plus-service network target.
// Existing role CIDRs and the certificate controller bridge remain stable.
func Slice6DesiredFinalNetworks() []Network {
	byName := make(map[string]Network)
	for _, network := range Slice6DesiredNetworks() {
		byName[network.Name] = network
	}
	for _, network := range Slice6DesiredFinalServiceBridges() {
		byName[network.Name] = network
	}
	result := make([]Network, 0, len(byName))
	for _, network := range byName {
		result = append(result, network)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func VerifySlice6DesiredFinalNetworks(networks []Network) error {
	wanted := Slice6DesiredFinalNetworks()
	if len(networks) != len(wanted) || !slices.EqualFunc(networks, wanted, func(left, right Network) bool {
		return left.Name == right.Name && left.Kind == right.Kind && left.Internal == right.Internal &&
			left.GatewayModeIPv4 == right.GatewayModeIPv4 && left.IPv4Subnet == right.IPv4Subnet &&
			!left.IPv6Enabled && slices.Equal(left.Principals, right.Principals) &&
			slices.Equal(left.ExternalServices, right.ExternalServices)
	}) || VerifySlice6DesiredFinalServiceBridges(Slice6DesiredFinalServiceBridges()) != nil {
		return errSlice6DesiredInventory
	}
	seen := map[string]bool{}
	for _, network := range networks {
		if seen[network.IPv4Subnet] {
			return errSlice6DesiredInventory
		}
		seen[network.IPv4Subnet] = true
	}
	return nil
}
