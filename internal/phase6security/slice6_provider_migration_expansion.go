package phase6security

import "slices"

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
	paths := Slice6DesiredExecutableExternalTransports()
	for _, dependency := range Slice6ProviderMigrationExternalDependencies() {
		paths = append(paths, Slice6ExternalTransportPath{LogicalCaller: dependency.Dialer,
			Dialer: dependency.Dialer, Service: dependency.Service, Network: dependency.Network,
			EdgeIDs: []string{dependency.EdgeID}})
	}
	if len(paths) != 32 || len(MissingSlice6FinalExternalDependencies(paths)) != 0 {
		return errSlice6DesiredInventory
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
			for _, edge := range profile.TrustEdges {
				if edge.ID == id && edge.To == path.Service && edge.Authentication == "mtls" &&
					edge.ServerAnchorID == "external-server-ca" && edge.ClientAnchorID == "" && edge.CrossDomain &&
					(edge.From == path.Dialer || edge.From == path.LogicalCaller) {
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
