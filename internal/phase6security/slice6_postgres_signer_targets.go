package phase6security

import "slices"

// Slice6PostgresSignerTarget is a purpose-specific key owner, distinct from
// the ordinary role TLS signer and any Vault material-agent TLS signer. The
// owner is the process whose PostgreSQL pool actually sends the client leaf.
// These are reviewed target tuples, not activated PKI roles or SQL grants.
type Slice6PostgresSignerTarget struct {
	AgentDeployment   string
	SubjectDeployment string
	DatabaseName      string
	SQLRole           string
	Migration         bool
}

var slice6PostgresSignerTargets = []Slice6PostgresSignerTarget{
	{"gateway-postgres-tls-agent", "gateway-runtime", "product", "product_gateway", false},
	{"product-migration-postgres-tls-agent", "product-migration-job", "product", "product_migrator", true},
	{"product-postgres-tls-agent", "product-runtime", "product", "product_runtime", false},
	{"provider-browser-postgres-tls-agent", "provider-browser-runtime", "provider_browser", "browser_provider_runtime", false},
	{"provider-desktop-postgres-tls-agent", "provider-desktop-runtime", "provider_desktop", "desktop_provider_runtime", false},
	{"provider-migration-postgres-tls-agent", "provider-migration-job", "provider", "provider_migrator", true},
	{"provider-postgres-tls-agent", "provider-runtime", "provider", "provider_runtime", false},
}

func Slice6DesiredPostgresSignerTargets() []Slice6PostgresSignerTarget {
	return append([]Slice6PostgresSignerTarget(nil), slice6PostgresSignerTargets...)
}

// VerifySlice6DesiredPostgresSignerTargets freezes the seven currently
// identified pool-owner identities. Additional Provider migration instances
// require their own reviewed tuple before a full deployment gate can run.
func VerifySlice6DesiredPostgresSignerTargets(targets []Slice6PostgresSignerTarget) error {
	if !slices.Equal(targets, slice6PostgresSignerTargets) || len(targets) != 7 {
		return errSlice6DesiredInventory
	}
	seenAgent, seenOwner, seenRole := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, target := range targets {
		if !namePattern.MatchString(target.AgentDeployment) || !namePattern.MatchString(target.SubjectDeployment) ||
			!postgresAuthorityID.MatchString(target.DatabaseName) || !postgresAuthorityID.MatchString(target.SQLRole) ||
			seenAgent[target.AgentDeployment] || seenOwner[target.SubjectDeployment] || seenRole[target.SQLRole] ||
			target.AgentDeployment == target.SubjectDeployment ||
			(target.Migration != (target.SubjectDeployment == "product-migration-job" || target.SubjectDeployment == "provider-migration-job")) {
			return errSlice6DesiredInventory
		}
		seenAgent[target.AgentDeployment], seenOwner[target.SubjectDeployment], seenRole[target.SQLRole] = true, true, true
	}
	for _, pair := range [][2]string{{"product-runtime", "gateway-runtime"}, {"product-runtime", "product-migration-job"}} {
		var first, second Slice6PostgresSignerTarget
		for _, target := range targets {
			if target.SubjectDeployment == pair[0] {
				first = target
			}
			if target.SubjectDeployment == pair[1] {
				second = target
			}
		}
		if first.DatabaseName != "product" || second.DatabaseName != "product" || first.SQLRole == second.SQLRole {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
