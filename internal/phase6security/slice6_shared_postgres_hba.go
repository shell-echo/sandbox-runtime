package phase6security

import (
	"net/netip"
	"slices"
	"strings"
)

// Slice6PostgresHBARule is one exact SQL login from one physical service
// bridge host. Runtime and migration rules cannot share a login, and the
// dialer may differ from the certificate-owning process only for the two
// established raw-tunnel Provider brokers.
type Slice6PostgresHBARule struct {
	Owner      string
	Dialer     string
	Database   string
	SQLRole    string
	SourceCIDR string
	Migration  bool
}

// Slice6DesiredSharedPostgresHBARules describes the complete main-PostgreSQL
// target for the current seven pool owners. It does not alter the separate
// action-history witness service or the historical Provider-only HBA.
func Slice6DesiredSharedPostgresHBARules() ([]Slice6PostgresHBARule, error) {
	if VerifySlice6DesiredPostgresSignerTargets(Slice6DesiredPostgresSignerTargets()) != nil ||
		VerifySlice6DesiredExecutableExternalTransports(Slice6DesiredExecutableExternalTransports()) != nil {
		return nil, errSlice6DesiredInventory
	}
	rules := make([]Slice6PostgresHBARule, 0, 7)
	for _, signer := range Slice6DesiredPostgresSignerTargets() {
		var path Slice6ExternalTransportPath
		for _, candidate := range Slice6DesiredExecutableExternalTransports() {
			if candidate.LogicalCaller == signer.SubjectDeployment && candidate.Service == "postgres" {
				if path.Network != "" {
					return nil, errSlice6DesiredInventory
				}
				path = candidate
			}
		}
		if path.Network == "" || path.Dialer == "" ||
			(path.Dialer != signer.SubjectDeployment &&
				!slices.Contains([]string{"provider-browser-runtime", "provider-desktop-runtime"}, signer.SubjectDeployment)) {
			return nil, errSlice6DesiredInventory
		}
		address, err := Slice6DesiredServiceEndpointAddress(path.Network, path.Dialer)
		parsed, parseErr := netip.ParseAddr(address)
		if err != nil || parseErr != nil || !parsed.Is4() {
			return nil, errSlice6DesiredInventory
		}
		rules = append(rules, Slice6PostgresHBARule{Owner: signer.SubjectDeployment, Dialer: path.Dialer,
			Database: signer.DatabaseName, SQLRole: signer.SQLRole,
			SourceCIDR: netip.PrefixFrom(parsed, 32).String(), Migration: signer.Migration})
	}
	return rules, nil
}

func VerifySlice6DesiredSharedPostgresHBARules(rules []Slice6PostgresHBARule) error {
	wanted, err := Slice6DesiredSharedPostgresHBARules()
	if err != nil || !slices.Equal(rules, wanted) || len(rules) != 7 {
		return errSlice6DesiredInventory
	}
	seenSourceRole := map[string]bool{}
	for _, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.SourceCIDR)
		if err != nil || prefix.Bits() != 32 || !prefix.Addr().IsPrivate() ||
			!postgresAuthorityID.MatchString(rule.Database) || !postgresAuthorityID.MatchString(rule.SQLRole) ||
			seenSourceRole[rule.SourceCIDR+"/"+rule.Database+"/"+rule.SQLRole] {
			return errSlice6DesiredInventory
		}
		seenSourceRole[rule.SourceCIDR+"/"+rule.Database+"/"+rule.SQLRole] = true
	}
	return nil
}

// RenderSlice6DesiredSharedPostgresHBA emits exact raw bytes for the shared
// main service. The production gate must still prove read-only mount,
// PostgreSQL load, client certificate, SCRAM and SQL-grant enforcement.
func RenderSlice6DesiredSharedPostgresHBA() ([]byte, error) {
	rules, err := Slice6DesiredSharedPostgresHBARules()
	if err != nil || VerifySlice6DesiredSharedPostgresHBARules(rules) != nil {
		return nil, errSlice6DesiredInventory
	}
	var hba strings.Builder
	hba.WriteString("local all postgres peer\n")
	for _, rule := range rules {
		hba.WriteString("hostssl ")
		hba.WriteString(rule.Database)
		hba.WriteByte(' ')
		hba.WriteString(rule.SQLRole)
		hba.WriteByte(' ')
		hba.WriteString(rule.SourceCIDR)
		hba.WriteString(" scram-sha-256 clientcert=verify-full clientname=CN\n")
	}
	hba.WriteString("host all all 0.0.0.0/0 reject\n")
	hba.WriteString("host all all ::/0 reject\n")
	return []byte(hba.String()), nil
}
