package phase6security

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// Slice6DesiredFinalPostgresSignerTargets extends the seven-owner intermediate
// matrix with separate Browser/Desktop migration job signers. Actual agent
// processes, PKI roles, socket/key ownership and SQL grants remain gate work.
func Slice6DesiredFinalPostgresSignerTargets() []Slice6PostgresSignerTarget {
	targets := Slice6DesiredPostgresSignerTargets()
	for _, migration := range Slice6DesiredProviderMigrationExpansions() {
		targets = append(targets, Slice6PostgresSignerTarget{AgentDeployment: migration.PostgresSigner,
			SubjectDeployment: migration.Job, DatabaseName: migration.Database,
			SQLRole: migration.SQLRole, Migration: true})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].AgentDeployment < targets[j].AgentDeployment })
	return targets
}

func VerifySlice6DesiredFinalPostgresSignerTargets(targets []Slice6PostgresSignerTarget) error {
	wanted := Slice6DesiredFinalPostgresSignerTargets()
	if len(targets) != 9 || !slices.Equal(targets, wanted) ||
		VerifySlice6DesiredProviderMigrationExpansions(Slice6DesiredProviderMigrationExpansions()) != nil {
		return errSlice6DesiredInventory
	}
	seenAgent, seenSubject, seenRole := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, target := range targets {
		if !namePattern.MatchString(target.AgentDeployment) || !namePattern.MatchString(target.SubjectDeployment) ||
			!postgresAuthorityID.MatchString(target.DatabaseName) || !postgresAuthorityID.MatchString(target.SQLRole) ||
			seenAgent[target.AgentDeployment] || seenSubject[target.SubjectDeployment] || seenRole[target.SQLRole] ||
			target.AgentDeployment == target.SubjectDeployment+"-tls-agent" {
			return errSlice6DesiredInventory
		}
		seenAgent[target.AgentDeployment], seenSubject[target.SubjectDeployment], seenRole[target.SQLRole] = true, true, true
	}
	return nil
}

// Slice6DesiredFinalSharedPostgresHBARules binds the actual broker or direct
// dialer address, not the logical caller's address, to every SQL login.
func Slice6DesiredFinalSharedPostgresHBARules() ([]Slice6PostgresHBARule, error) {
	if VerifySlice6DesiredFinalPostgresSignerTargets(Slice6DesiredFinalPostgresSignerTargets()) != nil ||
		VerifySlice6DesiredFinalExternalGraph(Slice6DesiredFinalExternalTransports(), Slice6DesiredFinalExternalEdges()) != nil {
		return nil, errSlice6DesiredInventory
	}
	rules := make([]Slice6PostgresHBARule, 0, 9)
	for _, signer := range Slice6DesiredFinalPostgresSignerTargets() {
		var match Slice6ExternalTransportPath
		for _, path := range Slice6DesiredFinalExternalTransports() {
			if path.LogicalCaller == signer.SubjectDeployment && path.Service == "postgres" {
				if match.Network != "" {
					return nil, errSlice6DesiredInventory
				}
				match = path
			}
		}
		if match.Network == "" || (match.Dialer != signer.SubjectDeployment &&
			!slices.Contains([]string{"provider-browser-runtime", "provider-desktop-runtime"}, signer.SubjectDeployment)) {
			return nil, errSlice6DesiredInventory
		}
		address, err := Slice6DesiredFinalServiceEndpointAddress(match.Network, match.Dialer)
		ip, parseErr := netip.ParseAddr(address)
		if err != nil || parseErr != nil || !ip.Is4() {
			return nil, errSlice6DesiredInventory
		}
		rules = append(rules, Slice6PostgresHBARule{Owner: signer.SubjectDeployment,
			Dialer: match.Dialer, Database: signer.DatabaseName, SQLRole: signer.SQLRole,
			SourceCIDR: netip.PrefixFrom(ip, 32).String(), Migration: signer.Migration})
	}
	return rules, nil
}

func VerifySlice6DesiredFinalSharedPostgresHBARules(rules []Slice6PostgresHBARule) error {
	wanted, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil || len(rules) != 9 || !slices.Equal(rules, wanted) {
		return errSlice6DesiredInventory
	}
	for _, rule := range rules {
		prefix, err := netip.ParsePrefix(rule.SourceCIDR)
		if err != nil || prefix.Bits() != 32 || !prefix.Addr().IsPrivate() ||
			!postgresAuthorityID.MatchString(rule.Database) || !postgresAuthorityID.MatchString(rule.SQLRole) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}

// RenderSlice6DesiredFinalSharedPostgresHBA emits only candidate raw bytes.
// No server reload, certificate enforcement or SQL grant is inferred.
func RenderSlice6DesiredFinalSharedPostgresHBA() ([]byte, error) {
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil || VerifySlice6DesiredFinalSharedPostgresHBARules(rules) != nil {
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
