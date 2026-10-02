package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
)

// VerifySlice6FinalGateProfile is the static admission boundary for the live
// Slice 6 runner. It does not attest any running process or external service.
// Earlier 17/12 and 28/33 profiles must never reach Docker side effects.
func VerifySlice6FinalGateProfile(profile Profile) error {
	if VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		VerifySlice6ControllerLedgerMounts(profile) != nil ||
		VerifySlice6PrivateConfigMounts(profile) != nil ||
		VerifySlice6MaterialSocketBindings(profile) != nil ||
		VerifySlice6BreakGlassBoundaries(profile) != nil ||
		VerifySlice6BreakGlassKeyAuthority(profile.BreakGlassKeyAuthority) != nil ||
		VerifySlice6BreakGlassExecutableArtifact(profile) != nil ||
		VerifySlice6DNSClientCA(profile) != nil ||
		VerifySlice6DNSRuntimePolicy(profile) != nil ||
		VerifySlice6DesiredImageLocations(profile) != nil ||
		len(profile.Principals) != len(Slice6DesiredDeploymentNames()) ||
		len(profile.Networks) != len(Slice6DesiredFinalNetworks()) {
		return errSlice6DesiredInventory
	}
	hba, err := profile.PostgresServerAuth.RenderApprovedHBA(profile.ProviderDatabases)
	if err != nil {
		return errSlice6DesiredInventory
	}
	sum := sha256.Sum256(hba)
	if profile.PostgresServerAuth.HBADigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return errSlice6DesiredInventory
	}
	targets := Slice6DesiredFinalPostgresSignerTargets()
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil || len(profile.PostgresClientAgents) != len(targets) || len(rules) != len(targets) {
		return errSlice6DesiredInventory
	}
	byOwner := make(map[string]Slice6PostgresHBARule, len(rules))
	for _, rule := range rules {
		if byOwner[rule.Owner].Owner != "" {
			return errSlice6DesiredInventory
		}
		byOwner[rule.Owner] = rule
	}
	for index, target := range targets {
		binding := profile.PostgresClientAgents[index]
		rule := byOwner[target.SubjectDeployment]
		if binding.AgentDeployment != target.AgentDeployment ||
			binding.SubjectDeployment != target.SubjectDeployment ||
			binding.CommonName != postgresClientCommonName(target.SQLRole) ||
			rule.Owner != target.SubjectDeployment || rule.Database != target.DatabaseName ||
			rule.SQLRole != target.SQLRole || rule.Migration != target.Migration {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
