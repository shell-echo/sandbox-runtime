package phase6security

import (
	"bytes"
	"strings"
	"testing"
)

func TestSlice6FinalSharedPostgresHBAIncludesIndependentMigrations(t *testing.T) {
	signers := Slice6DesiredFinalPostgresSignerTargets()
	if err := VerifySlice6DesiredFinalPostgresSignerTargets(signers); err != nil {
		t.Fatalf("final PG signer target rejected: %v", err)
	}
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil || VerifySlice6DesiredFinalSharedPostgresHBARules(rules) != nil {
		t.Fatalf("final HBA target rejected: %v", err)
	}
	if len(rules) != 9 {
		t.Fatalf("shared PG logins = %d, want 9", len(rules))
	}
	for _, migration := range Slice6DesiredProviderMigrationExpansions() {
		found := false
		for _, rule := range rules {
			if rule.Owner == migration.Job && rule.Database == migration.Database &&
				rule.SQLRole == migration.SQLRole && rule.Migration &&
				strings.HasSuffix(rule.SourceCIDR, ".2/32") {
				found = true
			}
		}
		if !found {
			t.Fatalf("migration HBA login or exact source missing: %+v", migration)
		}
	}
	document, err := RenderSlice6DesiredFinalSharedPostgresHBA()
	if err != nil || bytes.Count(document, []byte("hostssl ")) != 9 ||
		!bytes.HasSuffix(document, []byte("host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n")) {
		t.Fatalf("incomplete final HBA bytes: %v", err)
	}
	mutated := append([]Slice6PostgresHBARule(nil), rules...)
	mutated[len(mutated)-1].SQLRole = "provider_migrator"
	if VerifySlice6DesiredFinalSharedPostgresHBARules(mutated) == nil {
		t.Fatal("Desktop migration borrowed coding migration SQL login")
	}
}
