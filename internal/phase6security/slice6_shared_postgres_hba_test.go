package phase6security

import (
	"bytes"
	"strings"
	"testing"
)

func TestSlice6SharedPostgresHBATargetHasDistinctExactHostRules(t *testing.T) {
	rules, err := Slice6DesiredSharedPostgresHBARules()
	if err != nil || VerifySlice6DesiredSharedPostgresHBARules(rules) != nil {
		t.Fatalf("shared main-PG HBA target rejected: %v", err)
	}
	if len(rules) != 7 || rules[0].Database != "product" || rules[1].Database != "product" ||
		rules[2].Database != "product" {
		t.Fatalf("Product/Gateway/migration business DB split: %+v", rules)
	}
	for _, rule := range rules {
		if !strings.HasSuffix(rule.SourceCIDR, ".2/32") {
			t.Fatalf("HBA widened beyond one bridge dialer host: %+v", rule)
		}
	}
	document, err := RenderSlice6DesiredSharedPostgresHBA()
	if err != nil || bytes.Count(document, []byte("hostssl ")) != len(rules) ||
		!bytes.HasSuffix(document, []byte("host all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n")) {
		t.Fatalf("HBA omitted an exact login or deny tail: %v", err)
	}
	if bytes.Contains(document, []byte("map=")) || bytes.Contains(document, []byte(" 172.31.0.0/16 ")) {
		t.Fatal("unsupported mapping or broad source range in HBA")
	}
	wrong := append([]Slice6PostgresHBARule(nil), rules...)
	wrong[0].SourceCIDR = "172.31.0.0/16"
	if VerifySlice6DesiredSharedPostgresHBARules(wrong) == nil {
		t.Fatal("broad source subnet admitted")
	}
	wrong = append([]Slice6PostgresHBARule(nil), rules...)
	wrong[1].SQLRole = wrong[2].SQLRole
	if VerifySlice6DesiredSharedPostgresHBARules(wrong) == nil {
		t.Fatal("migration and Product runtime SQL role alias admitted")
	}
}
