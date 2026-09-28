package phase6security

import "testing"

func TestSlice6PostgresPurposeSignersHaveDistinctOwnersAndProductState(t *testing.T) {
	targets := Slice6DesiredPostgresSignerTargets()
	if err := VerifySlice6DesiredPostgresSignerTargets(targets); err != nil {
		t.Fatalf("reviewed PG-purpose signer target rejected: %v", err)
	}
	if len(targets) != 7 {
		t.Fatalf("PG-purpose signers = %d, want 7", len(targets))
	}
	for _, target := range targets {
		if target.AgentDeployment == target.SubjectDeployment+"-tls-agent" ||
			target.AgentDeployment == target.SubjectDeployment+"-agent-tls-agent" {
			t.Fatalf("PG signer aliases ordinary or material signer: %+v", target)
		}
	}
	wrong := Slice6DesiredPostgresSignerTargets()
	wrong[0].DatabaseName = "gateway_copy"
	if VerifySlice6DesiredPostgresSignerTargets(wrong) == nil {
		t.Fatal("Gateway split from Product business database")
	}
	wrong = Slice6DesiredPostgresSignerTargets()
	wrong[5].AgentDeployment = "provider-migration-agent-tls-agent"
	if VerifySlice6DesiredPostgresSignerTargets(wrong) == nil {
		t.Fatal("Provider migration borrowed Vault material signer")
	}
	wrong = Slice6DesiredPostgresSignerTargets()
	wrong[1].SQLRole = "product_runtime"
	if VerifySlice6DesiredPostgresSignerTargets(wrong) == nil {
		t.Fatal("Product migration borrowed runtime SQL login")
	}
}
