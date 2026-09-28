package phase6security

import "testing"

func TestSlice6BrowserDesktopMigrationExpansionCannotBorrowCodingAuthority(t *testing.T) {
	values := Slice6DesiredProviderMigrationExpansions()
	if err := VerifySlice6DesiredProviderMigrationExpansions(values); err != nil {
		t.Fatalf("reviewed migration expansion rejected: %v", err)
	}
	for _, value := range values {
		if value.Job == value.MaterialAgent || value.MaterialVaultSigner == value.PostgresSigner ||
			value.Database == "provider" || value.PostgresNetwork == value.VaultNetwork {
			t.Fatalf("migration identity, database or transport alias: %+v", value)
		}
	}
	wrong := Slice6DesiredProviderMigrationExpansions()
	wrong[0].MaterialVaultSigner = "provider-migration-agent-tls-agent"
	if VerifySlice6DesiredProviderMigrationExpansions(wrong) == nil {
		t.Fatal("Browser migration borrowed coding Provider Vault signer")
	}
	wrong = Slice6DesiredProviderMigrationExpansions()
	wrong[1].SQLRole = "provider_migrator"
	if VerifySlice6DesiredProviderMigrationExpansions(wrong) == nil {
		t.Fatal("Desktop migration borrowed coding Provider SQL role")
	}
	wrong = Slice6DesiredProviderMigrationExpansions()
	wrong[0].PostgresNetwork = wrong[1].PostgresNetwork
	if VerifySlice6DesiredProviderMigrationExpansions(wrong) == nil {
		t.Fatal("two migrations shared a physical PostgreSQL bridge")
	}
}

func TestSlice6FinalExternalAuditRejectsEarlierTwentyEightPathCandidate(t *testing.T) {
	intermediate := Slice6DesiredExecutableExternalTransports()
	missing := MissingSlice6FinalExternalDependencies(intermediate)
	if len(missing) != 4 {
		t.Fatalf("missing final migration paths = %d, want 4: %+v", len(missing), missing)
	}
	profile, err := BuildSlice6ExecutableProfileTarget(validProfile())
	if err != nil || VerifySlice6FinalExternalDependencyClosure(profile) == nil {
		t.Fatal("intermediate 33/28 profile admitted as final dependency closure")
	}
	for _, dependency := range Slice6ProviderMigrationExternalDependencies() {
		intermediate = append(intermediate, Slice6ExternalTransportPath{LogicalCaller: dependency.Dialer,
			Dialer: dependency.Dialer, Service: dependency.Service, Network: dependency.Network,
			EdgeIDs: []string{dependency.EdgeID}})
	}
	if got := MissingSlice6FinalExternalDependencies(intermediate); len(got) != 0 {
		t.Fatalf("full command target still omits migrations: %+v", got)
	}
	intermediate[len(intermediate)-1].Dialer = "provider-migration-job"
	if got := MissingSlice6FinalExternalDependencies(intermediate); len(got) != 1 ||
		got[0].Dialer != "provider-desktop-migration-job" {
		t.Fatalf("migration caller alias was not caught: %+v", got)
	}
}

func TestSlice6FinalExternalGraphHasThirtyTwoDedicatedBridges(t *testing.T) {
	paths, edges := Slice6DesiredFinalExternalTransports(), Slice6DesiredFinalExternalEdges()
	if err := VerifySlice6DesiredFinalExternalGraph(paths, edges); err != nil {
		t.Fatalf("final external target rejected: %v", err)
	}
	bridges := Slice6DesiredFinalServiceBridges()
	if err := VerifySlice6DesiredFinalServiceBridges(bridges); err != nil {
		t.Fatalf("final bridge target rejected: %v", err)
	}
	if err := VerifySlice6DesiredFinalNetworks(Slice6DesiredFinalNetworks()); err != nil {
		t.Fatalf("final merged network target rejected: %v", err)
	}
	if len(Slice6DesiredFinalNetworks()) != len(Slice6DesiredNetworks())+31 {
		t.Fatal("final role networks did not merge exactly 31 new service bridges")
	}
	for _, dependency := range Slice6ProviderMigrationExternalDependencies() {
		dialer, err := Slice6DesiredFinalServiceEndpointAddress(dependency.Network, dependency.Dialer)
		if err != nil || dialer == "" {
			t.Fatalf("migration dialer has no exact .2 address: %+v", dependency)
		}
		service, err := Slice6DesiredFinalServiceEndpointAddress(dependency.Network, dependency.Service)
		if err != nil || service == dialer {
			t.Fatalf("migration service has no distinct .3 address: %+v", dependency)
		}
	}
	wrong := Slice6DesiredFinalExternalTransports()
	wrong[0].Network = "external-uplink"
	if VerifySlice6DesiredFinalExternalGraph(wrong, edges) == nil {
		t.Fatal("NAT migration target admitted")
	}
	wrongBridges := Slice6DesiredFinalServiceBridges()
	wrongBridges[0].Principals = []string{"provider-migration-job"}
	if VerifySlice6DesiredFinalServiceBridges(wrongBridges) == nil {
		t.Fatal("shared or substituted bridge dialer admitted")
	}
}
