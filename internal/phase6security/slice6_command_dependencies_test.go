package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6CommandDependencyAuditDoesNotMistakeEdgeCoverageForCompleteTransport(t *testing.T) {
	paths := Slice6DesiredExternalTransports()
	if err := VerifySlice6DesiredExternalTransportCoverage(paths); err != nil {
		t.Fatalf("existing reviewed-edge table rejected: %v", err)
	}
	missing := MissingSlice6DirectExternalDependencies(paths)
	if VerifySlice6ExecutableExternalDependencyCoverage(paths) == nil {
		t.Fatal("incomplete command-level dependencies admitted")
	}
	if len(missing) != 16 {
		t.Fatalf("missing command-level direct paths = %d, want 16", len(missing))
	}
	if !slices.Contains(missing, Slice6DirectExternalDependency{
		Dialer: "provider-runtime", Service: "postgres", Network: "service-provider-runtime-postgres"}) ||
		!slices.Contains(missing, Slice6DirectExternalDependency{
			Dialer: "gateway-runtime", Service: "postgres", Network: "service-gateway-postgres"}) ||
		!slices.Contains(missing, Slice6DirectExternalDependency{
			Dialer: "workload-credential-controller", Service: "vault", Network: "service-workload-credential-controller-vault"}) {
		t.Fatalf("critical required direct dials not reported: %v", missing)
	}
	for _, dependency := range Slice6RequiredDirectExternalDependencies() {
		paths = append(paths, Slice6ExternalTransportPath{LogicalCaller: dependency.Dialer,
			Dialer: dependency.Dialer, Service: dependency.Service, Network: dependency.Network})
	}
	if got := MissingSlice6DirectExternalDependencies(paths); len(got) != 0 {
		t.Fatalf("complete direct dial inventory still has gaps: %v", got)
	}
	if err := VerifySlice6ExecutableExternalDependencyCoverage(paths); err != nil {
		t.Fatalf("complete direct dial inventory rejected: %v", err)
	}
	paths[len(paths)-1].Dialer = "egress-broker-product"
	if got := MissingSlice6DirectExternalDependencies(paths); len(got) != 1 || got[0].Dialer != "workload-credential-controller" {
		t.Fatalf("broker substitution was not reported: %v", got)
	}
}

func TestSlice6DirectExternalDependencyAuditHasExactOwners(t *testing.T) {
	wanted := Slice6RequiredDirectExternalDependencies()
	if len(wanted) != 18 {
		t.Fatalf("direct dependency count = %d, want 18", len(wanted))
	}
	seen := make(map[string]bool, len(wanted))
	materialAgents := 0
	for _, dependency := range wanted {
		if seen[dependency.Dialer] || dependency.Dialer == "" || dependency.Service == "" || dependency.Network == "" {
			t.Fatalf("duplicate or incomplete direct dial requirement: %+v", dependency)
		}
		seen[dependency.Dialer] = true
		if kind := slice6ApprovedDeploymentKinds[dependency.Dialer]; kind == "" || kind == "sandbox" {
			t.Fatalf("unregistered direct dialer: %+v", dependency)
		} else if kind == "material_agent" {
			materialAgents++
			if dependency.Service != "vault" {
				t.Fatalf("material agent must resolve only Vault: %+v", dependency)
			}
		}
	}
	if materialAgents != 11 {
		t.Fatalf("material-agent direct Vault dials = %d, want 11", materialAgents)
	}
	for deployment, kind := range slice6ApprovedDeploymentKinds {
		if kind == "material_agent" && !seen[deployment] {
			t.Fatalf("material agent %s has no Vault dial requirement", deployment)
		}
	}
}
