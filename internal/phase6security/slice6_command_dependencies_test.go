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
		Dialer: "provider-runtime", Service: "postgres", Network: "service-provider-runtime-postgres", EdgeID: "provider-coding-postgres"}) ||
		!slices.Contains(missing, Slice6DirectExternalDependency{
			Dialer: "gateway-runtime", Service: "postgres", Network: "service-gateway-postgres", EdgeID: "gateway-postgres"}) ||
		!slices.Contains(missing, Slice6DirectExternalDependency{
			Dialer: "workload-credential-controller", Service: "vault", Network: "service-workload-credential-controller-vault", EdgeID: "credential-controller-vault"}) {
		t.Fatalf("critical required direct dials not reported: %v", missing)
	}
	for _, dependency := range Slice6RequiredDirectExternalDependencies() {
		paths = append(paths, Slice6ExternalTransportPath{LogicalCaller: dependency.Dialer,
			Dialer: dependency.Dialer, Service: dependency.Service, Network: dependency.Network,
			EdgeIDs: []string{dependency.EdgeID}})
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
		if seen[dependency.Dialer] || dependency.Dialer == "" || dependency.Service == "" || dependency.Network == "" || dependency.EdgeID == "" {
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
	finalMaterialAgents := materialAgents
	for _, dependency := range Slice6ProviderMigrationExternalDependencies() {
		if dependency.Service == "vault" {
			if seen[dependency.Dialer] || slice6ApprovedDeploymentKinds[dependency.Dialer] != "material_agent" {
				t.Fatalf("migration material agent has duplicate or unapproved Vault dial: %+v", dependency)
			}
			seen[dependency.Dialer] = true
			finalMaterialAgents++
		}
	}
	if finalMaterialAgents != 13 {
		t.Fatalf("final material-agent Vault dials = %d, want 13", finalMaterialAgents)
	}
	for deployment, kind := range slice6ApprovedDeploymentKinds {
		if kind == "material_agent" && !seen[deployment] {
			t.Fatalf("material agent %s has no Vault dial requirement", deployment)
		}
	}
}

func TestSlice6ExecutableExternalTransportPlanIsExactAndComplete(t *testing.T) {
	plan := Slice6DesiredExecutableExternalTransports()
	if err := VerifySlice6DesiredExecutableExternalTransports(plan); err != nil {
		t.Fatalf("reviewed 28-path command transport plan rejected: %v", err)
	}
	if len(plan) != 28 {
		t.Fatalf("physical path count = %d, want 28", len(plan))
	}
	seenNetworks := make(map[string]bool, len(plan))
	seenEdges := make(map[string]bool, 33)
	for _, path := range plan {
		if seenNetworks[path.Network] {
			t.Fatalf("two actual dialers share %s", path.Network)
		}
		seenNetworks[path.Network] = true
		for _, edge := range path.EdgeIDs {
			if seenEdges[edge] {
				t.Fatalf("two physical paths claim %s", edge)
			}
			seenEdges[edge] = true
		}
	}
	if len(seenEdges) != 33 {
		t.Fatalf("reviewed external logical/egress edges = %d, want 33", len(seenEdges))
	}
	wrong := append([]Slice6ExternalTransportPath(nil), plan...)
	wrong[0].Network = "external-uplink"
	if VerifySlice6DesiredExecutableExternalTransports(wrong) == nil {
		t.Fatal("host/NAT bypass plan admitted")
	}
	wrong = append([]Slice6ExternalTransportPath(nil), plan...)
	wrong = wrong[1:]
	if VerifySlice6DesiredExecutableExternalTransports(wrong) == nil {
		t.Fatal("omitted actual dial path admitted")
	}
}

func TestSlice6ExecutableExternalEdgeTargetIsExactAndOwnerBound(t *testing.T) {
	edges := Slice6DesiredExecutableExternalEdges()
	if err := VerifySlice6DesiredExecutableExternalEdges(edges); err != nil {
		t.Fatalf("complete 33-edge target rejected: %v", err)
	}
	if len(edges) != 33 {
		t.Fatalf("external target edges = %d, want 33", len(edges))
	}
	byID := make(map[string]slice6ExternalEdge, len(edges))
	for _, edge := range edges {
		byID[edge.id] = edge
	}
	for _, dependency := range Slice6RequiredDirectExternalDependencies() {
		edge, found := byID[dependency.EdgeID]
		if !found || edge.from != dependency.Dialer || edge.to != dependency.Service {
			t.Fatalf("direct dependency has no owner-bound target edge: %+v", dependency)
		}
		if dependency.Service == "vault" && (edge.protocol != "https" || edge.port != 8200 || edge.maxSeconds != 60) {
			t.Fatalf("Vault edge not short-lived and TLS-bound: %+v", edge)
		}
		if dependency.Dialer == "product-migration-job" || dependency.Dialer == "provider-migration-job" {
			if edge.maxSeconds != 60 || edge.scope != "system" {
				t.Fatalf("migration edge inherited runtime authority: %+v", edge)
			}
		}
	}
	wrong := append([]slice6ExternalEdge(nil), edges...)
	wrong[0].from = "egress-broker-product"
	if VerifySlice6DesiredExecutableExternalEdges(wrong) == nil {
		t.Fatal("substituted external caller admitted")
	}
	wrong = append([]slice6ExternalEdge(nil), edges[1:]...)
	if VerifySlice6DesiredExecutableExternalEdges(wrong) == nil {
		t.Fatal("missing external edge admitted")
	}
}
