package phase6security

import (
	"slices"
	"sort"
)

// These names, workload identities and DNS SANs are the reviewed local-gate
// external dependency boundary. Image descriptors and CA material are not
// supplied here: they must come from independently verified run inputs.
var slice6DesiredExternalServices = []struct {
	name, uri, dnsName string
}{
	{"action-history-postgres", "spiffe://sandbox-runtime.test/external/action-history-postgres", "action-history.sandbox-runtime.test"},
	{"capacity-valkey", "spiffe://sandbox-runtime.test/external/capacity-valkey", "capacity.sandbox-runtime.test"},
	{"dns", "spiffe://sandbox-runtime.test/external/dns", "dns.sandbox-runtime.test"},
	{"postgres", "spiffe://sandbox-runtime.test/external/postgres", "postgres.sandbox-runtime.test"},
	{"vault", "spiffe://sandbox-runtime.test/external/vault", "vault.sandbox-runtime.test"},
}

// Slice6DesiredExternalServiceNames returns the reviewed five-service set for
// exact resource-budget binding. It grants no service identity or network edge.
func Slice6DesiredExternalServiceNames() []string {
	names := make([]string, 0, len(slice6DesiredExternalServices))
	for _, service := range slice6DesiredExternalServices {
		names = append(names, service.name)
	}
	return names
}

// VerifySlice6DesiredExternalServices rejects a self-consistent profile that
// silently substitutes an external identity, name, SAN or allowed inbound edge.
// It does not attest that the pinned image, certificate or server was observed.
func VerifySlice6DesiredExternalServices(profile Profile) error {
	if profile.Validate() != nil || len(profile.External) != len(slice6DesiredExternalServices) {
		return errSlice6DesiredInventory
	}
	ingress := make(map[string][]string, len(slice6DesiredExternalServices))
	for _, edge := range slice6DesiredExternalEdges {
		ingress[edge.to] = append(ingress[edge.to], edge.id)
	}
	for index, service := range profile.External {
		expected := slice6DesiredExternalServices[index]
		edges := ingress[expected.name]
		sort.Strings(edges)
		if service.Name != expected.name || service.URI != expected.uri ||
			!slices.Equal(service.DNSNames, []string{expected.dnsName}) ||
			!slices.Equal(service.IngressEdges, edges) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
