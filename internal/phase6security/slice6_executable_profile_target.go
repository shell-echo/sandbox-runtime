package phase6security

import (
	"slices"
	"sort"
)

// BuildSlice6ExecutableProfileTarget upgrades a reviewed 17/12 draft to the
// complete 33/28 command-level target. It is a profile construction step,
// not launch authorization or observed evidence. The caller must still bind
// real image, trust, credential, resource and issuer inputs, then run all
// named live gates before accepting the profile.
func BuildSlice6ExecutableProfileTarget(draft Profile) (Profile, error) {
	bound, err := BindSlice6DesiredNetworkPlan(draft)
	if err != nil || VerifySlice6DesiredExecutableExternalEdges(Slice6DesiredExecutableExternalEdges()) != nil ||
		VerifySlice6DesiredCompleteNetworks(Slice6DesiredCompleteNetworks()) != nil {
		return Profile{}, errSlice6DesiredInventory
	}
	bound.Networks = Slice6DesiredCompleteNetworks()
	bound.Principals = append([]Principal(nil), bound.Principals...)
	bound.External = append([]ExternalService(nil), bound.External...)
	bound.TrustEdges = append([]TrustEdge(nil), bound.TrustEdges...)
	bound.TrustAnchors = append([]TrustAnchor(nil), bound.TrustAnchors...)
	bound.ProviderDatabases = append([]ProviderDatabaseBinding(nil), bound.ProviderDatabases...)

	principals := make(map[string]int, len(bound.Principals))
	for index := range bound.Principals {
		bound.Principals[index].Networks = append([]string(nil), bound.Principals[index].Networks...)
		bound.Principals[index].Mounts = append([]Mount(nil), bound.Principals[index].Mounts...)
		principals[bound.Principals[index].Name] = index
	}
	services := make(map[string]int, len(bound.External))
	for index := range bound.External {
		bound.External[index].Networks = append([]string(nil), bound.External[index].Networks...)
		bound.External[index].IngressEdges = append([]string(nil), bound.External[index].IngressEdges...)
		services[bound.External[index].Name] = index
	}
	for _, path := range Slice6DesiredExecutableExternalTransports() {
		dialerIndex, dialerFound := principals[path.Dialer]
		serviceIndex, serviceFound := services[path.Service]
		if !dialerFound || !serviceFound {
			return Profile{}, errSlice6DesiredInventory
		}
		if !slices.Contains(bound.Principals[dialerIndex].Networks, path.Network) {
			bound.Principals[dialerIndex].Networks = append(bound.Principals[dialerIndex].Networks, path.Network)
			sort.Strings(bound.Principals[dialerIndex].Networks)
		}
		bound.External[serviceIndex].Networks = append(bound.External[serviceIndex].Networks, path.Network)
		for _, id := range path.EdgeIDs {
			if !slices.Contains(bound.External[serviceIndex].IngressEdges, id) {
				bound.External[serviceIndex].IngressEdges = append(bound.External[serviceIndex].IngressEdges, id)
			}
		}
	}
	for index := range bound.External {
		sort.Strings(bound.External[index].Networks)
		sort.Strings(bound.External[index].IngressEdges)
		bound.External[index].IdentityDigest = bound.External[index].Digest()
	}
	byService := make(map[string]ExternalService, len(bound.External))
	for _, service := range bound.External {
		byService[service.Name] = service
	}
	for index := range bound.TrustEdges {
		if bound.TrustEdges[index].CrossDomain {
			bound.TrustEdges[index].ExternalIdentityDigest = byService[bound.TrustEdges[index].To].IdentityDigest
		}
	}
	for _, binding := range Slice6RequiredDirectExternalDependencies() {
		if slices.ContainsFunc(bound.TrustEdges, func(edge TrustEdge) bool { return edge.ID == binding.EdgeID }) {
			continue
		}
		var spec slice6ExternalEdge
		for _, target := range Slice6DesiredExecutableExternalEdges() {
			if target.id == binding.EdgeID {
				spec = target
				break
			}
		}
		from := bound.Principals[principals[spec.from]]
		to := byService[spec.to]
		if spec.id == "" || from.TLS == nil || to.Name == "" {
			return Profile{}, errSlice6DesiredInventory
		}
		bound.TrustEdges = append(bound.TrustEdges, TrustEdge{ID: spec.id, From: spec.from, To: spec.to,
			Protocol: spec.protocol, Port: spec.port, Authentication: "mtls", ServerAnchorID: "external-server-ca",
			FromURI: from.TLS.URI, ToURI: to.URI, FromPrincipalDigest: from.PrincipalDigest,
			ExternalIdentityDigest: to.IdentityDigest, TenantScope: spec.scope, MaxConnectionSeconds: spec.maxSeconds,
			CrossDomain: true})
	}
	sort.Slice(bound.TrustEdges, func(i, j int) bool { return bound.TrustEdges[i].ID < bound.TrustEdges[j].ID })
	for index := range bound.ProviderDatabases {
		bound.ProviderDatabases[index].ServiceIdentityDigest = byService[bound.ProviderDatabases[index].ServiceName].IdentityDigest
	}
	bound.PostgresServerAuth.ServiceIdentityDigest = byService["postgres"].IdentityDigest
	for index := range bound.TrustAnchors {
		anchor := &bound.TrustAnchors[index]
		anchor.Consumers = append([]string(nil), anchor.Consumers...)
		for _, dependency := range Slice6RequiredDirectExternalDependencies() {
			if anchor.ID != "external-server-ca" && (anchor.ID != "vault-client-ca" || dependency.Service != "vault") {
				continue
			}
			if !slices.Contains(anchor.Consumers, dependency.Dialer) {
				anchor.Consumers = append(anchor.Consumers, dependency.Dialer)
			}
			principal := &bound.Principals[principals[dependency.Dialer]]
			if !hasTrustAnchorMount(*principal, *anchor) {
				principal.Mounts = append(principal.Mounts, Mount{Target: anchor.TargetPath, Kind: "trust_anchor",
					ReadOnly: true, StorageID: anchor.StorageID})
			}
		}
		sort.Strings(anchor.Consumers)
	}
	bound.ProfileDigest = bound.Digest()
	if bound.Validate() != nil || VerifySlice6DesiredCompleteNetworks(bound.Networks) != nil ||
		VerifySlice6DesiredExecutableExternalProfile(bound) != nil {
		return Profile{}, errSlice6DesiredInventory
	}
	return bound, nil
}

// VerifySlice6DesiredExecutableExternalProfile closes the new network and
// edge inventory. It is separate from the historical 17/12 admission and
// intentionally does not claim live service or credential observations.
func VerifySlice6DesiredExecutableExternalProfile(profile Profile) error {
	if profile.Validate() != nil || VerifySlice6DesiredCompleteNetworks(profile.Networks) != nil ||
		VerifySlice6DesiredPrincipalIDs(profile) != nil || len(profile.TrustEdges) != len(slice6DesiredTrustEdges())+16 ||
		len(profile.External) != len(slice6DesiredExternalServices) {
		return errSlice6DesiredInventory
	}
	actual := make(map[string]TrustEdge, len(profile.TrustEdges))
	for _, edge := range profile.TrustEdges {
		actual[edge.ID] = edge
	}
	for _, desired := range slice6DesiredTrustEdges() {
		edge, found := actual[desired.id]
		if !found || edge.From != desired.from || edge.To != desired.to || edge.Protocol != desired.protocol ||
			edge.Port != desired.port || edge.RoutePath != desired.route || edge.Authentication != desired.authentication ||
			edge.TenantScope != desired.scope || edge.ServerAnchorID != desired.serverAnchor ||
			edge.ClientAnchorID != desired.clientAnchor || edge.MaxConnectionSeconds != desired.maxSeconds ||
			edge.CrossDomain != desired.crossDomain || (edge.TargetAddress != "") != desired.numericTarget {
			return errSlice6DesiredInventory
		}
		if desired.numericTarget {
			planned, err := slice6PlannedLocalTarget(edge)
			if err != nil || edge.TargetAddress != planned {
				return errSlice6DesiredInventory
			}
		}
	}
	for _, desired := range Slice6DesiredExecutableExternalEdges() {
		edge, found := actual[desired.id]
		if !found || edge.From != desired.from || edge.To != desired.to || edge.Protocol != desired.protocol ||
			edge.Port != desired.port || edge.TenantScope != desired.scope ||
			edge.MaxConnectionSeconds != desired.maxSeconds || edge.Authentication != "mtls" ||
			edge.ServerAnchorID != "external-server-ca" || edge.ClientAnchorID != "" ||
			!edge.CrossDomain || edge.TargetAddress != "" {
			return errSlice6DesiredInventory
		}
	}
	for index, service := range profile.External {
		identity := slice6DesiredExternalServices[index]
		if service.Name != identity.name || service.URI != identity.uri ||
			!slices.Equal(service.DNSNames, []string{identity.dnsName}) {
			return errSlice6DesiredInventory
		}
		var networks, ingress []string
		for _, path := range Slice6DesiredExecutableExternalTransports() {
			if path.Service == service.Name {
				networks = append(networks, path.Network)
			}
		}
		for _, edge := range Slice6DesiredExecutableExternalEdges() {
			if edge.to == service.Name {
				ingress = append(ingress, edge.id)
			}
		}
		sort.Strings(networks)
		sort.Strings(ingress)
		if !slices.Equal(service.Networks, networks) || !slices.Equal(service.IngressEdges, ingress) {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
