package phase6security

import (
	"net/netip"
)

// BindSlice6DesiredNetworkPlan translates a structurally valid draft onto the
// reviewed local network/IPAM plan before it is frozen. It does not resolve
// image, issuer, HBA or secret artifacts, and it is not an evidence producer.
// It checks the full reviewed trust-edge inventory; the full gate must still
// independently observe every live endpoint and handshake after launch.
func BindSlice6DesiredNetworkPlan(draft Profile) (Profile, error) {
	if draft.Validate() != nil || VerifySlice6DesiredNetworkGraph(draft) != nil ||
		VerifySlice6DesiredPrincipalIDs(draft) != nil || VerifySlice6DesiredTrustEdges(draft) != nil ||
		VerifySlice6DesiredExternalServices(draft) != nil || VerifySlice6DesiredEgressPolicies(draft) != nil ||
		VerifySlice6DesiredTrustAnchors(draft) != nil ||
		VerifySlice6DesiredIngressPolicy(draft) != nil {
		return Profile{}, errSlice6DesiredInventory
	}
	bound := draft
	bound.Networks = Slice6DesiredNetworks()
	bound.TrustEdges = append([]TrustEdge(nil), draft.TrustEdges...)
	for index, edge := range bound.TrustEdges {
		if edge.TargetAddress == "" {
			continue
		}
		planned, err := slice6PlannedLocalTarget(edge)
		if err != nil {
			return Profile{}, errSlice6DesiredInventory
		}
		bound.TrustEdges[index].TargetAddress = planned
	}
	bound.IngressBindings = append([]IngressBinding(nil), draft.IngressBindings...)
	for index, binding := range bound.IngressBindings {
		frontend, frontendErr := netip.ParseAddrPort(binding.FrontendAddress)
		upstream, upstreamErr := netip.ParseAddrPort(binding.UpstreamAddress)
		if frontendErr != nil || upstreamErr != nil {
			return Profile{}, errSlice6DesiredInventory
		}
		frontendIP, frontendErr := Slice6DesiredEndpointAddress(binding.FrontendNetwork, binding.Relay)
		upstreamIP, upstreamErr := Slice6DesiredEndpointAddress(binding.TrustNetwork, binding.Target)
		if frontendErr != nil || upstreamErr != nil {
			return Profile{}, errSlice6DesiredInventory
		}
		frontendAddress, frontendErr := netip.ParseAddr(frontendIP)
		upstreamAddress, upstreamErr := netip.ParseAddr(upstreamIP)
		if frontendErr != nil || upstreamErr != nil {
			return Profile{}, errSlice6DesiredInventory
		}
		bound.IngressBindings[index].FrontendAddress = netip.AddrPortFrom(frontendAddress, frontend.Port()).String()
		bound.IngressBindings[index].UpstreamAddress = netip.AddrPortFrom(upstreamAddress, upstream.Port()).String()
		bound.IngressBindings[index].ConfigurationDigest = bound.IngressBindings[index].Digest()
	}
	bound.ProfileDigest = bound.Digest()
	if VerifySlice6DesiredNetworks(bound) != nil || VerifySlice6DesiredPrincipalIDs(bound) != nil ||
		VerifySlice6DesiredEdgeAddresses(bound) != nil || VerifySlice6DesiredExternalServices(bound) != nil ||
		VerifySlice6DesiredEgressPolicies(bound) != nil || VerifySlice6DesiredTrustAnchors(bound) != nil ||
		VerifySlice6DesiredIngress(bound) != nil {
		return Profile{}, errSlice6DesiredInventory
	}
	return bound, nil
}
