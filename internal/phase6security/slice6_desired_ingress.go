package phase6security

import "net/netip"

type slice6IngressSpec struct {
	id, target, trustNetwork, hostBind string
	port                               uint16
}

var slice6DesiredIngress = []slice6IngressSpec{
	{"gateway-public", "gateway-runtime", "ingress-gateway", "127.0.0.1:18445", 8445},
	{"product-public", "product-runtime", "ingress-product", "127.0.0.1:18444", 8444},
}

// VerifySlice6DesiredIngressPolicy freezes the operator ingress relay's
// allowed host publications and resource policy. The pre-freeze IP binder
// calls this before assigning frontend/upstream container addresses.
func VerifySlice6DesiredIngressPolicy(profile Profile) error {
	if profile.Validate() != nil || len(profile.IngressBindings) != len(slice6DesiredIngress) {
		return errSlice6DesiredInventory
	}
	for index, binding := range profile.IngressBindings {
		expected := slice6DesiredIngress[index]
		if binding.ID != expected.id || binding.Relay != "public-ingress-relay" ||
			binding.PublicListenerID != expected.id || binding.Target != expected.target ||
			binding.FrontendNetwork != "public-ingress" || binding.TrustNetwork != expected.trustNetwork ||
			binding.HostBindAddress != expected.hostBind || binding.MaxConnections != 16 ||
			binding.DialTimeoutMillis != 1000 || binding.IdleTimeoutSeconds != 30 ||
			binding.MaxLifetimeSeconds != 300 || binding.DrainTimeoutSeconds != 10 || binding.BufferBytes != 4096 {
			return errSlice6DesiredInventory
		}
		frontend, frontendErr := netip.ParseAddrPort(binding.FrontendAddress)
		upstream, upstreamErr := netip.ParseAddrPort(binding.UpstreamAddress)
		if frontendErr != nil || upstreamErr != nil || frontend.Port() != expected.port || upstream.Port() != expected.port {
			return errSlice6DesiredInventory
		}
	}
	return nil
}

// VerifySlice6DesiredIngress also requires exact preplanned relay and target
// container IPs; profile-valid arbitrary addresses inside a /24 are denied.
func VerifySlice6DesiredIngress(profile Profile) error {
	if VerifySlice6DesiredIngressPolicy(profile) != nil || VerifySlice6DesiredNetworks(profile) != nil {
		return errSlice6DesiredInventory
	}
	for index, binding := range profile.IngressBindings {
		expected := slice6DesiredIngress[index]
		frontend, err := Slice6DesiredEndpointAddress("public-ingress", "public-ingress-relay")
		frontendAddress, parseErr := netip.ParseAddr(frontend)
		if err != nil || parseErr != nil || binding.FrontendAddress != netip.AddrPortFrom(frontendAddress, expected.port).String() {
			return errSlice6DesiredInventory
		}
		upstream, err := Slice6DesiredEndpointAddress(expected.trustNetwork, expected.target)
		upstreamAddress, parseErr := netip.ParseAddr(upstream)
		if err != nil || parseErr != nil || binding.UpstreamAddress != netip.AddrPortFrom(upstreamAddress, expected.port).String() {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
