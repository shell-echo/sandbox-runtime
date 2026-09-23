package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/ingressrelay"
)

func (b IngressBinding) Digest() string {
	b.ConfigurationDigest = ""
	document, _ := json.Marshal(b)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-ingress-binding/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateIngressBindings(bindings []IngressBinding, public []PublicListenerBinding, principals map[string]Principal, networks []Network) error {
	relay, ok := principals["public-ingress-relay"]
	if !ok || relay.Kind != "ingress_relay" || relay.TLS != nil || len(bindings) != 2 {
		return ErrInvalidProfile
	}
	byNetwork := make(map[string]Network, len(networks))
	for _, network := range networks {
		byNetwork[network.Name] = network
	}
	if !slices.Equal(relay.Networks, []string{"ingress-gateway", "ingress-product", "public-ingress"}) {
		return ErrInvalidProfile
	}
	frontend := byNetwork["public-ingress"]
	if frontend.Kind != "public_ingress" || !slices.Equal(frontend.Principals, []string{"public-ingress-relay"}) {
		return ErrInvalidProfile
	}
	config := ingressrelay.Config{Mappings: make([]ingressrelay.Mapping, 0, len(bindings))}
	hostPorts := map[string]bool{}
	for index, binding := range bindings {
		listener := public[index]
		target, exists := principals[binding.Target]
		trust := byNetwork[binding.TrustNetwork]
		frontendSubnet, frontendSubnetErr := netip.ParsePrefix(frontend.IPv4Subnet)
		trustSubnet, trustSubnetErr := netip.ParsePrefix(trust.IPv4Subnet)
		frontendAddress, frontendErr := netip.ParseAddrPort(binding.FrontendAddress)
		upstreamAddress, upstreamErr := netip.ParseAddrPort(binding.UpstreamAddress)
		hostAddress, hostErr := netip.ParseAddrPort(binding.HostBindAddress)
		if !exists || binding.ID != listener.ID || binding.PublicListenerID != listener.ID ||
			binding.Relay != relay.Name || binding.RelayPrincipalDigest != relay.PrincipalDigest ||
			binding.Target != listener.DeploymentName || binding.TargetPrincipalDigest != target.PrincipalDigest ||
			binding.FrontendNetwork != "public-ingress" ||
			binding.TrustNetwork != "ingress-"+strings.TrimSuffix(binding.ID, "-public") ||
			trust.Kind != "trust_edge" || !trust.Internal ||
			!slices.Equal(trust.Principals, sortedPair(relay.Name, target.Name)) ||
			frontendErr != nil || upstreamErr != nil || hostErr != nil ||
			frontendSubnetErr != nil || trustSubnetErr != nil ||
			!frontendSubnet.Contains(frontendAddress.Addr()) || !trustSubnet.Contains(upstreamAddress.Addr()) ||
			frontendAddress.Addr() == frontendSubnet.Addr() || frontendAddress.Addr() == ipv4Broadcast(frontendSubnet) ||
			frontendAddress.Addr() == frontendSubnet.Addr().Next() ||
			upstreamAddress.Addr() == trustSubnet.Addr() || upstreamAddress.Addr() == ipv4Broadcast(trustSubnet) ||
			!hostAddress.Addr().Is4() || !hostAddress.Addr().IsValid() || hostAddress.Addr().IsUnspecified() ||
			hostAddress.Addr().IsMulticast() || hostAddress.Addr().IsLinkLocalUnicast() || hostAddress.Port() == 0 ||
			hostAddress.String() != binding.HostBindAddress || hostPorts[binding.HostBindAddress] ||
			frontendAddress.Port() != uint16(listener.Port) || upstreamAddress.Port() != uint16(listener.Port) ||
			binding.ConfigurationDigest != binding.Digest() {
			return ErrInvalidProfile
		}
		hostPorts[binding.HostBindAddress] = true
		matched := 0
		for _, declared := range relay.Listeners {
			if declared.Name == binding.ID && declared.Protocol == "tcp" && declared.Port == int(frontendAddress.Port()) &&
				declared.Exposure == "ingress_frontend" {
				matched++
			}
		}
		if matched != 1 {
			return ErrInvalidProfile
		}
		config.Mappings = append(config.Mappings, ingressrelay.Mapping{
			ID: binding.ID, FrontendAddress: binding.FrontendAddress, UpstreamAddress: binding.UpstreamAddress,
			MaxConnections: binding.MaxConnections, DialTimeout: time.Duration(binding.DialTimeoutMillis) * time.Millisecond,
			IdleTimeout:  time.Duration(binding.IdleTimeoutSeconds) * time.Second,
			MaxLifetime:  time.Duration(binding.MaxLifetimeSeconds) * time.Second,
			DrainTimeout: time.Duration(binding.DrainTimeoutSeconds) * time.Second, BufferBytes: binding.BufferBytes,
		})
	}
	if _, err := ingressrelay.New(config); err != nil {
		return ErrInvalidProfile
	}
	return nil
}

func sortedPair(first, second string) []string {
	result := []string{first, second}
	slices.Sort(result)
	return result
}

func (p Profile) IngressRelayConfig() (ingressrelay.Config, Principal, error) {
	if p.Validate() != nil {
		return ingressrelay.Config{}, Principal{}, ErrInvalidProfile
	}
	var relay Principal
	for _, principal := range p.Principals {
		if principal.Name == "public-ingress-relay" {
			relay = principal
		}
	}
	config := ingressrelay.Config{Mappings: make([]ingressrelay.Mapping, 0, len(p.IngressBindings))}
	for _, binding := range p.IngressBindings {
		config.Mappings = append(config.Mappings, ingressrelay.Mapping{ID: binding.ID,
			FrontendAddress: binding.FrontendAddress, UpstreamAddress: binding.UpstreamAddress,
			MaxConnections: binding.MaxConnections, DialTimeout: time.Duration(binding.DialTimeoutMillis) * time.Millisecond,
			IdleTimeout:  time.Duration(binding.IdleTimeoutSeconds) * time.Second,
			MaxLifetime:  time.Duration(binding.MaxLifetimeSeconds) * time.Second,
			DrainTimeout: time.Duration(binding.DrainTimeoutSeconds) * time.Second, BufferBytes: binding.BufferBytes})
	}
	return config, relay, nil
}
