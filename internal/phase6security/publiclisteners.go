package phase6security

import "slices"

var requiredPublicListeners = map[string]string{
	"gateway-public": "gateway-runtime",
	"product-public": "product-runtime",
}

func validatePublicListeners(bindings []PublicListenerBinding, principals map[string]Principal) error {
	seen := make(map[string]bool, len(bindings))
	previous := ""
	for _, binding := range bindings {
		expectedDeployment, required := requiredPublicListeners[binding.ID]
		principal, exists := principals[binding.DeploymentName]
		if !required || !exists || binding.ID <= previous || seen[binding.ID] ||
			binding.DeploymentName != expectedDeployment || binding.PrincipalDigest != principal.PrincipalDigest ||
			principal.Kind != "runtime" || principal.TLS == nil || !slices.Contains(principal.TLS.Usages, "server_auth") ||
			len(principal.TLS.DNSNames) == 0 || binding.ListenerName == "" || binding.Port < 1 || binding.Port > 65535 ||
			binding.ClientAuthentication != "none" || !namePattern.MatchString(binding.IssuerAnchorID) {
			return ErrInvalidProfile
		}
		matched := 0
		for _, listener := range principal.Listeners {
			if listener.Exposure == "public" && listener.Name == binding.ListenerName && listener.Protocol == "tcp" && listener.Port == binding.Port {
				matched++
			}
		}
		if matched != 1 {
			return ErrInvalidProfile
		}
		seen[binding.ID] = true
		previous = binding.ID
	}
	if len(seen) != len(requiredPublicListeners) {
		return ErrInvalidProfile
	}
	for _, principal := range principals {
		for _, listener := range principal.Listeners {
			if listener.Exposure != "public" {
				continue
			}
			count := 0
			for _, binding := range bindings {
				if binding.DeploymentName == principal.Name && binding.ListenerName == listener.Name &&
					listener.Protocol == "tcp" && binding.Port == listener.Port {
					count++
				}
			}
			if count != 1 {
				return ErrInvalidProfile
			}
		}
	}
	return nil
}

// PublicTLSBoundary returns only one of the two exact server-only public
// listeners. It does not authorize an internal peer or application request.
func (p Profile) PublicTLSBoundary(id string, port int) (TLSAgentBinding, Principal, Principal, TrustAnchor, error) {
	if p.Validate() != nil {
		return TLSAgentBinding{}, Principal{}, Principal{}, TrustAnchor{}, ErrInvalidProfile
	}
	for _, listener := range p.PublicListeners {
		if listener.ID != id || listener.Port != port {
			continue
		}
		binding, agent, subject, err := p.TLSAgentForSubject(listener.DeploymentName)
		if err != nil {
			return TLSAgentBinding{}, Principal{}, Principal{}, TrustAnchor{}, ErrInvalidProfile
		}
		anchor, err := p.ConsumerTrustAnchor(listener.IssuerAnchorID, listener.DeploymentName, "server_verification")
		if err != nil {
			return TLSAgentBinding{}, Principal{}, Principal{}, TrustAnchor{}, ErrInvalidProfile
		}
		return binding, agent, subject, anchor, nil
	}
	return TLSAgentBinding{}, Principal{}, Principal{}, TrustAnchor{}, ErrInvalidProfile
}
