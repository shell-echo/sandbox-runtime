package phase6security

import (
	"encoding/json"
	"slices"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

// Validate is deliberately independent of Profile.Validate. It remains
// fail-closed while the v2 source-to-image and role composition are unfinished.
func (p ProfileV2) Validate() error {
	if p.validateFields() != nil {
		return ErrInvalidProfile
	}
	return ErrInvalidProfile
}

// validateFields is an unexported pure check so test-only complete synthetic
// fixtures can establish that the field chain has a success path. It never
// authorizes launch; neither the v1 registry nor its protocol/digest decision
// is consulted for this v2 field check.
func (p ProfileV2) validateFields() error { //nolint:gocyclo
	if p.Protocol != ProtocolIDV2 || p.Version != VersionV2 || !namePattern.MatchString(p.Revision) ||
		!digestPattern.MatchString(p.ProfileDigest) || !digestPattern.MatchString(p.EnvironmentDigest) ||
		!digestPattern.MatchString(p.PrincipalProfileDigest) || len(p.Principals) != 82 ||
		len(p.Components) != 1 || len(p.Networks) == 0 || len(p.Networks) > 256 ||
		len(p.External) != 5 || len(p.TrustEdges) == 0 || len(p.TrustEdges) > 512 ||
		len(p.ProviderDatabases) != 2 || len(p.TrustAnchors) == 0 || len(p.TrustAnchors) > 128 ||
		len(p.PublicListeners) != 2 || len(p.IngressBindings) != 2 ||
		len(p.PostgresClientAgents) != 9 || len(p.EgressPolicies) > 128 ||
		!exactStrings(p.CleanupClasses, []string{"connections", "containers", "files", "networks", "processes", "sockets"}) ||
		VerifySlice6V2IdentityFragment(p.EnvironmentDigest, p.PrincipalProfileDigest,
			p.Principals, p.TLSAgentBindings) != nil {
		return ErrInvalidProfile
	}
	registry, err := p.principalRegistryV2()
	if err != nil {
		return ErrInvalidProfile
	}
	principals := make(map[string]Principal, len(p.Principals))
	authorityBindings := make(map[string]principalBinding, len(p.EgressPolicies))
	dynamicTLSBindings := make(map[string]principalBinding, len(p.EgressPolicies))
	for _, policy := range p.EgressPolicies {
		authority := policy.Authority
		if _, duplicate := authorityBindings[authority.DeploymentName]; duplicate {
			return ErrInvalidProfile
		}
		authorityBindings[authority.DeploymentName] = principalBinding{securityprincipal.KindController, authority.AuthorizationName, ""}
		for _, binding := range p.TLSAgentBindings {
			if binding.SubjectDeployment != policy.Broker {
				continue
			}
			for _, principal := range p.Principals {
				if principal.Name == policy.Broker && principal.AuthorizationPrincipal != nil {
					identity := principal.AuthorizationPrincipal
					dynamicTLSBindings[binding.AgentDeployment] = principalBinding{
						securityprincipal.KindTLSAgent, identity.Name + "_tls_agent", identity.Role}
					break
				}
			}
		}
	}
	for _, principal := range p.Principals {
		if _, newRole := slice6V2IdentityDelta[principal.Name]; newRole {
			if validateV2NewPrincipal(principal, p.DockerControl, p.ArtifactScanner) != nil {
				return ErrInvalidProfile
			}
		} else if validatePrincipal(principal, registry, authorityBindings, dynamicTLSBindings) != nil {
			return ErrInvalidProfile
		}
		principals[principal.Name] = principal
	}
	if c := p.Components[0]; c.Name != "desktop-broker" || c.ParentDeployment != "desktop-sandbox-runtime" ||
		c.Executable != "/usr/local/libexec/sandbox-runtime/desktop-broker" || !digestPattern.MatchString(c.ExecutableDigest) ||
		!exactStrings(c.Argv, []string{c.Executable, "serve"}) || c.Socket != "/tmp/sandbox-runtime-desktop-broker.sock" ||
		c.BrokerProtocol != "sandbox.runtime/desktop-broker/v1" || c.SessionProtocol != "sandbox.runtime/desktop-session.v2" {
		return ErrInvalidProfile
	}
	if validateSandboxIdentitySlots(p.SandboxIdentitySlots, principals) != nil ||
		VerifySlice6V2CodingSlots(p.CodingTemplate, p.Principals, p.SandboxIdentitySlots) != nil {
		return ErrInvalidProfile
	}
	external, err := validateExternal(p.External)
	if err != nil || validateV2DNSClientCA(p.External) != nil ||
		validateNetworks(p.Networks, principals, external, p.EgressPolicies) != nil {
		return ErrInvalidProfile
	}
	edges, err := validateEdges(p.TrustEdges, principals, external)
	if err != nil || validateProviderDatabases(p.ProviderDatabases, principals, external, edges, p.EgressPolicies) != nil ||
		p.PostgresServerAuth.validate(p.ProviderDatabases, external, p.TrustAnchors) != nil ||
		validateRuntimeEdges(edges, principals, p.Networks) != nil || validateBrowserMux(principals, edges) != nil ||
		validatePublicListeners(p.PublicListeners, principals) != nil ||
		validateIngressBindings(p.IngressBindings, p.PublicListeners, principals, p.Networks) != nil ||
		validateTrustAnchorsWithPostgres(p.TrustAnchors, p.TrustEdges, p.PublicListeners,
			p.CertificateController, p.PostgresClientAgents, principals, external) != nil ||
		validateEgress(p.EgressPolicies, principals, edges) != nil ||
		validateBrokerBoundaries(p.EgressPolicies, edges, principals, p.Networks) != nil ||
		validateBrowserExternalAuthority(external, edges, p.EgressPolicies) != nil ||
		validateCertificateControllerAuthority(p.CertificateController, principals, edges) != nil ||
		validateCredentialIssuerSockets(p.CredentialIssuerSockets, principals, edges) != nil ||
		validatePostgresClientAgents(p.PostgresClientAgents, p.ProviderDatabases, p.TLSAgentBindings,
			p.EgressPolicies, p.CertificateController, p.TrustAnchors, principals, edges) != nil ||
		validateTLSAgentBindingsV2(p.TLSAgentBindings, p.PostgresClientAgents, p.EgressPolicies,
			p.CertificateController, p.CredentialIssuerSockets, p.MaterialSockets,
			p.BreakGlassSockets, principals, edges) != nil {
		return ErrInvalidProfile
	}
	for name, service := range external {
		for _, edge := range service.IngressEdges {
			if bound, ok := edges[edge]; !ok || bound.To != name {
				return ErrInvalidProfile
			}
		}
	}
	// These helper views contain only fields read by the corresponding pure
	// validators. They are never presented to Profile.Validate or Decode.
	shared := Profile{Revision: p.Revision, Principals: p.Principals, MaterialSockets: p.MaterialSockets,
		BreakGlassSockets: p.BreakGlassSockets, BreakGlassOperatorTasks: p.BreakGlassOperatorTasks,
		BreakGlassExecutableArtifact: p.BreakGlassExecutableArtifact}
	if VerifySlice6MaterialSocketBindings(shared) != nil ||
		VerifySlice6BreakGlassBoundaries(shared) != nil ||
		VerifySlice6BreakGlassKeyAuthority(p.BreakGlassKeyAuthority) != nil ||
		VerifySlice6BreakGlassExecutableArtifact(shared) != nil ||
		validateV2ControlAuthority(p, principals, edges) != nil ||
		validateV2ScannerAuthority(p, principals, edges) != nil {
		return ErrInvalidProfile
	}
	budget, err := CalculateSlice6V2ResourceBudget(p.Principals, p.SandboxIdentitySlots,
		p.CodingTemplate, p.SandboxGatewayLimits, p.ExternalResourceLimits)
	if err != nil || budget != p.ResourceBudget {
		return ErrInvalidProfile
	}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > maxBytes || p.ProfileDigest != p.Digest() {
		return ErrInvalidProfile
	}
	return nil
}

func validateV2DNSClientCA(services []ExternalService) error {
	count := 0
	for _, service := range services {
		if service.Name != "dns" {
			if service.DNSClientCA != nil {
				return ErrInvalidProfile
			}
			continue
		}
		count++
		ca := service.DNSClientCA
		if ca == nil || ca.ArtifactID != "dns-broker-client-ca" ||
			!digestPattern.MatchString(ca.BundleDigest) ||
			!ValidSlice6IssuerID(ca.IssuerID) ||
			!digestPattern.MatchString(ca.IssuerDigest) ||
			!slices.Equal(ca.AllowedSubjects, slice6DNSBrokerSubjects) {
			return ErrInvalidProfile
		}
	}
	if count != 1 {
		return ErrInvalidProfile
	}
	return nil
}

func (p ProfileV2) principalRegistryV2() (*securityprincipal.Registry, error) {
	egressBrokers := map[string]securityprincipal.Role{}
	authorities := map[string]securityprincipal.Role{}
	for _, policy := range p.EgressPolicies {
		if _, duplicate := authorities[policy.Authority.AuthorizationName]; duplicate {
			return nil, ErrInvalidProfile
		}
		authorities[policy.Authority.AuthorizationName] = ""
	}
	for _, principal := range p.Principals {
		if principal.Kind != "egress_broker" || principal.AuthorizationPrincipal == nil {
			continue
		}
		identity := principal.AuthorizationPrincipal
		if identity.Kind != securityprincipal.KindEgressBroker {
			return nil, ErrInvalidProfile
		}
		if _, duplicate := egressBrokers[identity.Name]; duplicate {
			return nil, ErrInvalidProfile
		}
		egressBrokers[identity.Name] = identity.Role
	}
	registry, err := securityprincipal.NewSlice6V2Registry(p.EnvironmentDigest,
		p.PrincipalProfileDigest, egressBrokers, authorities)
	if err != nil {
		return nil, ErrInvalidProfile
	}
	return registry, nil
}
