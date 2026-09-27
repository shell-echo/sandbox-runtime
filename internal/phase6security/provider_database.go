package phase6security

import "regexp"

var postgresAuthorityID = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// ProviderDatabaseBinding is the closed owner-to-PostgreSQL authority in the
// complete deployment profile. It references an existing material binding;
// it never contains a DSN, password or secret-value digest.
type ProviderDatabaseBinding struct {
	OwnerDeployment       string `json:"owner_deployment"`
	OwnerPrincipalDigest  string `json:"owner_principal_digest"`
	Template              string `json:"template"`
	Namespace             string `json:"namespace"`
	ControllerID          string `json:"controller_id"`
	ServiceName           string `json:"service_name"`
	ServiceIdentityDigest string `json:"service_identity_digest"`
	TrustEdgeID           string `json:"trust_edge_id"`
	EgressPolicyID        string `json:"egress_policy_id"`
	BrokerDeployment      string `json:"broker_deployment"`
	BrokerRoleEdgeID      string `json:"broker_role_edge_id"`
	BrokerExternalEdgeID  string `json:"broker_external_edge_id"`
	DatabaseName          string `json:"database_name"`
	RuntimeRole           string `json:"runtime_role"`
	ServerAuthPolicyID    string `json:"server_auth_policy_id"`
	RuntimeDSNBindingID   string `json:"runtime_dsn_binding_id"`
}

func validateProviderDatabases(bindings []ProviderDatabaseBinding, principals map[string]Principal,
	external map[string]ExternalService, edges map[string]TrustEdge, policies []EgressPolicy) error {
	if len(bindings) != 2 {
		return ErrInvalidProfile
	}
	previous := ""
	seenMaterial := map[string]struct{}{}
	for _, binding := range bindings {
		owner, ownerOK := principals[binding.OwnerDeployment]
		service, serviceOK := external[binding.ServiceName]
		edge, edgeOK := edges[binding.TrustEdgeID]
		broker, brokerOK := principals[binding.BrokerDeployment]
		roleEdge, roleEdgeOK := edges[binding.BrokerRoleEdgeID]
		externalEdge, externalEdgeOK := edges[binding.BrokerExternalEdgeID]
		var policy EgressPolicy
		for _, candidate := range policies {
			if candidate.ID == binding.EgressPolicyID {
				policy = candidate
				break
			}
		}
		if binding.OwnerDeployment <= previous || !ownerOK || owner.AuthorizationPrincipal == nil ||
			binding.OwnerPrincipalDigest != owner.PrincipalDigest ||
			sandboxTemplateOwners[binding.Template] != binding.OwnerDeployment ||
			!namePattern.MatchString(binding.Namespace) || !namePattern.MatchString(binding.ControllerID) ||
			binding.ServiceName != "postgres" || !serviceOK || len(service.DNSNames) != 1 ||
			binding.ServiceIdentityDigest != service.IdentityDigest ||
			!edgeOK || edge.From != binding.OwnerDeployment || edge.To != binding.ServiceName ||
			edge.Protocol != "postgres" || edge.Authentication != "mtls" || edge.Port != 5432 ||
			edge.ExternalIdentityDigest != service.IdentityDigest || edge.ServerAnchorID == "" ||
			!brokerOK || broker.Kind != "egress_broker" || policy.ID == "" ||
			policy.Principal != binding.OwnerDeployment || policy.Broker != binding.BrokerDeployment ||
			len(policy.Targets) != 1 || policy.Targets[0] != (EgressTarget{Alias: "postgres", Host: service.DNSNames[0], Port: 5432, Protocol: "postgres"}) ||
			!roleEdgeOK || roleEdge.From != binding.OwnerDeployment || roleEdge.To != binding.BrokerDeployment ||
			roleEdge.Protocol != "tls" || roleEdge.Authentication != "mtls" ||
			!externalEdgeOK || externalEdge.From != binding.BrokerDeployment || externalEdge.To != binding.ServiceName ||
			externalEdge.Protocol != "postgres" || externalEdge.Authentication != "mtls" ||
			externalEdge.ExternalIdentityDigest != service.IdentityDigest ||
			!postgresAuthorityID.MatchString(binding.DatabaseName) || !postgresAuthorityID.MatchString(binding.RuntimeRole) ||
			binding.ServerAuthPolicyID != postgresServerAuthPolicyID ||
			!namePattern.MatchString(binding.RuntimeDSNBindingID) {
			return ErrInvalidProfile
		}
		if _, repeated := seenMaterial[binding.RuntimeDSNBindingID]; repeated {
			return ErrInvalidProfile
		}
		seenMaterial[binding.RuntimeDSNBindingID] = struct{}{}
		previous = binding.OwnerDeployment
	}
	if bindings[0].OwnerDeployment != "provider-browser-runtime" || bindings[1].OwnerDeployment != "provider-desktop-runtime" ||
		bindings[0].DatabaseName == bindings[1].DatabaseName || bindings[0].RuntimeRole == bindings[1].RuntimeRole ||
		(bindings[0].Namespace == bindings[1].Namespace && bindings[0].ControllerID == bindings[1].ControllerID) {
		return ErrInvalidProfile
	}
	return nil
}

// ProviderDatabaseAuthority returns only the profile-owned target and trust
// identity. Callers must compare their configuration and the resolved DSN to
// these values before opening a pool; SQL names alone do not prove server
// identity.
func (p Profile) ProviderDatabaseAuthority(owner string) (ProviderDatabaseBinding, ExternalService, TrustEdge, TrustAnchor, error) {
	if p.Validate() != nil {
		return ProviderDatabaseBinding{}, ExternalService{}, TrustEdge{}, TrustAnchor{}, ErrInvalidProfile
	}
	for _, binding := range p.ProviderDatabases {
		if binding.OwnerDeployment != owner {
			continue
		}
		var service ExternalService
		var edge TrustEdge
		var anchor TrustAnchor
		for _, item := range p.External {
			if item.Name == binding.ServiceName {
				service = item
			}
		}
		for _, item := range p.TrustEdges {
			if item.ID == binding.TrustEdgeID {
				edge = item
			}
		}
		for _, item := range p.TrustAnchors {
			if item.ID == edge.ServerAnchorID {
				anchor = item
			}
		}
		if service.Name != "" && edge.ID != "" && anchor.ID != "" {
			return binding, service, edge, anchor, nil
		}
	}
	return ProviderDatabaseBinding{}, ExternalService{}, TrustEdge{}, TrustAnchor{}, ErrInvalidProfile
}

// AssertProviderDatabaseRuntime compares non-secret process configuration to
// profile authority. The database name and service are not caller inputs.
func (p Profile) AssertProviderDatabaseRuntime(owner, namespace, controllerID, runtimeRole, materialBindingID string) error {
	binding, _, _, _, err := p.ProviderDatabaseAuthority(owner)
	if err != nil || binding.Namespace != namespace || binding.ControllerID != controllerID ||
		binding.RuntimeRole != runtimeRole || binding.RuntimeDSNBindingID != materialBindingID {
		return ErrInvalidProfile
	}
	return nil
}
