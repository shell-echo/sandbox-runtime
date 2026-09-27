package phase6security

import "path"

const postgresClientIssuerAnchorID = "postgres-client-ca"

func postgresClientCommonName(runtimeRole string) string {
	return runtimeRole
}

func postgresAgentMember(bindings []PostgresClientAgentBinding, name string) bool {
	for _, binding := range bindings {
		if binding.AgentDeployment == name {
			return true
		}
	}
	return false
}

func postgresAgentEdgeMember(bindings []PostgresClientAgentBinding, edgeID string) bool {
	for _, binding := range bindings {
		if binding.UnixEdgeID == edgeID {
			return true
		}
	}
	return false
}

func postgresControllerEdgeMember(bindings []PostgresClientAgentBinding, edgeID string) bool {
	for _, binding := range bindings {
		if binding.ControllerUnixEdgeID == edgeID {
			return true
		}
	}
	return false
}

func postgresSocketMember(bindings []PostgresClientAgentBinding, name string, mount Mount) bool {
	for _, binding := range bindings {
		if mount.Kind != "private_socket" {
			continue
		}
		if mount.Target == binding.SocketDirectory && mount.StorageID == binding.SocketStorageID &&
			((name == binding.AgentDeployment && !mount.ReadOnly) ||
				(name == binding.SubjectDeployment && mount.ReadOnly)) {
			return true
		}
		if mount.Target == binding.ControllerSocketDirectory && mount.StorageID == binding.ControllerSocketStorageID &&
			((name == binding.ControllerDeployment && !mount.ReadOnly) ||
				(name == binding.AgentDeployment && mount.ReadOnly)) {
			return true
		}
	}
	return false
}

func validatePostgresClientAgents(bindings []PostgresClientAgentBinding, databases []ProviderDatabaseBinding,
	ordinary []TLSAgentBinding, policies []EgressPolicy, controllerAuthority CertificateControllerAuthority,
	anchors []TrustAnchor, principals map[string]Principal, edges map[string]TrustEdge) error {
	if len(bindings) != 2 || len(databases) != 2 {
		return ErrInvalidProfile
	}
	controller := principals[controllerAuthority.DeploymentName]
	usedNames, usedStorage, usedEdges, usedPolicies, usedRoles, usedKeys, usedKeyIDs :=
		map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, ordinaryBinding := range ordinary {
		usedNames[ordinaryBinding.AgentDeployment] = true
		usedStorage[ordinaryBinding.SocketStorageID], usedStorage[ordinaryBinding.ControllerSocketStorageID] = true, true
		usedEdges[ordinaryBinding.UnixEdgeID], usedEdges[ordinaryBinding.ControllerUnixEdgeID] = true, true
		usedPolicies[ordinaryBinding.IssuerPolicyID], usedRoles[ordinaryBinding.IssuerVaultRole] = true, true
		usedKeys[ordinaryBinding.AgentRequestKeyDigest], usedKeyIDs[ordinaryBinding.AgentRequestKeyID] = true, true
	}
	usedStorage[controllerAuthority.SelfSocketStorageID] = true
	usedStorage[BrowserMuxSocketStorageID] = true
	for _, policy := range policies {
		usedStorage[policy.Authority.SocketStorageID] = true
		usedStorage[policy.Authority.LedgerStorageID] = true
	}
	for _, anchor := range anchors {
		usedStorage[anchor.StorageID] = true
	}
	usedPolicies[controllerAuthority.ManagedPolicyID], usedRoles[controllerAuthority.ManagedVaultRole] = true, true
	usedKeys[controllerAuthority.ManagedRequestKeyDigest], usedKeyIDs[controllerAuthority.ManagedRequestKeyID] = true, true
	var anchor TrustAnchor
	for _, candidate := range anchors {
		if candidate.ID == postgresClientIssuerAnchorID {
			anchor = candidate
		}
	}
	if anchor.ID == "" || anchor.Purpose != "client_verification" || len(anchor.Consumers) != 2 ||
		anchor.Consumers[0] != "provider-browser-runtime" || anchor.Consumers[1] != "provider-desktop-runtime" {
		return ErrInvalidProfile
	}
	for index, binding := range bindings {
		value := binding.TLSAgentBinding
		database := databases[index]
		owner, ownerOK := principals[database.OwnerDeployment]
		agent, agentOK := principals[value.AgentDeployment]
		unixEdge, edgeOK := edges[value.UnixEdgeID]
		controllerEdge, controllerEdgeOK := edges[value.ControllerUnixEdgeID]
		expectedAgent := "provider-browser-postgres-tls-agent"
		if index == 1 {
			expectedAgent = "provider-desktop-postgres-tls-agent"
		}
		if !ownerOK || !agentOK || !edgeOK || !controllerEdgeOK || owner.TLS == nil || agent.TLS == nil || controller.TLS == nil ||
			value.SubjectDeployment != database.OwnerDeployment || value.AgentDeployment != expectedAgent ||
			value.SubjectPrincipalDigest != owner.PrincipalDigest || value.AgentPrincipalDigest != agent.PrincipalDigest ||
			agent.Kind != "tls_agent" || agent.AuthorizationPrincipal == nil || owner.AuthorizationPrincipal == nil ||
			agent.AuthorizationPrincipal.Role != owner.AuthorizationPrincipal.Role ||
			value.AgentUID != agent.UID || value.AgentGID != agent.GID || value.SubjectUID != owner.UID || value.SubjectGID != owner.GID ||
			value.AgentUID == value.SubjectUID || value.AgentGID == value.SubjectGID ||
			value.SocketDirectory != path.Join("/run/tls", expectedAgent) || value.SocketPath != path.Join(value.SocketDirectory, "signer.sock") ||
			!namePattern.MatchString(value.SocketStorageID) || !namePattern.MatchString(value.UnixEdgeID) ||
			value.DirectoryMode != 0o710 || value.SocketMode != 0o666 ||
			!namePattern.MatchString(value.IssuerPolicyID) || !namePattern.MatchString(value.IssuerVaultRole) ||
			!namePattern.MatchString(value.AgentRequestKeyID) || !digestPattern.MatchString(value.AgentRequestKeyDigest) ||
			value.ControllerDeployment != controller.Name || value.ControllerUID != controller.UID || value.ControllerGID != controller.GID ||
			value.ControllerSocketDirectory != path.Join("/run/certificate-controller", expectedAgent) ||
			value.ControllerSocketPath != path.Join(value.ControllerSocketDirectory, "request.sock") ||
			!namePattern.MatchString(value.ControllerSocketStorageID) || !namePattern.MatchString(value.ControllerUnixEdgeID) ||
			value.ControllerDirectoryMode != 0o710 || value.ControllerSocketMode != 0o666 || value.CleanupClass != "sockets" ||
			binding.CommonName != postgresClientCommonName(database.RuntimeRole) || len(binding.CommonName) > 64 ||
			binding.IssuerAnchorID != postgresClientIssuerAnchorID || anchor.TrustDomain != owner.TLS.TrustDomain ||
			!exactPolicyMount(agent, "private_socket", value.SocketDirectory, value.SocketStorageID, false) ||
			!exactPolicyMount(owner, "private_socket", value.SocketDirectory, value.SocketStorageID, true) ||
			!exactPolicyMount(agent, "private_socket", value.ControllerSocketDirectory, value.ControllerSocketStorageID, true) ||
			!exactPolicyMount(controller, "private_socket", value.ControllerSocketDirectory, value.ControllerSocketStorageID, false) ||
			!hasTrustAnchorMount(owner, anchor) ||
			unixEdge.From != owner.Name || unixEdge.To != agent.Name || unixEdge.Protocol != "unix" ||
			unixEdge.Authentication != "unix_peer_credentials" || unixEdge.TenantScope != "system" || unixEdge.MaxConnectionSeconds > 30 ||
			unixEdge.FromPrincipalDigest != owner.PrincipalDigest || unixEdge.ToPrincipalDigest != agent.PrincipalDigest ||
			unixEdge.FromURI != owner.TLS.URI || unixEdge.ToURI != agent.TLS.URI ||
			controllerEdge.From != agent.Name || controllerEdge.To != controller.Name || controllerEdge.Protocol != "unix" ||
			controllerEdge.Authentication != "unix_peer_credentials" || controllerEdge.TenantScope != "system" ||
			controllerEdge.MaxConnectionSeconds > 30 || controllerEdge.FromPrincipalDigest != agent.PrincipalDigest ||
			controllerEdge.ToPrincipalDigest != controller.PrincipalDigest || controllerEdge.FromURI != agent.TLS.URI ||
			controllerEdge.ToURI != controller.TLS.URI ||
			usedNames[value.AgentDeployment] || usedStorage[value.SocketStorageID] || usedStorage[value.ControllerSocketStorageID] ||
			value.SocketStorageID == value.ControllerSocketStorageID || usedEdges[value.UnixEdgeID] || usedEdges[value.ControllerUnixEdgeID] ||
			usedPolicies[value.IssuerPolicyID] || usedRoles[value.IssuerVaultRole] ||
			usedKeys[value.AgentRequestKeyDigest] || usedKeyIDs[value.AgentRequestKeyID] {
			return ErrInvalidProfile
		}
		usedNames[value.AgentDeployment] = true
		usedStorage[value.SocketStorageID], usedStorage[value.ControllerSocketStorageID] = true, true
		usedEdges[value.UnixEdgeID], usedEdges[value.ControllerUnixEdgeID] = true, true
		usedPolicies[value.IssuerPolicyID], usedRoles[value.IssuerVaultRole] = true, true
		usedKeys[value.AgentRequestKeyDigest], usedKeyIDs[value.AgentRequestKeyID] = true, true
	}
	return nil
}

// PostgresClientAgentForOwner resolves the separate certificate purpose and
// immutable issuer artifact for exactly one Provider database owner.
func (p Profile) PostgresClientAgentForOwner(owner string) (PostgresClientAgentBinding, ProviderDatabaseBinding, Principal, Principal, TrustAnchor, error) {
	if p.Validate() != nil {
		return PostgresClientAgentBinding{}, ProviderDatabaseBinding{}, Principal{}, Principal{}, TrustAnchor{}, ErrInvalidProfile
	}
	for index, binding := range p.PostgresClientAgents {
		if binding.SubjectDeployment != owner {
			continue
		}
		var agent, subject Principal
		var anchor TrustAnchor
		for _, principal := range p.Principals {
			if principal.Name == binding.AgentDeployment {
				agent = principal
			}
			if principal.Name == owner {
				subject = principal
			}
		}
		for _, item := range p.TrustAnchors {
			if item.ID == binding.IssuerAnchorID {
				anchor = item
			}
		}
		return binding, p.ProviderDatabases[index], agent, subject, anchor, nil
	}
	return PostgresClientAgentBinding{}, ProviderDatabaseBinding{}, Principal{}, Principal{}, TrustAnchor{}, ErrInvalidProfile
}
