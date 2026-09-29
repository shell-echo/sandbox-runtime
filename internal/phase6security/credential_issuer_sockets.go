package phase6security

import (
	"path"
	"strings"
)

// CredentialIssuerSocketBinding grants one client a private, read-only view
// of one credential-controller listener. Identity and modes are derived from
// the existing principal records, not independently configured here.
type CredentialIssuerSocketBinding struct {
	ClientDeployment string `json:"client_deployment"`
	SocketDirectory  string `json:"socket_directory"`
	SocketStorageID  string `json:"socket_storage_id"`
	SocketPath       string `json:"socket_path"`
	UnixEdgeID       string `json:"unix_edge_id"`
}

var approvedCredentialIssuerClients = []string{
	"browser-action-ingress-agent", "browser-agent", "certificate-controller", "desktop-agent",
	"gateway-agent", "guest-agent", "product-migration-agent", "product-runtime-agent",
	"provider-browser-migration-agent", "provider-browser-runtime-agent",
	"provider-desktop-migration-agent", "provider-desktop-runtime-agent",
	"provider-migration-agent", "provider-runtime-agent",
}

func credentialIssuerBinding(client string) CredentialIssuerSocketBinding {
	directory := path.Join("/run/workload-credential-controller", client)
	return CredentialIssuerSocketBinding{ClientDeployment: client, SocketDirectory: directory,
		SocketStorageID: "credential-issuer-" + client + "-socket", SocketPath: path.Join(directory, "issuer.sock"),
		UnixEdgeID: "credential-issuer-" + client}
}

func BuildCredentialIssuerSocketBindings(principals []Principal) ([]CredentialIssuerSocketBinding, error) {
	byName := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		if byName[principal.Name].Name != "" {
			return nil, ErrInvalidProfile
		}
		byName[principal.Name] = principal
	}
	server := byName["workload-credential-controller"]
	if server.Kind != "controller" || server.AuthorizationPrincipal == nil {
		return nil, ErrInvalidProfile
	}
	result := make([]CredentialIssuerSocketBinding, 0, len(approvedCredentialIssuerClients))
	for _, clientName := range approvedCredentialIssuerClients {
		client := byName[clientName]
		if client.AuthorizationPrincipal == nil || (client.Kind != "material_agent" && clientName != "certificate-controller") ||
			client.UID == server.UID || client.GID == server.GID {
			return nil, ErrInvalidProfile
		}
		result = append(result, credentialIssuerBinding(clientName))
	}
	return result, nil
}

func validateCredentialIssuerSockets(bindings []CredentialIssuerSocketBinding, principals map[string]Principal, edges map[string]TrustEdge) error {
	if len(bindings) != len(approvedCredentialIssuerClients) {
		return ErrInvalidProfile
	}
	server := principals["workload-credential-controller"]
	knownStorage := make(map[string]CredentialIssuerSocketBinding, len(bindings))
	knownEdges := make(map[string]struct{}, len(bindings))
	for index, clientName := range approvedCredentialIssuerClients {
		binding := bindings[index]
		client := principals[clientName]
		expected := credentialIssuerBinding(clientName)
		edge, found := edges[binding.UnixEdgeID]
		if binding != expected || !found || client.UID == server.UID || client.GID == server.GID ||
			!exactPolicyMount(server, "private_socket", binding.SocketDirectory, binding.SocketStorageID, false) ||
			!exactPolicyMount(client, "private_socket", binding.SocketDirectory, binding.SocketStorageID, true) ||
			edge.From != clientName || edge.To != server.Name || edge.Protocol != "unix" ||
			edge.Authentication != "unix_peer_credentials" || edge.TenantScope != "system" || edge.MaxConnectionSeconds > 30 ||
			edge.FromPrincipalDigest != client.PrincipalDigest || edge.ToPrincipalDigest != server.PrincipalDigest ||
			edge.FromURI != client.TLS.URI || edge.ToURI != server.TLS.URI {
			return ErrInvalidProfile
		}
		knownStorage[binding.SocketStorageID] = binding
		knownEdges[binding.UnixEdgeID] = struct{}{}
	}
	for name, principal := range principals {
		for _, mount := range principal.Mounts {
			if binding, exists := knownStorage[mount.StorageID]; exists {
				if mount.Target != binding.SocketDirectory ||
					mount.Kind != "private_socket" ||
					!((name == server.Name && !mount.ReadOnly) || (name == binding.ClientDeployment && mount.ReadOnly)) {
					return ErrInvalidProfile
				}
			}
			for _, binding := range bindings {
				if mount.Target == binding.SocketDirectory {
					if mount.StorageID != binding.SocketStorageID || mount.Kind != "private_socket" {
						return ErrInvalidProfile
					}
				} else if strings.HasPrefix(mount.Target, binding.SocketDirectory+"/") ||
					strings.HasPrefix(binding.SocketDirectory, mount.Target+"/") {
					return ErrInvalidProfile
				}
			}
		}
	}
	for _, edge := range edges {
		if edge.To == server.Name && edge.Protocol == "unix" {
			if _, exists := knownEdges[edge.ID]; !exists {
				return ErrInvalidProfile
			}
		}
	}
	return nil
}

func credentialIssuerStorageMember(bindings []CredentialIssuerSocketBinding, principalName string, mount Mount) bool {
	for _, binding := range bindings {
		if mount.Kind == "private_socket" && mount.Target == binding.SocketDirectory && mount.StorageID == binding.SocketStorageID &&
			((principalName == "workload-credential-controller" && !mount.ReadOnly) ||
				(principalName == binding.ClientDeployment && mount.ReadOnly)) {
			return true
		}
	}
	return false
}

// CredentialIssuerSocketForClient resolves the sole path and principals from
// an already-verified profile. Production callers must first use VerifyFile.
func (p Profile) CredentialIssuerSocketForClient(name string) (CredentialIssuerSocketBinding, Principal, Principal, error) {
	approved := false
	for _, client := range approvedCredentialIssuerClients {
		if client == name {
			approved = true
			break
		}
	}
	if !approved {
		return CredentialIssuerSocketBinding{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	var binding CredentialIssuerSocketBinding
	count := 0
	for _, candidate := range p.CredentialIssuerSockets {
		if candidate.ClientDeployment == name {
			binding, count = candidate, count+1
		}
	}
	if count != 1 || binding != credentialIssuerBinding(name) {
		return CredentialIssuerSocketBinding{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	var client, server Principal
	for _, principal := range p.Principals {
		switch principal.Name {
		case name:
			client = principal
		case "workload-credential-controller":
			server = principal
		}
	}
	if client.Name != name || server.Name != "workload-credential-controller" ||
		client.UID == server.UID || client.GID == server.GID {
		return CredentialIssuerSocketBinding{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	return binding, server, client, nil
}
