package phase6security

import (
	"crypto/ed25519"
	"path"
	"slices"
	"sort"
)

const (
	slice6ControllerResponseKey = "certificate-controller-response"
	slice6ControllerManagedKey  = "request-certificate-controller-self"
	slice6CredentialManagedKey  = "request-credential-controller-managed"
)

// Slice6DesiredCertificateKeyIDs is the complete, closed source-key
// inventory for the production controller and all ordinary/purpose-specific
// TLS agents. A key ID is a private FD owner, not a profile secret.
func Slice6DesiredCertificateKeyIDs() []string {
	result := []string{slice6ControllerResponseKey, slice6ControllerManagedKey, slice6CredentialManagedKey}
	for agent := range slice6ApprovedTLSAgentSubjects {
		result = append(result, "request-"+agent)
	}
	sort.Strings(result)
	return result
}

type Slice6CertificateBindings struct {
	Controller CertificateControllerAuthority
	Ordinary   []TLSAgentBinding
	Postgres   []PostgresClientAgentBinding
}

// BuildSlice6DesiredCertificateBindings derives the exact socket/key policy
// from reviewed deployment relationships and distinct source-bound public
// keys. Private-key possession, Vault issuer state and live peer proof remain
// separate gates.
func BuildSlice6DesiredCertificateBindings(principals []Principal,
	publicKeys map[string]ed25519.PublicKey) (Slice6CertificateBindings, error) {
	keyIDs := Slice6DesiredCertificateKeyIDs()
	if len(publicKeys) != len(keyIDs) || VerifySlice6DesiredFinalPostgresSignerTargets(Slice6DesiredFinalPostgresSignerTargets()) != nil {
		return Slice6CertificateBindings{}, errSlice6DesiredInventory
	}
	keyDigests := make(map[string]string, len(keyIDs))
	seenDigests := make(map[string]bool, len(keyIDs))
	seenPublicKeys := make(map[string]bool, len(keyIDs))
	for _, id := range keyIDs {
		key, found := publicKeys[id]
		digest := TLSAgentRequestPublicKeyDigest(key)
		if id == slice6ControllerResponseKey {
			digest = CertificateControllerPublicKeyDigest(key)
		}
		if !found || digest == "" || seenDigests[digest] || seenPublicKeys[string(key)] {
			return Slice6CertificateBindings{}, errSlice6DesiredInventory
		}
		keyDigests[id], seenDigests[digest], seenPublicKeys[string(key)] = digest, true, true
	}
	byName := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		if _, duplicate := byName[principal.Name]; duplicate {
			return Slice6CertificateBindings{}, errSlice6DesiredInventory
		}
		byName[principal.Name] = principal
	}
	controller, controllerOK := byName["certificate-controller"]
	credential, credentialOK := byName["workload-credential-controller"]
	if !controllerOK || !credentialOK || controller.Kind != "controller" || credential.Kind != "controller" ||
		controller.TLS == nil || credential.TLS == nil || controller.PrincipalDigest == "" || credential.PrincipalDigest == "" {
		return Slice6CertificateBindings{}, errSlice6DesiredInventory
	}
	result := Slice6CertificateBindings{Controller: CertificateControllerAuthority{
		DeploymentName: controller.Name, PrincipalDigest: controller.PrincipalDigest, UID: controller.UID, GID: controller.GID,
		ResponseKeyID: slice6ControllerResponseKey, ResponsePublicKeyDigest: keyDigests[slice6ControllerResponseKey],
		ManagedPolicyID: "issuer-certificate-controller-self", ManagedVaultRole: "vault-certificate-controller",
		ManagedRequestKeyID: slice6ControllerManagedKey, ManagedRequestKeyDigest: keyDigests[slice6ControllerManagedKey],
		BootstrapClientAnchorID: "vault-client-ca", SelfSocketDirectory: "/run/certificate-controller/self",
		SelfSocketStorageID: "certificate-controller-self-socket", SelfSocketPath: "/run/certificate-controller/self/managed.sock",
		SelfDirectoryMode: 0o700, SelfSocketMode: 0o600, SelfUnixEdgeID: "certificate-controller-self",
		CredentialController: CredentialControllerManagedAuthority{
			PolicyID: "issuer-credential-controller-managed", VaultRole: "vault-credential-controller",
			RequestKeyID: slice6CredentialManagedKey, RequestKeyDigest: keyDigests[slice6CredentialManagedKey],
			SocketDirectory: "/run/certificate-controller/workload-credential-controller",
			SocketStorageID: "certificate-credential-controller-socket",
			SocketPath:      "/run/certificate-controller/workload-credential-controller/request.sock",
			DirectoryMode:   0o710, SocketMode: 0o666, UnixEdgeID: "certificate-credential-controller",
		},
	}}
	postgresByAgent := make(map[string]Slice6PostgresSignerTarget)
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		postgresByAgent[target.AgentDeployment] = target
	}
	for agentName, subjectName := range slice6ApprovedTLSAgentSubjects {
		agent, agentOK := byName[agentName]
		subject, subjectOK := byName[subjectName]
		if !agentOK || !subjectOK || agent.Kind != "tls_agent" || agent.TLS == nil || subject.TLS == nil ||
			agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil ||
			agent.AuthorizationPrincipal.Role != subject.AuthorizationPrincipal.Role ||
			agent.UID == subject.UID || agent.GID == subject.GID ||
			agent.PrincipalDigest == "" || subject.PrincipalDigest == "" {
			return Slice6CertificateBindings{}, errSlice6DesiredInventory
		}
		requestKeyID := "request-" + agentName
		binding := TLSAgentBinding{
			AgentDeployment: agentName, AgentPrincipalDigest: agent.PrincipalDigest,
			SubjectDeployment: subjectName, SubjectPrincipalDigest: subject.PrincipalDigest,
			AgentUID: agent.UID, AgentGID: agent.GID, SubjectUID: subject.UID, SubjectGID: subject.GID,
			SocketDirectory: path.Join("/run/tls", agentName), SocketStorageID: agentName + "-socket",
			SocketPath: path.Join("/run/tls", agentName, "signer.sock"), DirectoryMode: 0o710, SocketMode: 0o666,
			UnixEdgeID: "tls-agent-" + agentName, IssuerPolicyID: "issuer-" + agentName,
			IssuerVaultRole: "vault-" + agentName, AgentRequestKeyID: requestKeyID,
			AgentRequestKeyDigest: keyDigests[requestKeyID], ControllerDeployment: controller.Name,
			ControllerUID: controller.UID, ControllerGID: controller.GID,
			ControllerSocketDirectory: path.Join("/run/certificate-controller", agentName),
			ControllerSocketStorageID: agentName + "-controller-socket",
			ControllerSocketPath:      path.Join("/run/certificate-controller", agentName, "request.sock"),
			ControllerDirectoryMode:   0o710, ControllerSocketMode: 0o666,
			ControllerUnixEdgeID: "certificate-agent-" + agentName, CleanupClass: "sockets",
		}
		if target, purposeSpecific := postgresByAgent[agentName]; purposeSpecific {
			if target.SubjectDeployment != subjectName {
				return Slice6CertificateBindings{}, errSlice6DesiredInventory
			}
			result.Postgres = append(result.Postgres, PostgresClientAgentBinding{TLSAgentBinding: binding,
				CommonName: target.SQLRole, IssuerAnchorID: postgresClientIssuerAnchorID})
		} else {
			result.Ordinary = append(result.Ordinary, binding)
		}
	}
	sort.Slice(result.Ordinary, func(i, j int) bool { return result.Ordinary[i].AgentDeployment < result.Ordinary[j].AgentDeployment })
	sort.Slice(result.Postgres, func(i, j int) bool { return result.Postgres[i].AgentDeployment < result.Postgres[j].AgentDeployment })
	if len(result.Ordinary)+len(result.Postgres) != len(slice6ApprovedTLSAgentSubjects) ||
		len(result.Postgres) != 9 || !slices.EqualFunc(result.Postgres, Slice6DesiredFinalPostgresSignerTargets(),
		func(a PostgresClientAgentBinding, b Slice6PostgresSignerTarget) bool {
			return a.AgentDeployment == b.AgentDeployment && a.SubjectDeployment == b.SubjectDeployment && a.CommonName == b.SQLRole
		}) {
		return Slice6CertificateBindings{}, errSlice6DesiredInventory
	}
	return result, nil
}
