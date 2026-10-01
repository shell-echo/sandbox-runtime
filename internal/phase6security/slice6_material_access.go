package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadcredential"
)

// Slice6MaterialAccess is private bootstrap input, not a Provider or local
// management API. It binds one real material consumer to one Vault token role
// and exact KV v2 data paths. The bytes stored at those paths are separate
// run-owned inputs and must be verified against the consuming command.
type Slice6MaterialAccess struct {
	SecurityProfileDigest string              `json:"security_profile_digest"`
	Agent                 string              `json:"agent"`
	Owner                 string              `json:"owner"`
	Migration             bool                `json:"migration"`
	AgentPrincipal        string              `json:"agent_principal"`
	OwnerPrincipal        string              `json:"owner_principal"`
	AgentUID              uint32              `json:"agent_uid"`
	AgentGID              uint32              `json:"agent_gid"`
	CredentialSocket      string              `json:"credential_socket"`
	CredentialPolicyID    string              `json:"credential_policy_id"`
	BackendPolicy         string              `json:"backend_policy"`
	TokenRole             string              `json:"token_role"`
	Role                  secretref.Role      `json:"role"`
	Bindings              []secretref.Binding `json:"bindings"`
	KVDataPaths           []string            `json:"kv_data_paths"`
	ACL                   string              `json:"acl"`
	Digest                string              `json:"digest"`
}

type slice6MaterialAccessTemplate struct {
	agent, owner string
	role         secretref.Role
	purposes     []secretref.Purpose
}

// The v3 Browser/Desktop executors use live TLS signers and have no KV
// material consumer. Historical V2 material agents are intentionally absent.
// Each remaining path corresponds to a purpose read by an existing v3 role
// or migration command; no TLS private key or future-slice material is KV.
var slice6MaterialAccessTemplates = []slice6MaterialAccessTemplate{
	{"browser-action-ingress-agent", "browser-action-ingress-runtime", secretref.RoleGateway,
		[]secretref.Purpose{secretref.PurposeActionHistoryWitnessDSN, secretref.PurposeCapacityValkeyCredentials}},
	{"gateway-agent", "gateway-runtime", secretref.RoleGateway,
		[]secretref.Purpose{secretref.PurposeGatewayGrantKey, secretref.PurposePostgresRuntimeDSN}},
	{"guest-agent", "guest-runtime", secretref.RoleGuest,
		[]secretref.Purpose{secretref.PurposeGuestSigningKey}},
	{"product-migration-agent", "product-migration-job", secretref.RoleProduct,
		[]secretref.Purpose{secretref.PurposePostgresMigrationDSN}},
	{"product-runtime-agent", "product-runtime", secretref.RoleProduct,
		[]secretref.Purpose{secretref.PurposeIdentityKeyRing, secretref.PurposePostgresRuntimeDSN}},
	{"provider-browser-migration-agent", "provider-browser-migration-job", secretref.RoleProvider,
		[]secretref.Purpose{secretref.PurposePostgresMigrationDSN}},
	{"provider-browser-runtime-agent", "provider-browser-runtime", secretref.RoleProvider,
		[]secretref.Purpose{secretref.PurposeAdmissionVerification, secretref.PurposePostgresRuntimeDSN}},
	{"provider-desktop-migration-agent", "provider-desktop-migration-job", secretref.RoleProvider,
		[]secretref.Purpose{secretref.PurposePostgresMigrationDSN}},
	{"provider-desktop-runtime-agent", "provider-desktop-runtime", secretref.RoleProvider,
		[]secretref.Purpose{secretref.PurposeAdmissionVerification, secretref.PurposeExecutorBridgeKey, secretref.PurposePostgresRuntimeDSN}},
	{"provider-migration-agent", "provider-migration-job", secretref.RoleProvider,
		[]secretref.Purpose{secretref.PurposePostgresMigrationDSN}},
	{"provider-runtime-agent", "provider-runtime", secretref.RoleProvider,
		[]secretref.Purpose{secretref.PurposeAdmissionVerification, secretref.PurposePostgresRuntimeDSN}},
}

// BuildSlice6DesiredMaterialAccess cross-checks the exact v3 material
// inventory against a complete verified Profile. It does not mint a token,
// populate KV, or claim that an ACL is installed until Vault readback proves
// those separate steps.
func BuildSlice6DesiredMaterialAccess(profile Profile) ([]Slice6MaterialAccess, error) {
	if VerifySlice6DesiredFinalExternalProfile(profile) != nil ||
		len(profile.CredentialIssuerSockets) != len(slice6MaterialAccessTemplates)+1 ||
		len(slice6MaterialAccessTemplates) != 11 {
		return nil, errSlice6DesiredInventory
	}
	byName := make(map[string]Principal, len(profile.Principals))
	for _, principal := range profile.Principals {
		byName[principal.Name] = principal
	}
	seenAgents, seenPaths := map[string]bool{}, map[string]bool{}
	result := make([]Slice6MaterialAccess, 0, len(slice6MaterialAccessTemplates))
	for _, template := range slice6MaterialAccessTemplates {
		agent, owner := byName[template.agent], byName[template.owner]
		binding, _, resolved, err := profile.CredentialIssuerSocketForClient(template.agent)
		if err != nil || seenAgents[template.agent] || agent.Name != template.agent || owner.Name != template.owner ||
			resolved.PrincipalDigest != agent.PrincipalDigest || resolved.UID != agent.UID || resolved.GID != agent.GID ||
			agent.Kind != "material_agent" || agent.AuthorizationPrincipal == nil ||
			owner.AuthorizationPrincipal == nil || (owner.Kind != "runtime" && owner.Kind != "migration_job") ||
			string(agent.AuthorizationPrincipal.Role) != string(template.role) ||
			string(owner.AuthorizationPrincipal.Role) != string(template.role) ||
			len(template.purposes) < 1 {
			return nil, errSlice6DesiredInventory
		}
		seenAgents[template.agent] = true
		entry := Slice6MaterialAccess{SecurityProfileDigest: profile.ProfileDigest, Agent: agent.Name, Owner: owner.Name,
			Migration:      owner.Kind == "migration_job",
			AgentPrincipal: agent.PrincipalDigest, OwnerPrincipal: owner.PrincipalDigest,
			AgentUID: agent.UID, AgentGID: agent.GID, CredentialSocket: binding.SocketPath,
			CredentialPolicyID: "credential-" + agent.Name,
			BackendPolicy:      agent.Name + "-kv", Role: template.role}
		entry.TokenRole = workloadcredential.Phase6TokenRole(entry.BackendPolicy)
		if entry.TokenRole == "" {
			return nil, errSlice6DesiredInventory
		}
		for _, purpose := range template.purposes {
			if !secretref.DeploymentPurposeAllowed(agent.Name, template.role, purpose) ||
				purpose == secretref.PurposeWorkloadCredential {
				return nil, errSlice6DesiredInventory
			}
			path := agent.Name + "/" + string(purpose)
			if seenPaths[path] {
				return nil, errSlice6DesiredInventory
			}
			seenPaths[path] = true
			binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
				Reference: secretref.Reference("secret://phase6/kv/" + path), Version: "v1",
				Purpose: purpose, TenantID: secretref.SystemTenant, Role: template.role}
			if binding.Validate() != nil {
				return nil, errSlice6DesiredInventory
			}
			entry.Bindings = append(entry.Bindings, binding)
			entry.KVDataPaths = append(entry.KVDataPaths, "kv/data/"+path)
		}
		if !slices.IsSorted(entry.KVDataPaths) {
			return nil, errSlice6DesiredInventory
		}
		var acl strings.Builder
		for _, path := range entry.KVDataPaths {
			fmt.Fprintf(&acl, "path %q { capabilities = [\"read\"] }\n", path)
		}
		entry.ACL = acl.String()
		encoded, err := json.Marshal(entry)
		if err != nil {
			return nil, errSlice6DesiredInventory
		}
		sum := sha256.Sum256(append([]byte("sandbox-runtime/phase6-slice6-material-access/v1\x00"+profile.ProfileDigest+"\x00"), encoded...))
		entry.Digest = "sha256:" + hex.EncodeToString(sum[:])
		result = append(result, entry)
	}
	for _, binding := range profile.CredentialIssuerSockets {
		if binding.ClientDeployment != "certificate-controller" && !seenAgents[binding.ClientDeployment] {
			return nil, errSlice6DesiredInventory
		}
	}
	if len(result) != 11 || len(seenPaths) != 18 {
		return nil, errSlice6DesiredInventory
	}
	return result, nil
}

// VerifySlice6MaterialACLReadback is called by the controlled bootstrap
// after Vault returns the installed policy text. Token-role validation alone
// proves only a policy name, never the authority in the ACL body.
func VerifySlice6MaterialACLReadback(profile Profile, entry Slice6MaterialAccess, installed []byte) error {
	plan, err := BuildSlice6DesiredMaterialAccess(profile)
	if err != nil || len(installed) == 0 || len(installed) > 64<<10 {
		return errSlice6DesiredInventory
	}
	for _, expected := range plan {
		if expected.Agent == entry.Agent {
			if !reflect.DeepEqual(expected, entry) || string(installed) != expected.ACL {
				return errSlice6DesiredInventory
			}
			return nil
		}
	}
	return errSlice6DesiredInventory
}
