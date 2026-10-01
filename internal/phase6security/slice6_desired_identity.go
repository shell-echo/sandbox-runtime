package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

// Slice6DesiredAuthorizationPrincipals constructs one run-bound copy of the
// reviewed deployment identity inventory. Instance digests derive from the
// fresh run ID and deployment name, never from a running container. Actual
// certificate/key ownership and live peer authentication remain gate work.
func Slice6DesiredAuthorizationPrincipals(runID, environmentDigest, principalProfileDigest string) (map[string]securityprincipal.Principal, error) {
	if len(runID) != 32 || !lowerHexIdentity(runID) || !digestPattern.MatchString(environmentDigest) ||
		!digestPattern.MatchString(principalProfileDigest) {
		return nil, errSlice6DesiredInventory
	}
	brokers := make(map[string]securityprincipal.Role, len(slice6DesiredEgress))
	authorities := make(map[string]securityprincipal.Role, len(slice6DesiredEgress))
	for _, policy := range slice6DesiredEgress {
		owner, found := requiredAuthorizationBindings[policy.principal]
		prefix := strings.TrimSuffix(policy.authorizationName, "_policy_authority")
		if !found || prefix == policy.authorizationName || prefix == "" {
			return nil, errSlice6DesiredInventory
		}
		brokers[prefix+"_egress_broker"] = owner.role
		authorities[policy.authorizationName] = ""
	}
	registry, err := securityprincipal.NewRegistryWithPolicyAuthorities(environmentDigest,
		principalProfileDigest, brokers, authorities)
	if err != nil {
		return nil, errSlice6DesiredInventory
	}
	result := make(map[string]securityprincipal.Principal, len(requiredAuthorizationBindings)+len(slice6DesiredEgress)*3)
	add := func(deployment string, kind securityprincipal.Kind, name string, role securityprincipal.Role) error {
		if _, exists := result[deployment]; exists {
			return errSlice6DesiredInventory
		}
		sum := sha256.Sum256([]byte("sandbox-runtime/phase6-slice6-instance/v1\x00" + runID + "\x00" + deployment))
		instance := "sha256:" + hex.EncodeToString(sum[:])
		principal, err := registry.New(kind, name, role, instance)
		if err != nil {
			return errSlice6DesiredInventory
		}
		result[deployment] = principal
		return nil
	}
	for deployment, binding := range requiredAuthorizationBindings {
		if err := add(deployment, binding.kind, binding.name, binding.role); err != nil {
			return nil, err
		}
	}
	for _, policy := range slice6DesiredEgress {
		owner := requiredAuthorizationBindings[policy.principal]
		prefix := strings.TrimSuffix(policy.authorizationName, "_policy_authority")
		for _, item := range []struct {
			deployment string
			kind       securityprincipal.Kind
			name       string
			role       securityprincipal.Role
		}{
			{policy.broker, securityprincipal.KindEgressBroker, prefix + "_egress_broker", owner.role},
			{policy.broker + "-tls-agent", securityprincipal.KindTLSAgent, prefix + "_egress_broker_tls_agent", owner.role},
			{policy.authority, securityprincipal.KindController, policy.authorizationName, ""},
		} {
			if err := add(item.deployment, item.kind, item.name, item.role); err != nil {
				return nil, err
			}
		}
	}
	if len(result) != len(slice6ApprovedDeploymentKinds)-len(requiredResourceControllers) {
		return nil, errSlice6DesiredInventory
	}
	return result, nil
}

func lowerHexIdentity(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// Slice6DesiredDeploymentKind is the reviewed static deployment vocabulary;
// it cannot be widened by an operator-authored profile.
func Slice6DesiredDeploymentKind(name string) (string, error) {
	kind, approved := slice6ApprovedDeploymentKinds[name]
	if !approved || kind == "" {
		return "", errSlice6DesiredInventory
	}
	return kind, nil
}

// This second explicit partition preserves all prior 69 deployment IDs while
// the two migration jobs, agents, Vault signers and seven PG-purpose signers
// are integrated. The ordinal is frozen by name, not inferred from map order.
var slice6AdditionalDeploymentOrdinals = map[string]int{
	"gateway-postgres-tls-agent":                    0,
	"product-migration-postgres-tls-agent":          1,
	"product-postgres-tls-agent":                    2,
	"provider-browser-migration-agent":              3,
	"provider-browser-migration-agent-tls-agent":    4,
	"provider-browser-migration-job":                5,
	"provider-browser-migration-postgres-tls-agent": 6,
	"provider-desktop-migration-agent":              7,
	"provider-desktop-migration-agent-tls-agent":    8,
	"provider-desktop-migration-job":                9,
	"provider-desktop-migration-postgres-tls-agent": 10,
	"provider-migration-postgres-tls-agent":         11,
	"provider-postgres-tls-agent":                   12,
}

// Slice6DesiredUIDGID freezes each static container's non-root identity from
// the reviewed 20000/30000 partitions, 55000/57000 material-agent signer
// partition and 56000/58000 added migration/PG-purpose partition. Dynamic sandbox workload/gateway
// account slots are separately constrained by SandboxIdentitySlots and the
// actual Desktop image account allowlist before launch.
func Slice6DesiredUIDGID() map[string][2]uint32 {
	// These four retired V2 material deployments retain their old ordinal
	// slots. Removing an unused principal must not renumber any surviving
	// production identity or grant it another process's former UID/GID.
	retiredSigner := map[string]bool{
		"browser-agent-tls-agent": true,
		"desktop-agent-tls-agent": true,
	}
	retiredBase := map[string]bool{
		"browser-agent": true,
		"desktop-agent": true,
	}
	names := append(slice6ApprovedDeploymentNames(),
		"browser-agent", "browser-agent-tls-agent", "desktop-agent", "desktop-agent-tls-agent")
	sort.Strings(names)
	result := make(map[string][2]uint32, len(slice6ApprovedDeploymentKinds))
	baseIndex, signerIndex := 0, 0
	for _, name := range names {
		if retiredSigner[name] {
			signerIndex++
			continue
		}
		if retiredBase[name] {
			baseIndex++
			continue
		}
		if ordinal, added := slice6AdditionalDeploymentOrdinals[name]; added {
			result[name] = [2]uint32{uint32(56000 + ordinal), uint32(58000 + ordinal)}
			continue
		}
		if subject := requiredTLSAgentSubjects[name]; requiredPrincipals[subject] == "material_agent" {
			// New signer deployments do not shift already reviewed role IDs.
			result[name] = [2]uint32{uint32(55000 + signerIndex), uint32(57000 + signerIndex)}
			signerIndex++
			continue
		}
		result[name] = [2]uint32{uint32(20000 + baseIndex), uint32(30000 + baseIndex)}
		baseIndex++
	}
	return result
}

func VerifySlice6DesiredPrincipalIDs(profile Profile) error {
	if profile.Validate() != nil {
		return errSlice6DesiredInventory
	}
	wanted := Slice6DesiredUIDGID()
	if len(profile.Principals) != len(wanted) {
		return errSlice6DesiredInventory
	}
	for _, principal := range profile.Principals {
		pair, ok := wanted[principal.Name]
		if !ok || principal.UID != pair[0] || principal.GID != pair[1] {
			return errSlice6DesiredInventory
		}
	}
	return nil
}
