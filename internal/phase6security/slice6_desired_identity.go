package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
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

// Slice6DesiredUIDGID freezes each static container's non-root identity from
// the reviewed 20000/30000 partitions and reserves 55000/57000 for the 11
// newly reviewed material-agent signer deployments. Dynamic sandbox workload/gateway
// account slots are separately constrained by SandboxIdentitySlots and the
// actual Desktop image account allowlist before launch.
func Slice6DesiredUIDGID() map[string][2]uint32 {
	names := slice6ApprovedDeploymentNames()
	result := make(map[string][2]uint32, len(names))
	baseIndex, signerIndex := 0, 0
	for _, name := range names {
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
