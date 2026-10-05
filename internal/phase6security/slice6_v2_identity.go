package phase6security

import (
	"slices"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

const (
	ProtocolIDV2 = "sandbox-runtime.phase6-security-profile.v2"
	VersionV2    = 2
)

var slice6V2IdentityDelta = map[string]principalBinding{
	"provider-docker-control":             {securityprincipal.KindDockerControl, "provider_docker_control", securityprincipal.RoleControl},
	"provider-artifact-scanner":           {securityprincipal.KindArtifactScanner, "provider_artifact_scanner", securityprincipal.RoleScanner},
	"provider-docker-control-tls-agent":   {securityprincipal.KindTLSAgent, "provider_docker_control_tls_agent", securityprincipal.RoleControl},
	"provider-artifact-scanner-tls-agent": {securityprincipal.KindTLSAgent, "provider_artifact_scanner_tls_agent", securityprincipal.RoleScanner},
}

var slice6V2TLSAgentDelta = map[string]string{
	"provider-docker-control-tls-agent":   "provider-docker-control",
	"provider-artifact-scanner-tls-agent": "provider-artifact-scanner",
}

// Slice6V2ProvisionalStaticInventoryNames adds the reviewed four-principal
// delta to the historical 78-entry Profile inventory. Those 78 include
// one-shot migration bundles and Browser/Desktop dynamic templates, not 78
// always-running processes. Coding slots and peak scenarios are not counted
// here, so this list is not a final gate roster or capacity plan.
func Slice6V2ProvisionalStaticInventoryNames() []string {
	result := make([]string, 0, len(slice6ApprovedDeploymentKinds)+len(slice6V2IdentityDelta))
	for name := range slice6ApprovedDeploymentKinds {
		result = append(result, name)
	}
	for name := range slice6V2IdentityDelta {
		result = append(result, name)
	}
	slices.Sort(result)
	return result
}

// VerifySlice6V2IdentityFragment checks only the provisional static roster,
// four reviewed new identities and their dedicated TLS delegation.
// Callers MUST additionally validate the full v2 topology and digest before
// starting any role or interpreting this as a runnable security profile. This
// fragment does not authorize or count dynamic coding allocations.
func VerifySlice6V2IdentityFragment(environmentDigest, principalProfileDigest string, principals []Principal, tlsAgents []TLSAgentBinding) error {
	if len(slice6ApprovedDeploymentKinds) != 78 || len(principals) != 82 || len(slice6V2IdentityDelta) != 4 {
		return ErrInvalidProfile
	}
	egressBrokers := map[string]securityprincipal.Role{}
	authorities := map[string]securityprincipal.Role{}
	for _, principal := range principals {
		if principal.AuthorizationPrincipal == nil {
			continue
		}
		identity := principal.AuthorizationPrincipal
		switch principal.Kind {
		case "egress_broker":
			egressBrokers[identity.Name] = identity.Role
		case "controller":
			if strings.HasPrefix(principal.Name, "egress-policy-authority-") {
				authorities[identity.Name] = identity.Role
			}
		}
	}
	registry, err := securityprincipal.NewSlice6V2Registry(environmentDigest, principalProfileDigest, egressBrokers, authorities)
	if err != nil {
		return ErrInvalidProfile
	}
	byName := make(map[string]Principal, len(principals))
	uids, gids, uris := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	previous := ""
	for _, principal := range principals {
		if principal.Name <= previous || uids[principal.UID] || gids[principal.GID] || principal.UID < 10000 || principal.GID < 10000 {
			return ErrInvalidProfile
		}
		previous = principal.Name
		if principal.TLS != nil {
			if uris[principal.TLS.URI] {
				return ErrInvalidProfile
			}
			uris[principal.TLS.URI] = true
		}
		uids[principal.UID], gids[principal.GID] = true, true
		if expected, added := slice6V2IdentityDelta[principal.Name]; added {
			if principal.Kind != deploymentKindForV2Principal(expected.kind) || principal.AuthorizationPrincipal == nil ||
				principal.AuthorizationPrincipal.Kind != expected.kind || principal.AuthorizationPrincipal.Name != expected.name ||
				principal.AuthorizationPrincipal.Role != expected.role {
				return ErrInvalidProfile
			}
		} else if kind, approved := slice6ApprovedDeploymentKinds[principal.Name]; !approved || principal.Kind != kind {
			return ErrInvalidProfile
		}
		if principal.Kind == "sandbox" {
			if principal.AuthorizationPrincipal != nil || principal.PrincipalDigest != "" ||
				!digestPattern.MatchString(principal.ControllingPrincipalDigest) || principal.TLS != nil {
				return ErrInvalidProfile
			}
		} else {
			identity := principal.AuthorizationPrincipal
			if identity == nil || registry.Validate(*identity) != nil ||
				principal.Kind != deploymentKindForV2Principal(identity.Kind) ||
				principal.PrincipalDigest != identity.Digest() || principal.ControllingPrincipalDigest != "" ||
				(principal.Kind == "ingress_relay" && principal.TLS != nil) ||
				(principal.Kind != "ingress_relay" && (principal.TLS == nil ||
					principal.TLS.PrincipalDigest != principal.PrincipalDigest || validateTLS(*principal.TLS) != nil)) {
				return ErrInvalidProfile
			}
			if expected, fixed := requiredAuthorizationBindings[principal.Name]; fixed &&
				(identity.Kind != expected.kind || identity.Name != expected.name || identity.Role != expected.role) {
				return ErrInvalidProfile
			}
		}
		byName[principal.Name] = principal
	}
	if len(byName) != len(principals) {
		return ErrInvalidProfile
	}
	for resource, controller := range requiredResourceControllers {
		if byName[resource].ControllingPrincipalDigest != byName[controller].PrincipalDigest {
			return ErrInvalidProfile
		}
	}
	expectedAgents := make(map[string]string, len(requiredTLSAgentSubjects)+len(slice6V2TLSAgentDelta)+5)
	for agent, subject := range requiredTLSAgentSubjects {
		expectedAgents[agent] = subject
	}
	for agent, subject := range slice6ApprovedTLSAgentSubjects {
		if strings.HasPrefix(agent, "egress-broker-") {
			expectedAgents[agent] = subject
		}
	}
	for agent, subject := range slice6V2TLSAgentDelta {
		expectedAgents[agent] = subject
	}
	if len(tlsAgents) != len(expectedAgents) {
		return ErrInvalidProfile
	}
	delegations := map[string]string{}
	for _, binding := range tlsAgents {
		if _, duplicate := delegations[binding.AgentDeployment]; duplicate {
			return ErrInvalidProfile
		}
		if expectedAgents[binding.AgentDeployment] != binding.SubjectDeployment {
			return ErrInvalidProfile
		}
		delegations[binding.AgentDeployment] = binding.SubjectDeployment
		agent, agentOK := byName[binding.AgentDeployment]
		subject, subjectOK := byName[binding.SubjectDeployment]
		if !agentOK || !subjectOK || agent.PrincipalDigest != binding.AgentPrincipalDigest ||
			subject.PrincipalDigest != binding.SubjectPrincipalDigest ||
			agent.UID != binding.AgentUID || agent.GID != binding.AgentGID ||
			subject.UID != binding.SubjectUID || subject.GID != binding.SubjectGID {
			return ErrInvalidProfile
		}
	}
	for agent, subject := range expectedAgents {
		if delegations[agent] != subject {
			return ErrInvalidProfile
		}
	}
	return nil
}

func deploymentKindForV2Principal(kind securityprincipal.Kind) string {
	switch kind {
	case securityprincipal.KindDockerControl:
		return "docker_control"
	case securityprincipal.KindArtifactScanner:
		return "artifact_scanner"
	default:
		return deploymentKindForPrincipal(kind)
	}
}
