package phase6security

import (
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

func testSlice6V2IdentityFragment(t *testing.T) Profile {
	t.Helper()
	p := validProfile()
	if len(p.Principals) != 78 {
		t.Fatalf("historical roster changed: %d", len(p.Principals))
	}
	registry, err := securityprincipal.NewSlice6V2Registry(p.EnvironmentDigest, p.PrincipalProfileDigest, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var subjectTemplate, agentTemplate Principal
	var bindingTemplate TLSAgentBinding
	for _, principal := range p.Principals {
		switch principal.Name {
		case "provider-runtime":
			subjectTemplate = principal
		case "provider-tls-agent":
			agentTemplate = principal
		}
	}
	for _, binding := range p.TLSAgentBindings {
		if binding.AgentDeployment == "provider-tls-agent" {
			bindingTemplate = binding
		}
	}
	for index, pair := range []struct {
		subject, agent string
	}{
		{"provider-docker-control", "provider-docker-control-tls-agent"},
		{"provider-artifact-scanner", "provider-artifact-scanner-tls-agent"},
	} {
		var subject, agent Principal
		for _, template := range []struct {
			name string
			base Principal
			dest *Principal
		}{
			{pair.subject, subjectTemplate, &subject},
			{pair.agent, agentTemplate, &agent},
		} {
			candidate := template.base
			candidate.Name = template.name
			candidate.UID = 59000 + uint32(index*2)
			candidate.GID = 59000 + uint32(index*2)
			if template.name == pair.agent {
				candidate.UID++
				candidate.GID++
			}
			approved := slice6V2IdentityDelta[template.name]
			candidate.Kind = deploymentKindForV2Principal(approved.kind)
			identity, identityErr := registry.New(approved.kind, approved.name, approved.role, testDigest("v2/"+template.name))
			if identityErr != nil {
				t.Fatal(identityErr)
			}
			candidate.AuthorizationPrincipal = &identity
			candidate.PrincipalDigest = identity.Digest()
			candidate.TLS = new(TLSIdentity)
			*candidate.TLS = *template.base.TLS
			candidate.TLS.PrincipalDigest = candidate.PrincipalDigest
			candidate.TLS.URI = "spiffe://sandbox-runtime.test/" + template.name
			*template.dest = candidate
			p.Principals = append(p.Principals, candidate)
		}
		binding := bindingTemplate
		binding.AgentDeployment, binding.SubjectDeployment = agent.Name, subject.Name
		binding.AgentPrincipalDigest, binding.SubjectPrincipalDigest = agent.PrincipalDigest, subject.PrincipalDigest
		binding.AgentUID, binding.AgentGID = agent.UID, agent.GID
		binding.SubjectUID, binding.SubjectGID = subject.UID, subject.GID
		p.TLSAgentBindings = append(p.TLSAgentBindings, binding)
	}
	slices.SortFunc(p.Principals, func(a, b Principal) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
	return p
}

func TestSlice6V2IdentityFragmentIsExplicitAndNotV1(t *testing.T) {
	p := testSlice6V2IdentityFragment(t)
	if names := Slice6V2ProvisionalStaticInventoryNames(); len(names) != 82 || !slices.IsSorted(names) {
		t.Fatalf("v2 deployment roster = %v", names)
	}
	if err := VerifySlice6V2IdentityFragment(p.EnvironmentDigest, p.PrincipalProfileDigest, p.Principals, p.TLSAgentBindings); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err == nil {
		t.Fatal("v1 security profile accepted the v2-only identity fragment")
	}
	for name, mutate := range map[string]func(*Profile){
		"missing principal": func(value *Profile) { value.Principals = value.Principals[1:] },
		"cross role": func(value *Profile) {
			for index := range value.Principals {
				if value.Principals[index].Name == "provider-docker-control" {
					value.Principals[index].AuthorizationPrincipal.Role = securityprincipal.RoleProvider
				}
			}
		},
		"duplicate uid": func(value *Profile) { value.Principals[1].UID = value.Principals[0].UID },
		"historical principal digest drift": func(value *Profile) {
			for index := range value.Principals {
				if value.Principals[index].Name == "provider-runtime" {
					value.Principals[index].PrincipalDigest = testDigest("drifted-provider")
				}
			}
		},
		"historical authorization drift": func(value *Profile) {
			for index := range value.Principals {
				if value.Principals[index].Name == "gateway-runtime" {
					value.Principals[index].AuthorizationPrincipal.Role = securityprincipal.RoleProvider
				}
			}
		},
		"historical missing delegation": func(value *Profile) {
			value.TLSAgentBindings = slices.DeleteFunc(value.TLSAgentBindings, func(b TLSAgentBinding) bool {
				return b.AgentDeployment == "provider-tls-agent"
			})
		},
		"historical cross delegation": func(value *Profile) {
			for index := range value.TLSAgentBindings {
				if value.TLSAgentBindings[index].AgentDeployment == "provider-tls-agent" {
					value.TLSAgentBindings[index].SubjectDeployment = "gateway-runtime"
				}
			}
		},
		"missing delegation": func(value *Profile) {
			value.TLSAgentBindings = slices.DeleteFunc(value.TLSAgentBindings, func(b TLSAgentBinding) bool {
				return b.AgentDeployment == "provider-docker-control-tls-agent"
			})
		},
		"cross delegation": func(value *Profile) {
			for index := range value.TLSAgentBindings {
				if value.TLSAgentBindings[index].AgentDeployment == "provider-docker-control-tls-agent" {
					value.TLSAgentBindings[index].SubjectDeployment = "provider-artifact-scanner"
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testSlice6V2IdentityFragment(t)
			mutate(&candidate)
			if err := VerifySlice6V2IdentityFragment(candidate.EnvironmentDigest, candidate.PrincipalProfileDigest,
				candidate.Principals, candidate.TLSAgentBindings); err == nil {
				t.Fatal("invalid v2 identity fragment accepted")
			}
		})
	}
}
