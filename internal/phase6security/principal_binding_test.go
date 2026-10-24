package phase6security

import (
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

func principalBindingFixture(t *testing.T) (map[string]Principal, *securityprincipal.Registry) {
	t.Helper()
	p := validProfile()
	r, err := p.principalRegistry()
	if err != nil {
		t.Fatal(err)
	}
	principals := make(map[string]Principal, len(p.Principals))
	for _, v := range p.Principals {
		principals[v.Name] = v
	}
	return principals, r
}

func TestPrincipalDigestBindingAndKinds(t *testing.T) {
	principals, r := principalBindingFixture(t)
	authorities := map[string]principalBinding{
		"egress-policy-authority-product": {securityprincipal.KindController, "product_policy_authority", ""},
	}
	agents := map[string]principalBinding{
		"egress-broker-product-tls-agent": {securityprincipal.KindTLSAgent, "product_egress_broker_tls_agent", securityprincipal.RoleProduct},
	}
	for _, name := range []string{"product-runtime", "egress-policy-authority-product", "egress-broker-product-tls-agent",
		"egress-broker-product", "public-ingress-relay", "browser-sandbox-runtime", "desktop-sandbox-runtime"} {
		t.Run(name, func(t *testing.T) {
			v, ok := principals[name]
			if !ok || validatePrincipal(v, r, authorities, agents) != nil {
				t.Fatal("valid component identity rejected")
			}
			if v.AuthorizationPrincipal != nil {
				if r.Validate(*v.AuthorizationPrincipal) != nil || v.PrincipalDigest != v.AuthorizationPrincipal.Digest() ||
					!digestPattern.MatchString(v.PrincipalDigest) {
					t.Fatal("accepted identity did not bind a canonical digest")
				}
			}
		})
	}
}

func TestPrincipalDigestBindingRejectsSubstitution(t *testing.T) {
	principals, r := principalBindingFixture(t)
	base := principals["product-runtime"]
	if validatePrincipal(base, r, nil, nil) != nil {
		t.Fatal("invalid rejection fixture")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Principal, **securityprincipal.Registry)
	}{
		{"outer_empty", func(p *Principal, _ **securityprincipal.Registry) { p.PrincipalDigest = "" }},
		{"outer_uppercase", func(p *Principal, _ **securityprincipal.Registry) {
			p.PrincipalDigest = "sha256:" + strings.Repeat("A", 64)
		}},
		{"outer_nul", func(p *Principal, _ **securityprincipal.Registry) { p.PrincipalDigest += "\x00" }},
		{"outer_newline", func(p *Principal, _ **securityprincipal.Registry) { p.PrincipalDigest += "\n" }},
		{"outer_wrong_hash", func(p *Principal, _ **securityprincipal.Registry) { p.PrincipalDigest = testDigest("wrong") }},
		{"both_empty", func(p *Principal, _ **securityprincipal.Registry) {
			p.PrincipalDigest = ""
			p.AuthorizationPrincipal.PrincipalDigest = ""
			p.TLS.PrincipalDigest = ""
		}},
		{"both_uppercase", func(p *Principal, _ **securityprincipal.Registry) {
			p.PrincipalDigest = "sha256:" + strings.Repeat("A", 64)
			p.AuthorizationPrincipal.PrincipalDigest = p.PrincipalDigest
			p.TLS.PrincipalDigest = p.PrincipalDigest
		}},
		{"both_wrong_hash", func(p *Principal, _ **securityprincipal.Registry) {
			p.PrincipalDigest = testDigest("wrong")
			p.AuthorizationPrincipal.PrincipalDigest = p.PrincipalDigest
			p.TLS.PrincipalDigest = p.PrincipalDigest
		}},
		{"nil_registry", func(_ *Principal, r **securityprincipal.Registry) { *r = nil }},
		{"wrong_registry", func(p *Principal, r **securityprincipal.Registry) {
			var err error
			*r, err = securityprincipal.NewRegistry(testDigest("different-environment"), p.AuthorizationPrincipal.ProfileDigest, nil)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"valid_other_identity", func(p *Principal, _ **securityprincipal.Registry) {
			identity := *principals["gateway-runtime"].AuthorizationPrincipal
			if r.Validate(identity) != nil {
				t.Fatal("replacement must be a valid registered identity")
			}
			p.AuthorizationPrincipal = &identity
			p.PrincipalDigest, p.TLS.PrincipalDigest = identity.Digest(), identity.Digest()
		}},
		{"missing_identity", func(p *Principal, _ **securityprincipal.Registry) { p.AuthorizationPrincipal = nil }},
		{"extra_controller", func(p *Principal, _ **securityprincipal.Registry) {
			p.ControllingPrincipalDigest = testDigest("controller")
		}},
		{"tls_digest", func(p *Principal, _ **securityprincipal.Registry) { p.TLS.PrincipalDigest = testDigest("wrong") }},
		{"missing_tls", func(p *Principal, _ **securityprincipal.Registry) { p.TLS = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, registry := base, r
			identity, tls := *base.AuthorizationPrincipal, *base.TLS
			v.AuthorizationPrincipal, v.TLS = &identity, &tls
			tc.mutate(&v, &registry)
			if validatePrincipal(v, registry, nil, nil) != ErrInvalidProfile {
				t.Fatal("identity substitution did not fail closed")
			}
		})
	}
}

func TestPrincipalDynamicAuthorizationBindingRejectsSwap(t *testing.T) {
	principals, r := principalBindingFixture(t)
	for _, name := range []string{"egress-policy-authority-product", "egress-broker-product-tls-agent"} {
		t.Run(name, func(t *testing.T) {
			v := principals[name]
			binding := principalBinding{v.AuthorizationPrincipal.Kind, v.AuthorizationPrincipal.Name, v.AuthorizationPrincipal.Role}
			authorities, agents := map[string]principalBinding{}, map[string]principalBinding{}
			target := agents
			if v.Kind == "controller" {
				target = authorities
			}
			target[name] = binding
			if validatePrincipal(v, r, authorities, agents) != nil {
				t.Fatal("valid dynamic binding rejected")
			}
			binding.name = "wrong_registered_binding"
			target[name] = binding
			if validatePrincipal(v, r, authorities, agents) != ErrInvalidProfile {
				t.Fatal("dynamic binding swap accepted")
			}
		})
	}
}

func TestPrincipalSandboxControlDigestRemainsStrict(t *testing.T) {
	principals, r := principalBindingFixture(t)
	base := principals["desktop-sandbox-runtime"]
	if validatePrincipal(base, r, nil, nil) != nil {
		t.Fatal("invalid sandbox fixture")
	}
	for _, tc := range []struct{ name, digest string }{
		{"empty", ""}, {"uppercase", "sha256:" + strings.Repeat("A", 64)}, {"short", "sha256:0"}, {"newline", base.ControllingPrincipalDigest + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			v.ControllingPrincipalDigest = tc.digest
			if validatePrincipal(v, r, nil, nil) != ErrInvalidProfile {
				t.Fatal("bad sandbox controller digest accepted")
			}
		})
	}
}

func TestPrincipalDigestRechecksIdentityAfterMutation(t *testing.T) {
	principals, r := principalBindingFixture(t)
	v := principals["product-runtime"]
	if validatePrincipal(v, r, nil, nil) != nil {
		t.Fatal("valid identity rejected")
	}
	alias := v.AuthorizationPrincipal
	before := *alias
	alias.InstanceDigest = testDigest("other-instance")
	if validatePrincipal(v, r, nil, nil) != ErrInvalidProfile {
		t.Fatal("mutated identity reused earlier validation")
	}
	*alias = before
	if validatePrincipal(v, r, nil, nil) != nil {
		t.Fatal("restored identity rejected")
	}
}
