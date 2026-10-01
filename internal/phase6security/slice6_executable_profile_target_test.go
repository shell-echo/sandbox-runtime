package phase6security

import (
	"bytes"
	"strings"
	"testing"
)

func TestSlice6ExecutableProfileTargetBindsAllPhysicalDependencies(t *testing.T) {
	draft := validProfile()
	if err := draft.Validate(); err != nil {
		t.Fatalf("base fixture invalid: %v", err)
	}
	if VerifySlice6DesiredExecutableExternalProfile(draft) == nil {
		t.Fatal("partial 17/12 graph admitted as the executable target")
	}
	target, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatalf("complete external target could not be built: %v", err)
	}
	if err := VerifySlice6DesiredExecutableExternalProfile(target); err != nil {
		t.Fatalf("complete target rejected: %v", err)
	}
	if len(target.Networks) != len(Slice6DesiredNetworks())+25 ||
		len(target.TrustEdges) != len(slice6DesiredTrustEdges())+14 {
		t.Fatalf("incomplete target: %d networks, %d trust edges", len(target.Networks), len(target.TrustEdges))
	}
	if len(draft.Networks) == len(target.Networks) || len(draft.TrustEdges) == len(target.TrustEdges) {
		t.Fatal("construction mutated the input draft")
	}
	for _, mutation := range []struct {
		name   string
		change func(*Profile)
	}{
		{"remove bridge", func(p *Profile) { p.Networks = p.Networks[1:] }},
		{"share Vault material bridge", func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "service-browser-action-ingress-agent-vault" {
					p.Networks[index].Principals = []string{"browser-action-ingress-agent", "gateway-agent"}
				}
			}
		}},
		{"swap agent Vault edge", func(p *Profile) {
			for index := range p.TrustEdges {
				if p.TrustEdges[index].ID == "browser-action-ingress-agent-vault" {
					p.TrustEdges[index].From = "gateway-agent"
				}
			}
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := target
			changed.Networks = append([]Network(nil), target.Networks...)
			changed.TrustEdges = append([]TrustEdge(nil), target.TrustEdges...)
			mutation.change(&changed)
			changed.ProfileDigest = changed.Digest()
			if VerifySlice6DesiredExecutableExternalProfile(changed) == nil {
				t.Fatal("unsafe complete target mutation admitted")
			}
		})
	}
}

func TestSlice6FinalExternalProfileTargetClosesMigrationDependencies(t *testing.T) {
	draft := validProfile()
	intermediate, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatalf("intermediate external target: %v", err)
	}
	if VerifySlice6DesiredFinalExternalProfile(intermediate) == nil {
		t.Fatal("intermediate target admitted as final")
	}
	final, err := BuildSlice6FinalExternalProfileTarget(draft)
	if err != nil {
		t.Fatalf("final external target: %v", err)
	}
	if err := VerifySlice6DesiredFinalExternalProfile(final); err != nil {
		t.Fatalf("final external target rejected: %v", err)
	}
	hba, err := final.PostgresServerAuth.RenderApprovedHBA(final.ProviderDatabases)
	if err != nil {
		t.Fatalf("shared PostgreSQL HBA rejected: %v", err)
	}
	wantHBA, err := RenderSlice6DesiredFinalSharedPostgresHBA()
	if err != nil || !bytes.Equal(hba, wantHBA) || strings.Count(string(hba), "hostssl ") != 9 {
		t.Fatal("final profile does not bind the exact nine-role shared PostgreSQL HBA")
	}
	if _, err := final.PostgresServerAuth.RenderProviderHBA(final.ProviderDatabases); err == nil {
		t.Fatal("shared PostgreSQL scope admitted the historical Provider-only HBA")
	}
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil {
		t.Fatal(err)
	}
	proof := &Slice6PostgresServerAuthEvidence{ApprovedSourceCIDRs: make([]string, len(rules))}
	for i, rule := range rules {
		proof.ApprovedSourceCIDRs[i] = rule.SourceCIDR
	}
	if !validSlice6PostgresIngressProof(final.PostgresServerAuth, proof) {
		t.Fatal("exact shared HBA source evidence rejected")
	}
	proof.ApprovedSourceCIDRs[0] = "172.17.0.1/32"
	if validSlice6PostgresIngressProof(final.PostgresServerAuth, proof) {
		t.Fatal("wrong shared HBA source evidence accepted")
	}
	if got, want := len(final.TrustEdges), len(slice6DesiredTrustEdges())+18; got != want {
		t.Fatalf("trust edges = %d, want %d", got, want)
	}
	if got, want := len(final.Networks), len(Slice6DesiredNetworks())+29; got != want {
		t.Fatalf("networks = %d, want %d", got, want)
	}
	if len(draft.Networks) == len(final.Networks) || len(draft.TrustEdges) == len(final.TrustEdges) {
		t.Fatal("construction mutated the draft")
	}
	for _, test := range []struct {
		name   string
		mutate func(*Profile)
	}{
		{"remove migration bridge", func(p *Profile) {
			for i, n := range p.Networks {
				if n.Name == "service-provider-browser-migration-job-postgres" {
					p.Networks = append(p.Networks[:i], p.Networks[i+1:]...)
					return
				}
			}
		}},
		{"share migration bridge", func(p *Profile) {
			for i := range p.Networks {
				if p.Networks[i].Name == "service-provider-browser-migration-job-postgres" {
					p.Networks[i].Principals = []string{"provider-browser-migration-job", "provider-desktop-migration-job"}
				}
			}
		}},
		{"swap migration edge", func(p *Profile) {
			for i := range p.TrustEdges {
				if p.TrustEdges[i].ID == "provider-browser-migration-postgres" {
					p.TrustEdges[i].From = "provider-desktop-migration-job"
				}
			}
		}},
		{"reuse provider HBA", func(p *Profile) {
			p.PostgresServerAuth.Scope = postgresServerAuthScope
			p.PostgresServerAuth.IngressCIDR = "172.17.0.1/32"
		}},
		{"change shared HBA digest", func(p *Profile) {
			p.PostgresServerAuth.HBADigest = testDigest("wrong-shared-hba")
		}},
		{"leak Vault client CA", func(p *Profile) {
			for i := range p.TrustAnchors {
				if p.TrustAnchors[i].ID == "vault-client-ca" {
					p.TrustAnchors[i].Consumers = append(p.TrustAnchors[i].Consumers, "guest-runtime")
				}
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := final
			changed.Networks = append([]Network(nil), final.Networks...)
			changed.TrustEdges = append([]TrustEdge(nil), final.TrustEdges...)
			changed.TrustAnchors = append([]TrustAnchor(nil), final.TrustAnchors...)
			for i := range changed.TrustAnchors {
				changed.TrustAnchors[i].Consumers = append([]string(nil), final.TrustAnchors[i].Consumers...)
			}
			test.mutate(&changed)
			changed.ProfileDigest = changed.Digest()
			if VerifySlice6DesiredFinalExternalProfile(changed) == nil {
				t.Fatal("unsafe final external target admitted")
			}
		})
	}
}
