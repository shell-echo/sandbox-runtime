package main

import (
	"slices"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/workloadpki"
)

func TestFiniteIssuerGroupsKeepDNSBrokerCAExclusive(t *testing.T) {
	brokers := []string{"egress-broker-product", "egress-broker-gateway",
		"egress-broker-browser-action-ingress", "egress-broker-provider-browser", "egress-broker-provider-desktop"}
	profile := phase6security.Profile{}
	policies := []workloadpki.Policy{{ID: "ordinary-policy", IssuerSourceID: "general"}}
	for _, broker := range brokers {
		id := "policy-" + broker
		profile.TLSAgentBindings = append(profile.TLSAgentBindings, phase6security.TLSAgentBinding{
			SubjectDeployment: broker, IssuerPolicyID: id})
		policies = append(policies, workloadpki.Policy{ID: id, IssuerSourceID: "broker"})
	}
	profile.TrustEdges = []phase6security.TrustEdge{
		{ID: "to-broker", From: "ordinary", To: "egress-broker-product"},
		{ID: "broker-to-dns", From: "egress-broker-product", To: "dns"},
	}
	profile.External = []phase6security.ExternalService{{Name: "dns", DNSClientCA: &phase6security.DNSClientCA{
		IssuerID:     "11111111-1111-4111-8111-111111111111",
		IssuerDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}}
	sources := phase6security.PeerCRLSources{Sources: []phase6security.PeerCRLSource{
		{ID: "broker", IssuerID: "11111111-1111-4111-8111-111111111111", IssuerDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{ID: "general", IssuerID: "22222222-2222-4222-8222-222222222222", IssuerDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}, Edges: []phase6security.PeerCRLEdgeBinding{
		{EdgeID: "to-broker", Direction: "outbound", SourceID: "broker"},
		{EdgeID: "broker-to-dns", Direction: "outbound", SourceID: "general"},
	}}
	if err := validateFiniteIssuerPolicyGroupsBound(profile, sources, policies); err != nil {
		t.Fatalf("finite partition rejected: %v", err)
	}
	for name, change := range map[string]func(*phase6security.Profile, *phase6security.PeerCRLSources, *[]workloadpki.Policy){
		"ordinary gets broker issuer": func(_ *phase6security.Profile, _ *phase6security.PeerCRLSources, p *[]workloadpki.Policy) {
			(*p)[0].IssuerSourceID = "broker"
		},
		"broker gets general issuer": func(_ *phase6security.Profile, _ *phase6security.PeerCRLSources, p *[]workloadpki.Policy) {
			(*p)[1].IssuerSourceID = "general"
		},
		"wrong broker peer source": func(_ *phase6security.Profile, s *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			s.Edges[0].SourceID = "general"
		},
		"wrong DNS peer source": func(_ *phase6security.Profile, s *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			s.Edges[1].SourceID = "broker"
		},
		"same issuer certificate": func(_ *phase6security.Profile, s *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			s.Sources[1].IssuerDigest = s.Sources[0].IssuerDigest
		},
		"DNS trusts general issuer": func(p *phase6security.Profile, _ *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			p.External[0].DNSClientCA = &phase6security.DNSClientCA{
				IssuerID:     "22222222-2222-4222-8222-222222222222",
				IssuerDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			}
		},
		"missing broker binding": func(p *phase6security.Profile, _ *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			p.TLSAgentBindings = p.TLSAgentBindings[1:]
		},
		"extra issuer": func(_ *phase6security.Profile, s *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			s.Sources = append(s.Sources, phase6security.PeerCRLSource{ID: "extra"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedProfile := profile
			changedProfile.TLSAgentBindings = slices.Clone(profile.TLSAgentBindings)
			changedSources := sources
			changedSources.Sources = slices.Clone(sources.Sources)
			changedSources.Edges = slices.Clone(sources.Edges)
			changedPolicies := slices.Clone(policies)
			change(&changedProfile, &changedSources, &changedPolicies)
			if validateFiniteIssuerPolicyGroupsBound(changedProfile, changedSources, changedPolicies) == nil {
				t.Fatal("issuer boundary drift admitted")
			}
		})
	}
}
