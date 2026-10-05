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

func TestFiniteIssuerGroupsV2FieldsKeepControlScannerOnGeneral(t *testing.T) {
	brokers := phase6security.Slice6DNSBrokerSubjects()
	bindings := make([]phase6security.TLSAgentBinding, 0, len(brokers)+2)
	policies := []workloadpki.Policy{{ID: "ordinary-policy", IssuerSourceID: "general"}}
	for _, name := range brokers {
		id := "policy-" + name
		bindings = append(bindings, phase6security.TLSAgentBinding{
			SubjectDeployment: name, IssuerPolicyID: id})
		policies = append(policies, workloadpki.Policy{ID: id, IssuerSourceID: "broker"})
	}
	for _, name := range []string{"provider-docker-control", "provider-artifact-scanner"} {
		id := "policy-" + name
		bindings = append(bindings, phase6security.TLSAgentBinding{
			SubjectDeployment: name, IssuerPolicyID: id})
		policies = append(policies, workloadpki.Policy{ID: id, IssuerSourceID: "general"})
	}
	edges := []phase6security.TrustEdge{
		{ID: "provider-coding-control", From: "provider-runtime", To: "provider-docker-control"},
		{ID: "provider-coding-scanner", From: "provider-runtime", To: "provider-artifact-scanner"},
	}
	external := []phase6security.ExternalService{{Name: "dns", DNSClientCA: &phase6security.DNSClientCA{
		IssuerID:     "11111111-1111-4111-8111-111111111111",
		IssuerDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}
	sources := phase6security.PeerCRLSources{Sources: []phase6security.PeerCRLSource{
		{ID: "broker", IssuerID: "11111111-1111-4111-8111-111111111111",
			IssuerDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{ID: "general", IssuerID: "22222222-2222-4222-8222-222222222222",
			IssuerDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}, Edges: []phase6security.PeerCRLEdgeBinding{
		{EdgeID: "provider-coding-control", Direction: "inbound", SourceID: "general"},
		{EdgeID: "provider-coding-scanner", Direction: "inbound", SourceID: "general"},
	}}
	if err := validateFiniteIssuerPolicyGroupsFields(bindings, edges, external, sources, policies); err != nil {
		t.Fatalf("v2 source-only finite policy partition: %v", err)
	}
	profile := phase6security.ProfileV2{TLSAgentBindings: bindings, TrustEdges: edges, External: external}
	if validateFiniteIssuerPolicyGroupsV2(profile, sources, sources.Digest(), policies) == nil {
		t.Fatal("partial v2 policy fixture bypassed formal profile hold")
	}
	for name, mutate := range map[string]func(*phase6security.PeerCRLSources, *[]workloadpki.Policy){
		"Control signing policy gets broker": func(_ *phase6security.PeerCRLSources, p *[]workloadpki.Policy) {
			(*p)[len(*p)-2].IssuerSourceID = "broker"
		},
		"Scanner signing policy gets broker": func(_ *phase6security.PeerCRLSources, p *[]workloadpki.Policy) {
			(*p)[len(*p)-1].IssuerSourceID = "broker"
		},
		"Control peer source gets broker": func(s *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			s.Edges[0].SourceID = "broker"
		},
		"Scanner peer source gets broker": func(s *phase6security.PeerCRLSources, _ *[]workloadpki.Policy) {
			s.Edges[1].SourceID = "broker"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changedSources := sources
			changedSources.Edges = slices.Clone(sources.Edges)
			changedPolicies := slices.Clone(policies)
			mutate(&changedSources, &changedPolicies)
			if validateFiniteIssuerPolicyGroupsFields(bindings, edges, external,
				changedSources, changedPolicies) == nil {
				t.Fatal("v2 Control/Scanner broker issuer crossed signing or peer boundary")
			}
		})
	}
}
