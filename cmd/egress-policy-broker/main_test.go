package main

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestDNSConfigMustMatchExternalIdentityAndNumericEndpoint(t *testing.T) {
	profile := phase6security.Profile{
		External: []phase6security.ExternalService{{Name: "dns", URI: "spiffe://example.test/dns", DNSNames: []string{"dns.example.test"}, IdentityDigest: "identity-digest"}},
		TrustEdges: []phase6security.TrustEdge{{From: "egress-broker-product", To: "dns", CrossDomain: true,
			ExternalIdentityDigest: "identity-digest", Protocol: "dns_tcp", Authentication: "mtls", Port: 853}},
	}
	if _, ok := validateDNSConfig(profile, "egress-broker-product", "dns.example.test", "192.0.2.53:853"); !ok {
		t.Fatal("exact DNS identity and numeric endpoint rejected")
	}
	for name, change := range map[string]func(*phase6security.Profile, *string, *string){
		"wrong SAN":            func(_ *phase6security.Profile, serverName, _ *string) { *serverName = "attacker.example.test" },
		"DNS bootstrap bypass": func(_ *phase6security.Profile, _, address *string) { *address = "dns.example.test:853" },
		"wrong port":           func(_ *phase6security.Profile, _, address *string) { *address = "192.0.2.53:53" },
		"edge identity drift":  func(p *phase6security.Profile, _, _ *string) { p.TrustEdges[0].ExternalIdentityDigest = "other" },
		"extra SAN": func(p *phase6security.Profile, _, _ *string) {
			p.External[0].DNSNames = append(p.External[0].DNSNames, "extra.example.test")
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			candidate.External = append([]phase6security.ExternalService(nil), profile.External...)
			candidate.TrustEdges = append([]phase6security.TrustEdge(nil), profile.TrustEdges...)
			serverName, address := "dns.example.test", "192.0.2.53:853"
			change(&candidate, &serverName, &address)
			if _, ok := validateDNSConfig(candidate, "egress-broker-product", serverName, address); ok {
				t.Fatal("DNS identity/endpoint drift accepted")
			}
		})
	}
}
