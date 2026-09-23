package main

import (
	"bytes"
	"encoding/json"
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

func TestConfigRequiresBoundedOperatorPolicyState(t *testing.T) {
	valid := func() configDocument {
		return configDocument{Protocol: configProtocol, SecurityProfilePath: "/private/profile.json", PolicyID: "product-egress",
			ListenAddress: "127.0.0.1:8443", DNSAddress: "192.0.2.53:853", DNSServerName: "dns.example.test",
			MaxConnections: 4, ReplayCapacity: 16, OperationTimeoutSeconds: 5,
			PolicyStateKeyID: "operator-1", PolicyStatePublicKey: make([]byte, 32), PolicyCurrentPollMillis: 1000,
			PolicyAuthoritySocket: "/private/authority/current.sock", PolicyAuthorityUID: 501,
			PolicyAuthorityGID: 502, PolicyBrokerGID: 503, PolicyAuthorityTimeoutMS: 1000}
	}
	encode := func(value configDocument) []byte {
		t.Helper()
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return document
	}
	if _, err := decodeConfig(encode(valid())); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*configDocument){
		"wrong key":          func(c *configDocument) { c.PolicyStatePublicKey = nil },
		"slow polling":       func(c *configDocument) { c.PolicyCurrentPollMillis = 1001 },
		"missing authority":  func(c *configDocument) { c.PolicyAuthoritySocket = "" },
		"relative authority": func(c *configDocument) { c.PolicyAuthoritySocket = "authority.sock" },
		"slow attestation":   func(c *configDocument) { c.PolicyAuthorityTimeoutMS = 5001 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			change(&candidate)
			if _, err := decodeConfig(encode(candidate)); err == nil {
				t.Fatal("unsafe policy-state config accepted")
			}
		})
	}
	document := encode(valid())
	for name, candidate := range map[string][]byte{
		"unknown":      bytes.Replace(document, []byte(`"protocol":`), []byte(`"extra":true,"protocol":`), 1),
		"duplicate":    bytes.Replace(document, []byte(`"protocol":`), []byte(`"protocol":"x","protocol":`), 1),
		"noncanonical": append([]byte(" "), document...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfig(candidate); err == nil {
				t.Fatal("noncanonical config accepted")
			}
		})
	}
}

func TestBrokerPolicyAuthorityConfigMustMatchProfile(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	config := configDocument{PolicyAuthoritySocket: "/run/egress-authority/current.sock", PolicyStateKeyID: "operator-product-1",
		PolicyStatePublicKey: key, PolicyAuthorityUID: 20001, PolicyAuthorityGID: 30001, PolicyBrokerGID: 30000,
		PolicyCurrentPollMillis: 500, PolicyAuthorityTimeoutMS: 1000}
	broker := phase6security.Principal{Name: "egress-broker-product", GID: 30000}
	authority := phase6security.Principal{Name: "egress-policy-authority-product", Kind: "controller", UID: 20001,
		GID: 30001, PrincipalDigest: "authority-digest"}
	profile := phase6security.Profile{Principals: []phase6security.Principal{broker, authority}}
	policy := phase6security.EgressPolicy{Authority: phase6security.PolicyAuthority{DeploymentName: authority.Name,
		PrincipalDigest: authority.PrincipalDigest, KeyID: config.PolicyStateKeyID,
		PublicKeyDigest: phase6security.OperatorPublicKeyDigest(key),
		SocketDirectory: "/run/egress-authority", PollMillis: 500, CurrentTimeoutMS: 1000}}
	if !validatePolicyAuthorityConfig(profile, policy, broker, config) {
		t.Fatal("exact broker authority config rejected")
	}
	for name, change := range map[string]func(*configDocument){
		"socket":        func(c *configDocument) { c.PolicyAuthoritySocket = "/run/other/current.sock" },
		"poll":          func(c *configDocument) { c.PolicyCurrentPollMillis++ },
		"key":           func(c *configDocument) { c.PolicyStatePublicKey = bytes.Repeat([]byte{8}, 32) },
		"authority UID": func(c *configDocument) { c.PolicyAuthorityUID++ },
		"broker GID":    func(c *configDocument) { c.PolicyBrokerGID++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			change(&candidate)
			if validatePolicyAuthorityConfig(profile, policy, broker, candidate) {
				t.Fatal("broker authority drift accepted")
			}
		})
	}
}

func TestBrokerTLSAgentConfigMustMatchProfile(t *testing.T) {
	broker := phase6security.Principal{Name: "egress-broker-product", PrincipalDigest: "broker-digest", GID: 30001}
	subject := broker
	agent := phase6security.Principal{Name: "egress-broker-product-tls-agent", Kind: "tls_agent", PrincipalDigest: "agent-digest",
		UID: 20001, GID: 30002}
	binding := phase6security.TLSAgentBinding{AgentDeployment: agent.Name, AgentPrincipalDigest: agent.PrincipalDigest,
		SubjectDeployment: broker.Name, SubjectPrincipalDigest: broker.PrincipalDigest,
		AgentUID: 20001, AgentGID: 30002, SubjectGID: broker.GID, SocketPath: "/run/tls/egress-broker-product-tls-agent/signer.sock"}
	config := configDocument{TLSAgentSocket: binding.SocketPath, TLSAgentExpectedUID: binding.AgentUID, TLSAgentExpectedGID: binding.AgentGID}
	if !matchesTLSAgentConfig(binding, agent, subject, broker, config) {
		t.Fatal("exact broker TLS-agent binding rejected")
	}
	for name, change := range map[string]func(*configDocument){
		"socket":    func(c *configDocument) { c.TLSAgentSocket += "-other" },
		"agent UID": func(c *configDocument) { c.TLSAgentExpectedUID++ },
		"agent GID": func(c *configDocument) { c.TLSAgentExpectedGID++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			change(&candidate)
			if matchesTLSAgentConfig(binding, agent, subject, broker, candidate) {
				t.Fatal("broker TLS-agent drift accepted")
			}
		})
	}
	broker.GID++
	if matchesTLSAgentConfig(binding, agent, subject, broker, config) {
		t.Fatal("broker GID substitution accepted")
	}
}

func TestBrokerListenerMustMatchClosedProfile(t *testing.T) {
	broker := phase6security.Principal{Listeners: []phase6security.Listener{
		{Name: "egress", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}}
	if !validateBrokerListenConfig(broker, "0.0.0.0:8443") {
		t.Fatal("bound egress listener rejected")
	}
	for _, address := range []string{"127.0.0.1:8443", "0.0.0.0:9443", "[::]:8443", "broker.test:8443", "0.0.0.0:0"} {
		if validateBrokerListenConfig(broker, address) {
			t.Fatalf("listener drift %q accepted", address)
		}
	}
	broker.Listeners = append(broker.Listeners, phase6security.Listener{Name: "extra", Protocol: "tcp", Port: 9443, Exposure: "public"})
	if validateBrokerListenConfig(broker, "0.0.0.0:8443") {
		t.Fatal("extra listener accepted")
	}
}

func TestBrokerInboundEdgeIsUniqueAndPortBound(t *testing.T) {
	profile := phase6security.Profile{TrustEdges: []phase6security.TrustEdge{{ID: "role-broker", From: "product-runtime",
		To: "egress-broker-product", Protocol: "tls", Port: 8443, Authentication: "mtls"}}}
	if _, ok := brokerInboundEdge(profile, "product-runtime", "egress-broker-product", "0.0.0.0:8443"); !ok {
		t.Fatal("declared broker edge rejected")
	}
	if _, ok := brokerInboundEdge(profile, "product-runtime", "egress-broker-product", "0.0.0.0:9443"); ok {
		t.Fatal("port drift accepted")
	}
	profile.TrustEdges = append(profile.TrustEdges, phase6security.TrustEdge{ID: "other", From: "guest-runtime",
		To: "egress-broker-product", Protocol: "tls", Port: 8443, Authentication: "mtls"})
	if _, ok := brokerInboundEdge(profile, "product-runtime", "egress-broker-product", "0.0.0.0:8443"); ok {
		t.Fatal("extra inbound caller accepted")
	}
}
