package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func authorityFixture(t *testing.T) authority {
	t.Helper()
	binding := func(purpose secretref.Purpose, name string) string {
		value := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
			Reference: secretref.Reference("secret://vault/" + name), Version: "v1",
			Purpose: purpose, TenantID: secretref.SystemTenant, Role: secretref.RoleGateway}
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(document)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	return authority{Protocol: authorityProtocol,
		SecurityProfilePath: "/run/phase6/security.json", SecurityProfileDigest: digest,
		PeerCRLRoleFile: "/run/phase6/ingress-peer-crl.json", PeerCRLRoleDigest: digest,
		PeerCRLSourceMappingDigest: digest, ListenAddress: "10.26.0.3:8443",
		ProviderOrigin: "wss://10.26.1.3:8443/private/browser", ProviderAudience: "browser-provider-1",
		TLSAgentSocket: "/run/phase6/ingress-tls-agent.sock", TLSAgentUID: 2001, TLSAgentGID: 2002,
		MaterialProvider: materialProviderDocument{Type: "unix-workload-material.v2", Alias: "ingress-vault",
			SocketPath: "/run/phase6/ingress-material-agent.sock", ExpectedUID: 3001, ExpectedGID: 3002,
			OperationTimeoutSeconds: 2},
		MaterialBindings: []materialBindingDocument{
			{ID: "capacity", Provider: "ingress-vault", Document: binding(secretref.PurposeCapacityValkeyCredentials, "ingress-capacity")},
			{ID: "witness", Provider: "ingress-vault", Document: binding(secretref.PurposeActionHistoryWitnessDSN, "ingress-witness")},
		},
		CapacityBindingID: "capacity", WitnessBindingID: "witness",
		ExpectedCapacityUser: "ingress_capacity", WitnessDatabase: "action_history", WitnessUser: "ingress_witness",
		CapacityNamespace: "browser-production", CapacityMaxTotal: 256, CapacityMaxPerTenant: 32,
		LeaseTTLMillis: 10000, RenewIntervalMillis: 1000, RenewalSafetyMillis: 3000,
		OperationTimeoutMillis: 2000, ActionTimeoutMillis: 10000, CredentialPollMillis: 500,
		MaxSessions: 128, MaxActionBytes: 32 << 10}
}

func encodeAuthorityFixture(t *testing.T, value authority) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestDecodeAuthorityClosedCanonical(t *testing.T) {
	base := authorityFixture(t)
	if _, err := decodeAuthority(encodeAuthorityFixture(t, base)); err != nil {
		t.Fatalf("valid authority rejected: %v", err)
	}
	mutations := map[string]func(*authority){
		"wrong protocol":    func(a *authority) { a.Protocol = "sandbox-runtime.browser-action-ingress-authority.v0" },
		"loopback":          func(a *authority) { a.ListenAddress = "127.0.0.1:8443" },
		"wildcard":          func(a *authority) { a.ListenAddress = "0.0.0.0:8443" },
		"noncanonical port": func(a *authority) { a.ListenAddress = "10.26.0.3:08443" },
		"DNS listener":      func(a *authority) { a.ListenAddress = "ingress.test:8443" },
		"alternate origin":  func(a *authority) { a.ProviderOrigin = "ws://10.26.1.3:8443/private/browser" },
		"cached material":   func(a *authority) { a.MaterialProvider.CacheSeconds = 1 },
		"slow material":     func(a *authority) { a.MaterialProvider.OperationTimeoutSeconds = 60 },
		"duplicate binding": func(a *authority) { a.WitnessBindingID = a.CapacityBindingID },
		"unbounded poll":    func(a *authority) { a.CredentialPollMillis = 6000 },
		"short action":      func(a *authority) { a.ActionTimeoutMillis = 5000 },
		"too many sessions": func(a *authority) { a.MaxSessions = 10000 },
		"unclean profile":   func(a *authority) { a.SecurityProfilePath = "/run/phase6/../phase6/security.json" },
		"bad audience":      func(a *authority) { a.ProviderAudience = "browser provider" },
		"default ACL user":  func(a *authority) { a.ExpectedCapacityUser = "default" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := decodeAuthority(encodeAuthorityFixture(t, value)); err == nil {
				t.Fatal("unsafe authority accepted")
			}
		})
	}
	valid := encodeAuthorityFixture(t, base)
	for name, document := range map[string][]byte{
		"whitespace": append([]byte(" "), valid...),
		"unknown":    []byte(strings.Replace(string(valid), `"protocol":`, `"unexpected":1,"protocol":`, 1)),
		"duplicate":  []byte(strings.Replace(string(valid), `"protocol":`, `"protocol":"replay","protocol":`, 1)),
		"trailing":   append(append([]byte(nil), valid...), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAuthority(document); err == nil {
				t.Fatal("noncanonical authority accepted")
			}
		})
	}
}

func TestValidateMaterialBoundaryDeniesSameRoleSwaps(t *testing.T) {
	base := authorityFixture(t)
	profile := phase6security.Profile{Principals: []phase6security.Principal{{Name: "browser-action-ingress-agent", UID: 3001, GID: 3002}},
		MaterialSockets: []phase6security.Slice6MaterialSocketBinding{{AgentDeployment: "browser-action-ingress-agent",
			OwnerDeployment: "browser-action-ingress-runtime", AgentUID: 3001, AgentGID: 3002,
			OwnerUID: 3003, OwnerGID: 3004, SocketPath: base.MaterialProvider.SocketPath,
			MaxOperationSeconds: 30}}}
	if err := validateMaterialBoundary(profile, base); err != nil {
		t.Fatalf("exact ingress bindings rejected: %v", err)
	}
	for name, mutate := range map[string]func(*authority){
		"Gateway agent":       func(a *authority) { a.MaterialProvider.ExpectedUID = 4001 },
		"legacy material":     func(a *authority) { a.MaterialProvider.Type = "unix-workload-material.v1" },
		"alternate socket":    func(a *authority) { a.MaterialProvider.SocketPath = "/run/phase6/other.sock" },
		"Gateway capacity ID": func(a *authority) { a.CapacityBindingID = "witness" },
		"witness as capacity": func(a *authority) { a.MaterialBindings[0].Document = a.MaterialBindings[1].Document },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.MaterialBindings = append([]materialBindingDocument(nil), base.MaterialBindings...)
			mutate(&value)
			if err := validateMaterialBoundary(profile, value); err == nil {
				t.Fatal("cross-binding authority accepted")
			}
		})
	}
}
