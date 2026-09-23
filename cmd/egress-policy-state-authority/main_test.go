package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func testConfig() configDocument {
	return configDocument{Protocol: configProtocol, Mode: "serve", SecurityProfilePath: "/private/profile.json",
		PolicyID: "product-egress", LedgerPath: "/var/lib/egress-authority/ledger.json",
		SocketPath:    "/run/egress-authority/current.sock",
		OperatorKeyID: "operator-product-1", OperatorPublicKey: make([]byte, ed25519.PublicKeySize),
		ExpectedBrokerUID: 20000, ExpectedBrokerGID: 30000, MaxConnections: 4,
		StateRefreshMillis: 500, PolicyStateMaxAgeSeconds: 5}
}

func encodeConfig(t *testing.T, config configDocument) []byte {
	t.Helper()
	document, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestAuthorityConfigStrictAndBounded(t *testing.T) {
	if _, err := decodeConfig(encodeConfig(t, testConfig())); err != nil {
		t.Fatal(err)
	}
	inspect := testConfig()
	inspect.Mode = "inspect"
	if _, err := decodeConfig(encodeConfig(t, inspect)); err != nil {
		t.Fatalf("read-only inspect mode rejected: %v", err)
	}
	for name, mutate := range map[string]func(*configDocument){
		"unknown mode":          func(c *configDocument) { c.Mode = "resume-or-initialize" },
		"relative ledger":       func(c *configDocument) { c.LedgerPath = "ledger.json" },
		"missing key":           func(c *configDocument) { c.OperatorPublicKey = nil },
		"slow refresh":          func(c *configDocument) { c.StateRefreshMillis = 1001 },
		"stale refresh":         func(c *configDocument) { c.PolicyStateMaxAgeSeconds = 1; c.StateRefreshMillis = 501 },
		"large state age":       func(c *configDocument) { c.PolicyStateMaxAgeSeconds = 31 },
		"unbounded connections": func(c *configDocument) { c.MaxConnections = 65 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testConfig()
			mutate(&candidate)
			if _, err := decodeConfig(encodeConfig(t, candidate)); err == nil {
				t.Fatal("unsafe authority config accepted")
			}
		})
	}
	document := encodeConfig(t, testConfig())
	for name, candidate := range map[string][]byte{
		"unknown":      bytes.Replace(document, []byte(`"protocol":`), []byte(`"extra":true,"protocol":`), 1),
		"duplicate":    bytes.Replace(document, []byte(`"protocol":`), []byte(`"protocol":"x","protocol":`), 1),
		"noncanonical": append([]byte(" "), document...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfig(candidate); err == nil {
				t.Fatal("noncanonical authority config accepted")
			}
		})
	}
}

func TestAuthorityConfigBoundToExactProfilePolicyAndIdentity(t *testing.T) {
	config := testConfig()
	config.OperatorPublicKey = bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
	authority := phase6security.Principal{Name: "egress-policy-authority-product", Kind: "controller",
		PrincipalDigest: "authority-digest", UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	broker := phase6security.Principal{Name: "egress-broker-product", Kind: "egress_broker", UID: 20000, GID: 30000}
	profile := phase6security.Profile{Principals: []phase6security.Principal{authority, broker}}
	policy := phase6security.EgressPolicy{Broker: broker.Name, Authority: phase6security.PolicyAuthority{
		DeploymentName: authority.Name, PrincipalDigest: authority.PrincipalDigest, KeyID: config.OperatorKeyID,
		PublicKeyDigest:   phase6security.OperatorPublicKeyDigest(config.OperatorPublicKey),
		LedgerMountTarget: "/var/lib/egress-authority", StateMaxAgeSeconds: config.PolicyStateMaxAgeSeconds,
		SocketDirectory: "/run/egress-authority"}}
	if !validateProfileBinding(profile, policy, config) {
		t.Fatal("exact authority binding rejected")
	}
	for name, mutate := range map[string]func(*configDocument){
		"swapped ledger":   func(c *configDocument) { c.LedgerPath = "/other/ledger.json" },
		"swapped socket":   func(c *configDocument) { c.SocketPath = "/other/current.sock" },
		"swapped key":      func(c *configDocument) { c.OperatorPublicKey = bytes.Repeat([]byte{8}, ed25519.PublicKeySize) },
		"wrong broker UID": func(c *configDocument) { c.ExpectedBrokerUID++ },
		"stale state":      func(c *configDocument) { c.PolicyStateMaxAgeSeconds++ },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			mutate(&candidate)
			if validateProfileBinding(profile, policy, candidate) {
				t.Fatal("authority profile drift accepted")
			}
		})
	}
}
