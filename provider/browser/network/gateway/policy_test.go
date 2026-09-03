package gateway

import (
	"errors"
	"net/netip"
	"testing"
)

func TestNormalizePolicyAndDigest(t *testing.T) {
	policy, err := NormalizePolicy(Policy{
		Reference:    "browser-egress-policy-1",
		AllowedHosts: []string{" API.Example.COM ", "*.assets.example.com", "api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.AllowedHosts) != 2 || policy.AllowedHosts[0] != "*.assets.example.com" || policy.AllowedHosts[1] != "api.example.com" {
		t.Fatalf("normalized hosts = %#v", policy.AllowedHosts)
	}
	digest, err := policy.Digest()
	if err != nil || digest != "sha256:bab18199962c75efe15bdb7277cc65750215cdd2dbb80730b13f0fa084025486" {
		t.Fatalf("digest = %q, %v", digest, err)
	}
	for host, allowed := range map[string]bool{
		"api.example.com": true, "API.EXAMPLE.COM.": true,
		"one.assets.example.com": true, "deep.one.assets.example.com": true,
		"assets.example.com": false, "badexample.com": false,
		"127.0.0.1": false, "user@api.example.com": false, "api.example.com:80": false,
	} {
		if got := policy.Allows(host); got != allowed {
			t.Errorf("Allows(%q) = %t, want %t", host, got, allowed)
		}
	}
}

func TestPolicyAndConfigRejectMalformedInput(t *testing.T) {
	invalidHosts := []string{"*", "*.com", "example", "-bad.example", "bad-.example", "bad..example", "127.0.0.1", "example.com:443", "user@example.com", "[::1]"}
	for _, host := range invalidHosts {
		if _, err := NormalizePolicy(Policy{Reference: "policy-1", AllowedHosts: []string{host}}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("host %q error = %v", host, err)
		}
	}
	valid := Config{GatewayAddress: "10.88.0.2", Policy: Policy{Reference: "policy-1", AllowedHosts: []string{"example.com"}}}
	encoded, err := EncodeConfig(valid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConfig(encoded)
	if err != nil || decoded.GatewayAddress != valid.GatewayAddress {
		t.Fatalf("decoded = %#v, %v", decoded, err)
	}
	for _, value := range []string{"", encoded + `{}`, encoded + ` trailing`, `{"gateway_address":"8.8.8.8","policy":{"reference":"policy-1","allowed_hosts":["example.com"]}}`, `{"gateway_address":"10.0.0.2","unknown":true,"policy":{"reference":"policy-1","allowed_hosts":["example.com"]}}`} {
		if _, err := DecodeConfig(value); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("DecodeConfig(%q) error = %v", value, err)
		}
	}
}

func TestPublicUpstreamAddress(t *testing.T) {
	for _, value := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !PublicUpstreamAddress(netip.MustParseAddr(value)) {
			t.Errorf("public address %s rejected", value)
		}
	}
	for _, value := range []string{
		"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1",
		"203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:8.8.8.8",
		"64:ff9b::808:808", "100::1", "2001:db8::1", "2002:0808:0808::1", "fc00::1", "fe80::1", "ff02::1",
	} {
		if PublicUpstreamAddress(netip.MustParseAddr(value)) {
			t.Errorf("unsafe address %s accepted", value)
		}
	}
}
