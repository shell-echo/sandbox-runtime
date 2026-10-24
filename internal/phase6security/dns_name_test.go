package phase6security

import (
	"math/rand/v2"
	"net"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The oracle freezes the original policy independently of the production scan.
var originalDNSHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func originalDNSName(value string) bool {
	return len(value) <= 253 && value == strings.ToLower(value) && originalDNSHostPattern.MatchString(value) &&
		!strings.Contains(value, "..") && net.ParseIP(value) == nil
}

func TestDNSNamePolicyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"empty", "", false}, {"single_letter", "a", true}, {"single_digit", "0", true},
		{"two", "a0", true}, {"domain", "sandbox-runtime.test", true},
		{"length_252", strings.Repeat("a", 252), true}, {"length_253", strings.Repeat("a", 253), true},
		{"length_254", strings.Repeat("a", 254), false}, {"long_label", strings.Repeat("a", 64) + ".test", true},
		{"dot_then_hyphen", "a.-b", true}, {"hyphen_then_dot", "a-.b", true},
		{"repeated_hyphens", "a--b", true}, {"punycode", "xn--p1ai.test", true},
		{"leading_dot", ".a", false}, {"trailing_dot", "a.", false},
		{"leading_hyphen", "-a", false}, {"trailing_hyphen", "a-", false},
		{"double_dot", "a..b", false}, {"uppercase", "A.test", false},
		{"unicode", "中文.test", false}, {"unicode_casefold", "K.test", false},
		{"invalid_utf8", "a\xffb", false}, {"nul", "a\x00b", false}, {"newline", "a\nb", false},
		{"wildcard", "*.test", false}, {"underscore", "a_b", false},
		{"port", "a:443", false}, {"path", "a/b", false}, {"space", "a b", false},
		{"ipv4", "127.0.0.1", false}, {"ipv6", "::1", false},
		{"bracketed_ipv6", "[::1]", false}, {"ipv4_mapped_ipv6", "::ffff:127.0.0.1", false},
		{"leading_zero_octet", "127.000.0.1", true}, {"short_numeric_name", "127.1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if originalDNSName(tc.value) != tc.want || validDNSName(tc.value) != tc.want {
				t.Fatalf("DNS policy changed for %q", tc.value)
			}
		})
	}
}

func TestDNSNameMatchesOriginalPolicy(t *testing.T) {
	check := func(value string) {
		t.Helper()
		if validDNSName(value) != originalDNSName(value) {
			t.Fatalf("DNS policy differs from original for %q", value)
		}
	}
	for n := 0; n < 256; n++ {
		check(string([]byte{byte(n)}))
		check("a" + string([]byte{byte(n)}) + "z")
	}
	// Exhaust all short strings over representatives of each lexical class.
	alphabet := []byte{'a', '0', '-', '.', 'A', 'Z', '_', 0}
	var visit func([]byte)
	visit = func(value []byte) {
		check(string(value))
		if len(value) == 4 {
			return
		}
		for _, c := range alphabet {
			visit(append(value, c))
		}
	}
	visit(nil)
	rng := rand.New(rand.NewPCG(0x12345678, 0xabcdef01))
	for n := 0; n < 2048; n++ {
		value := make([]byte, rng.IntN(261))
		for i := range value {
			if n%2 == 0 {
				value[i] = byte(rng.IntN(256))
			} else {
				value[i] = "abcdefghijklmnopqrstuvwxyz0123456789.-"[rng.IntN(38)]
			}
		}
		check(string(value))
	}
}

func TestDNSPolicyConsumersRejectInvalidNames(t *testing.T) {
	p := validProfile()
	principals := make(map[string]Principal, len(p.Principals))
	for _, v := range p.Principals {
		principals[v.Name] = v
	}
	external, err := validateExternal(p.External)
	if err != nil {
		t.Fatal(err)
	}
	edges, err := validateEdges(p.TrustEdges, principals, external)
	if err != nil || validateEgress(p.EgressPolicies, principals, edges) != nil {
		t.Fatal("invalid egress fixture")
	}
	baseTLS := *principals["product-runtime"].TLS
	if validateTLS(baseTLS) != nil {
		t.Fatal("invalid TLS fixture")
	}
	for _, consumer := range []string{"tls_trust_domain", "tls_san", "external_san", "egress_target"} {
		t.Run(consumer, func(t *testing.T) {
			for _, tc := range []struct{ name, value string }{
				{"uppercase", "A.test"}, {"unicode", "中文.test"}, {"wildcard", "*.test"},
				{"ip", "127.0.0.1"}, {"double_dot", "a..b"}, {"nul", "a\x00b"}, {"oversized", strings.Repeat("a", 254)},
			} {
				t.Run(tc.name, func(t *testing.T) {
					var got error
					switch consumer {
					case "tls_trust_domain":
						v := baseTLS
						v.TrustDomain, v.URI = tc.value, "spiffe://"+tc.value+"/role"
						got = validateTLS(v)
					case "tls_san":
						v := baseTLS
						v.DNSNames = []string{tc.value}
						got = validateTLS(v)
					case "external_san":
						values := slices.Clone(p.External)
						values[0].DNSNames = []string{tc.value}
						values[0].IdentityDigest = values[0].Digest()
						_, got = validateExternal(values)
					case "egress_target":
						values := slices.Clone(p.EgressPolicies)
						values[0].Targets = slices.Clone(values[0].Targets)
						values[0].Targets[0].Host = tc.value
						got = validateEgress(values, principals, edges)
					}
					if got != ErrInvalidProfile {
						t.Fatal("consumer accepted an invalid DNS name")
					}
				})
			}
		})
	}
}
