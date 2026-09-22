package phase6security

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func validProfile() Profile {
	digest := "sha256:" + strings.Repeat("a", 64)
	image := "registry.example.test/sandbox-runtime@" + digest
	names := make([]string, 0, len(requiredPrincipals)+1)
	for name := range requiredPrincipals {
		names = append(names, name)
	}
	names = append(names, "egress-broker-product")
	sort.Strings(names)
	principals := make([]Principal, 0, len(names))
	for index, name := range names {
		kind := requiredPrincipals[name]
		networks := []string{"role-internal"}
		external, blocked := false, true
		if name == "egress-broker-product" {
			kind = "egress_broker"
			networks, external, blocked = []string{"external-uplink", "product-internal"}, true, false
		}
		principals = append(principals, Principal{
			Name: name, Kind: kind, ImageReference: image, ImageDigest: digest,
			UID: uint32(20000 + index), GID: uint32(30000 + index),
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, DroppedCapabilities: []string{"ALL"}, SeccompDigest: digest,
			Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 250, PIDs: 32}, Networks: networks,
			ExternalUplink: external, DirectEgressBlocked: blocked,
			TLS: TLSIdentity{TrustDomain: "sandbox-runtime.test", URI: "spiffe://sandbox-runtime.test/" + name,
				Usages: []string{"client_auth"}, TTLSeconds: 900, RotateAfterSeconds: 500, OverlapSeconds: 30,
				RevocationMaxStalenessSeconds: 30, ConnectionDrainSeconds: 10},
		})
	}
	uri := func(name string) string {
		for _, principal := range principals {
			if principal.Name == name {
				return principal.TLS.URI
			}
		}
		return ""
	}
	external := []ExternalService{
		{Name: "dns", ImageReference: "registry.example.test/dns@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/dns", IngressEdges: []string{"egress-dns"}},
		{Name: "postgres", ImageReference: "registry.example.test/postgres@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/postgres", IngressEdges: []string{"product-postgres"}},
		{Name: "vault", ImageReference: "registry.example.test/vault@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/vault", IngressEdges: []string{"certificate-vault"}},
	}
	edges := []TrustEdge{
		{ID: "certificate-vault", From: "certificate-controller", To: "vault", Protocol: "https", Port: 8200, Authentication: "mtls", FromURI: uri("certificate-controller"), ToURI: external[2].URI, TenantScope: "system", MaxConnectionSeconds: 60},
		{ID: "egress-dns", From: "egress-broker-product", To: "dns", Protocol: "dns_tcp", Port: 853, Authentication: "mtls", FromURI: uri("egress-broker-product"), ToURI: external[0].URI, TenantScope: "system", MaxConnectionSeconds: 30},
		{ID: "product-postgres", From: "product-runtime", To: "postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", FromURI: uri("product-runtime"), ToURI: external[1].URI, TenantScope: "bound", MaxConnectionSeconds: 300},
	}
	profile := Profile{Protocol: ProtocolID, Version: Version, Revision: "slice6-security-1", Principals: principals, External: external, TrustEdges: edges,
		EgressPolicies: []EgressPolicy{{ID: "product-egress", Revision: "policy-1", Principal: "product-runtime", Broker: "egress-broker-product", LeaseSeconds: 60, DNSMaxAnswers: 8,
			DenyRawIP: true, DenyAlternateDNS: true, DenyProxyEnvironment: true, DenyRedirectAuthority: true, DenyMetadataPrivateRanges: true,
			Targets: []EgressTarget{{Alias: "example-api", Host: "api.example.test", Port: 443, Protocol: "https"}}}},
		CleanupClasses: []string{"connections", "containers", "files", "networks", "processes", "sockets"}}
	profile.ProfileDigest = profile.Digest()
	return profile
}

func TestProfileAcceptsClosedCompleteInventory(t *testing.T) {
	profile := validProfile()
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(document)
	if err != nil || decoded.ProfileDigest != profile.ProfileDigest {
		t.Fatalf("Decode() = %#v, %v", decoded, err)
	}
}

func TestProfileRejectsAuthorityAndEnforcementDrift(t *testing.T) {
	tests := map[string]func(*Profile){
		"missing principal": func(p *Profile) { p.Principals = p.Principals[1:] },
		"shared uid":        func(p *Profile) { p.Principals[1].UID = p.Principals[0].UID },
		"mutable image":     func(p *Profile) { p.Principals[0].ImageReference = "registry.example.test/app:latest" },
		"wildcard SAN":      func(p *Profile) { p.Principals[0].TLS.DNSNames = []string{"*.example.test"} },
		"late rotation":     func(p *Profile) { p.Principals[0].TLS.RotateAfterSeconds = 700 },
		"direct egress":     func(p *Profile) { p.Principals[0].DirectEgressBlocked = false },
		"shared broker": func(p *Profile) {
			copy := p.EgressPolicies[0]
			copy.ID, copy.Principal = "provider-egress", "provider-runtime"
			p.EgressPolicies = append(p.EgressPolicies, copy)
		},
		"wrong edge identity":     func(p *Profile) { p.TrustEdges[0].FromURI = p.TrustEdges[1].FromURI },
		"missing metadata denial": func(p *Profile) { p.EgressPolicies[0].DenyMetadataPrivateRanges = false },
		"extra cleanup class":     func(p *Profile) { p.CleanupClasses = append(p.CleanupClasses, "other") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("drift was accepted")
			}
		})
	}
}

func TestDecodeRejectsUnknownDuplicateAndNonCanonicalJSON(t *testing.T) {
	profile := validProfile()
	document, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(`{"unknown":true,`), document[1:]...)
	duplicate := append([]byte(`{"protocol":"sandbox-runtime.phase6-security-profile.v1",`), document[1:]...)
	for name, candidate := range map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "trailing whitespace": append(document, '\n'),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(candidate); !errorsIsInvalid(err) {
				t.Fatalf("Decode() error = %v", err)
			}
		})
	}
}

func TestVerifyFileRequiresPrivateCanonicalProfile(t *testing.T) {
	profile := validProfile()
	document, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(t.TempDir(), "security-profile.json")
	if err := os.WriteFile(filePath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(filePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(filePath); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("public profile mode error = %v", err)
	}
}

func errorsIsInvalid(err error) bool { return errors.Is(err, ErrInvalidProfile) }
