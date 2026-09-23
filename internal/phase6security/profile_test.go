package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

func validProfile() Profile {
	digest := "sha256:" + strings.Repeat("a", 64)
	environmentDigest, principalProfileDigest := testDigest("environment"), testDigest("principal-profile")
	image := "registry.example.test/sandbox-runtime@" + digest
	names := make([]string, 0, len(requiredPrincipals)+1)
	for name := range requiredPrincipals {
		names = append(names, name)
	}
	names = append(names, "egress-broker-product", "egress-policy-authority-product")
	sort.Strings(names)
	registry, err := securityprincipal.NewRegistryWithPolicyAuthorities(environmentDigest, principalProfileDigest,
		map[string]securityprincipal.Role{"product_egress_broker": securityprincipal.RoleProduct},
		map[string]securityprincipal.Role{"product_policy_authority": ""})
	if err != nil {
		panic(err)
	}
	identities := make(map[string]securityprincipal.Principal, len(requiredAuthorizationBindings)+1)
	for deploymentName, binding := range requiredAuthorizationBindings {
		identity, principalErr := registry.New(binding.kind, binding.name, binding.role, testDigest("instance/"+deploymentName))
		if principalErr != nil {
			panic(principalErr)
		}
		identities[deploymentName] = identity
	}
	egressIdentity, err := registry.New(securityprincipal.KindEgressBroker, "product_egress_broker", securityprincipal.RoleProduct,
		testDigest("instance/egress-broker-product"))
	if err != nil {
		panic(err)
	}
	identities["egress-broker-product"] = egressIdentity
	authorityIdentity, err := registry.New(securityprincipal.KindController, "product_policy_authority", "",
		testDigest("instance/egress-policy-authority-product"))
	if err != nil {
		panic(err)
	}
	identities["egress-policy-authority-product"] = authorityIdentity
	principals := make([]Principal, 0, len(names))
	for index, name := range names {
		kind := requiredPrincipals[name]
		networks := []string{"network-" + name}
		external, blocked := false, true
		if name == "product-runtime" {
			networks = []string{"product-internal"}
		}
		if name == "egress-broker-product" {
			kind = "egress_broker"
			networks, external, blocked = []string{"external-uplink", "product-internal"}, true, false
		}
		if name == "egress-policy-authority-product" {
			kind = "controller"
		}
		principal := Principal{
			Name: name, Kind: kind, ImageReference: image, ImageDigest: digest,
			UID: uint32(20000 + index), GID: uint32(30000 + index),
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, DroppedCapabilities: []string{"ALL"}, SeccompDigest: testDigest("seccomp/" + name),
			Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 250, PIDs: 32}, Networks: networks,
			ExternalUplink: external, DirectEgressBlocked: blocked,
		}
		if name == "egress-broker-product" {
			principal.Mounts = []Mount{
				{Target: "/run/egress-authority", Kind: "private_socket", ReadOnly: true, StorageID: "product-authority-socket"},
			}
			principal.Listeners = []Listener{{Name: "egress", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}
		}
		if name == "egress-policy-authority-product" {
			principal.Mounts = []Mount{
				{Target: "/run/egress-authority", Kind: "private_socket", StorageID: "product-authority-socket"},
				{Target: "/var/lib/egress-authority", Kind: "persistent_ledger", MaxBytes: 1 << 20, StorageID: "product-authority-ledger"},
			}
		}
		if identity, ok := identities[name]; ok {
			principal.AuthorizationPrincipal = &identity
			principal.PrincipalDigest = identity.Digest()
			principal.TLS = &TLSIdentity{PrincipalDigest: identity.Digest(), TrustDomain: "sandbox-runtime.test",
				URI: "spiffe://sandbox-runtime.test/" + name, Usages: []string{"client_auth"}, TTLSeconds: 900,
				RotateAfterSeconds: 500, OverlapSeconds: 30, RevocationMaxStalenessSeconds: 30, ConnectionDrainSeconds: 10}
		} else {
			controller := requiredResourceControllers[name]
			principal.ControllingPrincipalDigest = identities[controller].Digest()
		}
		principals = append(principals, principal)
	}
	networks := make([]Network, 0, len(principals)+1)
	for _, principal := range principals {
		if principal.Name == "egress-broker-product" || principal.Name == "product-runtime" {
			continue
		}
		networks = append(networks, Network{Name: principal.Networks[0], Kind: "role_internal", Internal: true,
			GatewayModeIPv4: "isolated", Principals: []string{principal.Name}})
	}
	networks = append(networks,
		Network{Name: "external-uplink", Kind: "external_uplink", GatewayModeIPv4: "nat", Principals: []string{"egress-broker-product"}},
		Network{Name: "product-internal", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated", Principals: []string{"egress-broker-product", "product-runtime"}},
	)
	sort.Slice(networks, func(first, second int) bool { return networks[first].Name < networks[second].Name })
	uri := func(name string) string {
		for _, principal := range principals {
			if principal.Name == name {
				return principal.TLS.URI
			}
		}
		return ""
	}
	external := []ExternalService{
		{Name: "dns", ImageReference: "registry.example.test/dns@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/dns", DNSNames: []string{"dns.sandbox-runtime.test"}, IngressEdges: []string{"egress-dns"}},
		{Name: "postgres", ImageReference: "registry.example.test/postgres@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/postgres", DNSNames: []string{"postgres.sandbox-runtime.test"}, IngressEdges: []string{"product-postgres"}},
		{Name: "vault", ImageReference: "registry.example.test/vault@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/vault", DNSNames: []string{"vault.sandbox-runtime.test"}, IngressEdges: []string{"certificate-vault"}},
	}
	for index := range external {
		external[index].IdentityDigest = external[index].Digest()
	}
	edges := []TrustEdge{
		{ID: "certificate-vault", From: "certificate-controller", To: "vault", Protocol: "https", Port: 8200, Authentication: "mtls", FromURI: uri("certificate-controller"), ToURI: external[2].URI,
			FromPrincipalDigest: identities["certificate-controller"].Digest(), ExternalIdentityDigest: external[2].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 60},
		{ID: "egress-authority-product", From: "egress-broker-product", To: "egress-policy-authority-product", Protocol: "unix", Authentication: "unix_peer_credentials",
			FromURI: uri("egress-broker-product"), ToURI: uri("egress-policy-authority-product"),
			FromPrincipalDigest: identities["egress-broker-product"].Digest(), ToPrincipalDigest: identities["egress-policy-authority-product"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 5},
		{ID: "egress-dns", From: "egress-broker-product", To: "dns", Protocol: "dns_tcp", Port: 853, Authentication: "mtls", FromURI: uri("egress-broker-product"), ToURI: external[0].URI,
			FromPrincipalDigest: identities["egress-broker-product"].Digest(), ExternalIdentityDigest: external[0].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 30},
		{ID: "product-postgres", From: "product-runtime", To: "postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", FromURI: uri("product-runtime"), ToURI: external[1].URI,
			FromPrincipalDigest: identities["product-runtime"].Digest(), ExternalIdentityDigest: external[1].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
	}
	profile := Profile{Protocol: ProtocolID, Version: Version, Revision: "slice6-security-1", EnvironmentDigest: environmentDigest,
		PrincipalProfileDigest: principalProfileDigest, Principals: principals, Networks: networks, External: external, TrustEdges: edges,
		EgressPolicies: []EgressPolicy{{ID: "product-egress", Revision: "policy-1", Principal: "product-runtime", Broker: "egress-broker-product",
			PrincipalDigest: identities["product-runtime"].Digest(), BrokerDigest: identities["egress-broker-product"].Digest(),
			Authority: PolicyAuthority{DeploymentName: "egress-policy-authority-product", AuthorizationName: "product_policy_authority",
				PrincipalDigest: identities["egress-policy-authority-product"].Digest(), KeyID: "operator-product-1",
				PublicKeyDigest: testDigest("operator-public-key"), SocketDirectory: "/run/egress-authority", SocketStorageID: "product-authority-socket",
				LedgerMountTarget: "/var/lib/egress-authority", LedgerStorageID: "product-authority-ledger", PollMillis: 500,
				CurrentTimeoutMS: 1000, StateMaxAgeSeconds: 5},
			LeaseSeconds: 60, DNSMaxAnswers: 8,
			DenyRawIP: true, DenyAlternateDNS: true, DenyProxyEnvironment: true, DenyRedirectAuthority: true, DenyMetadataPrivateRanges: true,
			Targets: []EgressTarget{{Alias: "example-api", Host: "api.example.test", Port: 443, Protocol: "https"}}}},
		CleanupClasses: []string{"connections", "containers", "files", "networks", "processes", "sockets"}}
	profile.ProfileDigest = profile.Digest()
	return profile
}

func testDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
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

func TestEgressPolicyDigestBindsTargetAndPrincipals(t *testing.T) {
	policy := validProfile().EgressPolicies[0]
	original := policy.Digest()
	if !digestPattern.MatchString(original) {
		t.Fatal("egress policy digest is not canonical")
	}
	changed := policy
	changed.Targets = append([]EgressTarget(nil), policy.Targets...)
	changed.Targets[0].Host = "other.example.test"
	if changed.Digest() == original {
		t.Fatal("target substitution retained policy digest")
	}
	changed = policy
	changed.PrincipalDigest = testDigest("other-principal")
	if changed.Digest() == original {
		t.Fatal("principal substitution retained policy digest")
	}
	changed = policy
	changed.Authority.PublicKeyDigest = testDigest("other-key")
	if changed.Digest() == original {
		t.Fatal("authority key substitution retained policy digest")
	}
}

func TestProfileRejectsAuthorityAndEnforcementDrift(t *testing.T) {
	tests := map[string]func(*Profile){
		"missing principal": func(p *Profile) { p.Principals = p.Principals[1:] },
		"shared uid":        func(p *Profile) { p.Principals[1].UID = p.Principals[0].UID },
		"shared seccomp":    func(p *Profile) { p.Principals[1].SeccompDigest = p.Principals[0].SeccompDigest },
		"mutable image":     func(p *Profile) { p.Principals[0].ImageReference = "registry.example.test/app:latest" },
		"wildcard SAN":      func(p *Profile) { p.Principals[0].TLS.DNSNames = []string{"*.example.test"} },
		"late rotation":     func(p *Profile) { p.Principals[0].TLS.RotateAfterSeconds = 700 },
		"direct egress":     func(p *Profile) { p.Principals[0].DirectEgressBlocked = false },
		"shared broker": func(p *Profile) {
			copy := p.EgressPolicies[0]
			copy.ID, copy.Principal = "provider-egress", "provider-runtime"
			p.EgressPolicies = append(p.EgressPolicies, copy)
		},
		"authority omitted":           func(p *Profile) { p.EgressPolicies[0].Authority = PolicyAuthority{} },
		"authority principal swapped": func(p *Profile) { p.EgressPolicies[0].Authority.PrincipalDigest = testDigest("other-authority") },
		"authority key omitted":       func(p *Profile) { p.EgressPolicies[0].Authority.PublicKeyDigest = "" },
		"authority too slow":          func(p *Profile) { p.EgressPolicies[0].Authority.CurrentTimeoutMS = 2000 },
		"authority stale budget":      func(p *Profile) { p.EgressPolicies[0].Authority.StateMaxAgeSeconds = 31 },
		"authority socket exchanged":  func(p *Profile) { p.EgressPolicies[0].Authority.SocketStorageID = "other-socket" },
		"authority ledger exchanged":  func(p *Profile) { p.EgressPolicies[0].Authority.LedgerStorageID = "other-ledger" },
		"broker extra listener": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "egress-broker-product" {
					p.Principals[index].Listeners = append(p.Principals[index].Listeners,
						Listener{Name: "extra", Protocol: "tcp", Port: 9443, Exposure: "public"})
				}
			}
		},
		"authority socket made public": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "egress-broker-product" {
					p.Principals[index].Mounts[0].ReadOnly = false
				}
			}
		},
		"authority ledger shared": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "product-runtime" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts,
						Mount{Target: "/var/lib/egress-authority", Kind: "persistent_ledger", MaxBytes: 1 << 20, StorageID: "product-authority-ledger"})
				}
			}
		},
		"missing authority Unix edge": func(p *Profile) { p.TrustEdges = append(p.TrustEdges[:1], p.TrustEdges[2:]...) },
		"wrong edge identity":         func(p *Profile) { p.TrustEdges[0].FromURI = p.TrustEdges[1].FromURI },
		"missing metadata denial":     func(p *Profile) { p.EgressPolicies[0].DenyMetadataPrivateRanges = false },
		"extra cleanup class":         func(p *Profile) { p.CleanupClasses = append(p.CleanupClasses, "other") },
		"principal digest tamper":     func(p *Profile) { p.Principals[0].PrincipalDigest = testDigest("tampered") },
		"TLS digest tamper":           func(p *Profile) { p.Principals[0].TLS.PrincipalDigest = testDigest("tampered") },
		"edge digest tamper":          func(p *Profile) { p.TrustEdges[0].FromPrincipalDigest = testDigest("tampered") },
		"external digest tamper":      func(p *Profile) { p.External[0].IdentityDigest = testDigest("tampered") },
		"external DNS omitted":        func(p *Profile) { p.External[0].DNSNames = nil },
		"cross environment splice": func(p *Profile) {
			p.EnvironmentDigest = testDigest("other-environment")
		},
		"external uplink on role": func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "external-uplink" {
					p.Networks[index].Principals = append(p.Networks[index].Principals, "product-runtime")
				}
			}
		},
		"ordinary internal gateway": func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Kind == "role_internal" {
					p.Networks[index].GatewayModeIPv4 = "nat"
					break
				}
			}
		},
		"IPv6 unproven": func(p *Profile) { p.Networks[0].IPv6Enabled = true },
		"network membership drift": func(p *Profile) {
			for index := range p.Networks {
				if p.Networks[index].Name == "product-internal" {
					p.Networks[index].Principals = []string{"egress-broker-product"}
				}
			}
		},
		"dangling resource controller": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "desktop-broker" {
					p.Principals[index].ControllingPrincipalDigest = testDigest("missing-controller")
				}
			}
		},
		"resource impersonates principal": func(p *Profile) {
			var source *Principal
			for index := range p.Principals {
				if p.Principals[index].Name == "desktop-executor-backend" {
					source = &p.Principals[index]
				}
			}
			for index := range p.Principals {
				if p.Principals[index].Name == "desktop-broker" {
					identity := *source.AuthorizationPrincipal
					p.Principals[index].AuthorizationPrincipal = &identity
					p.Principals[index].PrincipalDigest = identity.Digest()
					p.Principals[index].ControllingPrincipalDigest = ""
					tlsIdentity := *source.TLS
					p.Principals[index].TLS = &tlsIdentity
				}
			}
		},
		"wrong broker principal kind": func(p *Profile) {
			var runtime Principal
			for _, principal := range p.Principals {
				if principal.Name == "product-runtime" {
					runtime = principal
				}
			}
			for index := range p.Principals {
				if p.Principals[index].Name == "egress-broker-product" {
					identity := *runtime.AuthorizationPrincipal
					p.Principals[index].AuthorizationPrincipal = &identity
					p.Principals[index].PrincipalDigest = identity.Digest()
					p.Principals[index].TLS.PrincipalDigest = identity.Digest()
				}
			}
		},
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

func TestDeploymentRenameDoesNotChangeAuthorizationIdentity(t *testing.T) {
	profile := validProfile()
	for index := range profile.Principals {
		if profile.Principals[index].Name == "egress-broker-product" {
			profile.Principals[index].Name = "product-egress-service"
		}
	}
	for index := range profile.EgressPolicies {
		profile.EgressPolicies[index].Broker = "product-egress-service"
	}
	for index := range profile.TrustEdges {
		if profile.TrustEdges[index].From == "egress-broker-product" {
			profile.TrustEdges[index].From = "product-egress-service"
		}
	}
	for networkIndex := range profile.Networks {
		for principalIndex := range profile.Networks[networkIndex].Principals {
			if profile.Networks[networkIndex].Principals[principalIndex] == "egress-broker-product" {
				profile.Networks[networkIndex].Principals[principalIndex] = "product-egress-service"
			}
		}
		sort.Strings(profile.Networks[networkIndex].Principals)
	}
	sort.Slice(profile.Principals, func(first, second int) bool { return profile.Principals[first].Name < profile.Principals[second].Name })
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("deployment-only rename changed authorization: %v", err)
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
