package phase6security

import (
	"encoding/json"
	"net/netip"
	"sort"
	"testing"
)

func vaultServiceBridgeProfile(t *testing.T) Profile {
	t.Helper()
	profile := validProfile()
	for index := range profile.Networks {
		if profile.Networks[index].Name == "network-certificate-controller" {
			profile.Networks[index].ExternalServices = []string{"vault"}
		}
	}
	for index := range profile.External {
		if profile.External[index].Name == "vault" {
			profile.External[index].Networks = []string{"network-certificate-controller"}
			profile.External[index].IdentityDigest = profile.External[index].Digest()
			for edgeIndex := range profile.TrustEdges {
				if profile.TrustEdges[edgeIndex].ID == "certificate-vault" {
					profile.TrustEdges[edgeIndex].ExternalIdentityDigest = profile.External[index].IdentityDigest
				}
			}
		}
	}
	profile.ProfileDigest = profile.Digest()
	return profile
}

func TestExternalServiceBridgeRequiresBidirectionalIsolatedMembership(t *testing.T) {
	profile := vaultServiceBridgeProfile(t)
	if err := profile.Validate(); err != nil {
		t.Fatalf("dedicated isolated Vault bridge rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Profile)
	}{
		{"service omits bridge", func(p *Profile) { p.External[4].Networks = nil }},
		{"network omits service", func(p *Profile) { p.Networks[networkIndex(p, "network-certificate-controller")].ExternalServices = nil }},
		{"two services share bridge", func(p *Profile) {
			p.Networks[networkIndex(p, "network-certificate-controller")].ExternalServices = []string{"postgres", "vault"}
		}},
		{"two roles share service bridge", func(p *Profile) {
			p.Networks[networkIndex(p, "network-certificate-controller")].Principals = []string{"certificate-controller", "product-runtime"}
		}},
		{"external service joins NAT", func(p *Profile) { p.External[4].Networks = []string{"external-uplink"} }},
		{"external service joins unknown network", func(p *Profile) { p.External[4].Networks = []string{"unknown-network"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := vaultServiceBridgeProfile(t)
			test.mutate(&changed)
			changed.ProfileDigest = changed.Digest()
			if err := changed.Validate(); err == nil {
				t.Fatal("unsafe external-service network membership admitted")
			}
		})
	}
}

func networkIndex(profile *Profile, name string) int {
	for index := range profile.Networks {
		if profile.Networks[index].Name == name {
			return index
		}
	}
	return -1
}

func TestExternalServiceBridgeBindsRawInspectAndEvidenceEndpoint(t *testing.T) {
	profile := vaultServiceBridgeProfile(t)
	observations := validObservations(profile)
	index := networkIndex(&profile, "network-certificate-controller")
	expected := profile.Networks[index]
	externalID := testDigest("external-container/vault")[7:]
	roleID := testDigest("container/certificate-controller")[7:]
	externalAddress := netip.MustParsePrefix(expected.IPv4Subnet).Addr().Next().Next().Next().String()
	network := &observations.Networks[index]
	network.ContainerIDs = append(network.ContainerIDs, externalID)
	sort.Strings(network.ContainerIDs)
	network.Endpoints = append(network.Endpoints, NetworkEndpointObservation{ContainerID: externalID, IPv4Address: externalAddress})
	sort.Slice(network.Endpoints, func(i, j int) bool { return network.Endpoints[i].ContainerID < network.Endpoints[j].ContainerID })
	externalIDs := map[string]string{"vault": externalID}
	if err := ValidateObservationsWithExternal(profile, observations, externalIDs); err != nil {
		t.Fatalf("external endpoint observation rejected: %v", err)
	}
	if err := ValidateObservations(profile, observations); err == nil {
		t.Fatal("role-only validation admitted external network without service identity")
	}
	document, err := json.Marshal(observations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeObservationsWithExternal(document, profile, externalIDs); err != nil {
		t.Fatalf("canonical external observation rejected: %v", err)
	}
	if _, err := DecodeObservations(document, profile); err == nil {
		t.Fatal("role-only decoder admitted external network")
	}

	roleAddress := netip.MustParsePrefix(expected.IPv4Subnet).Addr().Next().Next().String()
	raw, err := json.Marshal([]any{map[string]any{
		"Name": expected.Name, "Id": testDigest("network/" + expected.Name)[7:], "Driver": "bridge",
		"Scope": "local", "Internal": true, "Attachable": false, "Ingress": false,
		"EnableIPv4": true, "EnableIPv6": false,
		"Options": map[string]string{"com.docker.network.bridge.gateway_mode_ipv4": "isolated",
			"com.docker.network.enable_ipv4": "true", "com.docker.network.enable_ipv6": "false"},
		"IPAM": map[string]any{"Config": []map[string]string{{"Subnet": expected.IPv4Subnet, "Gateway": ""}}},
		"Containers": map[string]any{roleID: map[string]string{"IPv4Address": roleAddress + "/24"},
			externalID: map[string]string{"IPv4Address": externalAddress + "/24"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ObserveDockerNetworkWithExternal(raw, expected,
		map[string]string{"certificate-controller": roleID}, externalIDs); err != nil {
		t.Fatalf("raw service-bridge inspect rejected: %v", err)
	}
	if _, err := ObserveDockerNetwork(raw, expected, map[string]string{"certificate-controller": roleID}); err == nil {
		t.Fatal("raw inspector omitted external service member")
	}
	wrong := map[string]string{"vault": testDigest("wrong-vault")[7:]}
	if ValidateObservationsWithExternal(profile, observations, wrong) == nil {
		t.Fatal("substituted external container admitted")
	}
	if ValidateObservationsWithExternal(profile, observations,
		map[string]string{"vault": externalID, "unknown-service": testDigest("unknown-service")[7:]}) == nil {
		t.Fatal("unregistered external container admitted")
	}
	if ValidateObservationsWithExternal(profile, observations,
		map[string]string{"vault": externalID, "postgres": externalID}) == nil {
		t.Fatal("two external services sharing one container ID admitted")
	}
	if _, err := ObserveDockerNetworkWithExternal(raw, expected,
		map[string]string{"certificate-controller": roleID}, wrong); err == nil {
		t.Fatal("raw inspector accepted substituted external container")
	}
}
