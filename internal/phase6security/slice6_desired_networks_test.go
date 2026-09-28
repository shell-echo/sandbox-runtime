package phase6security

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestSlice6ReviewedNetworkGraphMatchesClosedProfileShape(t *testing.T) {
	fixture := validProfile()
	if len(slice6ApprovedDeploymentKinds) != 82 || len(slice6ApprovedTLSAgentSubjects) != 38 ||
		len(slice6DesiredTrustEdges()) != 117 {
		t.Fatal("reviewed Slice 6 principal, key-owner or trust-edge count drifted")
	}
	if err := VerifySlice6DesiredPrincipalIDs(fixture); err != nil {
		t.Fatalf("reviewed UID/GID partitions and closed profile fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredNetworkGraph(fixture); err != nil {
		t.Fatalf("reviewed graph and closed profile fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredNetworks(fixture); err == nil {
		t.Fatal("synthetic fixture CIDRs were admitted as the real desired plan")
	}
	planned := Slice6DesiredNetworks()
	if len(planned) != len(fixture.Networks) || len(planned) < 30 {
		t.Fatal("desired network inventory is incomplete")
	}
	for index, network := range planned {
		if network.Name != fixture.Networks[index].Name || network.Kind != fixture.Networks[index].Kind ||
			!slices.Equal(network.Principals, fixture.Networks[index].Principals) {
			t.Fatalf("network %d differs from frozen routing shape", index)
		}
	}
	broadened := fixture
	broadened.Networks = append([]Network(nil), fixture.Networks...)
	for index := range broadened.Networks {
		if broadened.Networks[index].Name == "product-internal" {
			broadened.Networks[index].Kind = "trust_edge"
			break
		}
	}
	broadened.ProfileDigest = broadened.Digest()
	if err := VerifySlice6DesiredNetworkGraph(broadened); err == nil {
		t.Fatal("self-consistent broadened network kind was admitted")
	}
	if err := VerifySlice6DesiredNetworkGraph(Profile{}); err == nil {
		t.Fatal("missing profile was admitted")
	}
	changedID := fixture
	changedID.Principals = append([]Principal(nil), fixture.Principals...)
	changedID.Principals[0].UID = 25000
	changedID.ProfileDigest = changedID.Digest()
	if err := VerifySlice6DesiredPrincipalIDs(changedID); err == nil {
		t.Fatal("changed expected container UID was admitted")
	}
}

func TestSlice6DesiredEndpointPlanIsIndependentOfObservedAddress(t *testing.T) {
	var edge Network
	for _, network := range Slice6DesiredNetworks() {
		if network.Name == "guest-product" {
			edge = network
		}
	}
	if edge.Name == "" || !slices.Equal(edge.Principals, []string{"guest-runtime", "product-runtime"}) {
		t.Fatal("reviewed Guest/Product edge is absent")
	}
	guestAddress, err := Slice6DesiredEndpointAddress(edge.Name, "guest-runtime")
	if err != nil {
		t.Fatal(err)
	}
	productAddress, err := Slice6DesiredEndpointAddress(edge.Name, "product-runtime")
	if err != nil || guestAddress == productAddress {
		t.Fatal("reviewed Guest/Product endpoint allocation is invalid")
	}
	guestID, productID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	observed := NetworkObservation{Name: edge.Name, Endpoints: []NetworkEndpointObservation{
		{ContainerID: guestID, IPv4Address: guestAddress},
		{ContainerID: productID, IPv4Address: productAddress},
	}}
	actualIDs := map[string]string{"guest-runtime": guestID, "product-runtime": productID}
	if err := VerifySlice6DesiredEndpointObservation(edge, observed, actualIDs); err != nil {
		t.Fatalf("exact endpoint projection rejected: %v", err)
	}
	observed.Endpoints[1].IPv4Address = guestAddress
	if err := VerifySlice6DesiredEndpointObservation(edge, observed, actualIDs); err == nil {
		t.Fatal("post hoc observed endpoint substitution was admitted")
	}
	if _, err := Slice6DesiredEndpointAddress(edge.Name, "undeclared-role"); err == nil {
		t.Fatal("undeclared deployment received an endpoint")
	}
}

func TestSlice6DraftNetworkBindingRecomputesCanonicalAddresses(t *testing.T) {
	draft := validProfile()
	if err := VerifySlice6DesiredTrustEdges(draft); err != nil {
		t.Fatalf("reviewed trust graph and closed fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredExternalServices(draft); err != nil {
		t.Fatalf("reviewed external services and closed fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredEgressPolicies(draft); err != nil {
		t.Fatalf("reviewed egress policies and closed fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredTrustAnchors(draft); err != nil {
		t.Fatalf("reviewed trust anchors and closed fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredTLSIdentities(draft); err != nil {
		t.Fatalf("reviewed TLS identities and closed fixture diverged: %v", err)
	}
	if err := VerifySlice6DesiredIngressPolicy(draft); err != nil {
		t.Fatalf("reviewed ingress policy and closed fixture diverged: %v", err)
	}
	originalNetwork := draft.Networks[0].IPv4Subnet
	bound, err := BindSlice6DesiredNetworkPlan(draft)
	if err != nil {
		t.Fatalf("valid closed draft could not bind reviewed network plan: %v", err)
	}
	if err := VerifySlice6DesiredNetworks(bound); err != nil || VerifySlice6DesiredIngress(bound) != nil ||
		VerifySlice6DesiredEdgeAddresses(bound) != nil ||
		bound.ProfileDigest != bound.Digest() ||
		draft.Networks[0].IPv4Subnet != originalNetwork || draft.ProfileDigest != draft.Digest() {
		t.Fatalf("bound profile drifted or mutated the draft: %v", err)
	}
	for _, edge := range bound.TrustEdges {
		if edge.ID != "product-provider-contract" {
			continue
		}
		address, err := Slice6DesiredEndpointAddress("product-provider", "provider-runtime")
		if err != nil || edge.TargetAddress != address+":8444" {
			t.Fatalf("Provider contract target did not bind planned endpoint: %q, %v", edge.TargetAddress, err)
		}
	}
	for _, binding := range bound.IngressBindings {
		if binding.ID != "product-public" {
			continue
		}
		frontend, err := Slice6DesiredEndpointAddress("public-ingress", "public-ingress-relay")
		if err != nil || binding.FrontendAddress != frontend+":8444" || binding.ConfigurationDigest != binding.Digest() {
			t.Fatalf("Product ingress did not bind planned frontend: %q, %v", binding.FrontendAddress, err)
		}
	}
	broadened := draft
	broadened.Networks = append([]Network(nil), draft.Networks...)
	for index := range broadened.Networks {
		if broadened.Networks[index].Name == "product-internal" {
			broadened.Networks[index].Kind = "trust_edge"
			break
		}
	}
	broadened.ProfileDigest = broadened.Digest()
	if _, err := BindSlice6DesiredNetworkPlan(broadened); err == nil {
		t.Fatal("broadened network draft was rebound instead of rejected")
	}
	routeDrift := draft
	routeDrift.TrustEdges = append([]TrustEdge(nil), draft.TrustEdges...)
	for index := range routeDrift.TrustEdges {
		if routeDrift.TrustEdges[index].ID == "product-provider-contract" {
			routeDrift.TrustEdges[index].MaxConnectionSeconds = 301
			break
		}
	}
	routeDrift.ProfileDigest = routeDrift.Digest()
	if err := routeDrift.Validate(); err != nil {
		t.Fatalf("local drift fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredTrustEdges(routeDrift); err == nil {
		t.Fatal("changed local trust-edge lifetime was admitted")
	}
	externalDrift := draft
	externalDrift.TrustEdges = append([]TrustEdge(nil), draft.TrustEdges...)
	for index := range externalDrift.TrustEdges {
		if externalDrift.TrustEdges[index].ID == "certificate-vault" {
			externalDrift.TrustEdges[index].MaxConnectionSeconds = 61
			break
		}
	}
	externalDrift.ProfileDigest = externalDrift.Digest()
	if err := externalDrift.Validate(); err != nil {
		t.Fatalf("external drift fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredTrustEdges(externalDrift); err == nil {
		t.Fatal("changed external trust-edge lifetime was admitted")
	}
	wrongTarget := bound
	wrongTarget.TrustEdges = append([]TrustEdge(nil), bound.TrustEdges...)
	for index := range wrongTarget.TrustEdges {
		if wrongTarget.TrustEdges[index].ID != "product-provider-contract" {
			continue
		}
		original, err := netip.ParseAddrPort(wrongTarget.TrustEdges[index].TargetAddress)
		if err != nil {
			t.Fatal(err)
		}
		address := original.Addr().As4()
		address[3] = 4
		wrongTarget.TrustEdges[index].TargetAddress = netip.AddrPortFrom(netip.AddrFrom4(address), original.Port()).String()
		break
	}
	wrongTarget.ProfileDigest = wrongTarget.Digest()
	if err := wrongTarget.Validate(); err != nil {
		t.Fatalf("local endpoint drift fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredEdgeAddresses(wrongTarget); err == nil {
		t.Fatal("changed local target IP was admitted")
	}
	wrongPublication := bound
	wrongPublication.IngressBindings = append([]IngressBinding(nil), bound.IngressBindings...)
	wrongPublication.IngressBindings[1].HostBindAddress = "127.0.0.1:28444"
	wrongPublication.IngressBindings[1].ConfigurationDigest = wrongPublication.IngressBindings[1].Digest()
	wrongPublication.ProfileDigest = wrongPublication.Digest()
	if err := wrongPublication.Validate(); err != nil {
		t.Fatalf("host publication drift fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredIngress(wrongPublication); err == nil {
		t.Fatal("changed host publication was admitted")
	}
	wrongFrontend := bound
	wrongFrontend.IngressBindings = append([]IngressBinding(nil), bound.IngressBindings...)
	frontend, err := netip.ParseAddrPort(wrongFrontend.IngressBindings[1].FrontendAddress)
	if err != nil {
		t.Fatal(err)
	}
	address := frontend.Addr().As4()
	address[3] = 4
	for index := range wrongFrontend.IngressBindings {
		original, err := netip.ParseAddrPort(wrongFrontend.IngressBindings[index].FrontendAddress)
		if err != nil {
			t.Fatal(err)
		}
		wrongFrontend.IngressBindings[index].FrontendAddress = netip.AddrPortFrom(netip.AddrFrom4(address), original.Port()).String()
		wrongFrontend.IngressBindings[index].ConfigurationDigest = wrongFrontend.IngressBindings[index].Digest()
	}
	wrongFrontend.ProfileDigest = wrongFrontend.Digest()
	if err := wrongFrontend.Validate(); err != nil {
		t.Fatalf("frontend address drift fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredIngress(wrongFrontend); err == nil {
		t.Fatal("changed frontend IP was admitted")
	}
}

func TestSlice6ExternalIdentityCannotBeRewrittenWithMatchingDigests(t *testing.T) {
	profile := validProfile()
	profile.External = append([]ExternalService(nil), profile.External...)
	profile.TrustEdges = append([]TrustEdge(nil), profile.TrustEdges...)
	for index := range profile.External {
		if profile.External[index].Name != "vault" {
			continue
		}
		profile.External[index].URI = "spiffe://sandbox-runtime.test/external/alternate-vault"
		profile.External[index].DNSNames = []string{"alternate-vault.sandbox-runtime.test"}
		profile.External[index].IdentityDigest = profile.External[index].Digest()
		for edgeIndex := range profile.TrustEdges {
			if profile.TrustEdges[edgeIndex].To == "vault" {
				profile.TrustEdges[edgeIndex].ToURI = profile.External[index].URI
				profile.TrustEdges[edgeIndex].ExternalIdentityDigest = profile.External[index].IdentityDigest
			}
		}
		break
	}
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("rewritten external identity fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredExternalServices(profile); err == nil {
		t.Fatal("self-consistent substituted Vault identity and DNS SAN were admitted")
	}
}

func TestSlice6EgressDestinationCannotBeBroadenedWithMatchingDigest(t *testing.T) {
	profile := validProfile()
	profile.EgressPolicies = append([]EgressPolicy(nil), profile.EgressPolicies...)
	for index := range profile.EgressPolicies {
		if profile.EgressPolicies[index].ID != "product-egress" {
			continue
		}
		profile.EgressPolicies[index].Targets = []EgressTarget{{Alias: "registry-probe", Host: "unreviewed.example.test", Port: 443, Protocol: "https"}}
		break
	}
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("broadened egress fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredEgressPolicies(profile); err == nil {
		t.Fatal("self-consistent unreviewed egress destination was admitted")
	}
	profile = validProfile()
	profile.EgressPolicies = append([]EgressPolicy(nil), profile.EgressPolicies...)
	profile.EgressPolicies[0].LeaseSeconds = 61
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("extended lease fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredEgressPolicies(profile); err == nil {
		t.Fatal("self-consistent extended egress lease was admitted")
	}
}

func TestSlice6TrustAnchorArtifactCannotBeSubstituted(t *testing.T) {
	profile := validProfile()
	profile.TrustAnchors = append([]TrustAnchor(nil), profile.TrustAnchors...)
	profile.TrustAnchors[0].ArtifactID = "alternate-external-server-ca-artifact"
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("substituted trust anchor artifact fixture is not internally valid: %v", err)
	}
	if err := VerifySlice6DesiredTrustAnchors(profile); err == nil {
		t.Fatal("self-consistent substituted CA artifact ID was admitted")
	}
}

func TestSlice6TLSIdentityCannotBeReissuedWithBroaderSANOrLifetime(t *testing.T) {
	for name, mutate := range map[string]func(*TLSIdentity){
		"server SAN": func(identity *TLSIdentity) {
			identity.DNSNames = []string{"unreviewed.sandbox-runtime.test"}
		},
		"rotation lifetime": func(identity *TLSIdentity) {
			identity.TTLSeconds = 901
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			profile.Principals = append([]Principal(nil), profile.Principals...)
			for index := range profile.Principals {
				if profile.Principals[index].Name != "product-runtime" {
					continue
				}
				copyIdentity := *profile.Principals[index].TLS
				mutate(&copyIdentity)
				profile.Principals[index].TLS = &copyIdentity
				break
			}
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err != nil {
				t.Fatalf("rewritten TLS identity fixture is not internally valid: %v", err)
			}
			if err := VerifySlice6DesiredTLSIdentities(profile); err == nil {
				t.Fatal("self-consistent expanded TLS identity was admitted")
			}
		})
	}
}
