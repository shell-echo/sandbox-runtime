package phase6security

import (
	"slices"
	"testing"
)

func TestSlice6DNSPeerEligibilityIsClosedToFiveReviewedOutboundEdges(t *testing.T) {
	profile := validProfile()
	count := 0
	for _, edge := range profile.TrustEdges {
		if edge.To != "dns" {
			continue
		}
		count++
		if !profile.IsSlice6DNSPeerEdge(edge.ID, edge.FromPrincipalDigest, "outbound") ||
			profile.IsSlice6DNSPeerEdge(edge.ID, edge.FromPrincipalDigest, "inbound") ||
			profile.IsSlice6DNSPeerEdge(edge.ID, testDigest("other-broker"), "outbound") {
			t.Fatalf("DNS edge %s gained incorrect peer-CRL direction or principal", edge.ID)
		}
	}
	if count != 5 || profile.IsSlice6DNSPeerEdge("certificate-vault", "", "outbound") {
		t.Fatal("reviewed DNS edge set is incomplete or unrelated external edge admitted")
	}
	index := -1
	for i, edge := range profile.TrustEdges {
		if edge.ID == "egress-dns" {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatal("fixture has no product broker DNS edge")
	}
	for name, change := range map[string]func(*TrustEdge){
		"alternate service": func(e *TrustEdge) { e.To = "vault" },
		"wrong broker":      func(e *TrustEdge) { e.From = "egress-broker-gateway" },
		"wrong protocol":    func(e *TrustEdge) { e.Protocol = "tls" },
		"wrong port":        func(e *TrustEdge) { e.Port = 53 },
		"wrong anchor":      func(e *TrustEdge) { e.ServerAnchorID = "internal-server-ca" },
		"client anchor":     func(e *TrustEdge) { e.ClientAnchorID = "internal-client-ca" },
		"wrong DNS URI":     func(e *TrustEdge) { e.ToURI = "spiffe://sandbox-runtime.test/external/vault" },
		"wrong identity":    func(e *TrustEdge) { e.ExternalIdentityDigest = testDigest("other-dns") },
		"extra target":      func(e *TrustEdge) { e.TargetAddress = "10.1.1.2:853" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			candidate.TrustEdges = append([]TrustEdge(nil), profile.TrustEdges...)
			change(&candidate.TrustEdges[index])
			if candidate.IsSlice6DNSPeerEdge("egress-dns", profile.TrustEdges[index].FromPrincipalDigest, "outbound") {
				t.Fatal("drifted DNS edge admitted to peer-CRL map")
			}
		})
	}
}

func TestSlice6DNSPeerRoleRequiresExactOperatorSourceBinding(t *testing.T) {
	profile := validProfile()
	sources := completePeerCRLSources(t, profile)
	var digest string
	for _, edge := range profile.TrustEdges {
		if edge.ID == "egress-dns" {
			digest = edge.FromPrincipalDigest
		}
	}
	if digest == "" {
		t.Fatal("fixture has no product broker DNS principal")
	}
	role, err := DerivePeerCRLRoleDocument(profile, sources, digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := role.Binding("egress-dns", "outbound"); err != nil {
		t.Fatal("broker role omitted the DNS server-issuer source")
	}
	if _, err := role.Binding("egress-dns", "inbound"); err == nil {
		t.Fatal("broker role acquired an inbound DNS CRL authority")
	}
	missing := sources
	missing.Edges = slices.DeleteFunc(slices.Clone(sources.Edges), func(edge PeerCRLEdgeBinding) bool {
		return edge.EdgeID == "egress-dns" && edge.LocalPrincipalDigest == digest
	})
	if _, err := DerivePeerCRLRoleDocument(profile, missing, digest); err == nil {
		t.Fatal("broker role derived without the operator's DNS source binding")
	}
	wrongAnchor := sources
	wrongAnchor.Edges = slices.Clone(sources.Edges)
	for index := range wrongAnchor.Edges {
		if wrongAnchor.Edges[index].EdgeID == "egress-dns" {
			wrongAnchor.Edges[index].PeerAnchorID = "internal-server-ca"
		}
	}
	if wrongAnchor.Validate(profile) == nil {
		t.Fatal("DNS source mapped to an unrelated issuer anchor")
	}
}
