package phase6security

import "testing"

func TestResolveSlice6FinalPostgresAuthorityClosesNineOwners(t *testing.T) {
	draft := validProfile()
	intermediate, err := BuildSlice6ExecutableProfileTarget(draft)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intermediate.ResolveSlice6FinalPostgresAuthority("product-runtime"); err == nil {
		t.Fatal("intermediate profile admitted as final PostgreSQL authority")
	}
	final, err := BuildSlice6FinalExternalProfileTarget(draft)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil || len(rules) != 9 {
		t.Fatalf("closed nine-source rules: %v", err)
	}
	for _, rule := range rules {
		t.Run(rule.Owner, func(t *testing.T) {
			authority, err := final.ResolveSlice6FinalPostgresAuthority(rule.Owner)
			if err != nil {
				t.Fatal(err)
			}
			source, err := Slice6DesiredFinalServiceEndpointAddress(authority.Network, rule.Dialer)
			if err != nil || authority.Owner != rule.Owner || authority.Dialer != rule.Dialer ||
				authority.SourceAddress != source || authority.SourceAddress+"/32" != rule.SourceCIDR ||
				authority.ServerAddress == authority.SourceAddress ||
				authority.ServerPort != 5432 || authority.ServerHost != "postgres.sandbox-runtime.test" ||
				authority.PeerEdgeID == "" ||
				authority.Database != rule.Database || authority.SQLRole != rule.SQLRole ||
				authority.Migration != rule.Migration || authority.Signer.SubjectDeployment != rule.Owner ||
				authority.Signer.CommonName != rule.SQLRole || authority.ServerAnchor.ID != "external-server-ca" {
				t.Fatalf("incomplete authority: %+v, endpoint: %v", authority, err)
			}
			wantBroker := rule.Owner == "provider-browser-runtime" || rule.Owner == "provider-desktop-runtime"
			if authority.BrokerOnly != wantBroker {
				t.Fatal("broker-only boundary changed")
			}
		})
	}
	for _, owner := range []string{"", "gateway-runtime-typo", "egress-broker-provider-browser", "guest-runtime"} {
		if _, err := final.ResolveSlice6FinalPostgresAuthority(owner); err == nil {
			t.Fatalf("unreviewed PostgreSQL owner %q admitted", owner)
		}
	}
	mutated := final
	mutated.TrustEdges = append([]TrustEdge(nil), final.TrustEdges...)
	for index := range mutated.TrustEdges {
		if mutated.TrustEdges[index].ID == "product-postgres" {
			mutated.TrustEdges[index].From = "gateway-runtime"
		}
	}
	mutated.ProfileDigest = mutated.Digest()
	if _, err := mutated.ResolveSlice6FinalPostgresAuthority("product-runtime"); err == nil {
		t.Fatal("altered dialer/edge admitted")
	}
}
