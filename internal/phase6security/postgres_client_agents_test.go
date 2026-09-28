package phase6security

import "testing"

func TestPostgresClientAgentsAreSeparateClosedPurpose(t *testing.T) {
	profile := validProfile()
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"provider-browser-runtime", "provider-desktop-runtime"} {
		binding, database, agent, subject, anchor, err := profile.PostgresClientAgentForOwner(owner)
		if err != nil || binding.SubjectDeployment != owner || database.OwnerDeployment != owner ||
			agent.Name != binding.AgentDeployment || subject.Name != owner || anchor.ID != "postgres-client-ca" ||
			binding.CommonName != postgresClientCommonName(database.RuntimeRole) {
			t.Fatalf("PostgreSQL agent projection: %+v %+v %+v %+v %+v %v", binding, database, agent, subject, anchor, err)
		}
		ordinary, _, _, err := profile.TLSAgentForSubject(owner)
		if err != nil || ordinary.AgentDeployment == binding.AgentDeployment || ordinary.IssuerVaultRole == binding.IssuerVaultRole {
			t.Fatal("ordinary and PostgreSQL certificate purposes were conflated")
		}
	}
	if _, _, _, _, _, err := profile.PostgresClientAgentForOwner("product-runtime"); err == nil {
		t.Fatal("non-Provider owner projected as Provider database")
	}
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		binding, resolved, agent, subject, anchor, err := profile.PostgresClientSignerForOwner(target.SubjectDeployment)
		if err != nil || resolved != target || binding.AgentDeployment != target.AgentDeployment ||
			binding.CommonName != target.SQLRole || agent.Name != target.AgentDeployment ||
			subject.Name != target.SubjectDeployment || anchor.ID != "postgres-client-ca" {
			t.Fatalf("PostgreSQL signer %s mismatch: %+v %+v %v", target.SubjectDeployment, binding, resolved, err)
		}
	}
	if _, _, _, _, _, err := profile.PostgresClientSignerForOwner("other-runtime"); err == nil {
		t.Fatal("unreviewed PostgreSQL signer owner accepted")
	}
	for name, change := range map[string]func(*Profile){
		"missing agent": func(p *Profile) { p.PostgresClientAgents = p.PostgresClientAgents[:1] },
		"cross owner": func(p *Profile) {
			p.PostgresClientAgents[0].SubjectDeployment = "provider-desktop-runtime"
		},
		"wrong common name": func(p *Profile) { p.PostgresClientAgents[0].CommonName = "provider-browser" },
		"ordinary issuer": func(p *Profile) {
			p.PostgresClientAgents[0].IssuerVaultRole = p.TLSAgentBindings[0].IssuerVaultRole
		},
		"ordinary policy": func(p *Profile) {
			p.PostgresClientAgents[0].IssuerPolicyID = p.TLSAgentBindings[0].IssuerPolicyID
		},
		"ordinary signer key": func(p *Profile) {
			p.PostgresClientAgents[0].AgentRequestKeyDigest = p.TLSAgentBindings[0].AgentRequestKeyDigest
		},
		"cross socket": func(p *Profile) {
			p.PostgresClientAgents[0].SocketStorageID = p.PostgresClientAgents[1].SocketStorageID
		},
		"cross controller socket": func(p *Profile) {
			p.PostgresClientAgents[0].ControllerSocketStorageID = p.PostgresClientAgents[1].ControllerSocketStorageID
		},
		"wrong CA": func(p *Profile) { p.PostgresClientAgents[0].IssuerAnchorID = "internal-client-ca" },
		"leaked CA": func(p *Profile) {
			p.TrustAnchors[3].Consumers = append(p.TrustAnchors[3].Consumers, "provider-runtime")
		},
		"wrong peer UID": func(p *Profile) { p.PostgresClientAgents[0].SubjectUID++ },
		"wrong edge":     func(p *Profile) { p.PostgresClientAgents[0].UnixEdgeID = "egress-role-provider-browser" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validProfile()
			change(&candidate)
			candidate.ProfileDigest = candidate.Digest()
			if candidate.Validate() == nil {
				t.Fatal("unsafe PostgreSQL certificate binding accepted")
			}
		})
	}
}
