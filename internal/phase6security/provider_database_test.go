package phase6security

import "testing"

func TestProviderDatabaseBindingsAreClosedAndOwnerSpecific(t *testing.T) {
	for name, mutate := range map[string]func(*Profile){
		"missing owner":       func(p *Profile) { p.ProviderDatabases = p.ProviderDatabases[:1] },
		"duplicate owner":     func(p *Profile) { p.ProviderDatabases[1] = p.ProviderDatabases[0] },
		"wrong principal":     func(p *Profile) { p.ProviderDatabases[0].OwnerPrincipalDigest = testDigest("wrong-owner") },
		"wrong template":      func(p *Profile) { p.ProviderDatabases[0].Template = "desktop-sandbox-runtime" },
		"shared database":     func(p *Profile) { p.ProviderDatabases[1].DatabaseName = p.ProviderDatabases[0].DatabaseName },
		"shared runtime role": func(p *Profile) { p.ProviderDatabases[1].RuntimeRole = p.ProviderDatabases[0].RuntimeRole },
		"shared material": func(p *Profile) {
			p.ProviderDatabases[1].RuntimeDSNBindingID = p.ProviderDatabases[0].RuntimeDSNBindingID
		},
		"shared controller scope": func(p *Profile) {
			p.ProviderDatabases[1].Namespace = p.ProviderDatabases[0].Namespace
			p.ProviderDatabases[1].ControllerID = p.ProviderDatabases[0].ControllerID
		},
		"wrong external service": func(p *Profile) { p.ProviderDatabases[0].ServiceName = "action-history-postgres" },
		"wrong external digest":  func(p *Profile) { p.ProviderDatabases[0].ServiceIdentityDigest = testDigest("other-service") },
		"missing external DNS": func(p *Profile) {
			for index := range p.External {
				if p.External[index].Name == "postgres" {
					p.External[index].DNSNames = nil
				}
			}
		},
		"crossed edge":             func(p *Profile) { p.ProviderDatabases[0].TrustEdgeID = p.ProviderDatabases[1].TrustEdgeID },
		"product edge":             func(p *Profile) { p.ProviderDatabases[0].TrustEdgeID = "product-postgres" },
		"crossed broker":           func(p *Profile) { p.ProviderDatabases[0].BrokerDeployment = p.ProviderDatabases[1].BrokerDeployment },
		"crossed broker role edge": func(p *Profile) { p.ProviderDatabases[0].BrokerRoleEdgeID = p.ProviderDatabases[1].BrokerRoleEdgeID },
		"crossed broker external edge": func(p *Profile) {
			p.ProviderDatabases[0].BrokerExternalEdgeID = p.ProviderDatabases[1].BrokerExternalEdgeID
		},
		"crossed broker policy": func(p *Profile) { p.ProviderDatabases[0].EgressPolicyID = p.ProviderDatabases[1].EgressPolicyID },
		"invalid database":      func(p *Profile) { p.ProviderDatabases[0].DatabaseName = "Browser-DB" },
		"invalid runtime role":  func(p *Profile) { p.ProviderDatabases[0].RuntimeRole = "BrowserRole" },
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if err := profile.Validate(); err == nil {
				t.Fatal("unsafe Provider database binding accepted")
			}
		})
	}
}

func TestProviderDatabaseProjectionHasNoCallerChosenDatabase(t *testing.T) {
	profile := validProfile()
	browser, err := profile.ProjectSandboxIdentityPlan("browser-sandbox-runtime", "provider-browser-runtime", 1)
	if err != nil || browser.DatabaseName != "provider_browser" || browser.RuntimeRole != "browser_provider_runtime" ||
		browser.Namespace != "browser-production" || browser.ControllerID != "browser-provider-1" ||
		browser.MaterialBindingID != "browser-provider-runtime-dsn" || browser.TrustEdgeID != "provider-browser-postgres" {
		t.Fatalf("Browser projection = %+v, %v", browser, err)
	}
	desktop, err := profile.ProjectSandboxIdentityPlan("desktop-sandbox-runtime", "provider-desktop-runtime", 1)
	if err != nil || desktop.DatabaseName != "provider_desktop" || desktop.RuntimeRole != "desktop_provider_runtime" ||
		desktop.Namespace != "desktop-production" || desktop.ControllerID != "desktop-controller-1" ||
		desktop.MaterialBindingID != "desktop-provider-runtime-dsn" || desktop.TrustEdgeID != "provider-desktop-postgres" {
		t.Fatalf("Desktop projection = %+v, %v", desktop, err)
	}
}

func TestProviderDatabaseConfigMustMatchProfileOwner(t *testing.T) {
	profile := validProfile()
	browser := profile.ProviderDatabases[0]
	desktop := profile.ProviderDatabases[1]
	if err := profile.AssertProviderDatabaseRuntime(browser.OwnerDeployment, browser.Namespace,
		browser.ControllerID, browser.RuntimeRole, browser.RuntimeDSNBindingID); err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]struct {
		owner, namespace, controller, role, material string
	}{
		"cross owner": {desktop.OwnerDeployment, browser.Namespace, browser.ControllerID, browser.RuntimeRole, browser.RuntimeDSNBindingID},
		"namespace":   {browser.OwnerDeployment, desktop.Namespace, browser.ControllerID, browser.RuntimeRole, browser.RuntimeDSNBindingID},
		"controller":  {browser.OwnerDeployment, browser.Namespace, desktop.ControllerID, browser.RuntimeRole, browser.RuntimeDSNBindingID},
		"role":        {browser.OwnerDeployment, browser.Namespace, browser.ControllerID, desktop.RuntimeRole, browser.RuntimeDSNBindingID},
		"material":    {browser.OwnerDeployment, browser.Namespace, browser.ControllerID, browser.RuntimeRole, desktop.RuntimeDSNBindingID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := profile.AssertProviderDatabaseRuntime(input.owner, input.namespace,
				input.controller, input.role, input.material); err == nil {
				t.Fatal("swapped process authority accepted")
			}
		})
	}
	binding, service, edge, anchor, err := profile.ProviderDatabaseAuthority(browser.OwnerDeployment)
	if err != nil || binding != browser || service.Name != "postgres" || edge.ID != browser.TrustEdgeID ||
		anchor.ID != "external-server-ca" {
		t.Fatalf("bound server authority = %+v, %+v, %+v, %+v, %v", binding, service, edge, anchor, err)
	}
}

func TestProviderDatabaseUsesDistinctFixedBrokerBoundaries(t *testing.T) {
	profile := validProfile()
	seenBrokers := map[string]bool{}
	for _, binding := range profile.ProviderDatabases {
		boundary, caller, broker, network, err := profile.BrokerBoundaryForPolicy(binding.EgressPolicyID)
		if err != nil || boundary.ID != binding.BrokerRoleEdgeID || caller.Name != binding.OwnerDeployment ||
			broker.Name != binding.BrokerDeployment || broker.Kind != "egress_broker" ||
			network.Kind != "role_internal" || !network.Internal || seenBrokers[broker.Name] {
			t.Fatalf("Provider broker boundary = %+v, %+v, %+v, %+v, %v", boundary, caller, broker, network, err)
		}
		seenBrokers[broker.Name] = true
		if !caller.DirectEgressBlocked || caller.ExternalUplink || !broker.ExternalUplink || broker.DirectEgressBlocked {
			t.Fatal("Provider/broker egress roles were conflated")
		}
	}
}
