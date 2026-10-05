package phase6security

import (
	"slices"
	"testing"
)

func testV2PrivateBoundaries() (ProfileV2, map[string]Principal, map[string]TrustEdge) {
	principal := func(name, kind string, networks []string, listeners []Listener, mounts []Mount) Principal {
		return Principal{Name: name, Kind: kind, PrincipalDigest: testDigest("v2-peer/" + name),
			Networks: networks, Listeners: listeners, Mounts: mounts,
			TLS: &TLSIdentity{URI: "spiffe://sandbox-runtime.test/" + name}}
	}
	control := principal("provider-docker-control", "docker_control",
		[]string{"provider-browser-control", "provider-coding-control", "provider-desktop-control"},
		[]Listener{{Name: "browser", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"},
			{Name: "coding", Protocol: "tcp", Port: 8444, Exposure: "trust_edge"},
			{Name: "desktop", Protocol: "tcp", Port: 8445, Exposure: "trust_edge"}},
		[]Mount{{Target: v2DaemonSocketPath, Kind: "daemon_socket", ReadOnly: true,
			StorageID: v2DaemonSocketStorage}, {Target: v2ReceiptTarget, Kind: "persistent_ledger",
			StorageID: "control-receipts", MaxBytes: v2ReceiptMaxBytes}})
	control.DockerSocket = true
	scanner := principal("provider-artifact-scanner", "artifact_scanner",
		[]string{"provider-coding-scanner"},
		[]Listener{{Name: "scanner", Protocol: "tcp", Port: 8446, Exposure: "trust_edge"}},
		[]Mount{{Target: v2ScannerRuleTarget, Kind: "scanner_rules", ReadOnly: true,
			StorageID: "scanner-rules", MaxBytes: v2ScannerRuleMaxBytes}})
	principals := map[string]Principal{control.Name: control, scanner.Name: scanner}
	for _, spec := range v2ControlScopes {
		principals[spec.ProviderDeployment] = principal(spec.ProviderDeployment, "runtime",
			[]string{spec.Network}, nil, nil)
	}
	// Coding has one additional, scanner-only private network.
	coding := principals["provider-runtime"]
	coding.Networks = []string{"provider-coding-control", "provider-coding-scanner"}
	principals[coding.Name] = coding
	p := ProfileV2{DockerControl: DockerControlAuthorityV2{Deployment: control.Name,
		DaemonSocketPath: v2DaemonSocketPath, DaemonSocketGID: 0, DaemonSocketMode: 0o660,
		SupplementaryGIDs: []uint32{0}, ReceiptStorageID: "control-receipts",
		ReceiptTarget: v2ReceiptTarget, ReceiptMaxBytes: v2ReceiptMaxBytes,
		Endpoints: slices.Clone(v2ControlScopes)},
		ArtifactScanner: ArtifactScannerAuthorityV2{Deployment: scanner.Name,
			ProviderDeployment: coding.Name, Network: "provider-coding-scanner",
			EdgeID: "provider-coding-scanner", RoutePath: "/scan", RuleStorageID: "scanner-rules",
			RuleTarget: v2ScannerRuleTarget, RuleManifestDigest: testDigest("v2-rules"),
			MaxRuleAgeSeconds: 72 * 60 * 60, MaxArtifactBytes: 64 << 20, MaxConcurrentScans: 1}}
	for _, record := range principals {
		p.Principals = append(p.Principals, record)
	}
	for index, spec := range v2ControlScopes {
		provider, target := principals[spec.ProviderDeployment], principals[control.Name]
		port := 8443 + index
		address := "10.90.1.3:8443"
		subnet := "10.90.1.0/24"
		switch spec.Scope {
		case "coding":
			address, subnet = "10.90.2.3:8444", "10.90.2.0/24"
		case "desktop":
			address, subnet = "10.90.3.3:8445", "10.90.3.0/24"
		}
		p.Networks = append(p.Networks, Network{Name: spec.Network, Kind: "trust_edge", Internal: true,
			GatewayModeIPv4: "isolated", IPv4Subnet: subnet,
			Principals: []string{provider.Name, target.Name}})
		p.TrustEdges = append(p.TrustEdges, TrustEdge{ID: spec.EdgeID,
			From: provider.Name, To: target.Name, Protocol: "https", Port: port, TargetAddress: address,
			RoutePath: spec.RoutePath, Authentication: "mtls", ServerAnchorID: "internal-server-ca",
			ClientAnchorID: "internal-client-ca", FromURI: provider.TLS.URI, ToURI: target.TLS.URI,
			FromPrincipalDigest: provider.PrincipalDigest, ToPrincipalDigest: target.PrincipalDigest,
			TenantScope: "bound", MaxConnectionSeconds: 30})
	}
	provider := principals[coding.Name]
	p.Networks = append(p.Networks, Network{Name: "provider-coding-scanner", Kind: "trust_edge", Internal: true,
		GatewayModeIPv4: "isolated", IPv4Subnet: "10.90.4.0/24",
		Principals: []string{provider.Name, scanner.Name}})
	p.TrustEdges = append(p.TrustEdges, TrustEdge{ID: "provider-coding-scanner", From: provider.Name,
		To: scanner.Name, Protocol: "https", Port: 8446, TargetAddress: "10.90.4.3:8446",
		RoutePath: "/scan", Authentication: "mtls", ServerAnchorID: "internal-server-ca",
		ClientAnchorID: "internal-client-ca", FromURI: provider.TLS.URI, ToURI: scanner.TLS.URI,
		FromPrincipalDigest: provider.PrincipalDigest, ToPrincipalDigest: scanner.PrincipalDigest,
		TenantScope: "bound", MaxConnectionSeconds: 30})
	edges := make(map[string]TrustEdge, len(p.TrustEdges))
	for _, edge := range p.TrustEdges {
		edges[edge.ID] = edge
	}
	return p, principals, edges
}

func TestProfileV2PrivateControlAndScannerScopes(t *testing.T) {
	p, principals, edges := testV2PrivateBoundaries()
	if err := validateV2ControlAuthority(p, principals, edges); err != nil {
		t.Fatalf("Control boundary: %v", err)
	}
	if err := validateV2ScannerAuthority(p, principals, edges); err != nil {
		t.Fatalf("scanner boundary: %v", err)
	}
	for name, change := range map[string]func(*ProfileV2, map[string]Principal, map[string]TrustEdge){
		"extra supplementary gid": func(p *ProfileV2, _ map[string]Principal, _ map[string]TrustEdge) {
			p.DockerControl.SupplementaryGIDs = []uint32{0, 1}
		},
		"browser gets socket": func(_ *ProfileV2, principals map[string]Principal, _ map[string]TrustEdge) {
			provider := principals["provider-browser-runtime"]
			provider.DockerSocket = true
			principals[provider.Name] = provider
		},
		"browser gets scanner network": func(p *ProfileV2, principals map[string]Principal, _ map[string]TrustEdge) {
			provider := principals["provider-browser-runtime"]
			provider.Networks = append(provider.Networks, "provider-coding-scanner")
			principals[provider.Name] = provider
			for index := range p.Networks {
				if p.Networks[index].Name == "provider-coding-scanner" {
					p.Networks[index].Principals = append(p.Networks[index].Principals,
						"provider-browser-runtime")
				}
			}
		},
		"wrong coding route": func(_ *ProfileV2, _ map[string]Principal, edges map[string]TrustEdge) {
			edge := edges["provider-coding-control"]
			edge.RoutePath = "/control/browser"
			edges[edge.ID] = edge
		},
		"scanner gets second caller": func(p *ProfileV2, _ map[string]Principal, _ map[string]TrustEdge) {
			p.TrustEdges = append(p.TrustEdges, TrustEdge{ID: "unauthorized-scanner", To: "provider-artifact-scanner",
				Authentication: "mtls"})
		},
		"rules writable": func(_ *ProfileV2, principals map[string]Principal, _ map[string]TrustEdge) {
			scanner := principals["provider-artifact-scanner"]
			scanner.Mounts = slices.Clone(scanner.Mounts)
			scanner.Mounts[0].ReadOnly = false
			principals[scanner.Name] = scanner
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, byName, byEdge := testV2PrivateBoundaries()
			change(&candidate, byName, byEdge)
			if validateV2ControlAuthority(candidate, byName, byEdge) == nil &&
				validateV2ScannerAuthority(candidate, byName, byEdge) == nil {
				t.Fatal("private authority drift accepted")
			}
		})
	}
}

func TestProfileV2DedicatedTLSAgentsCannotListen(t *testing.T) {
	profile := testSlice6V2IdentityFragment(t)
	control := DockerControlAuthorityV2{Deployment: "provider-docker-control"}
	scanner := ArtifactScannerAuthorityV2{Deployment: "provider-artifact-scanner"}
	for _, name := range []string{"provider-docker-control-tls-agent", "provider-artifact-scanner-tls-agent"} {
		t.Run(name, func(t *testing.T) {
			var agent Principal
			for _, principal := range profile.Principals {
				if principal.Name == name {
					agent = principal
				}
			}
			agent.Networks = nil
			if agent.Name == "" || validateV2NewPrincipal(agent, control, scanner) != nil {
				t.Fatal("valid dedicated TLS agent fixture rejected")
			}
			agent.Networks = []string{"provider-coding-control"}
			if validateV2NewPrincipal(agent, control, scanner) == nil {
				t.Fatal("dedicated TLS agent gained a network")
			}
			agent.Networks = nil
			agent.Listeners = []Listener{{Name: "unexpected", Protocol: "tcp", Port: 8443,
				Exposure: "trust_edge"}}
			if validateV2NewPrincipal(agent, control, scanner) == nil {
				t.Fatal("dedicated TLS agent gained a TCP listener")
			}
		})
	}
}
