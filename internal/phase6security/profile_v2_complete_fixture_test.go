package phase6security

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// This fixture is synthetic and test-only. It proves that the v2 field
// checker has a positive path; production Validate/DecodeV2 still hold closed.
func testCompleteV2Fields(t *testing.T) ProfileV2 {
	t.Helper()
	base, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	base = bindSyntheticSlice6DNSClientCA(t, base)
	if err := VerifySlice6FinalGateProfile(base); err != nil {
		t.Fatalf("synthetic v1 common-field base is invalid: %v", err)
	}
	baseBytes, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var p ProfileV2
	if json.Unmarshal(baseBytes, &p) != nil {
		t.Fatal("could not copy common test fields")
	}
	p.Protocol, p.Version = ProtocolIDV2, VersionV2
	p.Principals = slices.Clone(p.Principals)
	p.Networks = slices.Clone(p.Networks)
	p.TrustEdges = slices.Clone(p.TrustEdges)
	p.TrustAnchors = slices.Clone(p.TrustAnchors)
	p.TLSAgentBindings = slices.Clone(p.TLSAgentBindings)
	fragment := testSlice6V2IdentityFragment(t)
	for _, candidate := range fragment.Principals {
		if _, newRole := slice6V2IdentityDelta[candidate.Name]; !newRole {
			continue
		}
		candidate.Mounts = nil
		candidate.Listeners = nil
		candidate.Networks = nil
		candidate.DockerSocket = false
		candidate.TLS = new(TLSIdentity)
		for _, original := range fragment.Principals {
			if original.Name == candidate.Name {
				*candidate.TLS = *original.TLS
				break
			}
		}
		candidate.TLS.DNSNames = []string{candidate.Name + ".sandbox-runtime.test"}
		switch candidate.Name {
		case "provider-docker-control":
			candidate.DockerSocket = true
			candidate.Networks = []string{"provider-browser-control", "provider-coding-control", "provider-desktop-control"}
			candidate.Listeners = []Listener{{Name: "browser", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"},
				{Name: "coding", Protocol: "tcp", Port: 8444, Exposure: "trust_edge"},
				{Name: "desktop", Protocol: "tcp", Port: 8445, Exposure: "trust_edge"}}
			candidate.Mounts = []Mount{{Target: v2DaemonSocketPath, Kind: "daemon_socket",
				ReadOnly: true, StorageID: v2DaemonSocketStorage},
				{Target: v2ReceiptTarget, Kind: "persistent_ledger", StorageID: "control-receipts",
					MaxBytes: v2ReceiptMaxBytes}}
		case "provider-artifact-scanner":
			candidate.Networks = []string{"provider-coding-scanner"}
			candidate.Listeners = []Listener{{Name: "scanner", Protocol: "tcp", Port: 8446,
				Exposure: "trust_edge"}}
			candidate.Mounts = []Mount{{Target: v2ScannerRuleTarget, Kind: "scanner_rules",
				ReadOnly: true, StorageID: "scanner-rules", MaxBytes: v2ScannerRuleMaxBytes}}
			candidate.Resources = Resources{MemoryBytes: 4 << 30, CPUMillis: 2000, PIDs: 64}
		}
		p.Principals = append(p.Principals, candidate)
	}
	p.DockerControl = DockerControlAuthorityV2{Deployment: "provider-docker-control",
		DaemonSocketPath: v2DaemonSocketPath, DaemonSocketGID: 0, DaemonSocketMode: 0o660,
		SupplementaryGIDs: []uint32{0}, ReceiptStorageID: "control-receipts",
		ReceiptTarget: v2ReceiptTarget, ReceiptMaxBytes: v2ReceiptMaxBytes,
		Endpoints: slices.Clone(v2ControlScopes)}
	p.ArtifactScanner = ArtifactScannerAuthorityV2{Deployment: "provider-artifact-scanner",
		ProviderDeployment: "provider-runtime", Network: "provider-coding-scanner",
		EdgeID: "provider-coding-scanner", RoutePath: "/scan", RuleStorageID: "scanner-rules",
		RuleTarget: v2ScannerRuleTarget, RuleManifestDigest: testDigest("synthetic-rules"),
		MaxRuleAgeSeconds: 72 * 60 * 60, MaxArtifactBytes: 64 << 20, MaxConcurrentScans: 1}
	byName := func(name string) *Principal {
		for index := range p.Principals {
			if p.Principals[index].Name == name {
				return &p.Principals[index]
			}
		}
		t.Fatalf("missing principal %s", name)
		return nil
	}
	for _, anchor := range p.TrustAnchors {
		if anchor.ID != "internal-server-ca" && anchor.ID != "internal-client-ca" {
			continue
		}
		for _, name := range []string{"provider-docker-control", "provider-artifact-scanner"} {
			record := byName(name)
			record.Mounts = append(record.Mounts, Mount{Target: anchor.TargetPath,
				Kind: "trust_anchor", ReadOnly: true, StorageID: anchor.StorageID})
		}
	}
	for index := range p.TrustAnchors {
		anchor := &p.TrustAnchors[index]
		if anchor.ID == "internal-server-ca" || anchor.ID == "internal-client-ca" {
			anchor.Consumers = append(slices.Clone(anchor.Consumers),
				"provider-docker-control", "provider-artifact-scanner")
			slices.Sort(anchor.Consumers)
		}
	}
	for _, spec := range v2ControlScopes {
		provider := byName(spec.ProviderDeployment)
		provider.Networks = append(slices.Clone(provider.Networks), spec.Network)
		slices.Sort(provider.Networks)
		port, subnet, address := 8443, "10.90.1.0/24", "10.90.1.3:8443"
		switch spec.Scope {
		case "coding":
			port, subnet, address = 8444, "10.90.2.0/24", "10.90.2.3:8444"
		case "desktop":
			port, subnet, address = 8445, "10.90.3.0/24", "10.90.3.3:8445"
		}
		p.Networks = append(p.Networks, Network{Name: spec.Network, Kind: "trust_edge", Internal: true,
			GatewayModeIPv4: "isolated", IPv4Subnet: subnet,
			Principals: sortedPair(spec.ProviderDeployment, "provider-docker-control")})
		p.TrustEdges = append(p.TrustEdges, testV2PrivateEdge(spec.EdgeID, spec.ProviderDeployment,
			"provider-docker-control", spec.RoutePath, port, address, byName))
	}
	provider := byName("provider-runtime")
	provider.Networks = append(slices.Clone(provider.Networks), "provider-coding-scanner")
	slices.Sort(provider.Networks)
	p.Networks = append(p.Networks, Network{Name: "provider-coding-scanner", Kind: "trust_edge",
		Internal: true, GatewayModeIPv4: "isolated", IPv4Subnet: "10.90.4.0/24",
		Principals: sortedPair("provider-runtime", "provider-artifact-scanner")})
	p.TrustEdges = append(p.TrustEdges, testV2PrivateEdge("provider-coding-scanner", "provider-runtime",
		"provider-artifact-scanner", "/scan", 8446, "10.90.4.3:8446", byName))
	for _, pair := range []struct{ subject, agent string }{
		{"provider-docker-control", "provider-docker-control-tls-agent"},
		{"provider-artifact-scanner", "provider-artifact-scanner-tls-agent"},
	} {
		subject, agent, controller := byName(pair.subject), byName(pair.agent), byName("certificate-controller")
		directory := "/run/tls/" + pair.agent
		controllerDirectory := "/run/certificate-controller/" + pair.agent
		binding := TLSAgentBinding{AgentDeployment: pair.agent,
			AgentPrincipalDigest: agent.PrincipalDigest, SubjectDeployment: pair.subject,
			SubjectPrincipalDigest: subject.PrincipalDigest, AgentUID: agent.UID, AgentGID: agent.GID,
			SubjectUID: subject.UID, SubjectGID: subject.GID, SocketDirectory: directory,
			SocketStorageID: pair.agent + "-socket", SocketPath: directory + "/signer.sock",
			DirectoryMode: 0o710, SocketMode: 0o666, UnixEdgeID: "tls-agent-" + pair.agent,
			IssuerPolicyID: "issuer-" + pair.agent, IssuerVaultRole: "vault-" + pair.agent,
			AgentRequestKeyID:     "request-" + pair.agent,
			AgentRequestKeyDigest: testDigest("request-public-key/" + pair.agent),
			ControllerDeployment:  controller.Name, ControllerUID: controller.UID,
			ControllerGID: controller.GID, ControllerSocketDirectory: controllerDirectory,
			ControllerSocketStorageID: pair.agent + "-controller-socket",
			ControllerSocketPath:      controllerDirectory + "/request.sock",
			ControllerDirectoryMode:   0o710, ControllerSocketMode: 0o666,
			ControllerUnixEdgeID: "certificate-agent-" + pair.agent, CleanupClass: "sockets"}
		p.TLSAgentBindings = append(p.TLSAgentBindings, binding)
		subject.Mounts = append(subject.Mounts, Mount{Target: directory, Kind: "private_socket",
			ReadOnly: true, StorageID: binding.SocketStorageID})
		agent.Mounts = append(agent.Mounts, Mount{Target: directory, Kind: "private_socket",
			StorageID: binding.SocketStorageID}, Mount{Target: controllerDirectory,
			Kind: "private_socket", ReadOnly: true, StorageID: binding.ControllerSocketStorageID})
		controller.Mounts = append(controller.Mounts, Mount{Target: controllerDirectory,
			Kind: "private_socket", StorageID: binding.ControllerSocketStorageID})
		p.TrustEdges = append(p.TrustEdges,
			TrustEdge{ID: binding.UnixEdgeID, From: subject.Name, To: agent.Name, Protocol: "unix",
				Authentication: "unix_peer_credentials", FromURI: subject.TLS.URI, ToURI: agent.TLS.URI,
				FromPrincipalDigest: subject.PrincipalDigest, ToPrincipalDigest: agent.PrincipalDigest,
				TenantScope: "system", MaxConnectionSeconds: 5},
			TrustEdge{ID: binding.ControllerUnixEdgeID, From: agent.Name, To: controller.Name,
				Protocol: "unix", Authentication: "unix_peer_credentials", FromURI: agent.TLS.URI,
				ToURI: controller.TLS.URI, FromPrincipalDigest: agent.PrincipalDigest,
				ToPrincipalDigest: controller.PrincipalDigest, TenantScope: "system", MaxConnectionSeconds: 5})
	}
	for index := range p.Principals {
		slices.SortFunc(p.Principals[index].Mounts, func(a, b Mount) int {
			return strings.Compare(a.Target, b.Target)
		})
	}
	slices.SortFunc(p.Principals, func(a, b Principal) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(p.Networks, func(a, b Network) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(p.TrustEdges, func(a, b TrustEdge) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(p.TLSAgentBindings, func(a, b TLSAgentBinding) int {
		return strings.Compare(a.AgentDeployment, b.AgentDeployment)
	})
	template, _ := testCodingTemplateV2(t)
	template.OwnerPrincipalDigest = byName("provider-runtime").PrincipalDigest
	template.Slots = slices.Clone(template.Slots)
	template.Slots[0].WorkloadGID = 57500
	template.Slots[1].WorkloadGID = 57501
	p.CodingTemplate = template
	p.SandboxGatewayLimits = map[string]Resources{
		"browser-sandbox-runtime": {MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16},
		"desktop-sandbox-runtime": {MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16}}
	p.ExternalResourceLimits = make(map[string]Resources)
	for _, service := range slice6DesiredExternalServices {
		p.ExternalResourceLimits[service.name] = Resources{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 16}
	}
	p.ResourceBudget, err = CalculateSlice6V2ResourceBudget(p.Principals, p.SandboxIdentitySlots,
		p.CodingTemplate, p.SandboxGatewayLimits, p.ExternalResourceLimits)
	if err != nil {
		t.Fatalf("synthetic v2 resource input: %v", err)
	}
	p.ProfileDigest = p.Digest()
	return p
}

func testV2PrivateEdge(id, from, to, route string, port int, address string,
	byName func(string) *Principal) TrustEdge {
	caller, target := byName(from), byName(to)
	return TrustEdge{ID: id, From: from, To: to, Protocol: "https", Port: port,
		TargetAddress: address, RoutePath: route, Authentication: "mtls",
		ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
		FromURI: caller.TLS.URI, ToURI: target.TLS.URI,
		FromPrincipalDigest: caller.PrincipalDigest, ToPrincipalDigest: target.PrincipalDigest,
		TenantScope: "bound", MaxConnectionSeconds: 30}
}

func TestCompleteV2SyntheticFieldsHaveSuccessPathButNoAdmission(t *testing.T) {
	p := testCompleteV2Fields(t)
	if err := p.validateFields(); err != nil {
		t.Fatalf("complete synthetic v2 field chain failed: %v", err)
	}
	if p.Validate() == nil {
		t.Fatal("source/image hold opened")
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV2(encoded); err == nil {
		t.Fatal("synthetic field fixture bypassed production v2 hold")
	}
	for name, mutate := range map[string]func(*ProfileV2){
		"v1 protocol downgrade":   func(v *ProfileV2) { v.Protocol = ProtocolID },
		"wrong version":           func(v *ProfileV2) { v.Version = Version },
		"control socket gid":      func(v *ProfileV2) { v.DockerControl.SupplementaryGIDs = []uint32{0, 1} },
		"missing control receipt": func(v *ProfileV2) { v.DockerControl.ReceiptStorageID = "" },
		"wrong control route":     func(v *ProfileV2) { v.DockerControl.Endpoints[1].RoutePath = "/control/browser" },
		"scanner scope":           func(v *ProfileV2) { v.ArtifactScanner.ProviderDeployment = "provider-browser-runtime" },
		"missing scanner rules":   func(v *ProfileV2) { v.ArtifactScanner.RuleManifestDigest = "" },
		"broker CA subject expansion": func(v *ProfileV2) {
			for index := range v.External {
				if v.External[index].Name == "dns" {
					v.External[index].DNSClientCA.AllowedSubjects = append(
						v.External[index].DNSClientCA.AllowedSubjects, "provider-docker-control")
					v.External[index].IdentityDigest = v.External[index].Digest()
				}
			}
		},
		"wrong scanner issuer": func(v *ProfileV2) {
			for index := range v.TrustEdges {
				if v.TrustEdges[index].ID == "provider-coding-scanner" {
					v.TrustEdges[index].ClientAnchorID = "external-server-ca"
				}
			}
		},
		"tls agent listener": func(v *ProfileV2) {
			for index := range v.Principals {
				if v.Principals[index].Name == "provider-docker-control-tls-agent" {
					v.Principals[index].Listeners = []Listener{{Name: "extra", Protocol: "tcp",
						Port: 8443, Exposure: "trust_edge"}}
				}
			}
		},
		"identity collision": func(v *ProfileV2) {
			for index := range v.Principals {
				if v.Principals[index].Name == "provider-docker-control" {
					v.Principals[index].UID = 57000
				}
			}
		},
		"resource omission":    func(v *ProfileV2) { delete(v.ExternalResourceLimits, "postgres") },
		"budget undercount":    func(v *ProfileV2) { v.ResourceBudget.MemoryBytes-- },
		"coding gid collision": func(v *ProfileV2) { v.CodingTemplate.Slots[0].WorkloadGID = 58000 },
		"coding volume alias": func(v *ProfileV2) {
			v.CodingTemplate.Slots[1].InputsVolume = v.CodingTemplate.Slots[0].InputsVolume
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testCompleteV2Fields(t)
			mutate(&candidate)
			candidate.ProfileDigest = candidate.Digest()
			if candidate.validateFields() == nil {
				t.Fatal("self-consistent v2 authority drift accepted")
			}
		})
	}
}
