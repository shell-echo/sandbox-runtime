package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	names = append(names, "egress-broker-product", "egress-broker-product-tls-agent", "egress-policy-authority-product")
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
	egressTLSIdentity, err := registry.New(securityprincipal.KindTLSAgent, "product_egress_broker_tls_agent", securityprincipal.RoleProduct,
		testDigest("instance/egress-broker-product-tls-agent"))
	if err != nil {
		panic(err)
	}
	identities["egress-broker-product-tls-agent"] = egressTLSIdentity
	authorityIdentity, err := registry.New(securityprincipal.KindController, "product_policy_authority", "",
		testDigest("instance/egress-policy-authority-product"))
	if err != nil {
		panic(err)
	}
	identities["egress-policy-authority-product"] = authorityIdentity
	ingressIdentity, err := registry.New(securityprincipal.KindIngressRelay, "public_ingress_relay", "",
		testDigest("instance/public-ingress-relay"))
	if err != nil {
		panic(err)
	}
	identities["public-ingress-relay"] = ingressIdentity
	tlsSubjects := make(map[string]string, len(requiredTLSAgentSubjects)+1)
	for agent, subject := range requiredTLSAgentSubjects {
		tlsSubjects[agent] = subject
	}
	tlsSubjects["egress-broker-product-tls-agent"] = "egress-broker-product"
	tlsAgentForSubject := make(map[string]string, len(tlsSubjects))
	for agent, subject := range tlsSubjects {
		tlsAgentForSubject[subject] = agent
	}
	principals := make([]Principal, 0, len(names))
	for index, name := range names {
		kind := requiredPrincipals[name]
		networks := []string{"network-" + name}
		external, blocked := false, true
		if name == "product-runtime" {
			networks = []string{"ingress-product", "product-internal"}
		}
		if name == "gateway-runtime" {
			networks = []string{"ingress-gateway", "network-gateway-runtime"}
		}
		if name == "browser-runtime-role" || name == "browser-executor-backend" {
			networks = []string{"executor-browser"}
		}
		if name == "desktop-runtime-role" || name == "desktop-executor-backend" {
			networks = []string{"executor-desktop"}
		}
		if name == "egress-broker-product" {
			kind = "egress_broker"
			networks, external, blocked = []string{"external-uplink", "product-internal"}, true, false
		}
		if name == "egress-policy-authority-product" {
			kind = "controller"
		}
		if name == "public-ingress-relay" {
			kind = "ingress_relay"
			networks, external, blocked = []string{"ingress-gateway", "ingress-product", "public-ingress"}, true, false
		}
		if name == "egress-broker-product-tls-agent" {
			kind = "tls_agent"
		}
		principal := Principal{
			Name: name, Kind: kind, ImageReference: image, ImageDigest: digest,
			UID: uint32(20000 + index), GID: uint32(30000 + index),
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, DroppedCapabilities: []string{"ALL"}, SeccompDigest: testDigest("seccomp/" + name),
			Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 250, PIDs: 32}, Networks: networks,
			ExternalUplink: external, DirectEgressBlocked: blocked,
		}
		if name == "browser-executor-backend" || name == "desktop-executor-backend" {
			principal.Listeners = []Listener{{Name: "executor", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/trust/internal-client-ca.pem", Kind: "trust_anchor",
				ReadOnly: true, StorageID: "internal-client-ca-storage"})
		}
		if name == "product-runtime" {
			principal.Listeners = []Listener{{Name: "api", Protocol: "tcp", Port: 8444, Exposure: "public"}}
		}
		if name == "gateway-runtime" {
			principal.Listeners = []Listener{{Name: "signaling", Protocol: "tcp", Port: 8445, Exposure: "public"}}
		}
		if name == "public-ingress-relay" {
			principal.Listeners = []Listener{
				{Name: "gateway-public", Protocol: "tcp", Port: 8445, Exposure: "ingress_frontend"},
				{Name: "product-public", Protocol: "tcp", Port: 8444, Exposure: "ingress_frontend"},
			}
		}
		if name == "browser-runtime-role" || name == "desktop-runtime-role" || name == "product-runtime" || name == "gateway-runtime" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/trust/internal-server-ca.pem", Kind: "trust_anchor",
				ReadOnly: true, StorageID: "internal-server-ca-storage"})
		}
		if name == "certificate-controller" || name == "egress-broker-product" || name == "product-runtime" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/trust/external-server-ca.pem", Kind: "trust_anchor",
				ReadOnly: true, StorageID: "external-server-ca-storage"})
		}
		if name == "certificate-controller" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/trust/vault-client-ca.pem", Kind: "trust_anchor",
				ReadOnly: true, StorageID: "vault-client-ca-storage"})
		}
		if name == "egress-broker-product" {
			principal.Mounts = []Mount{
				{Target: "/run/egress-authority", Kind: "private_socket", ReadOnly: true, StorageID: "product-authority-socket"},
				{Target: "/run/trust/external-server-ca.pem", Kind: "trust_anchor", ReadOnly: true, StorageID: "external-server-ca-storage"},
				{Target: "/run/trust/internal-client-ca.pem", Kind: "trust_anchor", ReadOnly: true, StorageID: "internal-client-ca-storage"},
			}
			principal.Listeners = []Listener{{Name: "egress", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}
		}
		if name == "egress-policy-authority-product" {
			principal.Mounts = []Mount{
				{Target: "/run/egress-authority", Kind: "private_socket", StorageID: "product-authority-socket"},
				{Target: "/var/lib/egress-authority", Kind: "persistent_ledger", MaxBytes: 1 << 20, StorageID: "product-authority-ledger"},
			}
		}
		if _, tlsAgent := tlsSubjects[name]; tlsAgent {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/tls/" + name, Kind: "private_socket", StorageID: name + "-socket"})
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/" + name, Kind: "private_socket",
				ReadOnly: true, StorageID: name + "-controller-socket"})
		}
		if agent, hasAgent := tlsAgentForSubject[name]; hasAgent {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/tls/" + agent, Kind: "private_socket", ReadOnly: true, StorageID: agent + "-socket"})
		}
		if name == "certificate-controller" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/self", Kind: "private_socket",
				StorageID: "certificate-controller-self-socket"})
			for agent := range tlsSubjects {
				principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/" + agent,
					Kind: "private_socket", StorageID: agent + "-controller-socket"})
			}
		}
		if identity, ok := identities[name]; ok {
			principal.AuthorizationPrincipal = &identity
			principal.PrincipalDigest = identity.Digest()
			if name != "public-ingress-relay" {
				principal.TLS = &TLSIdentity{PrincipalDigest: identity.Digest(), TrustDomain: "sandbox-runtime.test",
					URI: "spiffe://sandbox-runtime.test/" + name, Usages: []string{"client_auth"}, TTLSeconds: 900,
					RotateAfterSeconds: 500, OverlapSeconds: 30, RevocationMaxStalenessSeconds: 30, ConnectionDrainSeconds: 10}
			}
			if name == "browser-executor-backend" || name == "desktop-executor-backend" {
				principal.TLS.Usages = []string{"server_auth"}
			}
			if name == "product-runtime" {
				principal.TLS.DNSNames = []string{"product.sandbox-runtime.test"}
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
			}
			if name == "gateway-runtime" {
				principal.TLS.DNSNames = []string{"gateway.sandbox-runtime.test"}
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
			}
			if name == "egress-broker-product" {
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
			}
		} else {
			controller := requiredResourceControllers[name]
			principal.ControllingPrincipalDigest = identities[controller].Digest()
		}
		principals = append(principals, principal)
	}
	networks := make([]Network, 0, len(principals)+1)
	for _, principal := range principals {
		if principal.Name == "egress-broker-product" || principal.Name == "product-runtime" ||
			principal.Name == "gateway-runtime" || principal.Name == "public-ingress-relay" ||
			principal.Name == "browser-runtime-role" || principal.Name == "browser-executor-backend" ||
			principal.Name == "desktop-runtime-role" || principal.Name == "desktop-executor-backend" {
			continue
		}
		networks = append(networks, Network{Name: principal.Networks[0], Kind: "role_internal", Internal: true,
			GatewayModeIPv4: "isolated", Principals: []string{principal.Name}})
	}
	networks = append(networks,
		Network{Name: "network-gateway-runtime", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"gateway-runtime"}},
		Network{Name: "ingress-gateway", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"gateway-runtime", "public-ingress-relay"}},
		Network{Name: "ingress-product", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"product-runtime", "public-ingress-relay"}},
		Network{Name: "public-ingress", Kind: "public_ingress", GatewayModeIPv4: "nat",
			Principals: []string{"public-ingress-relay"}},
		Network{Name: "executor-browser", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"browser-executor-backend", "browser-runtime-role"}},
		Network{Name: "executor-desktop", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"desktop-executor-backend", "desktop-runtime-role"}},
		Network{Name: "external-uplink", Kind: "external_uplink", GatewayModeIPv4: "nat", Principals: []string{"egress-broker-product"}},
		Network{Name: "product-internal", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated", Principals: []string{"egress-broker-product", "product-runtime"}},
	)
	sort.Slice(networks, func(first, second int) bool { return networks[first].Name < networks[second].Name })
	for index := range networks {
		networks[index].IPv4Subnet = "172.20." + strconv.Itoa(index) + ".0/24"
		switch networks[index].Name {
		case "public-ingress":
			networks[index].IPv4Subnet = "10.11.0.0/24"
		case "ingress-gateway":
			networks[index].IPv4Subnet = "10.12.0.0/24"
		case "ingress-product":
			networks[index].IPv4Subnet = "10.13.0.0/24"
		}
	}
	uri := func(name string) string {
		for _, principal := range principals {
			if principal.Name == name {
				return principal.TLS.URI
			}
		}
		return ""
	}
	principalByName := make(map[string]Principal, len(principals))
	for _, principal := range principals {
		principalByName[principal.Name] = principal
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
		{ID: "egress-role-product", From: "product-runtime", To: "egress-broker-product", Protocol: "tls", Port: 8443,
			Authentication: "mtls", ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("product-runtime"), ToURI: uri("egress-broker-product"),
			FromPrincipalDigest: identities["product-runtime"].Digest(), ToPrincipalDigest: identities["egress-broker-product"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "executor-browser", From: "browser-runtime-role", To: "browser-executor-backend", Protocol: "wss", Port: 8443,
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			Authentication: "mtls", FromURI: uri("browser-runtime-role"), ToURI: uri("browser-executor-backend"),
			FromPrincipalDigest: identities["browser-runtime-role"].Digest(), ToPrincipalDigest: identities["browser-executor-backend"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "executor-desktop", From: "desktop-runtime-role", To: "desktop-executor-backend", Protocol: "wss", Port: 8443,
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			Authentication: "mtls", FromURI: uri("desktop-runtime-role"), ToURI: uri("desktop-executor-backend"),
			FromPrincipalDigest: identities["desktop-runtime-role"].Digest(), ToPrincipalDigest: identities["desktop-executor-backend"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "certificate-vault", From: "certificate-controller", To: "vault", Protocol: "https", Port: 8200, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("certificate-controller"), ToURI: external[2].URI,
			FromPrincipalDigest: identities["certificate-controller"].Digest(), ExternalIdentityDigest: external[2].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 60},
		{ID: "egress-authority-product", From: "egress-broker-product", To: "egress-policy-authority-product", Protocol: "unix", Authentication: "unix_peer_credentials",
			FromURI: uri("egress-broker-product"), ToURI: uri("egress-policy-authority-product"),
			FromPrincipalDigest: identities["egress-broker-product"].Digest(), ToPrincipalDigest: identities["egress-policy-authority-product"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 5},
		{ID: "egress-dns", From: "egress-broker-product", To: "dns", Protocol: "dns_tcp", Port: 853, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("egress-broker-product"), ToURI: external[0].URI,
			FromPrincipalDigest: identities["egress-broker-product"].Digest(), ExternalIdentityDigest: external[0].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 30},
		{ID: "product-postgres", From: "product-runtime", To: "postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("product-runtime"), ToURI: external[1].URI,
			FromPrincipalDigest: identities["product-runtime"].Digest(), ExternalIdentityDigest: external[1].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
	}
	controllerRecord := principalByName["certificate-controller"]
	edges = append(edges, TrustEdge{ID: "certificate-controller-self", From: "certificate-controller", To: "certificate-controller",
		Protocol: "unix", Authentication: "unix_peer_credentials", FromURI: uri("certificate-controller"),
		ToURI: uri("certificate-controller"), FromPrincipalDigest: controllerRecord.PrincipalDigest,
		ToPrincipalDigest: controllerRecord.PrincipalDigest, TenantScope: "system", MaxConnectionSeconds: 5})
	tlsBindings := make([]TLSAgentBinding, 0, len(tlsSubjects))
	for agent, subject := range tlsSubjects {
		agentRecord, subjectRecord := principalByName[agent], principalByName[subject]
		edgeID := "tls-agent-" + agent
		directory := "/run/tls/" + agent
		tlsBindings = append(tlsBindings, TLSAgentBinding{
			AgentDeployment: agent, AgentPrincipalDigest: agentRecord.PrincipalDigest,
			SubjectDeployment: subject, SubjectPrincipalDigest: subjectRecord.PrincipalDigest,
			AgentUID: agentRecord.UID, AgentGID: agentRecord.GID, SubjectUID: subjectRecord.UID, SubjectGID: subjectRecord.GID,
			SocketDirectory: directory, SocketStorageID: agent + "-socket", SocketPath: directory + "/signer.sock",
			DirectoryMode: 0o710, SocketMode: 0o666, UnixEdgeID: edgeID, IssuerPolicyID: "issuer-" + agent,
			IssuerVaultRole: "vault-" + agent, AgentRequestKeyID: "request-" + agent,
			AgentRequestKeyDigest: testDigest("request-public-key/" + agent), ControllerDeployment: "certificate-controller",
			ControllerUID: controllerRecord.UID, ControllerGID: controllerRecord.GID,
			ControllerSocketDirectory: "/run/certificate-controller/" + agent,
			ControllerSocketStorageID: agent + "-controller-socket",
			ControllerSocketPath:      "/run/certificate-controller/" + agent + "/request.sock",
			ControllerDirectoryMode:   0o710, ControllerSocketMode: 0o666,
			ControllerUnixEdgeID: "certificate-agent-" + agent, CleanupClass: "sockets",
		})
		edges = append(edges, TrustEdge{ID: edgeID, From: subject, To: agent, Protocol: "unix", Authentication: "unix_peer_credentials",
			FromURI: uri(subject), ToURI: uri(agent), FromPrincipalDigest: subjectRecord.PrincipalDigest,
			ToPrincipalDigest: agentRecord.PrincipalDigest, TenantScope: "system", MaxConnectionSeconds: 5})
		edges = append(edges, TrustEdge{ID: "certificate-agent-" + agent, From: agent, To: "certificate-controller",
			Protocol: "unix", Authentication: "unix_peer_credentials", FromURI: uri(agent), ToURI: uri("certificate-controller"),
			FromPrincipalDigest: agentRecord.PrincipalDigest, ToPrincipalDigest: controllerRecord.PrincipalDigest,
			TenantScope: "system", MaxConnectionSeconds: 5})
	}
	sort.Slice(tlsBindings, func(first, second int) bool {
		return tlsBindings[first].AgentDeployment < tlsBindings[second].AgentDeployment
	})
	sort.Slice(edges, func(first, second int) bool { return edges[first].ID < edges[second].ID })
	anchors := []TrustAnchor{
		{ID: "external-server-ca", BundleDigest: testDigest("external-server-ca"), Purpose: "server_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "external-server-ca-artifact", StorageID: "external-server-ca-storage",
			TargetPath: "/run/trust/external-server-ca.pem", WriterAuthority: "operator", Consumers: []string{"certificate-controller", "egress-broker-product", "product-runtime"}},
		{ID: "internal-client-ca", BundleDigest: testDigest("internal-client-ca"), Purpose: "client_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "internal-client-ca-artifact", StorageID: "internal-client-ca-storage",
			TargetPath: "/run/trust/internal-client-ca.pem", WriterAuthority: "operator", Consumers: []string{"browser-executor-backend", "desktop-executor-backend", "egress-broker-product"}},
		{ID: "internal-server-ca", BundleDigest: testDigest("internal-server-ca"), Purpose: "server_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "internal-server-ca-artifact", StorageID: "internal-server-ca-storage",
			TargetPath: "/run/trust/internal-server-ca.pem", WriterAuthority: "operator", Consumers: []string{"browser-runtime-role", "desktop-runtime-role", "gateway-runtime", "product-runtime"}},
		{ID: "vault-client-ca", BundleDigest: testDigest("vault-client-ca"), Purpose: "client_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "vault-client-ca-artifact", StorageID: "vault-client-ca-storage",
			TargetPath: "/run/trust/vault-client-ca.pem", WriterAuthority: "operator", Consumers: []string{"certificate-controller"}},
	}
	ingressBindings := []IngressBinding{
		{ID: "gateway-public", Relay: "public-ingress-relay", RelayPrincipalDigest: ingressIdentity.Digest(),
			PublicListenerID: "gateway-public", Target: "gateway-runtime", TargetPrincipalDigest: identities["gateway-runtime"].Digest(),
			FrontendNetwork: "public-ingress", TrustNetwork: "ingress-gateway", FrontendAddress: "10.11.0.2:8445",
			UpstreamAddress: "10.12.0.3:8445", HostBindAddress: "127.0.0.1:18445",
			MaxConnections: 16, DialTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxLifetimeSeconds: 300,
			DrainTimeoutSeconds: 10, BufferBytes: 4096},
		{ID: "product-public", Relay: "public-ingress-relay", RelayPrincipalDigest: ingressIdentity.Digest(),
			PublicListenerID: "product-public", Target: "product-runtime", TargetPrincipalDigest: identities["product-runtime"].Digest(),
			FrontendNetwork: "public-ingress", TrustNetwork: "ingress-product", FrontendAddress: "10.11.0.2:8444",
			UpstreamAddress: "10.13.0.3:8444", HostBindAddress: "127.0.0.1:18444",
			MaxConnections: 16, DialTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxLifetimeSeconds: 300,
			DrainTimeoutSeconds: 10, BufferBytes: 4096},
	}
	for index := range ingressBindings {
		ingressBindings[index].ConfigurationDigest = ingressBindings[index].Digest()
	}
	profile := Profile{Protocol: ProtocolID, Version: Version, Revision: "slice6-security-1", EnvironmentDigest: environmentDigest,
		PrincipalProfileDigest: principalProfileDigest, Principals: principals, Networks: networks, External: external, TrustEdges: edges, TrustAnchors: anchors,
		IngressBindings: ingressBindings,
		PublicListeners: []PublicListenerBinding{
			{ID: "gateway-public", DeploymentName: "gateway-runtime", PrincipalDigest: principalByName["gateway-runtime"].PrincipalDigest,
				ListenerName: "signaling", Port: 8445, IssuerAnchorID: "internal-server-ca", ClientAuthentication: "none"},
			{ID: "product-public", DeploymentName: "product-runtime", PrincipalDigest: principalByName["product-runtime"].PrincipalDigest,
				ListenerName: "api", Port: 8444, IssuerAnchorID: "internal-server-ca", ClientAuthentication: "none"},
		},
		TLSAgentBindings: tlsBindings,
		CertificateController: CertificateControllerAuthority{DeploymentName: "certificate-controller",
			PrincipalDigest: controllerRecord.PrincipalDigest, UID: controllerRecord.UID, GID: controllerRecord.GID,
			ResponseKeyID: "certificate-controller-response", ResponsePublicKeyDigest: testDigest("certificate-controller-response-key"),
			ManagedPolicyID: "issuer-certificate-controller-self", ManagedVaultRole: "vault-certificate-controller",
			ManagedRequestKeyID: "request-certificate-controller-self", ManagedRequestKeyDigest: testDigest("managed-request-key"),
			BootstrapClientAnchorID: "vault-client-ca",
			SelfSocketDirectory:     "/run/certificate-controller/self", SelfSocketStorageID: "certificate-controller-self-socket",
			SelfSocketPath: "/run/certificate-controller/self/managed.sock", SelfDirectoryMode: 0o700,
			SelfSocketMode: 0o600, SelfUnixEdgeID: "certificate-controller-self"},
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

func TestProfileAllowsReviewedEqualSeccompPolicyAcrossSeparateAgents(t *testing.T) {
	profile := validProfile()
	var first string
	for index := range profile.Principals {
		if profile.Principals[index].Kind != "tls_agent" {
			continue
		}
		if first == "" {
			first = profile.Principals[index].SeccompDigest
			continue
		}
		profile.Principals[index].SeccompDigest = first
		break
	}
	profile.ProfileDigest = profile.Digest()
	if err := profile.Validate(); err != nil {
		t.Fatalf("equal least-privilege seccomp policy must not require fabricated distinct bytes: %v", err)
	}
}

func TestTLSAgentBindingsRejectDriftAndUndeclaredSharing(t *testing.T) {
	tests := map[string]func(*Profile){
		"binding omitted":       func(p *Profile) { p.TLSAgentBindings = p.TLSAgentBindings[1:] },
		"agent digest":          func(p *Profile) { p.TLSAgentBindings[0].AgentPrincipalDigest = testDigest("other-agent") },
		"subject digest":        func(p *Profile) { p.TLSAgentBindings[0].SubjectPrincipalDigest = testDigest("other-subject") },
		"agent uid":             func(p *Profile) { p.TLSAgentBindings[0].AgentUID++ },
		"subject gid":           func(p *Profile) { p.TLSAgentBindings[0].SubjectGID++ },
		"directory mode":        func(p *Profile) { p.TLSAgentBindings[0].DirectoryMode = 0o750 },
		"socket mode":           func(p *Profile) { p.TLSAgentBindings[0].SocketMode = 0o660 },
		"socket path":           func(p *Profile) { p.TLSAgentBindings[0].SocketPath += "-other" },
		"issuer policy missing": func(p *Profile) { p.TLSAgentBindings[0].IssuerPolicyID = "" },
		"issuer role missing":   func(p *Profile) { p.TLSAgentBindings[0].IssuerVaultRole = "" },
		"shared issuer role":    func(p *Profile) { p.TLSAgentBindings[1].IssuerVaultRole = p.TLSAgentBindings[0].IssuerVaultRole },
		"request key shared": func(p *Profile) {
			p.TLSAgentBindings[1].AgentRequestKeyDigest = p.TLSAgentBindings[0].AgentRequestKeyDigest
		},
		"controller authority drift": func(p *Profile) {
			p.CertificateController.ResponsePublicKeyDigest = ""
		},
		"controller socket exchanged": func(p *Profile) { p.TLSAgentBindings[0].ControllerSocketPath += "-other" },
		"controller peer uid":         func(p *Profile) { p.TLSAgentBindings[0].ControllerUID++ },
		"controller storage shared": func(p *Profile) {
			p.TLSAgentBindings[1].ControllerSocketStorageID = p.TLSAgentBindings[0].ControllerSocketStorageID
		},
		"controller endpoint mode": func(p *Profile) { p.TLSAgentBindings[0].ControllerDirectoryMode = 0o750 },
		"controller edge exchanged": func(p *Profile) {
			p.TLSAgentBindings[0].ControllerUnixEdgeID = p.TLSAgentBindings[1].ControllerUnixEdgeID
		},
		"wrong cleanup":   func(p *Profile) { p.TLSAgentBindings[0].CleanupClass = "files" },
		"shared storage":  func(p *Profile) { p.TLSAgentBindings[1].SocketStorageID = p.TLSAgentBindings[0].SocketStorageID },
		"same subject":    func(p *Profile) { p.TLSAgentBindings[1].SubjectDeployment = p.TLSAgentBindings[0].SubjectDeployment },
		"undeclared edge": func(p *Profile) { p.TLSAgentBindings[0].UnixEdgeID = "egress-authority-product" },
		"agent mount read only": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == p.TLSAgentBindings[0].AgentDeployment {
					p.Principals[index].Mounts[0].ReadOnly = true
				}
			}
		},
		"agent TCP listener": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == p.TLSAgentBindings[0].AgentDeployment {
					p.Principals[index].Listeners = []Listener{{Name: "extra", Protocol: "tcp", Port: 9443, Exposure: "trust_edge"}}
				}
			}
		},
		"subject mount writable": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == p.TLSAgentBindings[0].SubjectDeployment {
					p.Principals[index].Mounts[0].ReadOnly = false
				}
			}
		},
		"third party mount": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "certificate-controller" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts, Mount{
						Target: p.TLSAgentBindings[0].SocketDirectory, Kind: "private_socket", ReadOnly: true,
						StorageID: p.TLSAgentBindings[0].SocketStorageID,
					})
				}
			}
		},
		"controller endpoint third party": func(p *Profile) {
			for index := range p.Principals {
				if p.Principals[index].Name == "provider-runtime" {
					p.Principals[index].Mounts = append(p.Principals[index].Mounts, Mount{
						Target: p.TLSAgentBindings[0].ControllerSocketDirectory, Kind: "private_socket", ReadOnly: true,
						StorageID: p.TLSAgentBindings[0].ControllerSocketStorageID,
					})
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
				t.Fatal("TLS agent authority drift was accepted")
			}
		})
	}
}

func TestTLSAgentForSubjectUsesValidatedProfile(t *testing.T) {
	profile := validProfile()
	binding, agent, subject, err := profile.TLSAgentForSubject("egress-broker-product")
	if err != nil || binding.AgentDeployment != "egress-broker-product-tls-agent" ||
		agent.PrincipalDigest != binding.AgentPrincipalDigest || subject.PrincipalDigest != binding.SubjectPrincipalDigest {
		t.Fatalf("TLSAgentForSubject() = %#v, %#v, %#v, %v", binding, agent, subject, err)
	}
	if _, _, _, err := profile.TLSAgentForSubject("certificate-controller"); err == nil {
		t.Fatal("unbound principal received a TLS agent")
	}
	profile.TLSAgentBindings[0].SocketMode = 0o777
	profile.ProfileDigest = profile.Digest()
	if _, _, _, err := profile.TLSAgentForSubject("egress-broker-product"); err == nil {
		t.Fatal("invalid profile produced a TLS agent binding")
	}
}

func TestExecutorTLSBoundaryRequiresExactRoleEdgeAndListener(t *testing.T) {
	for _, subject := range []string{"browser-executor-backend", "desktop-executor-backend"} {
		profile := validProfile()
		binding, agent, backend, caller, err := profile.ExecutorTLSBoundary(subject, 8443)
		if err != nil || binding.SubjectDeployment != subject || agent.Name != binding.AgentDeployment ||
			backend.Name != subject || caller.TLS == nil {
			t.Fatalf("%s boundary: %#v %#v %#v %#v %v", subject, binding, agent, backend, caller, err)
		}
		if _, _, _, _, err := profile.ExecutorTLSBoundary(subject, 8444); err == nil {
			t.Fatal("wrong listener port accepted")
		}
		for index := range profile.TrustEdges {
			if profile.TrustEdges[index].To == subject && profile.TrustEdges[index].Authentication == "mtls" {
				profile.TrustEdges[index].Protocol = "https"
				break
			}
		}
		profile.ProfileDigest = profile.Digest()
		if _, _, _, _, err := profile.ExecutorTLSBoundary(subject, 8443); err == nil {
			t.Fatal("wrong role edge protocol accepted")
		}
		profile = validProfile()
		for index := range profile.Networks {
			if profile.Networks[index].Name == "executor-browser" && subject == "browser-executor-backend" ||
				profile.Networks[index].Name == "executor-desktop" && subject == "desktop-executor-backend" {
				profile.Networks[index].Kind = "role_internal"
			}
		}
		profile.ProfileDigest = profile.Digest()
		if _, _, _, _, err := profile.ExecutorTLSBoundary(subject, 8443); err == nil {
			t.Fatal("non-trust-edge shared network accepted")
		}
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
	for index := range profile.TLSAgentBindings {
		if profile.TLSAgentBindings[index].SubjectDeployment == "egress-broker-product" {
			profile.TLSAgentBindings[index].SubjectDeployment = "product-egress-service"
		}
	}
	for index := range profile.TrustEdges {
		if profile.TrustEdges[index].From == "egress-broker-product" {
			profile.TrustEdges[index].From = "product-egress-service"
		}
		if profile.TrustEdges[index].To == "egress-broker-product" {
			profile.TrustEdges[index].To = "product-egress-service"
		}
	}
	for index := range profile.TrustAnchors {
		for consumer := range profile.TrustAnchors[index].Consumers {
			if profile.TrustAnchors[index].Consumers[consumer] == "egress-broker-product" {
				profile.TrustAnchors[index].Consumers[consumer] = "product-egress-service"
			}
		}
		sort.Strings(profile.TrustAnchors[index].Consumers)
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
