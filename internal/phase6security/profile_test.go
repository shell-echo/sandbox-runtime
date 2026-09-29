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
	for _, role := range []string{"browser-action-ingress", "gateway", "provider-browser", "provider-desktop"} {
		names = append(names, "egress-broker-"+role, "egress-broker-"+role+"-tls-agent", "egress-policy-authority-"+role)
	}
	sort.Strings(names)
	registry, err := securityprincipal.NewRegistryWithPolicyAuthorities(environmentDigest, principalProfileDigest,
		map[string]securityprincipal.Role{"product_egress_broker": securityprincipal.RoleProduct,
			"gateway_egress_broker": securityprincipal.RoleGateway, "browser_action_ingress_egress_broker": securityprincipal.RoleGateway,
			"provider_browser_egress_broker": securityprincipal.RoleProvider, "provider_desktop_egress_broker": securityprincipal.RoleProvider},
		map[string]securityprincipal.Role{"product_policy_authority": "", "gateway_policy_authority": "", "browser_action_ingress_policy_authority": "",
			"provider_browser_policy_authority": "", "provider_desktop_policy_authority": ""})
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
	for _, role := range []string{"browser-action-ingress", "gateway", "provider-browser", "provider-desktop"} {
		identityName := strings.ReplaceAll(role, "-", "_")
		for _, binding := range []struct {
			deployment, name string
			kind             securityprincipal.Kind
		}{
			{"egress-broker-" + role, identityName + "_egress_broker", securityprincipal.KindEgressBroker},
			{"egress-broker-" + role + "-tls-agent", identityName + "_egress_broker_tls_agent", securityprincipal.KindTLSAgent},
			{"egress-policy-authority-" + role, identityName + "_policy_authority", securityprincipal.KindController},
		} {
			bindingRole := securityprincipal.RoleGateway
			if strings.HasPrefix(role, "provider-") {
				bindingRole = securityprincipal.RoleProvider
			}
			if binding.kind == securityprincipal.KindController {
				bindingRole = ""
			}
			identity, identityErr := registry.New(binding.kind, binding.name, bindingRole, testDigest("instance/"+binding.deployment))
			if identityErr != nil {
				panic(identityErr)
			}
			identities[binding.deployment] = identity
		}
	}
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
	for _, role := range []string{"browser-action-ingress", "gateway", "provider-browser", "provider-desktop"} {
		tlsSubjects["egress-broker-"+role+"-tls-agent"] = "egress-broker-" + role
	}
	tlsAgentForSubject := make(map[string]string, len(tlsSubjects))
	for agent, subject := range tlsSubjects {
		tlsAgentForSubject[subject] = agent
	}
	postgresAgents := make(map[string]string)
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		postgresAgents[target.AgentDeployment] = target.SubjectDeployment
	}
	postgresAgentForSubject := map[string]string{}
	for agent, subject := range postgresAgents {
		postgresAgentForSubject[subject] = agent
	}
	principals := make([]Principal, 0, len(names))
	uidGID := Slice6DesiredUIDGID()
	for _, name := range names {
		kind := requiredPrincipals[name]
		networks := []string{"network-" + name}
		external, blocked := false, true
		if name == "product-runtime" {
			networks = []string{"guest-product", "ingress-product", "product-internal", "product-provider", "product-provider-browser", "product-provider-desktop"}
		}
		if name == "gateway-runtime" {
			networks = []string{"gateway-browser-action-ingress", "gateway-internal", "gateway-provider", "gateway-provider-desktop", "ingress-gateway", "network-gateway-runtime"}
		}
		if name == "browser-action-ingress-runtime" {
			networks = []string{"browser-action-ingress-internal", "browser-action-ingress-provider", "gateway-browser-action-ingress", "network-browser-action-ingress-runtime"}
		}
		if name == "provider-runtime" {
			networks = []string{"gateway-provider", "network-provider-runtime", "product-provider"}
		}
		if name == "provider-browser-runtime" {
			networks = []string{"browser-action-ingress-provider", "network-provider-browser-runtime", "product-provider-browser", "provider-browser", "provider-browser-internal"}
		}
		if name == "provider-desktop-runtime" {
			networks = []string{"gateway-provider-desktop", "network-provider-desktop-runtime", "product-provider-desktop", "provider-desktop", "provider-desktop-internal"}
		}
		if name == "guest-runtime" {
			networks = []string{"guest-product", "network-guest-runtime"}
		}
		if name == "browser-runtime-role" {
			networks = []string{"executor-browser", "provider-browser"}
		}
		if name == "browser-executor-backend" {
			networks = []string{"executor-browser"}
		}
		if name == "desktop-runtime-role" {
			networks = []string{"executor-desktop", "provider-desktop"}
		}
		if name == "desktop-executor-backend" {
			networks = []string{"executor-desktop"}
		}
		if name == "egress-broker-product" {
			kind = "egress_broker"
			networks, external, blocked = []string{"external-uplink", "product-internal"}, true, false
		}
		for _, role := range []string{"browser-action-ingress", "gateway", "provider-browser", "provider-desktop"} {
			if name == "egress-broker-"+role {
				kind = "egress_broker"
				networks, external, blocked = []string{"external-uplink-" + role, role + "-internal"}, true, false
				sort.Strings(networks)
			}
			if name == "egress-policy-authority-"+role {
				kind = "controller"
			}
			if name == "egress-broker-"+role+"-tls-agent" {
				kind = "tls_agent"
			}
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
			ImageLocation: "registry", ImageIdentityKind: ImageIdentityOCIManifest, ImagePlatform: "linux/arm64/v8",
			ImageConfigDigest: testDigest("image-config/" + name),
			UID:               uidGID[name][0], GID: uidGID[name][1],
			ReadOnlyRootFilesystem: true, NoNewPrivileges: true, DroppedCapabilities: []string{"ALL"}, SeccompDigest: testDigest("seccomp/" + name),
			Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 250, PIDs: 32}, Networks: networks,
			ExternalUplink: external, DirectEgressBlocked: blocked,
		}
		if name == "browser-executor-backend" || name == "desktop-executor-backend" {
			principal.Listeners = []Listener{{Name: "executor", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}
		}
		if name == "browser-executor-backend" || name == "provider-browser-runtime" {
			principal.Mounts = append(principal.Mounts, Mount{Target: BrowserMuxSocketDirectory, Kind: "private_socket",
				ReadOnly: name == "browser-executor-backend", StorageID: BrowserMuxSocketStorageID})
		}
		if name == "browser-executor-backend" || name == "desktop-executor-backend" || name == "guest-runtime" ||
			name == "browser-runtime-role" || name == "desktop-runtime-role" || name == "product-runtime" ||
			name == "gateway-runtime" || name == "browser-action-ingress-runtime" || name == "provider-runtime" || name == "provider-browser-runtime" ||
			name == "provider-desktop-runtime" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/trust/internal-client-ca.pem", Kind: "trust_anchor",
				ReadOnly: true, StorageID: "internal-client-ca-storage"})
		}
		if name == "product-runtime" {
			principal.Listeners = []Listener{{Name: "api", Protocol: "tcp", Port: 8444, Exposure: "public"},
				{Name: "guest-control", Protocol: "tcp", Port: 8449, Exposure: "trust_edge"}}
		}
		if name == "gateway-runtime" {
			principal.Listeners = []Listener{{Name: "signaling", Protocol: "tcp", Port: 8445, Exposure: "public"}}
		}
		if name == "browser-action-ingress-runtime" {
			principal.Listeners = []Listener{{Name: "action", Protocol: "tcp", Port: 8452, Exposure: "trust_edge"}}
		}
		if name == "public-ingress-relay" {
			principal.Listeners = []Listener{
				{Name: "gateway-public", Protocol: "tcp", Port: 8445, Exposure: "ingress_frontend"},
				{Name: "product-public", Protocol: "tcp", Port: 8444, Exposure: "ingress_frontend"},
			}
		}
		if name == "browser-runtime-role" || name == "desktop-runtime-role" || name == "guest-runtime" || name == "product-runtime" || name == "gateway-runtime" ||
			name == "browser-executor-backend" || name == "desktop-executor-backend" || strings.HasPrefix(name, "egress-broker-") && !strings.HasSuffix(name, "-tls-agent") ||
			name == "provider-runtime" || name == "browser-action-ingress-runtime" || name == "provider-browser-runtime" || name == "provider-desktop-runtime" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/trust/internal-server-ca.pem", Kind: "trust_anchor",
				ReadOnly: true, StorageID: "internal-server-ca-storage"})
		}
		if name == "certificate-controller" || name == "product-runtime" || name == "gateway-runtime" ||
			name == "provider-browser-runtime" || name == "provider-desktop-runtime" ||
			name == "browser-action-ingress-runtime" || strings.HasPrefix(name, "egress-broker-") && !strings.HasSuffix(name, "-tls-agent") {
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
				{Target: "/run/trust/internal-server-ca.pem", Kind: "trust_anchor", ReadOnly: true, StorageID: "internal-server-ca-storage"},
			}
			principal.Listeners = []Listener{{Name: "egress", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}
		}
		if name == "egress-policy-authority-product" {
			principal.Mounts = []Mount{
				{Target: "/run/egress-authority", Kind: "private_socket", StorageID: "product-authority-socket"},
				{Target: "/var/lib/egress-authority", Kind: "persistent_ledger", MaxBytes: 1 << 20, StorageID: "product-authority-ledger"},
			}
		}
		for _, role := range []string{"browser-action-ingress", "gateway", "provider-browser", "provider-desktop"} {
			if name == "egress-broker-"+role {
				principal.Mounts = []Mount{
					{Target: "/run/egress-authority-" + role, Kind: "private_socket", ReadOnly: true, StorageID: role + "-authority-socket"},
					{Target: "/run/trust/external-server-ca.pem", Kind: "trust_anchor", ReadOnly: true, StorageID: "external-server-ca-storage"},
					{Target: "/run/trust/internal-client-ca.pem", Kind: "trust_anchor", ReadOnly: true, StorageID: "internal-client-ca-storage"},
					{Target: "/run/trust/internal-server-ca.pem", Kind: "trust_anchor", ReadOnly: true, StorageID: "internal-server-ca-storage"},
				}
				principal.Listeners = []Listener{{Name: "egress", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}}
			}
			if name == "egress-policy-authority-"+role {
				principal.Mounts = []Mount{
					{Target: "/run/egress-authority-" + role, Kind: "private_socket", StorageID: role + "-authority-socket"},
					{Target: "/var/lib/egress-authority-" + role, Kind: "persistent_ledger", MaxBytes: 1 << 20, StorageID: role + "-authority-ledger"},
				}
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
		if _, postgresAgent := postgresAgents[name]; postgresAgent {
			principal.Mounts = append(principal.Mounts,
				Mount{Target: "/run/tls/" + name, Kind: "private_socket", StorageID: name + "-socket"},
				Mount{Target: "/run/certificate-controller/" + name, Kind: "private_socket", ReadOnly: true, StorageID: name + "-controller-socket"})
		}
		if agent, hasAgent := postgresAgentForSubject[name]; hasAgent {
			principal.Mounts = append(principal.Mounts,
				Mount{Target: "/run/tls/" + agent, Kind: "private_socket", ReadOnly: true, StorageID: agent + "-socket"},
				Mount{Target: "/run/trust/postgres-client-ca.pem", Kind: "trust_anchor", ReadOnly: true, StorageID: "postgres-client-ca-storage"})
		}
		if name == "certificate-controller" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/self", Kind: "private_socket",
				StorageID: "certificate-controller-self-socket"})
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/workload-credential-controller",
				Kind: "private_socket", StorageID: "certificate-credential-controller-socket"})
			for agent := range tlsSubjects {
				principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/" + agent,
					Kind: "private_socket", StorageID: agent + "-controller-socket"})
			}
			for agent := range postgresAgents {
				principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/" + agent,
					Kind: "private_socket", StorageID: agent + "-controller-socket"})
			}
		}
		if name == "workload-credential-controller" {
			principal.Mounts = append(principal.Mounts, Mount{Target: "/run/certificate-controller/workload-credential-controller",
				Kind: "private_socket", ReadOnly: true, StorageID: "certificate-credential-controller-socket"})
			for _, client := range approvedCredentialIssuerClients {
				binding := credentialIssuerBinding(client)
				principal.Mounts = append(principal.Mounts, Mount{Target: binding.SocketDirectory,
					Kind: "private_socket", StorageID: binding.SocketStorageID})
			}
		}
		for _, client := range approvedCredentialIssuerClients {
			if name == client {
				binding := credentialIssuerBinding(client)
				principal.Mounts = append(principal.Mounts, Mount{Target: binding.SocketDirectory,
					Kind: "private_socket", ReadOnly: true, StorageID: binding.SocketStorageID})
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
				principal.TLS.DNSNames = []string{name + ".sandbox-runtime.test"}
			}
			if name == "browser-runtime-role" || name == "desktop-runtime-role" {
				principal.TLS.DNSNames = []string{name + ".sandbox-runtime.test"}
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
				port := 8450
				if name == "desktop-runtime-role" {
					port = 8451
				}
				principal.Listeners = []Listener{{Name: "attach", Protocol: "tcp", Port: port, Exposure: "trust_edge"}}
			}
			if name == "product-runtime" {
				principal.TLS.DNSNames = []string{"product.sandbox-runtime.test"}
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
			}
			if name == "gateway-runtime" {
				principal.TLS.DNSNames = []string{"gateway.sandbox-runtime.test"}
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
			}
			if name == "browser-action-ingress-runtime" {
				principal.TLS.DNSNames = []string{"browser-action-ingress.sandbox-runtime.test"}
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
			}
			if name == "provider-runtime" || name == "provider-browser-runtime" || name == "provider-desktop-runtime" {
				principal.TLS.DNSNames = []string{name + ".sandbox-runtime.test"}
				principal.TLS.Usages = []string{"client_auth", "server_auth"}
				principal.Listeners = append(principal.Listeners,
					Listener{Name: "contract", Protocol: "tcp", Port: 8444, Exposure: "trust_edge"},
					Listener{Name: "private", Protocol: "tcp", Port: 8448, Exposure: "trust_edge"})
				if name == "provider-browser-runtime" {
					principal.Listeners = append(principal.Listeners, Listener{Name: "browser-mux", Protocol: "unix", Exposure: "private_socket"})
				}
			}
			if strings.HasPrefix(name, "egress-broker-") && !strings.HasSuffix(name, "-tls-agent") {
				principal.TLS.DNSNames = []string{name + ".sandbox-runtime.test"}
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
		if principal.Kind == "egress_broker" || principal.Name == "product-runtime" || principal.Name == "guest-runtime" ||
			principal.Name == "gateway-runtime" || principal.Name == "browser-action-ingress-runtime" || principal.Name == "provider-runtime" ||
			principal.Name == "provider-browser-runtime" || principal.Name == "provider-desktop-runtime" || principal.Name == "public-ingress-relay" ||
			principal.Name == "browser-runtime-role" || principal.Name == "browser-executor-backend" ||
			principal.Name == "desktop-runtime-role" || principal.Name == "desktop-executor-backend" {
			continue
		}
		networks = append(networks, Network{Name: principal.Networks[0], Kind: "role_internal", Internal: true,
			GatewayModeIPv4: "isolated", Principals: []string{principal.Name}})
	}
	networks = append(networks,
		Network{Name: "guest-product", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"guest-runtime", "product-runtime"}},
		Network{Name: "network-guest-runtime", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"guest-runtime"}},
		Network{Name: "gateway-provider", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"gateway-runtime", "provider-runtime"}},
		Network{Name: "gateway-browser-action-ingress", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"browser-action-ingress-runtime", "gateway-runtime"}},
		Network{Name: "browser-action-ingress-provider", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"browser-action-ingress-runtime", "provider-browser-runtime"}},
		Network{Name: "network-browser-action-ingress-runtime", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"browser-action-ingress-runtime"}},
		Network{Name: "gateway-provider-desktop", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"gateway-runtime", "provider-desktop-runtime"}},
		Network{Name: "network-provider-runtime", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"provider-runtime"}},
		Network{Name: "network-provider-browser-runtime", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"provider-browser-runtime"}},
		Network{Name: "network-provider-desktop-runtime", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"provider-desktop-runtime"}},
		Network{Name: "product-provider", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"product-runtime", "provider-runtime"}},
		Network{Name: "product-provider-browser", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"product-runtime", "provider-browser-runtime"}},
		Network{Name: "product-provider-desktop", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"product-runtime", "provider-desktop-runtime"}},
		Network{Name: "provider-browser", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"browser-runtime-role", "provider-browser-runtime"}},
		Network{Name: "provider-desktop", Kind: "trust_edge", Internal: true, GatewayModeIPv4: "isolated",
			Principals: []string{"desktop-runtime-role", "provider-desktop-runtime"}},
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
		Network{Name: "external-uplink-browser-action-ingress", Kind: "external_uplink", GatewayModeIPv4: "nat", Principals: []string{"egress-broker-browser-action-ingress"}},
		Network{Name: "external-uplink-gateway", Kind: "external_uplink", GatewayModeIPv4: "nat", Principals: []string{"egress-broker-gateway"}},
		Network{Name: "external-uplink-provider-browser", Kind: "external_uplink", GatewayModeIPv4: "nat", Principals: []string{"egress-broker-provider-browser"}},
		Network{Name: "external-uplink-provider-desktop", Kind: "external_uplink", GatewayModeIPv4: "nat", Principals: []string{"egress-broker-provider-desktop"}},
		Network{Name: "browser-action-ingress-internal", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated", Principals: []string{"browser-action-ingress-runtime", "egress-broker-browser-action-ingress"}},
		Network{Name: "gateway-internal", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated", Principals: []string{"egress-broker-gateway", "gateway-runtime"}},
		Network{Name: "provider-browser-internal", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated", Principals: []string{"egress-broker-provider-browser", "provider-browser-runtime"}},
		Network{Name: "provider-desktop-internal", Kind: "role_internal", Internal: true, GatewayModeIPv4: "isolated", Principals: []string{"egress-broker-provider-desktop", "provider-desktop-runtime"}},
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
		case "gateway-provider":
			networks[index].IPv4Subnet = "10.14.0.0/24"
		case "product-provider":
			networks[index].IPv4Subnet = "10.15.0.0/24"
		case "gateway-browser-action-ingress":
			networks[index].IPv4Subnet = "10.21.0.0/24"
		case "browser-action-ingress-provider":
			networks[index].IPv4Subnet = "10.25.0.0/24"
		case "gateway-provider-desktop":
			networks[index].IPv4Subnet = "10.22.0.0/24"
		case "product-provider-browser":
			networks[index].IPv4Subnet = "10.23.0.0/24"
		case "product-provider-desktop":
			networks[index].IPv4Subnet = "10.24.0.0/24"
		case "guest-product":
			networks[index].IPv4Subnet = "10.16.0.0/24"
		case "provider-browser":
			networks[index].IPv4Subnet = "10.17.0.0/24"
		case "provider-desktop":
			networks[index].IPv4Subnet = "10.18.0.0/24"
		case "executor-browser":
			networks[index].IPv4Subnet = "10.19.0.0/24"
		case "executor-desktop":
			networks[index].IPv4Subnet = "10.20.0.0/24"
		case "browser-action-ingress-internal":
			networks[index].IPv4Subnet = "10.26.0.0/24"
		case "gateway-internal":
			networks[index].IPv4Subnet = "10.27.0.0/24"
		case "product-internal":
			networks[index].IPv4Subnet = "10.28.0.0/24"
		case "provider-browser-internal":
			networks[index].IPv4Subnet = "10.29.0.0/24"
		case "provider-desktop-internal":
			networks[index].IPv4Subnet = "10.30.0.0/24"
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
		{Name: "action-history-postgres", ImageReference: "registry.example.test/postgres@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/action-history-postgres", DNSNames: []string{"action-history.sandbox-runtime.test"}, IngressEdges: []string{"browser-action-history-postgres", "egress-browser-action-history-postgres"}},
		{Name: "capacity-valkey", ImageReference: "registry.example.test/valkey@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/capacity-valkey", DNSNames: []string{"capacity.sandbox-runtime.test"}, IngressEdges: []string{"browser-capacity-valkey", "egress-browser-capacity-valkey", "egress-gateway-capacity-valkey", "gateway-capacity-valkey"}},
		{Name: "dns", ImageReference: "registry.example.test/dns@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/dns", DNSNames: []string{"dns.sandbox-runtime.test"}, IngressEdges: []string{"egress-dns", "egress-dns-browser-action-ingress", "egress-dns-gateway", "egress-dns-provider-browser", "egress-dns-provider-desktop"}},
		{Name: "postgres", ImageReference: "registry.example.test/postgres@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/postgres", DNSNames: []string{"postgres.sandbox-runtime.test"}, IngressEdges: []string{"egress-provider-browser-postgres", "egress-provider-desktop-postgres", "product-postgres", "provider-browser-postgres", "provider-desktop-postgres"}},
		{Name: "vault", ImageReference: "registry.example.test/vault@" + digest, ImageDigest: digest, URI: "spiffe://sandbox-runtime.test/external/vault", DNSNames: []string{"vault.sandbox-runtime.test"}, IngressEdges: []string{"certificate-vault"}},
	}
	for index := range external {
		external[index].ImageLocation = "registry"
		external[index].ImageIdentityKind = ImageIdentityOCIManifest
		external[index].ImagePlatform = "linux/arm64/v8"
		external[index].ImageConfigDigest = testDigest("external-image-config/" + external[index].Name)
		external[index].IdentityDigest = external[index].Digest()
	}
	externalByName := make(map[string]ExternalService, len(external))
	for _, service := range external {
		externalByName[service.Name] = service
	}
	edges := []TrustEdge{
		{ID: "product-provider-contract", From: "product-runtime", To: "provider-runtime", Protocol: "https", Port: 8444,
			TargetAddress: "10.15.0.3:8444", RoutePath: "/v1", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("product-runtime"), ToURI: uri("provider-runtime"),
			FromPrincipalDigest: identities["product-runtime"].Digest(), ToPrincipalDigest: identities["provider-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "gateway-provider-private", From: "gateway-runtime", To: "provider-runtime", Protocol: "wss", Port: 8448,
			TargetAddress: "10.14.0.3:8448", RoutePath: "/private/terminal", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("gateway-runtime"), ToURI: uri("provider-runtime"),
			FromPrincipalDigest: identities["gateway-runtime"].Digest(), ToPrincipalDigest: identities["provider-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "product-provider-browser-contract", From: "product-runtime", To: "provider-browser-runtime", Protocol: "https", Port: 8444,
			TargetAddress: "10.23.0.3:8444", RoutePath: "/v1", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("product-runtime"), ToURI: uri("provider-browser-runtime"),
			FromPrincipalDigest: identities["product-runtime"].Digest(), ToPrincipalDigest: identities["provider-browser-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "product-provider-desktop-contract", From: "product-runtime", To: "provider-desktop-runtime", Protocol: "https", Port: 8444,
			TargetAddress: "10.24.0.3:8444", RoutePath: "/v1", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("product-runtime"), ToURI: uri("provider-desktop-runtime"),
			FromPrincipalDigest: identities["product-runtime"].Digest(), ToPrincipalDigest: identities["provider-desktop-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "gateway-browser-action-ingress", From: "gateway-runtime", To: "browser-action-ingress-runtime", Protocol: "wss", Port: 8452,
			TargetAddress: "10.21.0.3:8452", RoutePath: "/browser/action", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("gateway-runtime"), ToURI: uri("browser-action-ingress-runtime"),
			FromPrincipalDigest: identities["gateway-runtime"].Digest(), ToPrincipalDigest: identities["browser-action-ingress-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "browser-action-ingress-provider-private", From: "browser-action-ingress-runtime", To: "provider-browser-runtime", Protocol: "wss", Port: 8448,
			TargetAddress: "10.25.0.3:8448", RoutePath: "/private/browser", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("browser-action-ingress-runtime"), ToURI: uri("provider-browser-runtime"),
			FromPrincipalDigest: identities["browser-action-ingress-runtime"].Digest(), ToPrincipalDigest: identities["provider-browser-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "gateway-provider-desktop-private", From: "gateway-runtime", To: "provider-desktop-runtime", Protocol: "wss", Port: 8448,
			TargetAddress: "10.22.0.3:8448", RoutePath: "/desktop", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("gateway-runtime"), ToURI: uri("provider-desktop-runtime"),
			FromPrincipalDigest: identities["gateway-runtime"].Digest(), ToPrincipalDigest: identities["provider-desktop-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "guest-product", From: "guest-runtime", To: "product-runtime", Protocol: "wss", Port: 8449,
			TargetAddress: "10.16.0.3:8449", RoutePath: "/agent", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("guest-runtime"), ToURI: uri("product-runtime"),
			FromPrincipalDigest: identities["guest-runtime"].Digest(), ToPrincipalDigest: identities["product-runtime"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "provider-browser-attach", From: "provider-browser-runtime", To: "browser-runtime-role", Protocol: "wss", Port: 8450,
			TargetAddress: "10.17.0.3:8450", RoutePath: "/executor", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("provider-browser-runtime"), ToURI: uri("browser-runtime-role"),
			FromPrincipalDigest: identities["provider-browser-runtime"].Digest(), ToPrincipalDigest: identities["browser-runtime-role"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "provider-desktop-attach", From: "provider-desktop-runtime", To: "desktop-runtime-role", Protocol: "wss", Port: 8451,
			TargetAddress: "10.18.0.3:8451", RoutePath: "/executor", Authentication: "mtls",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("provider-desktop-runtime"), ToURI: uri("desktop-runtime-role"),
			FromPrincipalDigest: identities["provider-desktop-runtime"].Digest(), ToPrincipalDigest: identities["desktop-runtime-role"].Digest(),
			TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "egress-role-product", From: "product-runtime", To: "egress-broker-product", Protocol: "tls", Port: 8443,
			TargetAddress:  "10.28.0.3:8443",
			Authentication: "mtls", ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("product-runtime"), ToURI: uri("egress-broker-product"),
			FromPrincipalDigest: identities["product-runtime"].Digest(), ToPrincipalDigest: identities["egress-broker-product"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "egress-role-gateway", From: "gateway-runtime", To: "egress-broker-gateway", Protocol: "tls", Port: 8443,
			TargetAddress:  "10.27.0.3:8443",
			Authentication: "mtls", ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("gateway-runtime"), ToURI: uri("egress-broker-gateway"),
			FromPrincipalDigest: identities["gateway-runtime"].Digest(), ToPrincipalDigest: identities["egress-broker-gateway"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "egress-role-browser-action-ingress", From: "browser-action-ingress-runtime", To: "egress-broker-browser-action-ingress", Protocol: "tls", Port: 8443,
			TargetAddress:  "10.26.0.3:8443",
			Authentication: "mtls", ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			FromURI: uri("browser-action-ingress-runtime"), ToURI: uri("egress-broker-browser-action-ingress"),
			FromPrincipalDigest: identities["browser-action-ingress-runtime"].Digest(), ToPrincipalDigest: identities["egress-broker-browser-action-ingress"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "executor-browser", From: "browser-runtime-role", To: "browser-executor-backend", Protocol: "wss", Port: 8443,
			TargetAddress: "10.19.0.3:8443", RoutePath: "/executor",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			Authentication: "mtls", FromURI: uri("browser-runtime-role"), ToURI: uri("browser-executor-backend"),
			FromPrincipalDigest: identities["browser-runtime-role"].Digest(), ToPrincipalDigest: identities["browser-executor-backend"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "executor-desktop", From: "desktop-runtime-role", To: "desktop-executor-backend", Protocol: "wss", Port: 8443,
			TargetAddress: "10.20.0.3:8443", RoutePath: "/executor",
			ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
			Authentication: "mtls", FromURI: uri("desktop-runtime-role"), ToURI: uri("desktop-executor-backend"),
			FromPrincipalDigest: identities["desktop-runtime-role"].Digest(), ToPrincipalDigest: identities["desktop-executor-backend"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 300},
		{ID: "certificate-vault", From: "certificate-controller", To: "vault", Protocol: "https", Port: 8200, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("certificate-controller"), ToURI: externalByName["vault"].URI,
			FromPrincipalDigest: identities["certificate-controller"].Digest(), ExternalIdentityDigest: externalByName["vault"].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 60},
		{ID: "egress-authority-product", From: "egress-broker-product", To: "egress-policy-authority-product", Protocol: "unix", Authentication: "unix_peer_credentials",
			FromURI: uri("egress-broker-product"), ToURI: uri("egress-policy-authority-product"),
			FromPrincipalDigest: identities["egress-broker-product"].Digest(), ToPrincipalDigest: identities["egress-policy-authority-product"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 5},
		{ID: "egress-authority-gateway", From: "egress-broker-gateway", To: "egress-policy-authority-gateway", Protocol: "unix", Authentication: "unix_peer_credentials",
			FromURI: uri("egress-broker-gateway"), ToURI: uri("egress-policy-authority-gateway"),
			FromPrincipalDigest: identities["egress-broker-gateway"].Digest(), ToPrincipalDigest: identities["egress-policy-authority-gateway"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 5},
		{ID: "egress-authority-browser-action-ingress", From: "egress-broker-browser-action-ingress", To: "egress-policy-authority-browser-action-ingress", Protocol: "unix", Authentication: "unix_peer_credentials",
			FromURI: uri("egress-broker-browser-action-ingress"), ToURI: uri("egress-policy-authority-browser-action-ingress"),
			FromPrincipalDigest: identities["egress-broker-browser-action-ingress"].Digest(), ToPrincipalDigest: identities["egress-policy-authority-browser-action-ingress"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 5},
		{ID: BrowserMuxUnixEdgeID, From: "browser-executor-backend", To: "provider-browser-runtime", Protocol: "unix", Authentication: "unix_peer_credentials",
			FromURI: uri("browser-executor-backend"), ToURI: uri("provider-browser-runtime"),
			FromPrincipalDigest: identities["browser-executor-backend"].Digest(), ToPrincipalDigest: identities["provider-browser-runtime"].Digest(),
			TenantScope: "system", MaxConnectionSeconds: 10},
		{ID: "egress-dns", From: "egress-broker-product", To: "dns", Protocol: "dns_tcp", Port: 853, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("egress-broker-product"), ToURI: externalByName["dns"].URI,
			FromPrincipalDigest: identities["egress-broker-product"].Digest(), ExternalIdentityDigest: externalByName["dns"].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 30},
		{ID: "egress-dns-browser-action-ingress", From: "egress-broker-browser-action-ingress", To: "dns", Protocol: "dns_tcp", Port: 853, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("egress-broker-browser-action-ingress"), ToURI: externalByName["dns"].URI,
			FromPrincipalDigest: identities["egress-broker-browser-action-ingress"].Digest(), ExternalIdentityDigest: externalByName["dns"].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 30},
		{ID: "egress-dns-gateway", From: "egress-broker-gateway", To: "dns", Protocol: "dns_tcp", Port: 853, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("egress-broker-gateway"), ToURI: externalByName["dns"].URI,
			FromPrincipalDigest: identities["egress-broker-gateway"].Digest(), ExternalIdentityDigest: externalByName["dns"].IdentityDigest, CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 30},
		{ID: "product-postgres", From: "product-runtime", To: "postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("product-runtime"), ToURI: externalByName["postgres"].URI,
			FromPrincipalDigest: identities["product-runtime"].Digest(), ExternalIdentityDigest: externalByName["postgres"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "provider-browser-postgres", From: "provider-browser-runtime", To: "postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("provider-browser-runtime"), ToURI: externalByName["postgres"].URI,
			FromPrincipalDigest: identities["provider-browser-runtime"].Digest(), ExternalIdentityDigest: externalByName["postgres"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "provider-desktop-postgres", From: "provider-desktop-runtime", To: "postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("provider-desktop-runtime"), ToURI: externalByName["postgres"].URI,
			FromPrincipalDigest: identities["provider-desktop-runtime"].Digest(), ExternalIdentityDigest: externalByName["postgres"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "browser-action-history-postgres", From: "browser-action-ingress-runtime", To: "action-history-postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("browser-action-ingress-runtime"), ToURI: externalByName["action-history-postgres"].URI,
			FromPrincipalDigest: identities["browser-action-ingress-runtime"].Digest(), ExternalIdentityDigest: externalByName["action-history-postgres"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "browser-capacity-valkey", From: "browser-action-ingress-runtime", To: "capacity-valkey", Protocol: "tls", Port: 6379, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("browser-action-ingress-runtime"), ToURI: externalByName["capacity-valkey"].URI,
			FromPrincipalDigest: identities["browser-action-ingress-runtime"].Digest(), ExternalIdentityDigest: externalByName["capacity-valkey"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "gateway-capacity-valkey", From: "gateway-runtime", To: "capacity-valkey", Protocol: "tls", Port: 6379, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("gateway-runtime"), ToURI: externalByName["capacity-valkey"].URI,
			FromPrincipalDigest: identities["gateway-runtime"].Digest(), ExternalIdentityDigest: externalByName["capacity-valkey"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "egress-browser-action-history-postgres", From: "egress-broker-browser-action-ingress", To: "action-history-postgres", Protocol: "postgres", Port: 5432, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("egress-broker-browser-action-ingress"), ToURI: externalByName["action-history-postgres"].URI,
			FromPrincipalDigest: identities["egress-broker-browser-action-ingress"].Digest(), ExternalIdentityDigest: externalByName["action-history-postgres"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "egress-browser-capacity-valkey", From: "egress-broker-browser-action-ingress", To: "capacity-valkey", Protocol: "tls", Port: 6379, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("egress-broker-browser-action-ingress"), ToURI: externalByName["capacity-valkey"].URI,
			FromPrincipalDigest: identities["egress-broker-browser-action-ingress"].Digest(), ExternalIdentityDigest: externalByName["capacity-valkey"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		{ID: "egress-gateway-capacity-valkey", From: "egress-broker-gateway", To: "capacity-valkey", Protocol: "tls", Port: 6379, Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri("egress-broker-gateway"), ToURI: externalByName["capacity-valkey"].URI,
			FromPrincipalDigest: identities["egress-broker-gateway"].Digest(), ExternalIdentityDigest: externalByName["capacity-valkey"].IdentityDigest, CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
	}
	for index, role := range []string{"provider-browser", "provider-desktop"} {
		provider, broker, authority := role+"-runtime", "egress-broker-"+role, "egress-policy-authority-"+role
		address := "10.29.0.3:8443"
		if index == 1 {
			address = "10.30.0.3:8443"
		}
		edges = append(edges,
			TrustEdge{ID: "egress-role-" + role, From: provider, To: broker, Protocol: "tls", Port: 8443,
				TargetAddress: address, Authentication: "mtls", ServerAnchorID: "internal-server-ca", ClientAnchorID: "internal-client-ca",
				FromURI: uri(provider), ToURI: uri(broker), FromPrincipalDigest: identities[provider].Digest(),
				ToPrincipalDigest: identities[broker].Digest(), TenantScope: "system", MaxConnectionSeconds: 300},
			TrustEdge{ID: "egress-authority-" + role, From: broker, To: authority, Protocol: "unix", Authentication: "unix_peer_credentials",
				FromURI: uri(broker), ToURI: uri(authority), FromPrincipalDigest: identities[broker].Digest(),
				ToPrincipalDigest: identities[authority].Digest(), TenantScope: "system", MaxConnectionSeconds: 5},
			TrustEdge{ID: "egress-dns-" + role, From: broker, To: "dns", Protocol: "dns_tcp", Port: 853,
				Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri(broker), ToURI: externalByName["dns"].URI,
				FromPrincipalDigest: identities[broker].Digest(), ExternalIdentityDigest: externalByName["dns"].IdentityDigest,
				CrossDomain: true, TenantScope: "system", MaxConnectionSeconds: 30},
			TrustEdge{ID: "egress-" + role + "-postgres", From: broker, To: "postgres", Protocol: "postgres", Port: 5432,
				Authentication: "mtls", ServerAnchorID: "external-server-ca", FromURI: uri(broker), ToURI: externalByName["postgres"].URI,
				FromPrincipalDigest: identities[broker].Digest(), ExternalIdentityDigest: externalByName["postgres"].IdentityDigest,
				CrossDomain: true, TenantScope: "bound", MaxConnectionSeconds: 300},
		)
	}
	controllerRecord := principalByName["certificate-controller"]
	edges = append(edges, TrustEdge{ID: "certificate-controller-self", From: "certificate-controller", To: "certificate-controller",
		Protocol: "unix", Authentication: "unix_peer_credentials", FromURI: uri("certificate-controller"),
		ToURI: uri("certificate-controller"), FromPrincipalDigest: controllerRecord.PrincipalDigest,
		ToPrincipalDigest: controllerRecord.PrincipalDigest, TenantScope: "system", MaxConnectionSeconds: 5})
	credentialRecord := principalByName["workload-credential-controller"]
	credentialSockets, credentialSocketsErr := BuildCredentialIssuerSocketBindings(principals)
	if credentialSocketsErr != nil {
		panic(credentialSocketsErr)
	}
	for _, binding := range credentialSockets {
		clientRecord := principalByName[binding.ClientDeployment]
		edges = append(edges, TrustEdge{ID: binding.UnixEdgeID, From: clientRecord.Name, To: credentialRecord.Name,
			Protocol: "unix", Authentication: "unix_peer_credentials", FromURI: uri(clientRecord.Name),
			ToURI: uri(credentialRecord.Name), FromPrincipalDigest: clientRecord.PrincipalDigest,
			ToPrincipalDigest: credentialRecord.PrincipalDigest, TenantScope: "system", MaxConnectionSeconds: 5})
	}
	edges = append(edges, TrustEdge{ID: "certificate-credential-controller", From: credentialRecord.Name, To: controllerRecord.Name,
		Protocol: "unix", Authentication: "unix_peer_credentials", FromURI: uri(credentialRecord.Name),
		ToURI: uri(controllerRecord.Name), FromPrincipalDigest: credentialRecord.PrincipalDigest,
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
	postgresBindings := make([]PostgresClientAgentBinding, 0, 9)
	for _, target := range Slice6DesiredFinalPostgresSignerTargets() {
		owner, agent := target.SubjectDeployment, target.AgentDeployment
		agentRecord, ownerRecord := principalByName[agent], principalByName[owner]
		base := TLSAgentBinding{AgentDeployment: agent, AgentPrincipalDigest: agentRecord.PrincipalDigest,
			SubjectDeployment: owner, SubjectPrincipalDigest: ownerRecord.PrincipalDigest,
			AgentUID: agentRecord.UID, AgentGID: agentRecord.GID, SubjectUID: ownerRecord.UID, SubjectGID: ownerRecord.GID,
			SocketDirectory: "/run/tls/" + agent, SocketStorageID: agent + "-socket",
			SocketPath: "/run/tls/" + agent + "/signer.sock", DirectoryMode: 0o710, SocketMode: 0o666,
			UnixEdgeID: "tls-agent-" + agent, IssuerPolicyID: "issuer-" + agent, IssuerVaultRole: "vault-" + agent,
			AgentRequestKeyID: "request-" + agent, AgentRequestKeyDigest: testDigest("request-public-key/" + agent),
			ControllerDeployment: "certificate-controller", ControllerUID: controllerRecord.UID, ControllerGID: controllerRecord.GID,
			ControllerSocketDirectory: "/run/certificate-controller/" + agent,
			ControllerSocketStorageID: agent + "-controller-socket",
			ControllerSocketPath:      "/run/certificate-controller/" + agent + "/request.sock",
			ControllerDirectoryMode:   0o710, ControllerSocketMode: 0o666,
			ControllerUnixEdgeID: "certificate-agent-" + agent, CleanupClass: "sockets"}
		postgresBindings = append(postgresBindings, PostgresClientAgentBinding{TLSAgentBinding: base,
			CommonName: postgresClientCommonName(target.SQLRole), IssuerAnchorID: postgresClientIssuerAnchorID})
		edges = append(edges,
			TrustEdge{ID: base.UnixEdgeID, From: owner, To: agent, Protocol: "unix", Authentication: "unix_peer_credentials",
				FromURI: uri(owner), ToURI: uri(agent), FromPrincipalDigest: ownerRecord.PrincipalDigest,
				ToPrincipalDigest: agentRecord.PrincipalDigest, TenantScope: "system", MaxConnectionSeconds: 5},
			TrustEdge{ID: base.ControllerUnixEdgeID, From: agent, To: "certificate-controller", Protocol: "unix", Authentication: "unix_peer_credentials",
				FromURI: uri(agent), ToURI: uri("certificate-controller"), FromPrincipalDigest: agentRecord.PrincipalDigest,
				ToPrincipalDigest: controllerRecord.PrincipalDigest, TenantScope: "system", MaxConnectionSeconds: 5})
	}
	sort.Slice(edges, func(first, second int) bool { return edges[first].ID < edges[second].ID })
	anchors := []TrustAnchor{
		{ID: "external-server-ca", BundleDigest: testDigest("external-server-ca"), Purpose: "server_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "external-server-ca-artifact", StorageID: "external-server-ca-storage",
			TargetPath: "/run/trust/external-server-ca.pem", WriterAuthority: "operator", Consumers: []string{"browser-action-ingress-runtime", "certificate-controller", "egress-broker-browser-action-ingress", "egress-broker-gateway", "egress-broker-product", "egress-broker-provider-browser", "egress-broker-provider-desktop", "gateway-runtime", "product-runtime", "provider-browser-runtime", "provider-desktop-runtime"}},
		{ID: "internal-client-ca", BundleDigest: testDigest("internal-client-ca"), Purpose: "client_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "internal-client-ca-artifact", StorageID: "internal-client-ca-storage",
			TargetPath: "/run/trust/internal-client-ca.pem", WriterAuthority: "operator", Consumers: []string{"browser-action-ingress-runtime", "browser-executor-backend", "browser-runtime-role", "desktop-executor-backend", "desktop-runtime-role", "egress-broker-browser-action-ingress", "egress-broker-gateway", "egress-broker-product", "egress-broker-provider-browser", "egress-broker-provider-desktop", "gateway-runtime", "guest-runtime", "product-runtime", "provider-browser-runtime", "provider-desktop-runtime", "provider-runtime"}},
		{ID: "internal-server-ca", BundleDigest: testDigest("internal-server-ca"), Purpose: "server_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "internal-server-ca-artifact", StorageID: "internal-server-ca-storage",
			TargetPath: "/run/trust/internal-server-ca.pem", WriterAuthority: "operator", Consumers: []string{"browser-action-ingress-runtime", "browser-executor-backend", "browser-runtime-role", "desktop-executor-backend", "desktop-runtime-role", "egress-broker-browser-action-ingress", "egress-broker-gateway", "egress-broker-product", "egress-broker-provider-browser", "egress-broker-provider-desktop", "gateway-runtime", "guest-runtime", "product-runtime", "provider-browser-runtime", "provider-desktop-runtime", "provider-runtime"}},
		{ID: "postgres-client-ca", BundleDigest: testDigest("postgres-client-ca"), Purpose: "client_verification",
			TrustDomain: "sandbox-runtime.test", ArtifactID: "postgres-client-ca-artifact", StorageID: "postgres-client-ca-storage",
			TargetPath: "/run/trust/postgres-client-ca.pem", WriterAuthority: "operator",
			Consumers: []string{"gateway-runtime", "product-migration-job", "product-runtime", "provider-browser-migration-job", "provider-browser-runtime", "provider-desktop-migration-job", "provider-desktop-runtime", "provider-migration-job", "provider-runtime"}},
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
		PrincipalProfileDigest: principalProfileDigest, Principals: principals,
		SandboxIdentitySlots: []SandboxIdentitySlot{
			{SlotID: "browser-0000", Template: "browser-sandbox-runtime",
				TemplateDigest:  SandboxTemplateDigest(principalByName["browser-sandbox-runtime"]),
				OwnerDeployment: "provider-browser-runtime", OwnerPrincipalDigest: principalByName["provider-browser-runtime"].PrincipalDigest,
				WorkloadUID: 41000, WorkloadGID: 51000, GatewayUID: 43000, GatewayGID: 53000},
			{SlotID: "desktop-0000", Template: "desktop-sandbox-runtime",
				TemplateDigest:  SandboxTemplateDigest(principalByName["desktop-sandbox-runtime"]),
				OwnerDeployment: "provider-desktop-runtime", OwnerPrincipalDigest: principalByName["provider-desktop-runtime"].PrincipalDigest,
				WorkloadUID: 42000, WorkloadGID: 52000, GatewayUID: 44000, GatewayGID: 54000},
		},
		ProviderDatabases: []ProviderDatabaseBinding{
			{OwnerDeployment: "provider-browser-runtime", OwnerPrincipalDigest: principalByName["provider-browser-runtime"].PrincipalDigest,
				Template: "browser-sandbox-runtime", Namespace: "browser-production", ControllerID: "browser-provider-1",
				ServiceName: "postgres", ServiceIdentityDigest: externalByName["postgres"].IdentityDigest,
				TrustEdgeID: "provider-browser-postgres", EgressPolicyID: "provider-browser-egress",
				BrokerDeployment: "egress-broker-provider-browser", BrokerRoleEdgeID: "egress-role-provider-browser",
				BrokerExternalEdgeID: "egress-provider-browser-postgres",
				DatabaseName:         "provider_browser", RuntimeRole: "browser_provider_runtime",
				ServerAuthPolicyID:  postgresServerAuthPolicyID,
				RuntimeDSNBindingID: "browser-provider-runtime-dsn"},
			{OwnerDeployment: "provider-desktop-runtime", OwnerPrincipalDigest: principalByName["provider-desktop-runtime"].PrincipalDigest,
				Template: "desktop-sandbox-runtime", Namespace: "desktop-production", ControllerID: "desktop-controller-1",
				ServiceName: "postgres", ServiceIdentityDigest: externalByName["postgres"].IdentityDigest,
				TrustEdgeID: "provider-desktop-postgres", EgressPolicyID: "provider-desktop-egress",
				BrokerDeployment: "egress-broker-provider-desktop", BrokerRoleEdgeID: "egress-role-provider-desktop",
				BrokerExternalEdgeID: "egress-provider-desktop-postgres",
				DatabaseName:         "provider_desktop", RuntimeRole: "desktop_provider_runtime",
				ServerAuthPolicyID:  postgresServerAuthPolicyID,
				RuntimeDSNBindingID: "desktop-provider-runtime-dsn"},
		},
		PostgresServerAuth: PostgresServerAuthPolicy{ID: postgresServerAuthPolicyID,
			Scope: postgresServerAuthScope, ServiceName: "postgres",
			ServiceIdentityDigest: externalByName["postgres"].IdentityDigest,
			HBAArtifactID:         "provider-postgres-hba", ClientCAAnchorID: postgresClientIssuerAnchorID,
			IngressCIDR: "172.17.0.1/32"},
		Components: []Component{{Name: "desktop-broker", ParentDeployment: "desktop-sandbox-runtime",
			Executable: "/usr/local/libexec/sandbox-runtime/desktop-broker", ExecutableDigest: testDigest("desktop-broker-executable"),
			Argv:   []string{"/usr/local/libexec/sandbox-runtime/desktop-broker", "serve"},
			Socket: "/tmp/sandbox-runtime-desktop-broker.sock", BrokerProtocol: "sandbox.runtime/desktop-broker/v1",
			SessionProtocol: "sandbox.runtime/desktop-session.v2"}},
		Networks: networks, External: external, TrustEdges: edges, TrustAnchors: anchors,
		IngressBindings: ingressBindings,
		PublicListeners: []PublicListenerBinding{
			{ID: "gateway-public", DeploymentName: "gateway-runtime", PrincipalDigest: principalByName["gateway-runtime"].PrincipalDigest,
				ListenerName: "signaling", Port: 8445, IssuerAnchorID: "internal-server-ca", ClientAuthentication: "none"},
			{ID: "product-public", DeploymentName: "product-runtime", PrincipalDigest: principalByName["product-runtime"].PrincipalDigest,
				ListenerName: "api", Port: 8444, IssuerAnchorID: "internal-server-ca", ClientAuthentication: "none"},
		},
		TLSAgentBindings:        tlsBindings,
		CredentialIssuerSockets: credentialSockets,
		PostgresClientAgents:    postgresBindings,
		CertificateController: CertificateControllerAuthority{DeploymentName: "certificate-controller",
			PrincipalDigest: controllerRecord.PrincipalDigest, UID: controllerRecord.UID, GID: controllerRecord.GID,
			ResponseKeyID: "certificate-controller-response", ResponsePublicKeyDigest: testDigest("certificate-controller-response-key"),
			ManagedPolicyID: "issuer-certificate-controller-self", ManagedVaultRole: "vault-certificate-controller",
			ManagedRequestKeyID: "request-certificate-controller-self", ManagedRequestKeyDigest: testDigest("managed-request-key"),
			BootstrapClientAnchorID: "vault-client-ca",
			SelfSocketDirectory:     "/run/certificate-controller/self", SelfSocketStorageID: "certificate-controller-self-socket",
			SelfSocketPath: "/run/certificate-controller/self/managed.sock", SelfDirectoryMode: 0o700,
			SelfSocketMode: 0o600, SelfUnixEdgeID: "certificate-controller-self",
			CredentialController: CredentialControllerManagedAuthority{PolicyID: "issuer-credential-controller-managed",
				VaultRole: "vault-credential-controller", RequestKeyID: "request-credential-controller-managed",
				RequestKeyDigest: testDigest("request-public-key/workload-credential-controller"),
				SocketDirectory:  "/run/certificate-controller/workload-credential-controller",
				SocketStorageID:  "certificate-credential-controller-socket",
				SocketPath:       "/run/certificate-controller/workload-credential-controller/request.sock",
				DirectoryMode:    0o710, SocketMode: 0o666, UnixEdgeID: "certificate-credential-controller"}},
		EgressPolicies: []EgressPolicy{{ID: "browser-action-ingress-egress", Revision: "policy-1", Principal: "browser-action-ingress-runtime", Broker: "egress-broker-browser-action-ingress",
			PrincipalDigest: identities["browser-action-ingress-runtime"].Digest(), BrokerDigest: identities["egress-broker-browser-action-ingress"].Digest(),
			Authority: PolicyAuthority{DeploymentName: "egress-policy-authority-browser-action-ingress", AuthorizationName: "browser_action_ingress_policy_authority",
				PrincipalDigest: identities["egress-policy-authority-browser-action-ingress"].Digest(), KeyID: "operator-browser-action-ingress-1",
				PublicKeyDigest: testDigest("operator-browser-action-ingress-key"), SocketDirectory: "/run/egress-authority-browser-action-ingress", SocketStorageID: "browser-action-ingress-authority-socket",
				LedgerMountTarget: "/var/lib/egress-authority-browser-action-ingress", LedgerStorageID: "browser-action-ingress-authority-ledger", PollMillis: 500,
				CurrentTimeoutMS: 1000, StateMaxAgeSeconds: 5},
			LeaseSeconds: 60, DNSMaxAnswers: 8,
			DenyRawIP: true, DenyAlternateDNS: true, DenyProxyEnvironment: true, DenyRedirectAuthority: true, DenyMetadataPrivateRanges: true,
			Targets: []EgressTarget{{Alias: "action-history", Host: "action-history.sandbox-runtime.test", Port: 5432, Protocol: "postgres"},
				{Alias: "capacity", Host: "capacity.sandbox-runtime.test", Port: 6379, Protocol: "tls"}}},
			{ID: "gateway-egress", Revision: "policy-1", Principal: "gateway-runtime", Broker: "egress-broker-gateway",
				PrincipalDigest: identities["gateway-runtime"].Digest(), BrokerDigest: identities["egress-broker-gateway"].Digest(),
				Authority: PolicyAuthority{DeploymentName: "egress-policy-authority-gateway", AuthorizationName: "gateway_policy_authority",
					PrincipalDigest: identities["egress-policy-authority-gateway"].Digest(), KeyID: "operator-gateway-1",
					PublicKeyDigest: testDigest("operator-gateway-key"), SocketDirectory: "/run/egress-authority-gateway", SocketStorageID: "gateway-authority-socket",
					LedgerMountTarget: "/var/lib/egress-authority-gateway", LedgerStorageID: "gateway-authority-ledger", PollMillis: 500,
					CurrentTimeoutMS: 1000, StateMaxAgeSeconds: 5},
				LeaseSeconds: 60, DNSMaxAnswers: 8,
				DenyRawIP: true, DenyAlternateDNS: true, DenyProxyEnvironment: true, DenyRedirectAuthority: true, DenyMetadataPrivateRanges: true,
				Targets: []EgressTarget{{Alias: "capacity", Host: "capacity.sandbox-runtime.test", Port: 6379, Protocol: "tls"}}},
			{ID: "product-egress", Revision: "policy-1", Principal: "product-runtime", Broker: "egress-broker-product",
				PrincipalDigest: identities["product-runtime"].Digest(), BrokerDigest: identities["egress-broker-product"].Digest(),
				Authority: PolicyAuthority{DeploymentName: "egress-policy-authority-product", AuthorizationName: "product_policy_authority",
					PrincipalDigest: identities["egress-policy-authority-product"].Digest(), KeyID: "operator-product-1",
					PublicKeyDigest: testDigest("operator-public-key"), SocketDirectory: "/run/egress-authority", SocketStorageID: "product-authority-socket",
					LedgerMountTarget: "/var/lib/egress-authority", LedgerStorageID: "product-authority-ledger", PollMillis: 500,
					CurrentTimeoutMS: 1000, StateMaxAgeSeconds: 5},
				LeaseSeconds: 60, DNSMaxAnswers: 16,
				DenyRawIP: true, DenyAlternateDNS: true, DenyProxyEnvironment: true, DenyRedirectAuthority: true, DenyMetadataPrivateRanges: true,
				Targets: []EgressTarget{{Alias: "registry-probe", Host: "registry-1.docker.io", Port: 443, Protocol: "https"}}}},
		CleanupClasses: []string{"connections", "containers", "files", "networks", "processes", "sockets"}}
	for _, role := range []string{"provider-browser", "provider-desktop"} {
		provider, broker, authority := role+"-runtime", "egress-broker-"+role, "egress-policy-authority-"+role
		identityName := strings.ReplaceAll(role, "-", "_")
		profile.EgressPolicies = append(profile.EgressPolicies, EgressPolicy{
			ID: role + "-egress", Revision: "policy-1", Principal: provider, Broker: broker,
			PrincipalDigest: identities[provider].Digest(), BrokerDigest: identities[broker].Digest(),
			Authority: PolicyAuthority{DeploymentName: authority, AuthorizationName: identityName + "_policy_authority",
				PrincipalDigest: identities[authority].Digest(), KeyID: "operator-" + role + "-1",
				PublicKeyDigest: testDigest("operator-" + role + "-key"), SocketDirectory: "/run/egress-authority-" + role,
				SocketStorageID: role + "-authority-socket", LedgerMountTarget: "/var/lib/egress-authority-" + role,
				LedgerStorageID: role + "-authority-ledger", PollMillis: 500, CurrentTimeoutMS: 1000, StateMaxAgeSeconds: 5},
			LeaseSeconds: 60, DNSMaxAnswers: 8, DenyRawIP: true, DenyAlternateDNS: true,
			DenyProxyEnvironment: true, DenyRedirectAuthority: true, DenyMetadataPrivateRanges: true,
			Targets: []EgressTarget{{Alias: "postgres", Host: "postgres.sandbox-runtime.test", Port: 5432, Protocol: "postgres"}},
		})
	}
	sort.Slice(profile.EgressPolicies, func(i, j int) bool { return profile.EgressPolicies[i].ID < profile.EgressPolicies[j].ID })
	hba, err := profile.PostgresServerAuth.RenderProviderHBA(profile.ProviderDatabases)
	if err != nil {
		panic(err)
	}
	hbaHash := sha256.Sum256(hba)
	profile.PostgresServerAuth.HBADigest = "sha256:" + hex.EncodeToString(hbaHash[:])
	profile.ProfileDigest = profile.Digest()
	return profile
}

func TestCredentialControllerManagedAuthorityIsExactAndSeparate(t *testing.T) {
	for name, mutate := range map[string]func(*Profile){
		"missing policy": func(p *Profile) { p.CertificateController.CredentialController.PolicyID = "" },
		"shared self policy": func(p *Profile) {
			p.CertificateController.CredentialController.PolicyID = p.CertificateController.ManagedPolicyID
		},
		"shared self key": func(p *Profile) {
			p.CertificateController.CredentialController.RequestKeyDigest = p.CertificateController.ManagedRequestKeyDigest
		},
		"shared agent role": func(p *Profile) {
			p.CertificateController.CredentialController.VaultRole = p.TLSAgentBindings[0].IssuerVaultRole
		},
		"socket path drift": func(p *Profile) {
			p.CertificateController.CredentialController.SocketPath += "-other"
		},
		"edge alias": func(p *Profile) {
			p.CertificateController.CredentialController.UnixEdgeID = p.CertificateController.SelfUnixEdgeID
		},
		"client mount writable": func(p *Profile) {
			for i := range p.Principals {
				if p.Principals[i].Name == "workload-credential-controller" {
					for j := range p.Principals[i].Mounts {
						if p.Principals[i].Mounts[j].StorageID == p.CertificateController.CredentialController.SocketStorageID {
							p.Principals[i].Mounts[j].ReadOnly = false
						}
					}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			profile := validProfile()
			mutate(&profile)
			profile.ProfileDigest = profile.Digest()
			if profile.Validate() == nil {
				t.Fatal("credential controller managed authority drift admitted")
			}
		})
	}
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
		"wrong edge identity":         func(p *Profile) { p.TrustEdges[0].FromURI = "spiffe://sandbox-runtime.test/other" },
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
				if p.Principals[index].Name == "desktop-sandbox-runtime" {
					p.Principals[index].ControllingPrincipalDigest = testDigest("missing-controller")
				}
			}
		},
		"desktop sandbox controlled by executor": func(p *Profile) {
			var executorDigest string
			for _, principal := range p.Principals {
				if principal.Name == "desktop-executor-backend" {
					executorDigest = principal.PrincipalDigest
				}
			}
			for index := range p.Principals {
				if p.Principals[index].Name == "desktop-sandbox-runtime" {
					p.Principals[index].ControllingPrincipalDigest = executorDigest
				}
			}
		},
		"browser sandbox controlled by executor": func(p *Profile) {
			var executorDigest string
			for _, principal := range p.Principals {
				if principal.Name == "browser-executor-backend" {
					executorDigest = principal.PrincipalDigest
				}
			}
			for index := range p.Principals {
				if p.Principals[index].Name == "browser-sandbox-runtime" {
					p.Principals[index].ControllingPrincipalDigest = executorDigest
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
				if p.Principals[index].Name == "desktop-sandbox-runtime" {
					identity := *source.AuthorizationPrincipal
					p.Principals[index].AuthorizationPrincipal = &identity
					p.Principals[index].PrincipalDigest = identity.Digest()
					p.Principals[index].ControllingPrincipalDigest = ""
					tlsIdentity := *source.TLS
					p.Principals[index].TLS = &tlsIdentity
				}
			}
		},
		"missing component":              func(p *Profile) { p.Components = nil },
		"component parent drift":         func(p *Profile) { p.Components[0].ParentDeployment = "desktop-executor-backend" },
		"component binary drift":         func(p *Profile) { p.Components[0].ExecutableDigest = "" },
		"component socket drift":         func(p *Profile) { p.Components[0].Socket = "/tmp/other.sock" },
		"legacy broker session protocol": func(p *Profile) { p.Components[0].SessionProtocol = "sandbox.runtime/desktop-session/v1" },
		"broker as fake container principal": func(p *Profile) {
			p.Principals = append(p.Principals, Principal{Name: "desktop-broker", Kind: "broker"})
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
		if profile.EgressPolicies[index].Broker == "egress-broker-product" {
			profile.EgressPolicies[index].Broker = "product-egress-service"
		}
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
