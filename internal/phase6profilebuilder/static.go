package phase6profilebuilder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidStaticDraft = errors.New("invalid Phase 6 Slice 6 static profile draft")

// StaticDraft binds the remaining repository-reviewed, non-secret policy
// fields. The Desktop broker executable is intentionally still absent: its
// digest must come from the verified selected Desktop OCI image bytes.
type StaticDraft struct {
	CertificateDraft
	SandboxIdentitySlots []phase6security.SandboxIdentitySlot
	ProviderDatabases    []phase6security.ProviderDatabaseBinding
	PostgresServerAuth   phase6security.PostgresServerAuthPolicy
	PublicListeners      []phase6security.PublicListenerBinding
	IngressBindings      []phase6security.IngressBinding
	CleanupClasses       []string
	base                 CertificateDraft
}

func (d StaticDraft) VerifySources(ctx context.Context, now time.Time) error {
	if d.base.VerifySources(ctx, now) != nil {
		return ErrInvalidStaticDraft
	}
	want, err := bindSlice6StaticDraft(d.base)
	if err != nil || !reflect.DeepEqual(d.CertificateDraft, want.CertificateDraft) ||
		!reflect.DeepEqual(d.SandboxIdentitySlots, want.SandboxIdentitySlots) ||
		!reflect.DeepEqual(d.ProviderDatabases, want.ProviderDatabases) ||
		!reflect.DeepEqual(d.PostgresServerAuth, want.PostgresServerAuth) ||
		!reflect.DeepEqual(d.PublicListeners, want.PublicListeners) ||
		!reflect.DeepEqual(d.IngressBindings, want.IngressBindings) ||
		!reflect.DeepEqual(d.CleanupClasses, want.CleanupClasses) {
		return ErrInvalidStaticDraft
	}
	return nil
}

func BindSlice6StaticDraft(ctx context.Context, draft CertificateDraft, now time.Time) (StaticDraft, error) {
	if draft.VerifySources(ctx, now) != nil {
		return StaticDraft{}, ErrInvalidStaticDraft
	}
	return bindSlice6StaticDraft(draft)
}

func bindSlice6StaticDraft(draft CertificateDraft) (StaticDraft, error) {
	if len(draft.Principals) != len(phase6security.Slice6DesiredDeploymentNames()) ||
		len(draft.External) != 5 || len(draft.TrustEdges) != 152 ||
		phase6security.VerifySlice6DesiredFinalNetworks(draft.Networks) != nil {
		return StaticDraft{}, ErrInvalidStaticDraft
	}
	bound := draft
	bound.Principals = slices.Clone(draft.Principals)
	indexes := make(map[string]int, len(bound.Principals))
	for index := range bound.Principals {
		principal := &bound.Principals[index]
		indexes[principal.Name] = index
		principal.Listeners = slices.Clone(principal.Listeners)
		principal.Mounts = slices.Clone(principal.Mounts)
	}
	listeners := map[string][]phase6security.Listener{
		"browser-action-ingress-runtime": {{Name: "action", Protocol: "tcp", Port: 8452, Exposure: "trust_edge"}},
		"browser-executor-backend":       {{Name: "executor", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}},
		"browser-runtime-role":           {{Name: "attach", Protocol: "tcp", Port: 8450, Exposure: "trust_edge"}},
		"desktop-executor-backend":       {{Name: "executor", Protocol: "tcp", Port: 8443, Exposure: "trust_edge"}},
		"desktop-runtime-role":           {{Name: "attach", Protocol: "tcp", Port: 8451, Exposure: "trust_edge"}},
		"gateway-runtime":                {{Name: "signaling", Protocol: "tcp", Port: 8445, Exposure: "public"}},
		"product-runtime": {{Name: "api", Protocol: "tcp", Port: 8444, Exposure: "public"},
			{Name: "guest-control", Protocol: "tcp", Port: 8449, Exposure: "trust_edge"}},
		"provider-runtime": {{Name: "contract", Protocol: "tcp", Port: 8444, Exposure: "trust_edge"},
			{Name: "private", Protocol: "tcp", Port: 8448, Exposure: "trust_edge"}},
		"provider-browser-runtime": {{Name: "contract", Protocol: "tcp", Port: 8444, Exposure: "trust_edge"},
			{Name: "private", Protocol: "tcp", Port: 8448, Exposure: "trust_edge"},
			{Name: "browser-mux", Protocol: "unix", Exposure: "private_socket"}},
		"provider-desktop-runtime": {{Name: "contract", Protocol: "tcp", Port: 8444, Exposure: "trust_edge"},
			{Name: "private", Protocol: "tcp", Port: 8448, Exposure: "trust_edge"}},
		"public-ingress-relay": {{Name: "gateway-public", Protocol: "tcp", Port: 8445, Exposure: "ingress_frontend"},
			{Name: "product-public", Protocol: "tcp", Port: 8444, Exposure: "ingress_frontend"}},
	}
	for name, set := range listeners {
		index, found := indexes[name]
		if !found || len(bound.Principals[index].Listeners) != 0 {
			return StaticDraft{}, ErrInvalidStaticDraft
		}
		bound.Principals[index].Listeners = slices.Clone(set)
	}
	for _, principal := range bound.Principals {
		for _, mount := range principal.Mounts {
			if mount.StorageID == phase6security.BrowserMuxSocketStorageID ||
				overlappingMountTarget(mount.Target, phase6security.BrowserMuxSocketDirectory) {
				return StaticDraft{}, ErrInvalidStaticDraft
			}
		}
	}
	for _, name := range []string{"provider-browser-runtime", "browser-executor-backend"} {
		index, found := indexes[name]
		if !found {
			return StaticDraft{}, ErrInvalidStaticDraft
		}
		bound.Principals[index].Mounts = append(bound.Principals[index].Mounts, phase6security.Mount{
			Target: phase6security.BrowserMuxSocketDirectory, Kind: "private_socket",
			ReadOnly: name == "browser-executor-backend", StorageID: phase6security.BrowserMuxSocketStorageID})
	}
	byName := make(map[string]phase6security.Principal, len(bound.Principals))
	for _, principal := range bound.Principals {
		byName[principal.Name] = principal
	}
	postgres := phase6security.ExternalService{}
	for _, service := range bound.External {
		if service.Name == "postgres" {
			postgres = service
		}
	}
	if postgres.Name == "" || postgres.IdentityDigest == "" {
		return StaticDraft{}, ErrInvalidStaticDraft
	}
	providerDatabases := []phase6security.ProviderDatabaseBinding{
		{OwnerDeployment: "provider-browser-runtime", OwnerPrincipalDigest: byName["provider-browser-runtime"].PrincipalDigest,
			Template: "browser-sandbox-runtime", Namespace: "browser-production", ControllerID: "browser-provider-1",
			ServiceName: "postgres", ServiceIdentityDigest: postgres.IdentityDigest,
			TrustEdgeID: "provider-browser-postgres", EgressPolicyID: "provider-browser-egress",
			BrokerDeployment: "egress-broker-provider-browser", BrokerRoleEdgeID: "egress-role-provider-browser",
			BrokerExternalEdgeID: "egress-provider-browser-postgres", DatabaseName: "provider_browser",
			RuntimeRole: "browser_provider_runtime", ServerAuthPolicyID: "provider-postgres-auth",
			RuntimeDSNBindingID: "browser-provider-runtime-dsn"},
		{OwnerDeployment: "provider-desktop-runtime", OwnerPrincipalDigest: byName["provider-desktop-runtime"].PrincipalDigest,
			Template: "desktop-sandbox-runtime", Namespace: "desktop-production", ControllerID: "desktop-controller-1",
			ServiceName: "postgres", ServiceIdentityDigest: postgres.IdentityDigest,
			TrustEdgeID: "provider-desktop-postgres", EgressPolicyID: "provider-desktop-egress",
			BrokerDeployment: "egress-broker-provider-desktop", BrokerRoleEdgeID: "egress-role-provider-desktop",
			BrokerExternalEdgeID: "egress-provider-desktop-postgres", DatabaseName: "provider_desktop",
			RuntimeRole: "desktop_provider_runtime", ServerAuthPolicyID: "provider-postgres-auth",
			RuntimeDSNBindingID: "desktop-provider-runtime-dsn"},
	}
	auth := phase6security.PostgresServerAuthPolicy{ID: "provider-postgres-auth", Scope: "shared_nine_roles",
		ServiceName: "postgres", ServiceIdentityDigest: postgres.IdentityDigest,
		HBAArtifactID: "shared-postgres-hba", ClientCAAnchorID: "postgres-client-ca"}
	hba, err := auth.RenderApprovedHBA(providerDatabases)
	if err != nil {
		return StaticDraft{}, ErrInvalidStaticDraft
	}
	hbaDigest := sha256.Sum256(hba)
	auth.HBADigest = "sha256:" + hex.EncodeToString(hbaDigest[:])
	slots := []phase6security.SandboxIdentitySlot{
		{SlotID: "browser-0000", Template: "browser-sandbox-runtime",
			TemplateDigest:  phase6security.SandboxTemplateDigest(byName["browser-sandbox-runtime"]),
			OwnerDeployment: "provider-browser-runtime", OwnerPrincipalDigest: byName["provider-browser-runtime"].PrincipalDigest,
			WorkloadUID: 41000, WorkloadGID: 51000, GatewayUID: 43000, GatewayGID: 53000},
		{SlotID: "desktop-0000", Template: "desktop-sandbox-runtime",
			TemplateDigest:  phase6security.SandboxTemplateDigest(byName["desktop-sandbox-runtime"]),
			OwnerDeployment: "provider-desktop-runtime", OwnerPrincipalDigest: byName["provider-desktop-runtime"].PrincipalDigest,
			WorkloadUID: 42000, WorkloadGID: 52000, GatewayUID: 44000, GatewayGID: 54000},
	}
	public := []phase6security.PublicListenerBinding{
		{ID: "gateway-public", DeploymentName: "gateway-runtime", PrincipalDigest: byName["gateway-runtime"].PrincipalDigest,
			ListenerName: "signaling", Port: 8445, IssuerAnchorID: "internal-server-ca", ClientAuthentication: "none"},
		{ID: "product-public", DeploymentName: "product-runtime", PrincipalDigest: byName["product-runtime"].PrincipalDigest,
			ListenerName: "api", Port: 8444, IssuerAnchorID: "internal-server-ca", ClientAuthentication: "none"},
	}
	relay := byName["public-ingress-relay"]
	ingress := make([]phase6security.IngressBinding, 0, len(public))
	for _, item := range []struct {
		id, target, trustNetwork, hostBind string
		port                               uint16
	}{{"gateway-public", "gateway-runtime", "ingress-gateway", "127.0.0.1:18445", 8445},
		{"product-public", "product-runtime", "ingress-product", "127.0.0.1:18444", 8444}} {
		frontendIP, frontendErr := phase6security.Slice6DesiredEndpointAddress("public-ingress", relay.Name)
		upstreamIP, upstreamErr := phase6security.Slice6DesiredEndpointAddress(item.trustNetwork, item.target)
		frontend, frontendParseErr := netip.ParseAddr(frontendIP)
		upstream, upstreamParseErr := netip.ParseAddr(upstreamIP)
		if frontendErr != nil || upstreamErr != nil || frontendParseErr != nil || upstreamParseErr != nil {
			return StaticDraft{}, ErrInvalidStaticDraft
		}
		binding := phase6security.IngressBinding{ID: item.id, Relay: relay.Name, RelayPrincipalDigest: relay.PrincipalDigest,
			PublicListenerID: item.id, Target: item.target, TargetPrincipalDigest: byName[item.target].PrincipalDigest,
			FrontendNetwork: "public-ingress", TrustNetwork: item.trustNetwork,
			FrontendAddress: netip.AddrPortFrom(frontend, item.port).String(),
			UpstreamAddress: netip.AddrPortFrom(upstream, item.port).String(), HostBindAddress: item.hostBind,
			MaxConnections: 16, DialTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxLifetimeSeconds: 300,
			DrainTimeoutSeconds: 10, BufferBytes: 4096}
		binding.ConfigurationDigest = binding.Digest()
		ingress = append(ingress, binding)
	}
	return StaticDraft{CertificateDraft: bound, SandboxIdentitySlots: slots, ProviderDatabases: providerDatabases,
		PostgresServerAuth: auth, PublicListeners: public, IngressBindings: ingress,
		CleanupClasses: []string{"connections", "containers", "files", "networks", "processes", "sockets"},
		base:           draft}, nil
}
