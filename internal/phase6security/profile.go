// Package phase6security defines the closed portable security contract for
// Product Phase 6 Slice 6. It is configuration authority, not proof that a
// deployment enforced the contract; the real Docker/Vault gates supply that
// evidence separately.
package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/securityprincipal"
)

const (
	ProtocolID = "sandbox-runtime.phase6-security-profile.v1"
	Version    = 1
	maxBytes   = 2 << 20
)

var (
	ErrInvalidProfile = errors.New("invalid Phase 6 security profile")
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imagePattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,510}@sha256:[0-9a-f]{64}$`)
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	hostPattern       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

var requiredPrincipals = map[string]string{
	"product-runtime":                "runtime",
	"gateway-runtime":                "runtime",
	"provider-runtime":               "runtime",
	"guest-runtime":                  "runtime",
	"browser-runtime-role":           "runtime",
	"desktop-runtime-role":           "runtime",
	"browser-executor-backend":       "executor",
	"desktop-executor-backend":       "executor",
	"product-runtime-agent":          "material_agent",
	"provider-runtime-agent":         "material_agent",
	"gateway-agent":                  "material_agent",
	"guest-agent":                    "material_agent",
	"browser-agent":                  "material_agent",
	"desktop-agent":                  "material_agent",
	"product-migration-agent":        "material_agent",
	"provider-migration-agent":       "material_agent",
	"workload-credential-controller": "controller",
	"break-glass-controller":         "controller",
	"certificate-controller":         "controller",
	"product-migration-job":          "migration_job",
	"provider-migration-job":         "migration_job",
	"desktop-broker":                 "broker",
	"browser-sandbox-runtime":        "sandbox",
	"desktop-sandbox-runtime":        "sandbox",
}

type principalBinding struct {
	kind securityprincipal.Kind
	name string
	role securityprincipal.Role
}

var requiredAuthorizationBindings = map[string]principalBinding{
	"product-runtime":                {securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct},
	"gateway-runtime":                {securityprincipal.KindRuntimeRole, "gateway", securityprincipal.RoleGateway},
	"provider-runtime":               {securityprincipal.KindRuntimeRole, "provider", securityprincipal.RoleProvider},
	"guest-runtime":                  {securityprincipal.KindRuntimeRole, "guest", securityprincipal.RoleGuest},
	"browser-runtime-role":           {securityprincipal.KindRuntimeRole, "browser", securityprincipal.RoleBrowser},
	"desktop-runtime-role":           {securityprincipal.KindRuntimeRole, "desktop", securityprincipal.RoleDesktop},
	"browser-executor-backend":       {securityprincipal.KindExecutorBackend, "browser_executor", securityprincipal.RoleBrowser},
	"desktop-executor-backend":       {securityprincipal.KindExecutorBackend, "desktop_executor", securityprincipal.RoleDesktop},
	"product-runtime-agent":          {securityprincipal.KindMaterialAgent, "product_runtime_agent", securityprincipal.RoleProduct},
	"provider-runtime-agent":         {securityprincipal.KindMaterialAgent, "provider_runtime_agent", securityprincipal.RoleProvider},
	"gateway-agent":                  {securityprincipal.KindMaterialAgent, "gateway_agent", securityprincipal.RoleGateway},
	"guest-agent":                    {securityprincipal.KindMaterialAgent, "guest_agent", securityprincipal.RoleGuest},
	"browser-agent":                  {securityprincipal.KindMaterialAgent, "browser_agent", securityprincipal.RoleBrowser},
	"desktop-agent":                  {securityprincipal.KindMaterialAgent, "desktop_agent", securityprincipal.RoleDesktop},
	"product-migration-agent":        {securityprincipal.KindMaterialAgent, "product_migration_agent", securityprincipal.RoleProduct},
	"provider-migration-agent":       {securityprincipal.KindMaterialAgent, "provider_migration_agent", securityprincipal.RoleProvider},
	"workload-credential-controller": {securityprincipal.KindController, "credential_controller", ""},
	"break-glass-controller":         {securityprincipal.KindController, "break_glass_controller", ""},
	"certificate-controller":         {securityprincipal.KindController, "certificate_controller", ""},
	"product-migration-job":          {securityprincipal.KindMigrationJob, "product_migration", securityprincipal.RoleProduct},
	"provider-migration-job":         {securityprincipal.KindMigrationJob, "provider_migration", securityprincipal.RoleProvider},
}

var requiredResourceControllers = map[string]string{
	"desktop-broker":          "desktop-executor-backend",
	"browser-sandbox-runtime": "browser-executor-backend",
	"desktop-sandbox-runtime": "desktop-executor-backend",
}

type Profile struct {
	Protocol               string            `json:"protocol"`
	Version                int               `json:"version"`
	Revision               string            `json:"revision"`
	ProfileDigest          string            `json:"profile_digest"`
	EnvironmentDigest      string            `json:"environment_digest"`
	PrincipalProfileDigest string            `json:"principal_profile_digest"`
	Principals             []Principal       `json:"principals"`
	Networks               []Network         `json:"networks"`
	External               []ExternalService `json:"external_services"`
	TrustEdges             []TrustEdge       `json:"trust_edges"`
	EgressPolicies         []EgressPolicy    `json:"egress_policies"`
	CleanupClasses         []string          `json:"cleanup_classes"`
}

type Principal struct {
	Name                       string                       `json:"name"`
	Kind                       string                       `json:"kind"`
	ImageReference             string                       `json:"image_reference"`
	ImageDigest                string                       `json:"image_digest"`
	UID                        uint32                       `json:"uid"`
	GID                        uint32                       `json:"gid"`
	ReadOnlyRootFilesystem     bool                         `json:"read_only_root_filesystem"`
	NoNewPrivileges            bool                         `json:"no_new_privileges"`
	DroppedCapabilities        []string                     `json:"dropped_capabilities"`
	SeccompDigest              string                       `json:"seccomp_digest"`
	Resources                  Resources                    `json:"resources"`
	Mounts                     []Mount                      `json:"mounts"`
	Networks                   []string                     `json:"networks"`
	HostNetwork                bool                         `json:"host_network"`
	ExternalUplink             bool                         `json:"external_uplink"`
	DirectEgressBlocked        bool                         `json:"direct_egress_blocked"`
	DockerSocket               bool                         `json:"docker_socket"`
	HostDevices                bool                         `json:"host_devices"`
	Listeners                  []Listener                   `json:"listeners"`
	AuthorizationPrincipal     *securityprincipal.Principal `json:"authorization_principal"`
	PrincipalDigest            string                       `json:"principal_digest"`
	ControllingPrincipalDigest string                       `json:"controlling_principal_digest"`
	TLS                        *TLSIdentity                 `json:"tls"`
}

type Resources struct {
	MemoryBytes int64 `json:"memory_bytes"`
	CPUMillis   int64 `json:"cpu_millis"`
	PIDs        int64 `json:"pids"`
}

type Network struct {
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	Internal        bool     `json:"internal"`
	IPv6Enabled     bool     `json:"ipv6_enabled"`
	GatewayModeIPv4 string   `json:"gateway_mode_ipv4"`
	Principals      []string `json:"principals"`
}

type Mount struct {
	Target   string `json:"target"`
	Kind     string `json:"kind"`
	ReadOnly bool   `json:"read_only"`
	MaxBytes int64  `json:"max_bytes"`
}

type Listener struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Exposure string `json:"exposure"`
}

type TLSIdentity struct {
	PrincipalDigest               string   `json:"principal_digest"`
	TrustDomain                   string   `json:"trust_domain"`
	URI                           string   `json:"uri"`
	DNSNames                      []string `json:"dns_names"`
	Usages                        []string `json:"usages"`
	TTLSeconds                    int64    `json:"ttl_seconds"`
	RotateAfterSeconds            int64    `json:"rotate_after_seconds"`
	OverlapSeconds                int64    `json:"overlap_seconds"`
	RevocationMaxStalenessSeconds int64    `json:"revocation_max_staleness_seconds"`
	ConnectionDrainSeconds        int64    `json:"connection_drain_seconds"`
}

type ExternalService struct {
	Name           string   `json:"name"`
	ImageReference string   `json:"image_reference"`
	ImageDigest    string   `json:"image_digest"`
	URI            string   `json:"uri"`
	DNSNames       []string `json:"dns_names"`
	IdentityDigest string   `json:"identity_digest"`
	IngressEdges   []string `json:"ingress_edges"`
}

type TrustEdge struct {
	ID                     string `json:"id"`
	From                   string `json:"from"`
	To                     string `json:"to"`
	Protocol               string `json:"protocol"`
	Port                   int    `json:"port"`
	Authentication         string `json:"authentication"`
	FromURI                string `json:"from_uri"`
	ToURI                  string `json:"to_uri"`
	FromPrincipalDigest    string `json:"from_principal_digest"`
	ToPrincipalDigest      string `json:"to_principal_digest"`
	ExternalIdentityDigest string `json:"external_identity_digest"`
	CrossDomain            bool   `json:"cross_domain"`
	TenantScope            string `json:"tenant_scope"`
	MaxConnectionSeconds   int64  `json:"max_connection_seconds"`
}

type EgressPolicy struct {
	ID                        string         `json:"id"`
	Revision                  string         `json:"revision"`
	Principal                 string         `json:"principal"`
	Broker                    string         `json:"broker"`
	PrincipalDigest           string         `json:"principal_digest"`
	BrokerDigest              string         `json:"broker_digest"`
	LeaseSeconds              int64          `json:"lease_seconds"`
	DNSMaxAnswers             int            `json:"dns_max_answers"`
	DenyRawIP                 bool           `json:"deny_raw_ip"`
	DenyAlternateDNS          bool           `json:"deny_alternate_dns"`
	DenyProxyEnvironment      bool           `json:"deny_proxy_environment"`
	DenyRedirectAuthority     bool           `json:"deny_redirect_authority"`
	DenyMetadataPrivateRanges bool           `json:"deny_metadata_private_ranges"`
	Targets                   []EgressTarget `json:"targets"`
}

type EgressTarget struct {
	Alias    string `json:"alias"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func Decode(document []byte) (Profile, error) {
	if len(document) < 1 || len(document) > maxBytes {
		return Profile{}, ErrInvalidProfile
	}
	if err := rejectDuplicateMembers(document); err != nil {
		return Profile{}, ErrInvalidProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var profile Profile
	if err := decoder.Decode(&profile); err != nil {
		return Profile{}, ErrInvalidProfile
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Profile{}, ErrInvalidProfile
	}
	canonical, err := json.Marshal(profile)
	if err != nil || !bytes.Equal(canonical, document) || profile.Validate() != nil {
		return Profile{}, ErrInvalidProfile
	}
	return profile, nil
}

func VerifyFile(filePath string) (Profile, error) {
	document, err := secretfile.Read(filePath, maxBytes)
	if err != nil {
		return Profile{}, ErrInvalidProfile
	}
	defer clear(document)
	return Decode(document)
}

func (p Profile) Validate() error { //nolint:gocyclo
	if p.Protocol != ProtocolID || p.Version != Version || !namePattern.MatchString(p.Revision) ||
		!digestPattern.MatchString(p.ProfileDigest) || !digestPattern.MatchString(p.EnvironmentDigest) ||
		!digestPattern.MatchString(p.PrincipalProfileDigest) || len(p.Principals) < len(requiredPrincipals) || len(p.Principals) > 128 ||
		len(p.Networks) < 1 || len(p.Networks) > 256 || len(p.External) != 3 || len(p.TrustEdges) < 1 || len(p.TrustEdges) > 512 || len(p.EgressPolicies) > 128 ||
		!exactStrings(p.CleanupClasses, []string{"connections", "containers", "files", "networks", "processes", "sockets"}) {
		return ErrInvalidProfile
	}
	registry, err := p.principalRegistry()
	if err != nil {
		return err
	}
	principals := make(map[string]Principal, len(p.Principals))
	principalDeployments := make(map[string]string, len(p.Principals))
	uids, gids, identities, seccomp := map[uint32]struct{}{}, map[uint32]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	previous := ""
	for _, principal := range p.Principals {
		if principal.Name <= previous || validatePrincipal(principal, registry) != nil {
			return ErrInvalidProfile
		}
		previous = principal.Name
		if _, exists := principals[principal.Name]; exists {
			return ErrInvalidProfile
		}
		if _, exists := uids[principal.UID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := gids[principal.GID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seccomp[principal.SeccompDigest]; exists {
			return ErrInvalidProfile
		}
		if principal.AuthorizationPrincipal != nil {
			if _, exists := principalDeployments[principal.PrincipalDigest]; exists {
				return ErrInvalidProfile
			}
			if _, exists := identities[principal.TLS.URI]; exists {
				return ErrInvalidProfile
			}
			principalDeployments[principal.PrincipalDigest] = principal.Name
			identities[principal.TLS.URI] = struct{}{}
		}
		uids[principal.UID], gids[principal.GID], seccomp[principal.SeccompDigest] = struct{}{}, struct{}{}, struct{}{}
		principals[principal.Name] = principal
	}
	for name, kind := range requiredPrincipals {
		if principal, ok := principals[name]; !ok || principal.Kind != kind {
			return ErrInvalidProfile
		}
	}
	for resource, controller := range requiredResourceControllers {
		resourceRecord, resourceOK := principals[resource]
		controllerRecord, controllerOK := principals[controller]
		if !resourceOK || !controllerOK || controllerRecord.AuthorizationPrincipal == nil ||
			resourceRecord.ControllingPrincipalDigest != controllerRecord.PrincipalDigest {
			return ErrInvalidProfile
		}
	}
	for _, principal := range principals {
		if principal.AuthorizationPrincipal == nil {
			if _, ok := principalDeployments[principal.ControllingPrincipalDigest]; !ok {
				return ErrInvalidProfile
			}
		}
	}
	if err := validateNetworks(p.Networks, principals, p.EgressPolicies); err != nil {
		return err
	}
	external, err := validateExternal(p.External)
	if err != nil {
		return err
	}
	edges, err := validateEdges(p.TrustEdges, principals, external)
	if err != nil {
		return err
	}
	if err := validateEgress(p.EgressPolicies, principals); err != nil {
		return err
	}
	for name, service := range external {
		for _, edge := range service.IngressEdges {
			if bound, ok := edges[edge]; !ok || bound.To != name {
				return ErrInvalidProfile
			}
		}
	}
	if p.ProfileDigest != p.Digest() {
		return ErrInvalidProfile
	}
	return nil
}

func (p Profile) Digest() string {
	p.ProfileDigest = ""
	document, _ := json.Marshal(p)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-security-profile/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (p Profile) principalRegistry() (*securityprincipal.Registry, error) {
	egressBrokers := make(map[string]securityprincipal.Role)
	for _, principal := range p.Principals {
		if principal.Kind != "egress_broker" || principal.AuthorizationPrincipal == nil {
			continue
		}
		identity := principal.AuthorizationPrincipal
		if identity.Kind != securityprincipal.KindEgressBroker {
			return nil, ErrInvalidProfile
		}
		if _, duplicate := egressBrokers[identity.Name]; duplicate {
			return nil, ErrInvalidProfile
		}
		egressBrokers[identity.Name] = identity.Role
	}
	registry, err := securityprincipal.NewRegistry(p.EnvironmentDigest, p.PrincipalProfileDigest, egressBrokers)
	if err != nil {
		return nil, ErrInvalidProfile
	}
	return registry, nil
}

func validatePrincipal(value Principal, registry *securityprincipal.Registry) error { //nolint:gocyclo
	if !namePattern.MatchString(value.Name) || !validPrincipalKind(value.Kind) || !imagePattern.MatchString(value.ImageReference) ||
		!digestPattern.MatchString(value.ImageDigest) || !strings.HasSuffix(value.ImageReference, "@"+value.ImageDigest) ||
		value.UID < 10000 || value.UID > 60000 || value.GID < 10000 || value.GID > 60000 ||
		!value.ReadOnlyRootFilesystem || !value.NoNewPrivileges || !exactStrings(value.DroppedCapabilities, []string{"ALL"}) ||
		!digestPattern.MatchString(value.SeccompDigest) || value.Resources.MemoryBytes < 16<<20 || value.Resources.MemoryBytes > 64<<30 ||
		value.Resources.CPUMillis < 10 || value.Resources.CPUMillis > 64000 || value.Resources.PIDs < 4 || value.Resources.PIDs > 4096 ||
		value.HostNetwork || value.DockerSocket || value.HostDevices || len(value.Networks) < 1 || len(value.Networks) > 4 ||
		len(value.Mounts) > 16 || len(value.Listeners) > 16 {
		return ErrInvalidProfile
	}
	if value.AuthorizationPrincipal != nil {
		identity := *value.AuthorizationPrincipal
		if registry == nil || registry.Validate(identity) != nil || value.PrincipalDigest != identity.Digest() ||
			!digestPattern.MatchString(value.PrincipalDigest) || value.ControllingPrincipalDigest != "" || value.TLS == nil ||
			value.TLS.PrincipalDigest != value.PrincipalDigest || validateTLS(*value.TLS) != nil ||
			validateAuthorizationBinding(value.Name, value.Kind, identity) != nil {
			return ErrInvalidProfile
		}
	} else if value.PrincipalDigest != "" || !digestPattern.MatchString(value.ControllingPrincipalDigest) || value.TLS != nil ||
		(value.Kind != "broker" && value.Kind != "sandbox") {
		return ErrInvalidProfile
	}
	if value.Kind == "egress_broker" {
		if value.AuthorizationPrincipal == nil || !value.ExternalUplink || value.DirectEgressBlocked || len(value.Networks) != 2 {
			return ErrInvalidProfile
		}
	} else if value.ExternalUplink || !value.DirectEgressBlocked {
		return ErrInvalidProfile
	}
	if !sortedUniqueNames(value.Networks) {
		return ErrInvalidProfile
	}
	seenMounts := map[string]struct{}{}
	for _, mount := range value.Mounts {
		if !strings.HasPrefix(mount.Target, "/") || path.Clean(mount.Target) != mount.Target || mount.Target == "/" ||
			(mount.Kind != "tmpfs" && mount.Kind != "private_socket") {
			return ErrInvalidProfile
		}
		if _, duplicate := seenMounts[mount.Target]; duplicate {
			return ErrInvalidProfile
		}
		seenMounts[mount.Target] = struct{}{}
		if mount.Kind == "tmpfs" && (mount.ReadOnly || mount.MaxBytes < 4096 || mount.MaxBytes > 1<<30) {
			return ErrInvalidProfile
		}
		if mount.Kind == "private_socket" && (!mount.ReadOnly || mount.MaxBytes != 0) {
			return ErrInvalidProfile
		}
	}
	seenListeners := map[string]struct{}{}
	for _, listener := range value.Listeners {
		if !namePattern.MatchString(listener.Name) || (listener.Protocol != "tcp" && listener.Protocol != "udp" && listener.Protocol != "unix") ||
			(listener.Exposure != "public" && listener.Exposure != "trust_edge" && listener.Exposure != "loopback" && listener.Exposure != "private_socket") ||
			(listener.Protocol == "unix" && listener.Port != 0) || (listener.Protocol != "unix" && (listener.Port < 1 || listener.Port > 65535)) {
			return ErrInvalidProfile
		}
		key := listener.Protocol + "/" + listener.Name
		if _, duplicate := seenListeners[key]; duplicate {
			return ErrInvalidProfile
		}
		seenListeners[key] = struct{}{}
	}
	return nil
}

func validateAuthorizationBinding(deploymentName, deploymentKind string, identity securityprincipal.Principal) error {
	if expected, required := requiredAuthorizationBindings[deploymentName]; required {
		if identity.Kind != expected.kind || identity.Name != expected.name || identity.Role != expected.role ||
			deploymentKindForPrincipal(identity.Kind) != deploymentKind {
			return ErrInvalidProfile
		}
		return nil
	}
	if deploymentKind != "egress_broker" || identity.Kind != securityprincipal.KindEgressBroker {
		return ErrInvalidProfile
	}
	return nil
}

func deploymentKindForPrincipal(kind securityprincipal.Kind) string {
	switch kind {
	case securityprincipal.KindRuntimeRole:
		return "runtime"
	case securityprincipal.KindExecutorBackend:
		return "executor"
	case securityprincipal.KindMaterialAgent:
		return "material_agent"
	case securityprincipal.KindController:
		return "controller"
	case securityprincipal.KindMigrationJob:
		return "migration_job"
	case securityprincipal.KindEgressBroker:
		return "egress_broker"
	default:
		return ""
	}
}

func validateTLS(value TLSIdentity) error {
	parsed, err := url.Parse(value.URI)
	if err != nil || parsed.Scheme != "spiffe" || parsed.Host != value.TrustDomain || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" ||
		!validDNSName(value.TrustDomain) || len(value.DNSNames) > 8 || !exactUsageSet(value.Usages) ||
		value.TTLSeconds < 60 || value.TTLSeconds > 3600 || value.RotateAfterSeconds < 1 || value.RotateAfterSeconds > value.TTLSeconds*2/3 ||
		value.OverlapSeconds < 0 || value.OverlapSeconds >= value.RotateAfterSeconds || value.RevocationMaxStalenessSeconds < 1 ||
		value.RevocationMaxStalenessSeconds > 300 || value.ConnectionDrainSeconds < 1 || value.ConnectionDrainSeconds > 300 {
		return ErrInvalidProfile
	}
	previous := ""
	for _, name := range value.DNSNames {
		if name <= previous || !validDNSName(name) || strings.Contains(name, "*") {
			return ErrInvalidProfile
		}
		previous = name
	}
	return nil
}

func validateNetworks(values []Network, principals map[string]Principal, egressPolicies []EgressPolicy) error { //nolint:gocyclo
	networks := make(map[string]Network, len(values))
	previous := ""
	for _, network := range values {
		if network.Name <= previous || !namePattern.MatchString(network.Name) || len(network.Principals) < 1 ||
			!sortedUniqueNames(network.Principals) || network.IPv6Enabled {
			return ErrInvalidProfile
		}
		previous = network.Name
		switch network.Kind {
		case "role_internal", "trust_edge":
			if !network.Internal || network.GatewayModeIPv4 != "isolated" {
				return ErrInvalidProfile
			}
		case "external_uplink":
			if network.Internal || network.GatewayModeIPv4 != "nat" || len(network.Principals) != 1 {
				return ErrInvalidProfile
			}
			principal, ok := principals[network.Principals[0]]
			if !ok || principal.Kind != "egress_broker" {
				return ErrInvalidProfile
			}
		default:
			return ErrInvalidProfile
		}
		for _, name := range network.Principals {
			principal, ok := principals[name]
			if !ok || !slicesContains(principal.Networks, network.Name) {
				return ErrInvalidProfile
			}
		}
		networks[network.Name] = network
	}
	for name, principal := range principals {
		externalCount := 0
		for _, networkName := range principal.Networks {
			network, ok := networks[networkName]
			if !ok || !slicesContains(network.Principals, name) {
				return ErrInvalidProfile
			}
			if network.Kind == "external_uplink" {
				externalCount++
			}
		}
		if principal.Kind == "egress_broker" {
			if externalCount != 1 {
				return ErrInvalidProfile
			}
		} else if externalCount != 0 {
			return ErrInvalidProfile
		}
	}
	for _, policy := range egressPolicies {
		principal, principalOK := principals[policy.Principal]
		broker, brokerOK := principals[policy.Broker]
		if !principalOK || !brokerOK {
			return ErrInvalidProfile
		}
		sharedInternal := 0
		for _, networkName := range principal.Networks {
			network := networks[networkName]
			if network.Internal && slicesContains(broker.Networks, networkName) {
				sharedInternal++
			}
		}
		if sharedInternal != 1 {
			return ErrInvalidProfile
		}
	}
	return nil
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func validateExternal(values []ExternalService) (map[string]ExternalService, error) {
	result := make(map[string]ExternalService, len(values))
	previous := ""
	for _, value := range values {
		if value.Name <= previous || !imagePattern.MatchString(value.ImageReference) || !digestPattern.MatchString(value.ImageDigest) ||
			!strings.HasSuffix(value.ImageReference, "@"+value.ImageDigest) || !validSPIFFE(value.URI) ||
			!digestPattern.MatchString(value.IdentityDigest) || value.IdentityDigest != value.Digest() ||
			len(value.DNSNames) < 1 || len(value.DNSNames) > 8 || len(value.IngressEdges) < 1 || !sortedUniqueNames(value.IngressEdges) {
			return nil, ErrInvalidProfile
		}
		previousDNS := ""
		for _, name := range value.DNSNames {
			if name <= previousDNS || !validDNSName(name) || strings.Contains(name, "*") {
				return nil, ErrInvalidProfile
			}
			previousDNS = name
		}
		if value.Name == "dns" && len(value.DNSNames) != 1 {
			return nil, ErrInvalidProfile
		}
		previous = value.Name
		result[value.Name] = value
	}
	for _, required := range []string{"dns", "postgres", "vault"} {
		if _, ok := result[required]; !ok {
			return nil, ErrInvalidProfile
		}
	}
	return result, nil
}

func (e ExternalService) Digest() string {
	e.IdentityDigest = ""
	document, _ := json.Marshal(e)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-external-identity/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateEdges(values []TrustEdge, principals map[string]Principal, external map[string]ExternalService) (map[string]TrustEdge, error) {
	result := make(map[string]TrustEdge, len(values))
	previous := ""
	for _, value := range values {
		from, fromOK := principals[value.From]
		to, toOK := principals[value.To]
		externalTo, externalOK := external[value.To]
		if value.ID <= previous || !namePattern.MatchString(value.ID) || !fromOK || from.AuthorizationPrincipal == nil || (!toOK && !externalOK) ||
			value.FromPrincipalDigest != from.PrincipalDigest || value.FromURI != from.TLS.URI ||
			(toOK && (to.AuthorizationPrincipal == nil || value.ToURI != to.TLS.URI || value.ToPrincipalDigest != to.PrincipalDigest ||
				value.ExternalIdentityDigest != "" || value.CrossDomain)) ||
			(externalOK && (value.ToURI != externalTo.URI || value.ToPrincipalDigest != "" ||
				value.ExternalIdentityDigest != externalTo.IdentityDigest || !value.CrossDomain)) ||
			(value.TenantScope != "system" && value.TenantScope != "bound") || value.MaxConnectionSeconds < 1 || value.MaxConnectionSeconds > 3600 {
			return nil, ErrInvalidProfile
		}
		previous = value.ID
		if value.Authentication == "mtls" {
			if value.Protocol == "unix" || value.Port < 1 || value.Port > 65535 {
				return nil, ErrInvalidProfile
			}
		} else if value.Authentication == "unix_peer_credentials" {
			if value.Protocol != "unix" || value.Port != 0 || externalOK {
				return nil, ErrInvalidProfile
			}
		} else {
			return nil, ErrInvalidProfile
		}
		if !validEdgeProtocol(value.Protocol) {
			return nil, ErrInvalidProfile
		}
		result[value.ID] = value
	}
	return result, nil
}

func validateEgress(values []EgressPolicy, principals map[string]Principal) error {
	seenPolicies, seenPrincipals, seenBrokers := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	previous := ""
	for _, value := range values {
		principal, principalOK := principals[value.Principal]
		broker, brokerOK := principals[value.Broker]
		if value.ID <= previous || !namePattern.MatchString(value.ID) || !namePattern.MatchString(value.Revision) || !principalOK || !brokerOK ||
			principal.Kind == "egress_broker" || broker.Kind != "egress_broker" || value.Principal == value.Broker ||
			principal.AuthorizationPrincipal == nil || broker.AuthorizationPrincipal == nil ||
			value.PrincipalDigest != principal.PrincipalDigest || value.BrokerDigest != broker.PrincipalDigest ||
			value.LeaseSeconds < 1 || value.LeaseSeconds > 300 || value.DNSMaxAnswers < 1 || value.DNSMaxAnswers > 32 ||
			!value.DenyRawIP || !value.DenyAlternateDNS || !value.DenyProxyEnvironment || !value.DenyRedirectAuthority || !value.DenyMetadataPrivateRanges ||
			len(value.Targets) < 1 || len(value.Targets) > 64 {
			return ErrInvalidProfile
		}
		previous = value.ID
		if _, duplicate := seenPolicies[value.ID]; duplicate {
			return ErrInvalidProfile
		}
		if _, duplicate := seenPrincipals[value.Principal]; duplicate {
			return ErrInvalidProfile
		}
		if _, duplicate := seenBrokers[value.Broker]; duplicate {
			return ErrInvalidProfile
		}
		seenPolicies[value.ID], seenPrincipals[value.Principal], seenBrokers[value.Broker] = struct{}{}, struct{}{}, struct{}{}
		aliasPrevious := ""
		for _, target := range value.Targets {
			if target.Alias <= aliasPrevious || !namePattern.MatchString(target.Alias) || !validDNSName(target.Host) || net.ParseIP(target.Host) != nil ||
				target.Port < 1 || target.Port > 65535 || !validTargetProtocol(target.Protocol) {
				return ErrInvalidProfile
			}
			aliasPrevious = target.Alias
		}
	}
	for name, principal := range principals {
		if principal.Kind == "egress_broker" {
			if _, ok := seenBrokers[name]; !ok {
				return ErrInvalidProfile
			}
		}
	}
	return nil
}

func validPrincipalKind(value string) bool {
	switch value {
	case "runtime", "executor", "material_agent", "controller", "migration_job", "broker", "sandbox", "egress_broker":
		return true
	default:
		return false
	}
}

func validEdgeProtocol(value string) bool {
	switch value {
	case "https", "wss", "postgres", "tls", "dns_tcp", "dns_udp", "unix":
		return true
	default:
		return false
	}
}

func validTargetProtocol(value string) bool {
	switch value {
	case "https", "wss", "postgres", "tls":
		return true
	default:
		return false
	}
}

func validDNSName(value string) bool {
	return len(value) <= 253 && value == strings.ToLower(value) && hostPattern.MatchString(value) && !strings.Contains(value, "..") && net.ParseIP(value) == nil
}

func validSPIFFE(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "spiffe" && validDNSName(parsed.Host) && parsed.Path != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func exactUsageSet(values []string) bool {
	if len(values) < 1 || len(values) > 2 || !sort.StringsAreSorted(values) {
		return false
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if value != "client_auth" && value != "server_auth" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func exactStrings(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func sortedUniqueNames(values []string) bool {
	previous := ""
	for _, value := range values {
		if value <= previous || !namePattern.MatchString(value) {
			return false
		}
		previous = value
	}
	return true
}

func rejectDuplicateMembers(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var scan func(json.Token) error
	scan = func(token json.Token) error {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidProfile
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalidProfile
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalidProfile
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || scan(value) != nil {
					return ErrInvalidProfile
				}
			}
			_, err := decoder.Token()
			return err
		default:
			return ErrInvalidProfile
		}
	}
	first, err := decoder.Token()
	if err != nil || scan(first) != nil {
		return ErrInvalidProfile
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidProfile
	}
	return nil
}
