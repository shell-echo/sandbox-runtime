// Package phase6security defines the closed portable security contract for
// Product Phase 6 Slice 6. It is configuration authority, not proof that a
// deployment enforced the contract; the real Docker/Vault gates supply that
// evidence separately.
package phase6security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
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
	ErrInvalidProfile    = errors.New("invalid Phase 6 security profile")
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imagePattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,510}@sha256:[0-9a-f]{64}$`)
	imagePlatformPattern = regexp.MustCompile(`^linux/(?:amd64|arm64(?:/v8)?)$`)
	namePattern          = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	routePathPattern     = regexp.MustCompile(`^/[a-z][a-z0-9-]*(?:/[a-z][a-z0-9-]*){0,7}$`)
	hostPattern          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
)

var requiredPrincipals = map[string]string{
	"product-runtime":                               "runtime",
	"gateway-runtime":                               "runtime",
	"browser-action-ingress-runtime":                "runtime",
	"provider-runtime":                              "runtime",
	"provider-browser-runtime":                      "runtime",
	"provider-desktop-runtime":                      "runtime",
	"guest-runtime":                                 "runtime",
	"browser-runtime-role":                          "runtime",
	"desktop-runtime-role":                          "runtime",
	"browser-executor-backend":                      "executor",
	"desktop-executor-backend":                      "executor",
	"product-tls-agent":                             "tls_agent",
	"provider-tls-agent":                            "tls_agent",
	"provider-browser-tls-agent":                    "tls_agent",
	"provider-desktop-tls-agent":                    "tls_agent",
	"provider-browser-postgres-tls-agent":           "tls_agent",
	"provider-desktop-postgres-tls-agent":           "tls_agent",
	"product-postgres-tls-agent":                    "tls_agent",
	"gateway-postgres-tls-agent":                    "tls_agent",
	"provider-postgres-tls-agent":                   "tls_agent",
	"product-migration-postgres-tls-agent":          "tls_agent",
	"provider-migration-postgres-tls-agent":         "tls_agent",
	"provider-browser-migration-postgres-tls-agent": "tls_agent",
	"provider-desktop-migration-postgres-tls-agent": "tls_agent",
	"gateway-tls-agent":                             "tls_agent",
	"browser-action-ingress-tls-agent":              "tls_agent",
	"guest-tls-agent":                               "tls_agent",
	"browser-tls-agent":                             "tls_agent",
	"desktop-tls-agent":                             "tls_agent",
	"browser-executor-tls-agent":                    "tls_agent",
	"desktop-executor-tls-agent":                    "tls_agent",
	"browser-action-ingress-agent-tls-agent":        "tls_agent",
	"browser-agent-tls-agent":                       "tls_agent",
	"desktop-agent-tls-agent":                       "tls_agent",
	"gateway-agent-tls-agent":                       "tls_agent",
	"guest-agent-tls-agent":                         "tls_agent",
	"product-migration-agent-tls-agent":             "tls_agent",
	"product-runtime-agent-tls-agent":               "tls_agent",
	"provider-browser-runtime-agent-tls-agent":      "tls_agent",
	"provider-desktop-runtime-agent-tls-agent":      "tls_agent",
	"provider-migration-agent-tls-agent":            "tls_agent",
	"provider-browser-migration-agent-tls-agent":    "tls_agent",
	"provider-desktop-migration-agent-tls-agent":    "tls_agent",
	"provider-runtime-agent-tls-agent":              "tls_agent",
	"product-runtime-agent":                         "material_agent",
	"provider-runtime-agent":                        "material_agent",
	"provider-browser-runtime-agent":                "material_agent",
	"provider-desktop-runtime-agent":                "material_agent",
	"gateway-agent":                                 "material_agent",
	"browser-action-ingress-agent":                  "material_agent",
	"guest-agent":                                   "material_agent",
	"browser-agent":                                 "material_agent",
	"desktop-agent":                                 "material_agent",
	"product-migration-agent":                       "material_agent",
	"provider-migration-agent":                      "material_agent",
	"provider-browser-migration-agent":              "material_agent",
	"provider-desktop-migration-agent":              "material_agent",
	"workload-credential-controller":                "controller",
	"break-glass-controller":                        "controller",
	"certificate-controller":                        "controller",
	"product-migration-job":                         "migration_job",
	"provider-migration-job":                        "migration_job",
	"provider-browser-migration-job":                "migration_job",
	"provider-desktop-migration-job":                "migration_job",
	"browser-sandbox-runtime":                       "sandbox",
	"desktop-sandbox-runtime":                       "sandbox",
	"public-ingress-relay":                          "ingress_relay",
}

type principalBinding struct {
	kind securityprincipal.Kind
	name string
	role securityprincipal.Role
}

var requiredAuthorizationBindings = map[string]principalBinding{
	"product-runtime":                               {securityprincipal.KindRuntimeRole, "product", securityprincipal.RoleProduct},
	"gateway-runtime":                               {securityprincipal.KindRuntimeRole, "gateway", securityprincipal.RoleGateway},
	"browser-action-ingress-runtime":                {securityprincipal.KindRuntimeRole, "browser_action_ingress", securityprincipal.RoleGateway},
	"provider-runtime":                              {securityprincipal.KindRuntimeRole, "provider", securityprincipal.RoleProvider},
	"provider-browser-runtime":                      {securityprincipal.KindRuntimeRole, "provider", securityprincipal.RoleProvider},
	"provider-desktop-runtime":                      {securityprincipal.KindRuntimeRole, "provider", securityprincipal.RoleProvider},
	"guest-runtime":                                 {securityprincipal.KindRuntimeRole, "guest", securityprincipal.RoleGuest},
	"browser-runtime-role":                          {securityprincipal.KindRuntimeRole, "browser", securityprincipal.RoleBrowser},
	"desktop-runtime-role":                          {securityprincipal.KindRuntimeRole, "desktop", securityprincipal.RoleDesktop},
	"browser-executor-backend":                      {securityprincipal.KindExecutorBackend, "browser_executor", securityprincipal.RoleBrowser},
	"desktop-executor-backend":                      {securityprincipal.KindExecutorBackend, "desktop_executor", securityprincipal.RoleDesktop},
	"product-tls-agent":                             {securityprincipal.KindTLSAgent, "product_tls_agent", securityprincipal.RoleProduct},
	"provider-tls-agent":                            {securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider},
	"provider-browser-tls-agent":                    {securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider},
	"provider-desktop-tls-agent":                    {securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider},
	"provider-browser-postgres-tls-agent":           {securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider},
	"provider-desktop-postgres-tls-agent":           {securityprincipal.KindTLSAgent, "provider_tls_agent", securityprincipal.RoleProvider},
	"product-postgres-tls-agent":                    {securityprincipal.KindTLSAgent, "product_postgres_tls_agent", securityprincipal.RoleProduct},
	"gateway-postgres-tls-agent":                    {securityprincipal.KindTLSAgent, "gateway_postgres_tls_agent", securityprincipal.RoleGateway},
	"provider-postgres-tls-agent":                   {securityprincipal.KindTLSAgent, "provider_postgres_tls_agent", securityprincipal.RoleProvider},
	"product-migration-postgres-tls-agent":          {securityprincipal.KindTLSAgent, "product_migration_postgres_tls_agent", securityprincipal.RoleProduct},
	"provider-migration-postgres-tls-agent":         {securityprincipal.KindTLSAgent, "provider_migration_postgres_tls_agent", securityprincipal.RoleProvider},
	"provider-browser-migration-postgres-tls-agent": {securityprincipal.KindTLSAgent, "provider_browser_migration_postgres_tls_agent", securityprincipal.RoleProvider},
	"provider-desktop-migration-postgres-tls-agent": {securityprincipal.KindTLSAgent, "provider_desktop_migration_postgres_tls_agent", securityprincipal.RoleProvider},
	"gateway-tls-agent":                             {securityprincipal.KindTLSAgent, "gateway_tls_agent", securityprincipal.RoleGateway},
	"browser-action-ingress-tls-agent":              {securityprincipal.KindTLSAgent, "browser_action_ingress_tls_agent", securityprincipal.RoleGateway},
	"guest-tls-agent":                               {securityprincipal.KindTLSAgent, "guest_tls_agent", securityprincipal.RoleGuest},
	"browser-tls-agent":                             {securityprincipal.KindTLSAgent, "browser_tls_agent", securityprincipal.RoleBrowser},
	"desktop-tls-agent":                             {securityprincipal.KindTLSAgent, "desktop_tls_agent", securityprincipal.RoleDesktop},
	"browser-executor-tls-agent":                    {securityprincipal.KindTLSAgent, "browser_executor_tls_agent", securityprincipal.RoleBrowser},
	"desktop-executor-tls-agent":                    {securityprincipal.KindTLSAgent, "desktop_executor_tls_agent", securityprincipal.RoleDesktop},
	"browser-action-ingress-agent-tls-agent":        {securityprincipal.KindTLSAgent, "browser_action_ingress_agent_tls_agent", securityprincipal.RoleGateway},
	"browser-agent-tls-agent":                       {securityprincipal.KindTLSAgent, "browser_agent_tls_agent", securityprincipal.RoleBrowser},
	"desktop-agent-tls-agent":                       {securityprincipal.KindTLSAgent, "desktop_agent_tls_agent", securityprincipal.RoleDesktop},
	"gateway-agent-tls-agent":                       {securityprincipal.KindTLSAgent, "gateway_agent_tls_agent", securityprincipal.RoleGateway},
	"guest-agent-tls-agent":                         {securityprincipal.KindTLSAgent, "guest_agent_tls_agent", securityprincipal.RoleGuest},
	"product-migration-agent-tls-agent":             {securityprincipal.KindTLSAgent, "product_migration_agent_tls_agent", securityprincipal.RoleProduct},
	"product-runtime-agent-tls-agent":               {securityprincipal.KindTLSAgent, "product_runtime_agent_tls_agent", securityprincipal.RoleProduct},
	"provider-browser-runtime-agent-tls-agent":      {securityprincipal.KindTLSAgent, "provider_browser_runtime_agent_tls_agent", securityprincipal.RoleProvider},
	"provider-desktop-runtime-agent-tls-agent":      {securityprincipal.KindTLSAgent, "provider_desktop_runtime_agent_tls_agent", securityprincipal.RoleProvider},
	"provider-migration-agent-tls-agent":            {securityprincipal.KindTLSAgent, "provider_migration_agent_tls_agent", securityprincipal.RoleProvider},
	"provider-browser-migration-agent-tls-agent":    {securityprincipal.KindTLSAgent, "provider_browser_migration_agent_tls_agent", securityprincipal.RoleProvider},
	"provider-desktop-migration-agent-tls-agent":    {securityprincipal.KindTLSAgent, "provider_desktop_migration_agent_tls_agent", securityprincipal.RoleProvider},
	"provider-runtime-agent-tls-agent":              {securityprincipal.KindTLSAgent, "provider_runtime_agent_tls_agent", securityprincipal.RoleProvider},
	"product-runtime-agent":                         {securityprincipal.KindMaterialAgent, "product_runtime_agent", securityprincipal.RoleProduct},
	"provider-runtime-agent":                        {securityprincipal.KindMaterialAgent, "provider_runtime_agent", securityprincipal.RoleProvider},
	"provider-browser-runtime-agent":                {securityprincipal.KindMaterialAgent, "provider_runtime_agent", securityprincipal.RoleProvider},
	"provider-desktop-runtime-agent":                {securityprincipal.KindMaterialAgent, "provider_runtime_agent", securityprincipal.RoleProvider},
	"gateway-agent":                                 {securityprincipal.KindMaterialAgent, "gateway_agent", securityprincipal.RoleGateway},
	"browser-action-ingress-agent":                  {securityprincipal.KindMaterialAgent, "browser_action_ingress_agent", securityprincipal.RoleGateway},
	"guest-agent":                                   {securityprincipal.KindMaterialAgent, "guest_agent", securityprincipal.RoleGuest},
	"browser-agent":                                 {securityprincipal.KindMaterialAgent, "browser_agent", securityprincipal.RoleBrowser},
	"desktop-agent":                                 {securityprincipal.KindMaterialAgent, "desktop_agent", securityprincipal.RoleDesktop},
	"product-migration-agent":                       {securityprincipal.KindMaterialAgent, "product_migration_agent", securityprincipal.RoleProduct},
	"provider-migration-agent":                      {securityprincipal.KindMaterialAgent, "provider_migration_agent", securityprincipal.RoleProvider},
	"provider-browser-migration-agent":              {securityprincipal.KindMaterialAgent, "provider_browser_migration_agent", securityprincipal.RoleProvider},
	"provider-desktop-migration-agent":              {securityprincipal.KindMaterialAgent, "provider_desktop_migration_agent", securityprincipal.RoleProvider},
	"workload-credential-controller":                {securityprincipal.KindController, "credential_controller", ""},
	"break-glass-controller":                        {securityprincipal.KindController, "break_glass_controller", ""},
	"certificate-controller":                        {securityprincipal.KindController, "certificate_controller", ""},
	"product-migration-job":                         {securityprincipal.KindMigrationJob, "product_migration", securityprincipal.RoleProduct},
	"provider-migration-job":                        {securityprincipal.KindMigrationJob, "provider_migration", securityprincipal.RoleProvider},
	"provider-browser-migration-job":                {securityprincipal.KindMigrationJob, "provider_browser_migration", securityprincipal.RoleProvider},
	"provider-desktop-migration-job":                {securityprincipal.KindMigrationJob, "provider_desktop_migration", securityprincipal.RoleProvider},
	"public-ingress-relay":                          {securityprincipal.KindIngressRelay, "public_ingress_relay", ""},
}

var requiredResourceControllers = map[string]string{
	"browser-sandbox-runtime": "provider-browser-runtime",
	"desktop-sandbox-runtime": "provider-desktop-runtime",
}

var requiredTLSAgentSubjects = map[string]string{
	"product-tls-agent":                          "product-runtime",
	"provider-tls-agent":                         "provider-runtime",
	"provider-browser-tls-agent":                 "provider-browser-runtime",
	"provider-desktop-tls-agent":                 "provider-desktop-runtime",
	"gateway-tls-agent":                          "gateway-runtime",
	"browser-action-ingress-tls-agent":           "browser-action-ingress-runtime",
	"guest-tls-agent":                            "guest-runtime",
	"browser-tls-agent":                          "browser-runtime-role",
	"desktop-tls-agent":                          "desktop-runtime-role",
	"browser-executor-tls-agent":                 "browser-executor-backend",
	"desktop-executor-tls-agent":                 "desktop-executor-backend",
	"browser-action-ingress-agent-tls-agent":     "browser-action-ingress-agent",
	"browser-agent-tls-agent":                    "browser-agent",
	"desktop-agent-tls-agent":                    "desktop-agent",
	"gateway-agent-tls-agent":                    "gateway-agent",
	"guest-agent-tls-agent":                      "guest-agent",
	"product-migration-agent-tls-agent":          "product-migration-agent",
	"product-runtime-agent-tls-agent":            "product-runtime-agent",
	"provider-browser-runtime-agent-tls-agent":   "provider-browser-runtime-agent",
	"provider-desktop-runtime-agent-tls-agent":   "provider-desktop-runtime-agent",
	"provider-migration-agent-tls-agent":         "provider-migration-agent",
	"provider-browser-migration-agent-tls-agent": "provider-browser-migration-agent",
	"provider-desktop-migration-agent-tls-agent": "provider-desktop-migration-agent",
	"provider-runtime-agent-tls-agent":           "provider-runtime-agent",
}

type Profile struct {
	Protocol                string                          `json:"protocol"`
	Version                 int                             `json:"version"`
	Revision                string                          `json:"revision"`
	ProfileDigest           string                          `json:"profile_digest"`
	EnvironmentDigest       string                          `json:"environment_digest"`
	PrincipalProfileDigest  string                          `json:"principal_profile_digest"`
	Principals              []Principal                     `json:"principals"`
	SandboxIdentitySlots    []SandboxIdentitySlot           `json:"sandbox_identity_slots"`
	ProviderDatabases       []ProviderDatabaseBinding       `json:"provider_databases"`
	PostgresServerAuth      PostgresServerAuthPolicy        `json:"postgres_server_auth"`
	Components              []Component                     `json:"components"`
	Networks                []Network                       `json:"networks"`
	External                []ExternalService               `json:"external_services"`
	TrustEdges              []TrustEdge                     `json:"trust_edges"`
	TrustAnchors            []TrustAnchor                   `json:"trust_anchors"`
	PublicListeners         []PublicListenerBinding         `json:"public_listeners"`
	IngressBindings         []IngressBinding                `json:"ingress_bindings"`
	CertificateController   CertificateControllerAuthority  `json:"certificate_controller"`
	CredentialIssuerSockets []CredentialIssuerSocketBinding `json:"credential_issuer_sockets"`
	TLSAgentBindings        []TLSAgentBinding               `json:"tls_agent_bindings"`
	PostgresClientAgents    []PostgresClientAgentBinding    `json:"postgres_client_agents"`
	EgressPolicies          []EgressPolicy                  `json:"egress_policies"`
	CleanupClasses          []string                        `json:"cleanup_classes"`
}

type Principal struct {
	Name                        string                       `json:"name"`
	Kind                        string                       `json:"kind"`
	ImageReference              string                       `json:"image_reference"`
	ImageDigest                 string                       `json:"image_digest"`
	ImageLocation               string                       `json:"image_location"`
	ImageIdentityKind           string                       `json:"image_identity_kind"`
	ImagePlatform               string                       `json:"image_platform"`
	ImageSelectedManifestDigest string                       `json:"image_selected_manifest_digest"`
	ImageConfigDigest           string                       `json:"image_config_digest"`
	UID                         uint32                       `json:"uid"`
	GID                         uint32                       `json:"gid"`
	ReadOnlyRootFilesystem      bool                         `json:"read_only_root_filesystem"`
	NoNewPrivileges             bool                         `json:"no_new_privileges"`
	DroppedCapabilities         []string                     `json:"dropped_capabilities"`
	SeccompDigest               string                       `json:"seccomp_digest"`
	Resources                   Resources                    `json:"resources"`
	Mounts                      []Mount                      `json:"mounts"`
	Networks                    []string                     `json:"networks"`
	HostNetwork                 bool                         `json:"host_network"`
	ExternalUplink              bool                         `json:"external_uplink"`
	DirectEgressBlocked         bool                         `json:"direct_egress_blocked"`
	DockerSocket                bool                         `json:"docker_socket"`
	HostDevices                 bool                         `json:"host_devices"`
	Listeners                   []Listener                   `json:"listeners"`
	AuthorizationPrincipal      *securityprincipal.Principal `json:"authorization_principal"`
	PrincipalDigest             string                       `json:"principal_digest"`
	ControllingPrincipalDigest  string                       `json:"controlling_principal_digest"`
	TLS                         *TLSIdentity                 `json:"tls"`
}

// Component is a required process within a parent container, not a second
// deployment principal or an independent UID/network/security boundary.
type Component struct {
	Name             string   `json:"name"`
	ParentDeployment string   `json:"parent_deployment"`
	Executable       string   `json:"executable"`
	ExecutableDigest string   `json:"executable_digest"`
	Argv             []string `json:"argv"`
	Socket           string   `json:"socket"`
	BrokerProtocol   string   `json:"broker_protocol"`
	SessionProtocol  string   `json:"session_protocol"`
}

type Resources struct {
	MemoryBytes int64 `json:"memory_bytes"`
	CPUMillis   int64 `json:"cpu_millis"`
	PIDs        int64 `json:"pids"`
}

type Network struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	Internal         bool     `json:"internal"`
	IPv6Enabled      bool     `json:"ipv6_enabled"`
	GatewayModeIPv4  string   `json:"gateway_mode_ipv4"`
	IPv4Subnet       string   `json:"ipv4_subnet"`
	Principals       []string `json:"principals"`
	ExternalServices []string `json:"external_services,omitempty"`
}

type Mount struct {
	Target    string `json:"target"`
	Kind      string `json:"kind"`
	ReadOnly  bool   `json:"read_only"`
	MaxBytes  int64  `json:"max_bytes"`
	StorageID string `json:"storage_id"`
}

// TrustAnchor pins one read-only CA bundle artifact and its exact consumers.
// BundleDigest covers the original bundle file bytes, not re-encoded PEM.
type TrustAnchor struct {
	ID              string   `json:"id"`
	BundleDigest    string   `json:"bundle_digest"`
	Purpose         string   `json:"purpose"`
	TrustDomain     string   `json:"trust_domain"`
	ArtifactID      string   `json:"artifact_id"`
	StorageID       string   `json:"storage_id"`
	TargetPath      string   `json:"target_path"`
	WriterAuthority string   `json:"writer_authority"`
	OwnerUID        uint32   `json:"owner_uid"`
	OwnerGID        uint32   `json:"owner_gid"`
	Consumers       []string `json:"consumers"`
}

type Listener struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Exposure string `json:"exposure"`
}

// PublicListenerBinding is the only server-auth-only ingress exception. It
// cannot be referenced by an internal mTLS edge or used as a client identity.
type PublicListenerBinding struct {
	ID                   string `json:"id"`
	DeploymentName       string `json:"deployment_name"`
	PrincipalDigest      string `json:"principal_digest"`
	ListenerName         string `json:"listener_name"`
	Port                 int    `json:"port"`
	IssuerAnchorID       string `json:"issuer_anchor_id"`
	ClientAuthentication string `json:"client_authentication"`
}

// IngressBinding pins one fixed L4 mapping from an operator relay frontend to
// a single existing Product or Gateway public listener.
type IngressBinding struct {
	ID                    string `json:"id"`
	Relay                 string `json:"relay"`
	RelayPrincipalDigest  string `json:"relay_principal_digest"`
	PublicListenerID      string `json:"public_listener_id"`
	Target                string `json:"target"`
	TargetPrincipalDigest string `json:"target_principal_digest"`
	FrontendNetwork       string `json:"frontend_network"`
	TrustNetwork          string `json:"trust_network"`
	FrontendAddress       string `json:"frontend_address"`
	UpstreamAddress       string `json:"upstream_address"`
	HostBindAddress       string `json:"host_bind_address"`
	MaxConnections        int    `json:"max_connections"`
	DialTimeoutMillis     int    `json:"dial_timeout_millis"`
	IdleTimeoutSeconds    int    `json:"idle_timeout_seconds"`
	MaxLifetimeSeconds    int    `json:"max_lifetime_seconds"`
	DrainTimeoutSeconds   int    `json:"drain_timeout_seconds"`
	BufferBytes           int    `json:"buffer_bytes"`
	ConfigurationDigest   string `json:"configuration_digest"`
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
	Name                        string   `json:"name"`
	ImageReference              string   `json:"image_reference"`
	ImageDigest                 string   `json:"image_digest"`
	ImageLocation               string   `json:"image_location"`
	ImageIdentityKind           string   `json:"image_identity_kind"`
	ImagePlatform               string   `json:"image_platform"`
	ImageSelectedManifestDigest string   `json:"image_selected_manifest_digest"`
	ImageConfigDigest           string   `json:"image_config_digest"`
	URI                         string   `json:"uri"`
	DNSNames                    []string `json:"dns_names"`
	IdentityDigest              string   `json:"identity_digest"`
	IngressEdges                []string `json:"ingress_edges"`
	Networks                    []string `json:"networks,omitempty"`
}

type TrustEdge struct {
	ID                     string `json:"id"`
	From                   string `json:"from"`
	To                     string `json:"to"`
	Protocol               string `json:"protocol"`
	Port                   int    `json:"port"`
	TargetAddress          string `json:"target_address,omitempty"`
	RoutePath              string `json:"route_path,omitempty"`
	Authentication         string `json:"authentication"`
	ServerAnchorID         string `json:"server_anchor_id,omitempty"`
	ClientAnchorID         string `json:"client_anchor_id,omitempty"`
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
	ID                        string          `json:"id"`
	Revision                  string          `json:"revision"`
	Principal                 string          `json:"principal"`
	Broker                    string          `json:"broker"`
	PrincipalDigest           string          `json:"principal_digest"`
	BrokerDigest              string          `json:"broker_digest"`
	Authority                 PolicyAuthority `json:"authority"`
	LeaseSeconds              int64           `json:"lease_seconds"`
	DNSMaxAnswers             int             `json:"dns_max_answers"`
	DenyRawIP                 bool            `json:"deny_raw_ip"`
	DenyAlternateDNS          bool            `json:"deny_alternate_dns"`
	DenyProxyEnvironment      bool            `json:"deny_proxy_environment"`
	DenyRedirectAuthority     bool            `json:"deny_redirect_authority"`
	DenyMetadataPrivateRanges bool            `json:"deny_metadata_private_ranges"`
	Targets                   []EgressTarget  `json:"targets"`
}

type PolicyAuthority struct {
	DeploymentName     string `json:"deployment_name"`
	AuthorizationName  string `json:"authorization_name"`
	PrincipalDigest    string `json:"principal_digest"`
	KeyID              string `json:"key_id"`
	PublicKeyDigest    string `json:"public_key_digest"`
	SocketDirectory    string `json:"socket_directory"`
	SocketStorageID    string `json:"socket_storage_id"`
	LedgerMountTarget  string `json:"ledger_mount_target"`
	LedgerStorageID    string `json:"ledger_storage_id"`
	PollMillis         int    `json:"poll_millis"`
	CurrentTimeoutMS   int    `json:"current_timeout_ms"`
	StateMaxAgeSeconds int    `json:"state_max_age_seconds"`
}

// TLSAgentBinding is the one-to-one deployment and signing authority for a
// role-owned TLS key. The socket directory is shared only by this pair.
type TLSAgentBinding struct {
	AgentDeployment           string `json:"agent_deployment"`
	AgentPrincipalDigest      string `json:"agent_principal_digest"`
	SubjectDeployment         string `json:"subject_deployment"`
	SubjectPrincipalDigest    string `json:"subject_principal_digest"`
	AgentUID                  uint32 `json:"agent_uid"`
	AgentGID                  uint32 `json:"agent_gid"`
	SubjectUID                uint32 `json:"subject_uid"`
	SubjectGID                uint32 `json:"subject_gid"`
	SocketDirectory           string `json:"socket_directory"`
	SocketStorageID           string `json:"socket_storage_id"`
	SocketPath                string `json:"socket_path"`
	DirectoryMode             uint32 `json:"directory_mode"`
	SocketMode                uint32 `json:"socket_mode"`
	UnixEdgeID                string `json:"unix_edge_id"`
	IssuerPolicyID            string `json:"issuer_policy_id"`
	IssuerVaultRole           string `json:"issuer_vault_role"`
	AgentRequestKeyID         string `json:"agent_request_key_id"`
	AgentRequestKeyDigest     string `json:"agent_request_key_digest"`
	ControllerDeployment      string `json:"controller_deployment"`
	ControllerUID             uint32 `json:"controller_uid"`
	ControllerGID             uint32 `json:"controller_gid"`
	ControllerSocketDirectory string `json:"controller_socket_directory"`
	ControllerSocketStorageID string `json:"controller_socket_storage_id"`
	ControllerSocketPath      string `json:"controller_socket_path"`
	ControllerDirectoryMode   uint32 `json:"controller_directory_mode"`
	ControllerSocketMode      uint32 `json:"controller_socket_mode"`
	ControllerUnixEdgeID      string `json:"controller_unix_edge_id"`
	CleanupClass              string `json:"cleanup_class"`
}

// PostgresClientAgentBinding is a second, purpose-specific agent for one
// Provider database owner. It does not replace that owner's ordinary TLS agent.
type PostgresClientAgentBinding struct {
	TLSAgentBinding
	CommonName     string `json:"common_name"`
	IssuerAnchorID string `json:"issuer_anchor_id"`
}

// CertificateControllerAuthority is one controller process with one private
// listener per TLS agent, one internal managed-TLS self listener and one
// credential-controller managed-TLS listener.
type CertificateControllerAuthority struct {
	DeploymentName          string                               `json:"deployment_name"`
	PrincipalDigest         string                               `json:"principal_digest"`
	UID                     uint32                               `json:"uid"`
	GID                     uint32                               `json:"gid"`
	ResponseKeyID           string                               `json:"response_key_id"`
	ResponsePublicKeyDigest string                               `json:"response_public_key_digest"`
	ManagedPolicyID         string                               `json:"managed_policy_id"`
	ManagedVaultRole        string                               `json:"managed_vault_role"`
	ManagedRequestKeyID     string                               `json:"managed_request_key_id"`
	ManagedRequestKeyDigest string                               `json:"managed_request_key_digest"`
	BootstrapClientAnchorID string                               `json:"bootstrap_client_anchor_id"`
	SelfSocketDirectory     string                               `json:"self_socket_directory"`
	SelfSocketStorageID     string                               `json:"self_socket_storage_id"`
	SelfSocketPath          string                               `json:"self_socket_path"`
	SelfDirectoryMode       uint32                               `json:"self_directory_mode"`
	SelfSocketMode          uint32                               `json:"self_socket_mode"`
	SelfUnixEdgeID          string                               `json:"self_unix_edge_id"`
	CredentialController    CredentialControllerManagedAuthority `json:"credential_controller"`
}

// CredentialControllerManagedAuthority is the one private CSR path by which
// the credential controller replaces its operator-supplied bootstrap TLS leaf.
type CredentialControllerManagedAuthority struct {
	PolicyID         string `json:"policy_id"`
	VaultRole        string `json:"vault_role"`
	RequestKeyID     string `json:"request_key_id"`
	RequestKeyDigest string `json:"request_key_digest"`
	SocketDirectory  string `json:"socket_directory"`
	SocketStorageID  string `json:"socket_storage_id"`
	SocketPath       string `json:"socket_path"`
	DirectoryMode    uint32 `json:"directory_mode"`
	SocketMode       uint32 `json:"socket_mode"`
	UnixEdgeID       string `json:"unix_edge_id"`
}

func CertificateControllerPublicKeyDigest(publicKey []byte) string {
	return principalKeyDigest("sandbox-runtime/phase6-certificate-controller-response-key/v1\x00", publicKey)
}

func TLSAgentRequestPublicKeyDigest(publicKey []byte) string {
	return principalKeyDigest("sandbox-runtime/phase6-tls-agent-request-key/v1\x00", publicKey)
}

func principalKeyDigest(domain string, publicKey []byte) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(append([]byte(domain), publicKey...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (p EgressPolicy) Digest() string {
	document, _ := json.Marshal(p)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-egress-policy/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func OperatorPublicKeyDigest(publicKey []byte) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return ""
	}
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-policy-authority-key/v1\x00"), publicKey...))
	return "sha256:" + hex.EncodeToString(digest[:])
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
		len(p.Components) != 1 ||
		len(p.Networks) < 1 || len(p.Networks) > 256 || len(p.External) != 5 || len(p.TrustEdges) < 1 || len(p.TrustEdges) > 512 ||
		len(p.ProviderDatabases) != 2 ||
		len(p.TrustAnchors) < 1 || len(p.TrustAnchors) > 128 || len(p.PublicListeners) != 2 || len(p.IngressBindings) != 2 ||
		len(p.TLSAgentBindings) < len(requiredTLSAgentSubjects) || len(p.TLSAgentBindings) > 136 ||
		len(p.PostgresClientAgents) != 9 || len(p.EgressPolicies) > 128 ||
		!exactStrings(p.CleanupClasses, []string{"connections", "containers", "files", "networks", "processes", "sockets"}) {
		return ErrInvalidProfile
	}
	registry, err := p.principalRegistry()
	if err != nil {
		return err
	}
	principals := make(map[string]Principal, len(p.Principals))
	principalDeployments := make(map[string]string, len(p.Principals))
	uids, gids, identities := map[uint32]struct{}{}, map[uint32]struct{}{}, map[string]struct{}{}
	previous := ""
	authorityBindings := make(map[string]principalBinding, len(p.EgressPolicies))
	dynamicTLSBindings := make(map[string]principalBinding, len(p.EgressPolicies))
	for _, policy := range p.EgressPolicies {
		authority := policy.Authority
		if _, duplicate := authorityBindings[authority.DeploymentName]; duplicate {
			return ErrInvalidProfile
		}
		authorityBindings[authority.DeploymentName] = principalBinding{securityprincipal.KindController, authority.AuthorizationName, ""}
		for _, binding := range p.TLSAgentBindings {
			if binding.SubjectDeployment != policy.Broker {
				continue
			}
			for _, principal := range p.Principals {
				if principal.Name == policy.Broker && principal.AuthorizationPrincipal != nil {
					identity := principal.AuthorizationPrincipal
					dynamicTLSBindings[binding.AgentDeployment] = principalBinding{
						securityprincipal.KindTLSAgent, identity.Name + "_tls_agent", identity.Role,
					}
					break
				}
			}
		}
	}
	for _, principal := range p.Principals {
		if principal.Name <= previous || validatePrincipal(principal, registry, authorityBindings, dynamicTLSBindings) != nil {
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
		if principal.AuthorizationPrincipal != nil {
			if _, exists := principalDeployments[principal.PrincipalDigest]; exists {
				return ErrInvalidProfile
			}
			if principal.TLS != nil {
				if _, exists := identities[principal.TLS.URI]; exists {
					return ErrInvalidProfile
				}
				identities[principal.TLS.URI] = struct{}{}
			}
			principalDeployments[principal.PrincipalDigest] = principal.Name
		}
		uids[principal.UID], gids[principal.GID] = struct{}{}, struct{}{}
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
	if c := p.Components[0]; c.Name != "desktop-broker" || c.ParentDeployment != "desktop-sandbox-runtime" ||
		c.Executable != "/usr/local/libexec/sandbox-runtime/desktop-broker" || !digestPattern.MatchString(c.ExecutableDigest) ||
		!exactStrings(c.Argv, []string{c.Executable, "serve"}) || c.Socket != "/tmp/sandbox-runtime-desktop-broker.sock" ||
		c.BrokerProtocol != "sandbox.runtime/desktop-broker/v1" || c.SessionProtocol != "sandbox.runtime/desktop-session.v2" ||
		principals[c.ParentDeployment].Kind != "sandbox" {
		return ErrInvalidProfile
	}
	for _, principal := range principals {
		if principal.AuthorizationPrincipal == nil {
			if _, ok := principalDeployments[principal.ControllingPrincipalDigest]; !ok {
				return ErrInvalidProfile
			}
		}
	}
	if validateSandboxIdentitySlots(p.SandboxIdentitySlots, principals) != nil {
		return ErrInvalidProfile
	}
	external, err := validateExternal(p.External)
	if err != nil {
		return err
	}
	if err := validateNetworks(p.Networks, principals, external, p.EgressPolicies); err != nil {
		return err
	}
	edges, err := validateEdges(p.TrustEdges, principals, external)
	if err != nil {
		return err
	}
	if err := validateProviderDatabases(p.ProviderDatabases, principals, external, edges, p.EgressPolicies); err != nil {
		return err
	}
	if err := p.PostgresServerAuth.validate(p.ProviderDatabases, external, p.TrustAnchors); err != nil {
		return err
	}
	if err := validateRuntimeEdges(edges, principals, p.Networks); err != nil {
		return err
	}
	if err := validateBrowserMux(principals, edges); err != nil {
		return err
	}
	if err := validatePublicListeners(p.PublicListeners, principals); err != nil {
		return err
	}
	if err := validateIngressBindings(p.IngressBindings, p.PublicListeners, principals, p.Networks); err != nil {
		return err
	}
	if err := validateTrustAnchorsWithPostgres(p.TrustAnchors, p.TrustEdges, p.PublicListeners, p.CertificateController, p.PostgresClientAgents, principals, external); err != nil {
		return err
	}
	if err := validateEgress(p.EgressPolicies, principals, edges); err != nil {
		return err
	}
	if err := validateBrokerBoundaries(p.EgressPolicies, edges, principals, p.Networks); err != nil {
		return err
	}
	if err := validateBrowserExternalAuthority(external, edges, p.EgressPolicies); err != nil {
		return err
	}
	if err := validateCertificateControllerAuthority(p.CertificateController, principals, edges); err != nil {
		return err
	}
	if err := validateCredentialIssuerSockets(p.CredentialIssuerSockets, principals, edges); err != nil {
		return err
	}
	if err := validatePostgresClientAgents(p.PostgresClientAgents, p.ProviderDatabases, p.TLSAgentBindings, p.EgressPolicies,
		p.CertificateController, p.TrustAnchors, principals, edges); err != nil {
		return err
	}
	if err := validateTLSAgentBindingsWithPostgres(p.TLSAgentBindings, p.PostgresClientAgents, p.EgressPolicies,
		p.CertificateController, p.CredentialIssuerSockets, principals, edges); err != nil {
		return err
	}
	for name, service := range external {
		for _, edge := range service.IngressEdges {
			if bound, ok := edges[edge]; !ok || bound.To != name {
				return ErrInvalidProfile
			}
		}
	}
	encoded, encodeErr := json.Marshal(p)
	if encodeErr != nil || len(encoded) > maxBytes || p.ProfileDigest != p.Digest() {
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
	authorities := make(map[string]securityprincipal.Role)
	for _, policy := range p.EgressPolicies {
		if _, duplicate := authorities[policy.Authority.AuthorizationName]; duplicate {
			return nil, ErrInvalidProfile
		}
		authorities[policy.Authority.AuthorizationName] = ""
	}
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
	registry, err := securityprincipal.NewRegistryWithPolicyAuthorities(p.EnvironmentDigest, p.PrincipalProfileDigest, egressBrokers, authorities)
	if err != nil {
		return nil, ErrInvalidProfile
	}
	return registry, nil
}

// PrincipalRegistry returns only the identities admitted by a valid profile.
func (p Profile) PrincipalRegistry() (*securityprincipal.Registry, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p.principalRegistry()
}

// TLSAgentForSubject returns the sole agent binding and its two deployments.
func (p Profile) TLSAgentForSubject(subjectName string) (TLSAgentBinding, Principal, Principal, error) {
	if err := p.Validate(); err != nil {
		return TLSAgentBinding{}, Principal{}, Principal{}, err
	}
	for _, binding := range p.TLSAgentBindings {
		if binding.SubjectDeployment != subjectName {
			continue
		}
		var agent, subject Principal
		for _, principal := range p.Principals {
			if principal.Name == binding.AgentDeployment {
				agent = principal
			}
			if principal.Name == binding.SubjectDeployment {
				subject = principal
			}
		}
		return binding, agent, subject, nil
	}
	return TLSAgentBinding{}, Principal{}, Principal{}, ErrInvalidProfile
}

// ExecutorTLSBoundary resolves the sole declared role-to-executor mTLS edge.
// A production executor may not invent an additional caller or listener.
func (p Profile) ExecutorTLSBoundary(subjectName string, port int) (TLSAgentBinding, Principal, Principal, Principal, error) {
	roleName, edgeID := "", ""
	switch subjectName {
	case "browser-executor-backend":
		roleName, edgeID = "browser-runtime-role", "executor-browser"
	case "desktop-executor-backend":
		roleName, edgeID = "desktop-runtime-role", "executor-desktop"
	default:
		return TLSAgentBinding{}, Principal{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	binding, agent, subject, err := p.TLSAgentForSubject(subjectName)
	if err != nil || subject.TLS == nil || !slices.Equal(subject.TLS.Usages, []string{"server_auth"}) ||
		len(subject.TLS.DNSNames) != 1 || !validDNSName(subject.TLS.DNSNames[0]) {
		return TLSAgentBinding{}, Principal{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	var caller Principal
	for _, principal := range p.Principals {
		if principal.Name == roleName {
			caller = principal
		}
	}
	if caller.TLS == nil || !slices.Contains(caller.TLS.Usages, "client_auth") || port < 1 || port > 65535 ||
		len(subject.Listeners) != 1 || subject.Listeners[0].Protocol != "tcp" ||
		subject.Listeners[0].Exposure != "trust_edge" || subject.Listeners[0].Port != port {
		return TLSAgentBinding{}, Principal{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	shared := 0
	for _, network := range p.Networks {
		if slices.Contains(caller.Networks, network.Name) && slices.Contains(subject.Networks, network.Name) {
			if network.Kind != "trust_edge" || !network.Internal {
				return TLSAgentBinding{}, Principal{}, Principal{}, Principal{}, ErrInvalidProfile
			}
			shared++
		}
	}
	if shared != 1 {
		return TLSAgentBinding{}, Principal{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	count := 0
	for _, edge := range p.TrustEdges {
		if edge.To != subjectName || edge.Authentication != "mtls" {
			continue
		}
		if edge.ID != edgeID || edge.From != roleName || edge.Protocol != "wss" || edge.Port != port ||
			edge.RoutePath != "/executor" || edge.TargetAddress == "" ||
			edge.FromURI != caller.TLS.URI || edge.ToURI != subject.TLS.URI {
			return TLSAgentBinding{}, Principal{}, Principal{}, Principal{}, ErrInvalidProfile
		}
		count++
	}
	if count != 1 {
		return TLSAgentBinding{}, Principal{}, Principal{}, Principal{}, ErrInvalidProfile
	}
	return binding, agent, subject, caller, nil
}

func validatePrincipal(value Principal, registry *securityprincipal.Registry, authorityBindings, dynamicTLSBindings map[string]principalBinding) error { //nolint:gocyclo
	if !namePattern.MatchString(value.Name) || !validPrincipalKind(value.Kind) || !validImageIdentity(value.ImageLocation, value.ImageIdentityKind,
		value.ImageReference, value.ImageDigest, value.ImagePlatform, value.ImageSelectedManifestDigest, value.ImageConfigDigest) ||
		value.UID < 10000 || value.UID > 60000 || value.GID < 10000 || value.GID > 60000 ||
		!value.ReadOnlyRootFilesystem || !value.NoNewPrivileges || !exactStrings(value.DroppedCapabilities, []string{"ALL"}) ||
		!digestPattern.MatchString(value.SeccompDigest) || value.Resources.MemoryBytes < 16<<20 || value.Resources.MemoryBytes > 64<<30 ||
		value.Resources.CPUMillis < 10 || value.Resources.CPUMillis > 64000 || value.Resources.PIDs < 4 || value.Resources.PIDs > 4096 ||
		value.HostNetwork || value.DockerSocket || value.HostDevices || len(value.Networks) < 1 || len(value.Networks) > 32 ||
		len(value.Mounts) > 128 || (value.Kind != "controller" && len(value.Mounts) > 16) || len(value.Listeners) > 16 {
		return ErrInvalidProfile
	}
	if value.Kind == "sandbox" && value.Name != "browser-sandbox-runtime" && value.Name != "desktop-sandbox-runtime" {
		return ErrInvalidProfile
	}
	if value.AuthorizationPrincipal != nil {
		identity := *value.AuthorizationPrincipal
		if registry == nil || registry.Validate(identity) != nil || value.PrincipalDigest != identity.Digest() ||
			!digestPattern.MatchString(value.PrincipalDigest) || value.ControllingPrincipalDigest != "" ||
			(value.Kind == "ingress_relay" && value.TLS != nil) || (value.Kind != "ingress_relay" && value.TLS == nil) ||
			(value.TLS != nil && (value.TLS.PrincipalDigest != value.PrincipalDigest || validateTLS(*value.TLS) != nil)) ||
			validateAuthorizationBinding(value.Name, value.Kind, identity, authorityBindings, dynamicTLSBindings) != nil {
			return ErrInvalidProfile
		}
	} else if value.PrincipalDigest != "" || !digestPattern.MatchString(value.ControllingPrincipalDigest) || value.TLS != nil ||
		value.Kind != "sandbox" {
		return ErrInvalidProfile
	}
	if value.Kind == "egress_broker" {
		if value.AuthorizationPrincipal == nil || !value.ExternalUplink || value.DirectEgressBlocked ||
			len(value.Networks) < 2 || len(value.Networks) > 8 {
			return ErrInvalidProfile
		}
	} else if value.Kind == "ingress_relay" {
		if value.AuthorizationPrincipal == nil || !value.ExternalUplink || value.DirectEgressBlocked ||
			len(value.Networks) != 3 || len(value.Mounts) != 0 || len(value.Listeners) != 2 {
			return ErrInvalidProfile
		}
	} else if value.ExternalUplink || !value.DirectEgressBlocked {
		return ErrInvalidProfile
	}
	if value.Kind == "tls_agent" && len(value.Listeners) != 0 {
		return ErrInvalidProfile
	}
	if !sortedUniqueNames(value.Networks) {
		return ErrInvalidProfile
	}
	seenMounts := map[string]struct{}{}
	for _, mount := range value.Mounts {
		if !strings.HasPrefix(mount.Target, "/") || path.Clean(mount.Target) != mount.Target || mount.Target == "/" ||
			(mount.Kind != "tmpfs" && mount.Kind != "private_socket" && mount.Kind != "persistent_ledger" && mount.Kind != "trust_anchor") {
			return ErrInvalidProfile
		}
		if _, duplicate := seenMounts[mount.Target]; duplicate {
			return ErrInvalidProfile
		}
		seenMounts[mount.Target] = struct{}{}
		switch mount.Kind {
		case "tmpfs":
			if mount.ReadOnly || mount.MaxBytes < 4096 || mount.MaxBytes > 1<<30 || mount.StorageID != "" {
				return ErrInvalidProfile
			}
		case "private_socket":
			if mount.MaxBytes != 0 || !namePattern.MatchString(mount.StorageID) {
				return ErrInvalidProfile
			}
		case "persistent_ledger":
			_, policyAuthority := authorityBindings[value.Name]
			if !policyAuthority || mount.ReadOnly || mount.MaxBytes < 4096 || mount.MaxBytes > 1<<30 ||
				!namePattern.MatchString(mount.StorageID) {
				return ErrInvalidProfile
			}
		case "trust_anchor":
			if !mount.ReadOnly || mount.MaxBytes != 0 || !namePattern.MatchString(mount.StorageID) {
				return ErrInvalidProfile
			}
		}
	}
	seenListeners := map[string]struct{}{}
	for _, listener := range value.Listeners {
		if !namePattern.MatchString(listener.Name) || (listener.Protocol != "tcp" && listener.Protocol != "udp" && listener.Protocol != "unix") ||
			(listener.Exposure != "public" && listener.Exposure != "trust_edge" && listener.Exposure != "loopback" && listener.Exposure != "private_socket" && listener.Exposure != "ingress_frontend") ||
			(listener.Exposure == "ingress_frontend" && (value.Kind != "ingress_relay" || listener.Protocol != "tcp")) ||
			(value.Kind == "ingress_relay" && listener.Exposure != "ingress_frontend") ||
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

func validateAuthorizationBinding(deploymentName, deploymentKind string, identity securityprincipal.Principal, authorityBindings, dynamicTLSBindings map[string]principalBinding) error {
	if expected, required := requiredAuthorizationBindings[deploymentName]; required {
		if identity.Kind != expected.kind || identity.Name != expected.name || identity.Role != expected.role ||
			deploymentKindForPrincipal(identity.Kind) != deploymentKind {
			return ErrInvalidProfile
		}
		return nil
	}
	if expected, authorized := authorityBindings[deploymentName]; authorized {
		if identity.Kind != expected.kind || identity.Name != expected.name || identity.Role != expected.role ||
			deploymentKind != "controller" {
			return ErrInvalidProfile
		}
		return nil
	}
	if expected, authorized := dynamicTLSBindings[deploymentName]; authorized {
		if identity.Kind != expected.kind || identity.Name != expected.name || identity.Role != expected.role || deploymentKind != "tls_agent" {
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
	case securityprincipal.KindTLSAgent:
		return "tls_agent"
	case securityprincipal.KindController:
		return "controller"
	case securityprincipal.KindMigrationJob:
		return "migration_job"
	case securityprincipal.KindEgressBroker:
		return "egress_broker"
	case securityprincipal.KindIngressRelay:
		return "ingress_relay"
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

func validateNetworks(values []Network, principals map[string]Principal, external map[string]ExternalService, egressPolicies []EgressPolicy) error { //nolint:gocyclo
	networks := make(map[string]Network, len(values))
	prefixes := make([]netip.Prefix, 0, len(values))
	previous := ""
	for _, network := range values {
		prefix, prefixErr := netip.ParsePrefix(network.IPv4Subnet)
		if network.Name <= previous || !namePattern.MatchString(network.Name) || len(network.Principals) < 1 ||
			!sortedUniqueNames(network.Principals) || !sortedUniqueNames(network.ExternalServices) ||
			len(network.ExternalServices) > 1 || network.IPv6Enabled || prefixErr != nil ||
			!validObservedSubnet(network.IPv4Subnet, "") || prefix.String() != network.IPv4Subnet {
			return ErrInvalidProfile
		}
		for _, existing := range prefixes {
			if existing.Contains(prefix.Addr()) || prefix.Contains(existing.Addr()) {
				return ErrInvalidProfile
			}
		}
		prefixes = append(prefixes, prefix)
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
		case "public_ingress":
			if network.Internal || network.GatewayModeIPv4 != "nat" || len(network.Principals) != 1 ||
				network.Principals[0] != "public-ingress-relay" {
				return ErrInvalidProfile
			}
			principal, ok := principals[network.Principals[0]]
			if !ok || principal.Kind != "ingress_relay" {
				return ErrInvalidProfile
			}
		default:
			return ErrInvalidProfile
		}
		if len(network.ExternalServices) != 0 {
			if !network.Internal || network.GatewayModeIPv4 != "isolated" ||
				len(network.Principals) != 1 ||
				(network.Kind != "role_internal" && network.Kind != "trust_edge") {
				return ErrInvalidProfile
			}
			service, ok := external[network.ExternalServices[0]]
			if !ok || !slicesContains(service.Networks, network.Name) {
				return ErrInvalidProfile
			}
		}
		for _, name := range network.Principals {
			principal, ok := principals[name]
			if !ok || !slicesContains(principal.Networks, network.Name) {
				return ErrInvalidProfile
			}
		}
		networks[network.Name] = network
	}
	for name, service := range external {
		for _, networkName := range service.Networks {
			network, ok := networks[networkName]
			if !ok || !slicesContains(network.ExternalServices, name) {
				return ErrInvalidProfile
			}
		}
	}
	for name, principal := range principals {
		externalCount := 0
		ingressCount := 0
		for _, networkName := range principal.Networks {
			network, ok := networks[networkName]
			if !ok || !slicesContains(network.Principals, name) {
				return ErrInvalidProfile
			}
			if network.Kind == "external_uplink" {
				externalCount++
			}
			if network.Kind == "public_ingress" {
				ingressCount++
			}
		}
		if principal.Kind == "egress_broker" {
			if externalCount != 1 || ingressCount != 0 {
				return ErrInvalidProfile
			}
		} else if principal.Kind == "ingress_relay" {
			if externalCount != 0 || ingressCount != 1 {
				return ErrInvalidProfile
			}
		} else if externalCount != 0 || ingressCount != 0 {
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
		if value.Name <= previous || value.ImageLocation != "registry" ||
			!validImageIdentity(value.ImageLocation, value.ImageIdentityKind, value.ImageReference, value.ImageDigest, value.ImagePlatform,
				value.ImageSelectedManifestDigest, value.ImageConfigDigest) || !validSPIFFE(value.URI) ||
			!digestPattern.MatchString(value.IdentityDigest) || value.IdentityDigest != value.Digest() ||
			len(value.DNSNames) < 1 || len(value.DNSNames) > 8 || len(value.IngressEdges) < 1 ||
			!sortedUniqueNames(value.IngressEdges) || !sortedUniqueNames(value.Networks) {
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
	for _, required := range []string{"action-history-postgres", "capacity-valkey", "dns", "postgres", "vault"} {
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
		if value.TargetAddress == "" && value.RoutePath != "" {
			return nil, ErrInvalidProfile
		}
		if value.TargetAddress != "" {
			target, err := netip.ParseAddrPort(value.TargetAddress)
			if err != nil || !target.Addr().Is4() || !target.Addr().IsPrivate() ||
				target.String() != value.TargetAddress || int(target.Port()) != value.Port ||
				!toOK || value.Authentication != "mtls" {
				return nil, ErrInvalidProfile
			}
			if value.Protocol == "tls" {
				if to.Kind != "egress_broker" || value.RoutePath != "" || value.CrossDomain {
					return nil, ErrInvalidProfile
				}
			} else if (value.Protocol != "wss" && value.Protocol != "https") ||
				!routePathPattern.MatchString(value.RoutePath) || path.Clean(value.RoutePath) != value.RoutePath {
				return nil, ErrInvalidProfile
			}
		}
		result[value.ID] = value
	}
	return result, nil
}

func validateEgress(values []EgressPolicy, principals map[string]Principal, edges map[string]TrustEdge) error {
	seenPolicies, seenPrincipals, seenBrokers, seenAuthorities := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	seenStorage := map[string]struct{}{}
	seenKeys := map[string]struct{}{}
	seenKeyIDs := map[string]struct{}{}
	previous := ""
	for _, value := range values {
		principal, principalOK := principals[value.Principal]
		broker, brokerOK := principals[value.Broker]
		authority, authorityOK := principals[value.Authority.DeploymentName]
		if value.ID <= previous || !namePattern.MatchString(value.ID) || !namePattern.MatchString(value.Revision) || !principalOK || !brokerOK ||
			principal.Kind == "egress_broker" || broker.Kind != "egress_broker" || value.Principal == value.Broker ||
			principal.AuthorizationPrincipal == nil || broker.AuthorizationPrincipal == nil ||
			value.PrincipalDigest != principal.PrincipalDigest || value.BrokerDigest != broker.PrincipalDigest ||
			!authorityOK || authority.Kind != "controller" || authority.AuthorizationPrincipal == nil ||
			value.Authority.PrincipalDigest != authority.PrincipalDigest ||
			value.Authority.AuthorizationName != authority.AuthorizationPrincipal.Name ||
			!namePattern.MatchString(value.Authority.KeyID) || !digestPattern.MatchString(value.Authority.PublicKeyDigest) ||
			!validAuthorityDirectory(value.Authority.SocketDirectory) ||
			!validAuthorityDirectory(value.Authority.LedgerMountTarget) ||
			!separateMountTargets(value.Authority.SocketDirectory, value.Authority.LedgerMountTarget) ||
			!namePattern.MatchString(value.Authority.SocketStorageID) ||
			!namePattern.MatchString(value.Authority.LedgerStorageID) ||
			value.Authority.SocketStorageID == value.Authority.LedgerStorageID ||
			value.Authority.PollMillis < 50 || value.Authority.PollMillis > 1000 ||
			value.Authority.CurrentTimeoutMS < 100 || value.Authority.CurrentTimeoutMS > 5000 ||
			value.Authority.PollMillis+value.Authority.CurrentTimeoutMS > 2000 ||
			value.Authority.StateMaxAgeSeconds < 1 || value.Authority.StateMaxAgeSeconds > 30 ||
			value.LeaseSeconds < 1 || value.LeaseSeconds > 300 || value.DNSMaxAnswers < 1 || value.DNSMaxAnswers > 32 ||
			!value.DenyRawIP || !value.DenyAlternateDNS || !value.DenyProxyEnvironment || !value.DenyRedirectAuthority || !value.DenyMetadataPrivateRanges ||
			len(value.Targets) < 1 || len(value.Targets) > 64 || len(broker.Listeners) != 1 ||
			broker.Listeners[0].Name != "egress" || broker.Listeners[0].Protocol != "tcp" ||
			broker.Listeners[0].Exposure != "trust_edge" || broker.Listeners[0].Port < 1 {
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
		if _, duplicate := seenAuthorities[value.Authority.DeploymentName]; duplicate {
			return ErrInvalidProfile
		}
		if _, duplicate := seenKeys[value.Authority.PublicKeyDigest]; duplicate {
			return ErrInvalidProfile
		}
		if _, duplicate := seenKeyIDs[value.Authority.KeyID]; duplicate {
			return ErrInvalidProfile
		}
		seenKeys[value.Authority.PublicKeyDigest] = struct{}{}
		seenKeyIDs[value.Authority.KeyID] = struct{}{}
		for _, storageID := range []string{value.Authority.SocketStorageID, value.Authority.LedgerStorageID} {
			if _, duplicate := seenStorage[storageID]; duplicate {
				return ErrInvalidProfile
			}
			seenStorage[storageID] = struct{}{}
		}
		if !exactPolicyMount(authority, "private_socket", value.Authority.SocketDirectory, value.Authority.SocketStorageID, false) ||
			!exactPolicyMount(broker, "private_socket", value.Authority.SocketDirectory, value.Authority.SocketStorageID, true) ||
			!exactPolicyMount(authority, "persistent_ledger", value.Authority.LedgerMountTarget, value.Authority.LedgerStorageID, false) {
			return ErrInvalidProfile
		}
		unixEdge := false
		for _, edge := range edges {
			if edge.From == value.Broker && edge.To == value.Authority.DeploymentName &&
				edge.Protocol == "unix" && edge.Authentication == "unix_peer_credentials" &&
				edge.FromPrincipalDigest == broker.PrincipalDigest && edge.ToPrincipalDigest == authority.PrincipalDigest {
				unixEdge = true
			}
		}
		if !unixEdge {
			return ErrInvalidProfile
		}
		seenPolicies[value.ID], seenPrincipals[value.Principal], seenBrokers[value.Broker], seenAuthorities[value.Authority.DeploymentName] = struct{}{}, struct{}{}, struct{}{}, struct{}{}
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
		for _, mount := range principal.Mounts {
			if mount.Kind == "persistent_ledger" || mount.Kind == "private_socket" {
				if _, expected := seenStorage[mount.StorageID]; expected &&
					!policyStorageMember(values, principal.Name, mount) {
					return ErrInvalidProfile
				}
			}
		}
	}
	return nil
}

func validAuthorityDirectory(directory string) bool {
	return path.IsAbs(directory) && path.Clean(directory) == directory && directory != "/"
}

func separateMountTargets(first, second string) bool {
	return first != second && !strings.HasPrefix(first, second+"/") && !strings.HasPrefix(second, first+"/")
}

func exactPolicyMount(principal Principal, kind, target, storageID string, readOnly bool) bool {
	for _, mount := range principal.Mounts {
		if mount.Kind == kind && mount.Target == target && mount.StorageID == storageID && mount.ReadOnly == readOnly {
			return true
		}
	}
	return false
}

func policyStorageMember(policies []EgressPolicy, principalName string, mount Mount) bool {
	for _, policy := range policies {
		authority := policy.Authority
		if principalName == authority.DeploymentName &&
			((mount.Kind == "private_socket" && mount.Target == authority.SocketDirectory && mount.StorageID == authority.SocketStorageID) ||
				(mount.Kind == "persistent_ledger" && mount.Target == authority.LedgerMountTarget && mount.StorageID == authority.LedgerStorageID)) {
			return true
		}
		if principalName == policy.Broker && mount.Kind == "private_socket" &&
			mount.Target == authority.SocketDirectory && mount.StorageID == authority.SocketStorageID {
			return true
		}
	}
	return false
}

func validateCertificateControllerAuthority(value CertificateControllerAuthority, principals map[string]Principal, edges map[string]TrustEdge) error {
	controller, found := principals[value.DeploymentName]
	edge, edgeFound := edges[value.SelfUnixEdgeID]
	credential, credentialFound := principals["workload-credential-controller"]
	managed := value.CredentialController
	managedEdge, managedEdgeFound := edges[managed.UnixEdgeID]
	if !found || !edgeFound || value.DeploymentName != "certificate-controller" || controller.Kind != "controller" ||
		value.PrincipalDigest != controller.PrincipalDigest || value.UID != controller.UID || value.GID != controller.GID ||
		!namePattern.MatchString(value.ResponseKeyID) || !digestPattern.MatchString(value.ResponsePublicKeyDigest) ||
		!namePattern.MatchString(value.ManagedPolicyID) || !namePattern.MatchString(value.ManagedVaultRole) ||
		!namePattern.MatchString(value.ManagedRequestKeyID) || !digestPattern.MatchString(value.ManagedRequestKeyDigest) ||
		value.SelfSocketDirectory != "/run/certificate-controller/self" ||
		value.SelfSocketPath != path.Join(value.SelfSocketDirectory, "managed.sock") ||
		value.SelfDirectoryMode != 0o700 || value.SelfSocketMode != 0o600 ||
		!namePattern.MatchString(value.SelfSocketStorageID) || !namePattern.MatchString(value.SelfUnixEdgeID) ||
		!exactPolicyMount(controller, "private_socket", value.SelfSocketDirectory, value.SelfSocketStorageID, false) ||
		edge.From != controller.Name || edge.To != controller.Name || edge.Protocol != "unix" ||
		edge.Authentication != "unix_peer_credentials" || edge.TenantScope != "system" || edge.MaxConnectionSeconds > 30 ||
		edge.FromPrincipalDigest != controller.PrincipalDigest || edge.ToPrincipalDigest != controller.PrincipalDigest ||
		edge.FromURI != controller.TLS.URI || edge.ToURI != controller.TLS.URI ||
		!credentialFound || credential.Kind != "controller" || credential.TLS == nil ||
		!namePattern.MatchString(managed.PolicyID) || !namePattern.MatchString(managed.VaultRole) ||
		!namePattern.MatchString(managed.RequestKeyID) || !digestPattern.MatchString(managed.RequestKeyDigest) ||
		managed.PolicyID == value.ManagedPolicyID || managed.VaultRole == value.ManagedVaultRole ||
		managed.RequestKeyID == value.ManagedRequestKeyID || managed.RequestKeyDigest == value.ManagedRequestKeyDigest ||
		managed.SocketDirectory != "/run/certificate-controller/workload-credential-controller" ||
		managed.SocketPath != path.Join(managed.SocketDirectory, "request.sock") ||
		managed.DirectoryMode != 0o710 || managed.SocketMode != 0o666 ||
		!namePattern.MatchString(managed.SocketStorageID) || managed.SocketStorageID == value.SelfSocketStorageID ||
		!namePattern.MatchString(managed.UnixEdgeID) || managed.UnixEdgeID == value.SelfUnixEdgeID ||
		!exactPolicyMount(controller, "private_socket", managed.SocketDirectory, managed.SocketStorageID, false) ||
		!exactPolicyMount(credential, "private_socket", managed.SocketDirectory, managed.SocketStorageID, true) ||
		!managedEdgeFound || managedEdge.From != credential.Name || managedEdge.To != controller.Name ||
		managedEdge.Protocol != "unix" || managedEdge.Authentication != "unix_peer_credentials" ||
		managedEdge.TenantScope != "system" || managedEdge.MaxConnectionSeconds > 30 ||
		managedEdge.FromPrincipalDigest != credential.PrincipalDigest || managedEdge.ToPrincipalDigest != controller.PrincipalDigest ||
		managedEdge.FromURI != credential.TLS.URI || managedEdge.ToURI != controller.TLS.URI {
		return ErrInvalidProfile
	}
	for name, principal := range principals {
		if name == controller.Name {
			continue
		}
		for _, mount := range principal.Mounts {
			if mount.Kind == "private_socket" && (mount.StorageID == value.SelfSocketStorageID ||
				mount.StorageID == managed.SocketStorageID && name != credential.Name) {
				return ErrInvalidProfile
			}
		}
	}
	return nil
}

func validateTLSAgentBindings(values []TLSAgentBinding, policies []EgressPolicy, controllerAuthority CertificateControllerAuthority,
	principals map[string]Principal, edges map[string]TrustEdge) error {
	return validateTLSAgentBindingsWithPostgres(values, nil, policies, controllerAuthority, nil, principals, edges)
}

func validateTLSAgentBindingsWithPostgres(values []TLSAgentBinding, postgres []PostgresClientAgentBinding,
	policies []EgressPolicy, controllerAuthority CertificateControllerAuthority, credentialSockets []CredentialIssuerSocketBinding,
	principals map[string]Principal, edges map[string]TrustEdge) error {
	expected := make(map[string]string, len(requiredTLSAgentSubjects)+len(policies))
	for agent, subject := range requiredTLSAgentSubjects {
		expected[agent] = subject
	}
	policyStorage := map[string]struct{}{controllerAuthority.SelfSocketStorageID: {}, controllerAuthority.CredentialController.SocketStorageID: {}}
	credentialStorage := make(map[string]struct{}, len(credentialSockets))
	for _, binding := range credentialSockets {
		credentialStorage[binding.SocketStorageID] = struct{}{}
	}
	brokerSubjects := map[string]struct{}{}
	for _, policy := range policies {
		brokerSubjects[policy.Broker] = struct{}{}
		policyStorage[policy.Authority.SocketStorageID] = struct{}{}
		policyStorage[policy.Authority.LedgerStorageID] = struct{}{}
	}
	if len(values) != len(expected)+len(policies) {
		return ErrInvalidProfile
	}
	seenAgents, seenSubjects, seenStorage, seenControllerStorage, seenEdges, seenControllerEdges, seenPolicies, seenVaultRoles, seenRequestKeys, seenRequestKeyIDs :=
		map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{},
		map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{},
		map[string]struct{}{}, map[string]struct{}{}
	controller := principals[controllerAuthority.DeploymentName]
	seenPolicies[controllerAuthority.ManagedPolicyID] = struct{}{}
	seenPolicies[controllerAuthority.CredentialController.PolicyID] = struct{}{}
	seenVaultRoles[controllerAuthority.ManagedVaultRole] = struct{}{}
	seenVaultRoles[controllerAuthority.CredentialController.VaultRole] = struct{}{}
	seenRequestKeys[controllerAuthority.ManagedRequestKeyDigest] = struct{}{}
	seenRequestKeys[controllerAuthority.CredentialController.RequestKeyDigest] = struct{}{}
	seenRequestKeyIDs[controllerAuthority.ManagedRequestKeyID] = struct{}{}
	seenRequestKeyIDs[controllerAuthority.CredentialController.RequestKeyID] = struct{}{}
	previous := ""
	for _, value := range values {
		agent, agentOK := principals[value.AgentDeployment]
		subject, subjectOK := principals[value.SubjectDeployment]
		edge, edgeOK := edges[value.UnixEdgeID]
		controllerEdge, controllerEdgeOK := edges[value.ControllerUnixEdgeID]
		staticSubject, staticAgent := expected[value.AgentDeployment]
		_, dynamicSubject := brokerSubjects[value.SubjectDeployment]
		if value.AgentDeployment <= previous || !agentOK || !subjectOK || !edgeOK || !controllerEdgeOK ||
			!(staticAgent && staticSubject == value.SubjectDeployment) && !(dynamicSubject && !staticAgent) || agent.Kind != "tls_agent" ||
			(subject.Kind != "runtime" && subject.Kind != "executor" && subject.Kind != "egress_broker" && subject.Kind != "material_agent") ||
			agent.AuthorizationPrincipal == nil || subject.AuthorizationPrincipal == nil ||
			agent.AuthorizationPrincipal.Role != subject.AuthorizationPrincipal.Role ||
			value.AgentPrincipalDigest != agent.PrincipalDigest || value.SubjectPrincipalDigest != subject.PrincipalDigest ||
			value.AgentUID != agent.UID || value.AgentGID != agent.GID || value.SubjectUID != subject.UID || value.SubjectGID != subject.GID ||
			value.AgentUID == value.SubjectUID || value.AgentGID == value.SubjectGID ||
			value.SocketDirectory != path.Join("/run/tls", value.AgentDeployment) || value.SocketPath != path.Join(value.SocketDirectory, "signer.sock") ||
			!namePattern.MatchString(value.SocketStorageID) || !namePattern.MatchString(value.UnixEdgeID) ||
			!namePattern.MatchString(value.IssuerPolicyID) || !namePattern.MatchString(value.IssuerVaultRole) ||
			!namePattern.MatchString(value.AgentRequestKeyID) || !digestPattern.MatchString(value.AgentRequestKeyDigest) ||
			value.DirectoryMode != 0o710 || value.SocketMode != 0o666 ||
			value.ControllerDeployment != controller.Name || value.ControllerUID != controller.UID || value.ControllerGID != controller.GID ||
			value.ControllerSocketDirectory != path.Join("/run/certificate-controller", value.AgentDeployment) ||
			value.ControllerSocketPath != path.Join(value.ControllerSocketDirectory, "request.sock") ||
			!namePattern.MatchString(value.ControllerSocketStorageID) || !namePattern.MatchString(value.ControllerUnixEdgeID) ||
			value.ControllerDirectoryMode != 0o710 || value.ControllerSocketMode != 0o666 ||
			!exactPolicyMount(controller, "private_socket", value.ControllerSocketDirectory, value.ControllerSocketStorageID, false) ||
			!exactPolicyMount(agent, "private_socket", value.ControllerSocketDirectory, value.ControllerSocketStorageID, true) ||
			value.CleanupClass != "sockets" || !exactPolicyMount(agent, "private_socket", value.SocketDirectory, value.SocketStorageID, false) ||
			!exactPolicyMount(subject, "private_socket", value.SocketDirectory, value.SocketStorageID, true) ||
			edge.From != value.SubjectDeployment || edge.To != value.AgentDeployment || edge.Protocol != "unix" ||
			edge.Authentication != "unix_peer_credentials" || edge.TenantScope != "system" || edge.MaxConnectionSeconds > 30 ||
			edge.FromPrincipalDigest != subject.PrincipalDigest || edge.ToPrincipalDigest != agent.PrincipalDigest ||
			edge.FromURI != subject.TLS.URI || edge.ToURI != agent.TLS.URI ||
			controllerEdge.From != agent.Name || controllerEdge.To != controller.Name || controllerEdge.Protocol != "unix" ||
			controllerEdge.Authentication != "unix_peer_credentials" || controllerEdge.TenantScope != "system" ||
			controllerEdge.MaxConnectionSeconds > 30 || controllerEdge.FromPrincipalDigest != agent.PrincipalDigest ||
			controllerEdge.ToPrincipalDigest != controller.PrincipalDigest || controllerEdge.FromURI != agent.TLS.URI ||
			controllerEdge.ToURI != controller.TLS.URI {
			return ErrInvalidProfile
		}
		previous = value.AgentDeployment
		if _, exists := seenAgents[value.AgentDeployment]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenSubjects[value.SubjectDeployment]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenStorage[value.SocketStorageID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenControllerStorage[value.ControllerSocketStorageID]; exists {
			return ErrInvalidProfile
		}
		if value.SocketStorageID == value.ControllerSocketStorageID {
			return ErrInvalidProfile
		}
		if _, exists := policyStorage[value.SocketStorageID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := policyStorage[value.ControllerSocketStorageID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenEdges[value.UnixEdgeID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenPolicies[value.IssuerPolicyID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenControllerEdges[value.ControllerUnixEdgeID]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenVaultRoles[value.IssuerVaultRole]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenRequestKeys[value.AgentRequestKeyDigest]; exists {
			return ErrInvalidProfile
		}
		if _, exists := seenRequestKeyIDs[value.AgentRequestKeyID]; exists {
			return ErrInvalidProfile
		}
		seenAgents[value.AgentDeployment], seenSubjects[value.SubjectDeployment] = struct{}{}, struct{}{}
		seenStorage[value.SocketStorageID], seenEdges[value.UnixEdgeID] = struct{}{}, struct{}{}
		seenControllerStorage[value.ControllerSocketStorageID], seenControllerEdges[value.ControllerUnixEdgeID] = struct{}{}, struct{}{}
		seenPolicies[value.IssuerPolicyID] = struct{}{}
		seenVaultRoles[value.IssuerVaultRole] = struct{}{}
		seenRequestKeys[value.AgentRequestKeyDigest], seenRequestKeyIDs[value.AgentRequestKeyID] = struct{}{}, struct{}{}
	}
	for storageID := range seenStorage {
		if _, shared := seenControllerStorage[storageID]; shared {
			return ErrInvalidProfile
		}
	}
	for name, principal := range principals {
		if principal.Kind == "tls_agent" {
			if _, expectedAgent := seenAgents[name]; !expectedAgent {
				if !postgresAgentMember(postgres, name) {
					return ErrInvalidProfile
				}
			}
		}
		for _, mount := range principal.Mounts {
			if mount.Kind != "private_socket" {
				continue
			}
			if _, credentialSocket := credentialStorage[mount.StorageID]; credentialSocket {
				if !credentialIssuerStorageMember(credentialSockets, name, mount) {
					return ErrInvalidProfile
				}
			} else if _, tlsStorage := seenStorage[mount.StorageID]; tlsStorage {
				if !tlsStorageMember(values, name, mount) {
					return ErrInvalidProfile
				}
			} else if _, controllerStorage := seenControllerStorage[mount.StorageID]; controllerStorage {
				if !controllerStorageMember(values, name, mount) {
					return ErrInvalidProfile
				}
			} else if mount.StorageID == controllerAuthority.SelfSocketStorageID {
				if name != controllerAuthority.DeploymentName || mount.Target != controllerAuthority.SelfSocketDirectory || mount.ReadOnly {
					return ErrInvalidProfile
				}
			} else if mount.StorageID == controllerAuthority.CredentialController.SocketStorageID {
				managed := controllerAuthority.CredentialController
				if mount.Target != managed.SocketDirectory ||
					!((name == controllerAuthority.DeploymentName && !mount.ReadOnly) ||
						(name == "workload-credential-controller" && mount.ReadOnly)) {
					return ErrInvalidProfile
				}
			} else if mount.StorageID == BrowserMuxSocketStorageID {
				if mount.Target != BrowserMuxSocketDirectory ||
					!((name == "provider-browser-runtime" && !mount.ReadOnly) ||
						(name == "browser-executor-backend" && mount.ReadOnly)) {
					return ErrInvalidProfile
				}
			} else if !postgresSocketMember(postgres, name, mount) && !policyStorageMember(policies, name, mount) {
				return ErrInvalidProfile
			}
		}
	}
	for broker := range brokerSubjects {
		if _, hasAgent := seenSubjects[broker]; !hasAgent {
			return ErrInvalidProfile
		}
	}
	for _, edge := range edges {
		to := principals[edge.To]
		if to.Kind == "tls_agent" {
			if _, declared := seenEdges[edge.ID]; !declared {
				if !postgresAgentEdgeMember(postgres, edge.ID) {
					return ErrInvalidProfile
				}
			}
		}
		if to.Name == controller.Name && edge.Protocol == "unix" && edge.ID != controllerAuthority.SelfUnixEdgeID &&
			edge.ID != controllerAuthority.CredentialController.UnixEdgeID {
			if _, declared := seenControllerEdges[edge.ID]; !declared {
				if !postgresControllerEdgeMember(postgres, edge.ID) {
					return ErrInvalidProfile
				}
			}
		}
	}
	return nil
}

func tlsStorageMember(bindings []TLSAgentBinding, principalName string, mount Mount) bool {
	for _, binding := range bindings {
		if mount.Kind == "private_socket" && mount.Target == binding.SocketDirectory && mount.StorageID == binding.SocketStorageID &&
			((principalName == binding.AgentDeployment && !mount.ReadOnly) || (principalName == binding.SubjectDeployment && mount.ReadOnly)) {
			return true
		}
	}
	return false
}

func controllerStorageMember(bindings []TLSAgentBinding, principalName string, mount Mount) bool {
	for _, binding := range bindings {
		if mount.Kind == "private_socket" && mount.Target == binding.ControllerSocketDirectory &&
			mount.StorageID == binding.ControllerSocketStorageID &&
			((principalName == binding.ControllerDeployment && !mount.ReadOnly) ||
				(principalName == binding.AgentDeployment && mount.ReadOnly)) {
			return true
		}
	}
	return false
}

func validPrincipalKind(value string) bool {
	switch value {
	case "runtime", "executor", "material_agent", "tls_agent", "controller", "migration_job", "sandbox", "egress_broker", "ingress_relay":
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
