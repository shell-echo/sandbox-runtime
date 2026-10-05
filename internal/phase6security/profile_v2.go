package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

// ProfileV2 is a fail-closed draft of the independent v2 wire type, digest
// domain and validation entry point. It does not embed Profile: no v2 document
// can inherit the v1 decoder, validator, registry or digest by Go method
// promotion or field stripping. Validate retains a final admission hold until
// source-bound Control/Scanner executables and image targets are present.
type ProfileV2 struct {
	Protocol                     string                             `json:"protocol"`
	Version                      int                                `json:"version"`
	Revision                     string                             `json:"revision"`
	ProfileDigest                string                             `json:"profile_digest"`
	EnvironmentDigest            string                             `json:"environment_digest"`
	PrincipalProfileDigest       string                             `json:"principal_profile_digest"`
	Principals                   []Principal                        `json:"principals"`
	SandboxIdentitySlots         []SandboxIdentitySlot              `json:"sandbox_identity_slots"`
	ProviderDatabases            []ProviderDatabaseBinding          `json:"provider_databases"`
	PostgresServerAuth           PostgresServerAuthPolicy           `json:"postgres_server_auth"`
	Components                   []Component                        `json:"components"`
	Networks                     []Network                          `json:"networks"`
	External                     []ExternalService                  `json:"external_services"`
	TrustEdges                   []TrustEdge                        `json:"trust_edges"`
	TrustAnchors                 []TrustAnchor                      `json:"trust_anchors"`
	PublicListeners              []PublicListenerBinding            `json:"public_listeners"`
	IngressBindings              []IngressBinding                   `json:"ingress_bindings"`
	CertificateController        CertificateControllerAuthority     `json:"certificate_controller"`
	CredentialIssuerSockets      []CredentialIssuerSocketBinding    `json:"credential_issuer_sockets"`
	MaterialSockets              []Slice6MaterialSocketBinding      `json:"material_sockets"`
	BreakGlassSockets            []Slice6BreakGlassSocketBinding    `json:"break_glass_sockets"`
	BreakGlassOperatorTasks      []Slice6BreakGlassOperatorTask     `json:"break_glass_operator_tasks"`
	BreakGlassKeyAuthority       Slice6BreakGlassKeyAuthority       `json:"break_glass_key_authority"`
	BreakGlassExecutableArtifact Slice6BreakGlassExecutableArtifact `json:"break_glass_executable_artifact"`
	TLSAgentBindings             []TLSAgentBinding                  `json:"tls_agent_bindings"`
	PostgresClientAgents         []PostgresClientAgentBinding       `json:"postgres_client_agents"`
	EgressPolicies               []EgressPolicy                     `json:"egress_policies"`
	CleanupClasses               []string                           `json:"cleanup_classes"`
	DockerControl                DockerControlAuthorityV2           `json:"docker_control"`
	ArtifactScanner              ArtifactScannerAuthorityV2         `json:"artifact_scanner"`
	CodingTemplate               CodingRuntimeTemplateV2            `json:"coding_template"`
	SandboxGatewayLimits         map[string]Resources               `json:"sandbox_gateway_limits"`
	ExternalResourceLimits       map[string]Resources               `json:"external_resource_limits"`
	ResourceBudget               Slice6V2ResourceBudget             `json:"resource_budget"`
}

// DockerControlAuthorityV2 is a single fixed daemon owner. Browser and
// Desktop get their own disjoint mTLS ingress scopes but never a daemon FD.
type DockerControlAuthorityV2 struct {
	Deployment        string              `json:"deployment"`
	DaemonSocketPath  string              `json:"daemon_socket_path"`
	DaemonSocketGID   uint32              `json:"daemon_socket_gid"`
	DaemonSocketMode  uint32              `json:"daemon_socket_mode"`
	SupplementaryGIDs []uint32            `json:"supplementary_gids"`
	ReceiptStorageID  string              `json:"receipt_storage_id"`
	ReceiptTarget     string              `json:"receipt_target"`
	ReceiptMaxBytes   int64               `json:"receipt_max_bytes"`
	Endpoints         []ControlEndpointV2 `json:"endpoints"`
}

type ControlEndpointV2 struct {
	Scope              string `json:"scope"`
	ProviderDeployment string `json:"provider_deployment"`
	Network            string `json:"network"`
	EdgeID             string `json:"edge_id"`
	RoutePath          string `json:"route_path"`
}

type ArtifactScannerAuthorityV2 struct {
	Deployment         string `json:"deployment"`
	ProviderDeployment string `json:"provider_deployment"`
	Network            string `json:"network"`
	EdgeID             string `json:"edge_id"`
	RoutePath          string `json:"route_path"`
	RuleStorageID      string `json:"rule_storage_id"`
	RuleTarget         string `json:"rule_target"`
	RuleManifestDigest string `json:"rule_manifest_digest"`
	MaxRuleAgeSeconds  int64  `json:"max_rule_age_seconds"`
	MaxArtifactBytes   int64  `json:"max_artifact_bytes"`
	MaxConcurrentScans int    `json:"max_concurrent_scans"`
}

func (p ProfileV2) Digest() string {
	p.ProfileDigest = ""
	document, _ := json.Marshal(p)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-security-profile/v2\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func DecodeV2(document []byte) (ProfileV2, error) {
	profile, err := decodeV2Canonical(document)
	if err != nil || profile.Validate() != nil {
		return ProfileV2{}, ErrInvalidProfile
	}
	return profile, nil
}

func decodeV2Canonical(document []byte) (ProfileV2, error) {
	if len(document) == 0 || len(document) > maxBytes || rejectDuplicateMembers(document) != nil {
		return ProfileV2{}, ErrInvalidProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var profile ProfileV2
	if decoder.Decode(&profile) != nil {
		return ProfileV2{}, ErrInvalidProfile
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ProfileV2{}, ErrInvalidProfile
	}
	canonical, err := json.Marshal(profile)
	if err != nil || !bytes.Equal(canonical, document) {
		return ProfileV2{}, ErrInvalidProfile
	}
	return profile, nil
}

func VerifyFileV2(filePath string) (ProfileV2, error) {
	document, err := secretfile.Read(filePath, maxBytes)
	if err != nil {
		return ProfileV2{}, ErrInvalidProfile
	}
	defer clear(document)
	return DecodeV2(document)
}
