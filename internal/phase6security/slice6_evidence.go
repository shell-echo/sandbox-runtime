package phase6security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"time"
)

// Slice6Evidence is a closed projection of an independently observed local
// Docker/Vault gate. Validation cannot manufacture observations or establish
// that the named commands ran; the gate must retain its raw private receipts.
const (
	Slice6EvidenceID      = "product-v1-phase-6-slice-6"
	Slice6EvidenceVersion = 3
	maxSlice6EvidenceSize = 8 << 20
)

var (
	ErrInvalidSlice6Evidence = errors.New("invalid Phase 6 Slice 6 evidence")
	slice6RevisionPattern    = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	slice6RunIDPattern       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	slice6ScenarioNames      = []string{
		"browser_cdp_and_capacity_replay", "browser_external_witness_isolation",
		"cross_role_and_tenant_denial", "desktop_media_input_and_cleanup",
		"direct_egress_and_metadata_denial", "dns_rebinding_and_alternate_path_denial",
		"external_dependency_loss", "guest_auth_and_reconnect",
		"least_privilege_active_probes", "mtls_identity_and_downgrade_denial",
		"policy_authority_loss_and_revocation", "provider_and_executor_restart",
		"resource_exhaustion_denial", "revoked_leaf_and_crl_rollback_denial",
		"role_and_controller_drain", "vault_pki_rotation_and_loss",
	}
	slice6RequiredParticipants = map[string][]string{
		"browser_cdp_and_capacity_replay":         {"browser-runtime-role", "browser-executor-backend", "provider-browser-runtime"},
		"browser_external_witness_isolation":      {"browser-action-ingress-runtime", "action-history-postgres", "capacity-valkey"},
		"cross_role_and_tenant_denial":            {"gateway-runtime", "provider-browser-runtime"},
		"desktop_media_input_and_cleanup":         {"desktop-broker", "desktop-runtime-role", "desktop-executor-backend", "provider-desktop-runtime", "desktop-sandbox-runtime"},
		"direct_egress_and_metadata_denial":       {"product-runtime", "egress-broker-product"},
		"dns_rebinding_and_alternate_path_denial": {"egress-broker-product", "dns"},
		"external_dependency_loss":                {"browser-action-ingress-runtime", "action-history-postgres", "capacity-valkey"},
		"guest_auth_and_reconnect":                {"guest-runtime", "product-runtime"},
		"least_privilege_active_probes":           {"product-runtime", "gateway-runtime"},
		"mtls_identity_and_downgrade_denial":      {"gateway-runtime", "provider-runtime"},
		"policy_authority_loss_and_revocation":    {"egress-broker-product", "egress-policy-authority-product"},
		"provider_and_executor_restart":           {"provider-runtime", "browser-executor-backend", "desktop-executor-backend"},
		"resource_exhaustion_denial":              {"product-runtime", "gateway-runtime"},
		"revoked_leaf_and_crl_rollback_denial":    {"gateway-runtime", "provider-runtime"},
		"role_and_controller_drain":               {"browser-runtime-role", "desktop-runtime-role", "certificate-controller"},
		"vault_pki_rotation_and_loss":             {"certificate-controller", "vault"},
	}
	slice6RequiredAssertions = map[string][]string{
		"browser_cdp_and_capacity_replay":         {"finite_capacity", "real_cdp_version", "same_authority_replay_denied"},
		"browser_external_witness_isolation":      {"distinct_external_identities", "grant_isolation", "restore_domain_isolation"},
		"cross_role_and_tenant_denial":            {"cross_tenant_denied", "wrong_peer_denied", "wrong_route_denied"},
		"desktop_media_input_and_cleanup":         {"broker_in_parent_observed", "exact_dynamic_cleanup", "real_rtp_and_input"},
		"direct_egress_and_metadata_denial":       {"alias_only_egress", "metadata_denied", "role_direct_ip_denied"},
		"dns_rebinding_and_alternate_path_denial": {"alternate_path_denied", "dns_receipt_observed", "rebinding_denied"},
		"external_dependency_loss":                {"bounded_recovery", "capacity_loss_closes_admission", "witness_loss_closes_admission"},
		"guest_auth_and_reconnect":                {"binding_revoke_denied", "signed_challenge_welcome", "upgraded_socket_drain"},
		"least_privilege_active_probes":           {"complete_container_inventory", "effective_uid_gid", "seccomp_capability_mount_limits"},
		"mtls_identity_and_downgrade_denial":      {"legacy_downgrade_denied", "plaintext_denied", "wrong_certificate_denied"},
		"policy_authority_loss_and_revocation":    {"authority_loss_closes_egress", "fresh_state_required", "revoked_policy_denied"},
		"provider_and_executor_restart":           {"distinct_process_instances", "retained_authority", "stale_admission_denied"},
		"resource_exhaustion_denial":              {"bounded_gateway_connections", "bounded_product_requests", "bounded_workers"},
		"revoked_leaf_and_crl_rollback_denial":    {"active_socket_drain", "crl_rollback_denied", "vault_revoked_leaf_denied"},
		"role_and_controller_drain":               {"active_socket_close", "bounded_sigterm", "exact_lease_socket_cleanup"},
		"vault_pki_rotation_and_loss":             {"fresh_issue_and_overlap", "live_rotation", "loss_closes_admission"},
	}
	slice6CleanupNames = []string{
		"agent_containers", "broker_containers", "controller_containers",
		"credential_leases", "external_containers", "networks",
		"role_containers", "run_owned_files", "sandbox_containers",
		"sessions", "sockets", "volumes",
	}
)

type Slice6Evidence struct {
	ID                 string                    `json:"id"`
	Version            int                       `json:"version"`
	RunID              string                    `json:"run_id"`
	ReceiptIndexDigest string                    `json:"receipt_index_digest"`
	ManifestDigest     string                    `json:"manifest_digest"`
	Scope              string                    `json:"scope"`
	RuntimeRevision    string                    `json:"runtime_revision"`
	RuntimeTreeDigest  string                    `json:"runtime_tree_digest"`
	EvidenceRevision   string                    `json:"evidence_revision"`
	EvidenceTreeDigest string                    `json:"evidence_tree_digest"`
	ObservedAt         string                    `json:"observed_at"`
	Profile            Profile                   `json:"profile"`
	Observations       ObservationSet            `json:"observations"`
	Candidates         []Slice6CandidateImage    `json:"candidates"`
	DescriptorReceipts []Slice6DescriptorReceipt `json:"descriptor_receipts"`
	Processes          []Slice6ProcessEvidence   `json:"processes"`
	Components         []Slice6ComponentEvidence `json:"components"`
	External           []Slice6ExternalEvidence  `json:"external"`
	Scenarios          []Slice6ScenarioEvidence  `json:"scenarios"`
	Cleanup            []Slice6ResourceEvidence  `json:"cleanup"`
	NonClaims          []string                  `json:"non_claims"`
}

const (
	Slice6CandidateRepositoryRole = "repository_role"
	Slice6CandidateDesktop        = "desktop_candidate"
	Slice6RoleManifestSchema      = "sandbox-runtime.phase6-local-role-candidate.v1"
	Slice6DesktopManifestSchema   = "sandbox.runtime/desktop-phase6-local-candidate/v3"
)

// Candidate records only the artifact identity shared by both supported local
// sources. Build-specific claims remain in each independently verified source
// manifest; this neutral projection cannot manufacture their meanings.
type Slice6CandidateImage struct {
	Kind                   string                     `json:"kind"`
	ManifestSchema         string                     `json:"manifest_schema"`
	ManifestDigest         string                     `json:"manifest_digest"`
	RuntimeStoreImageID    string                     `json:"runtime_store_image_id"`
	ImageIdentityKind      string                     `json:"image_identity_kind"`
	SelectedManifestDigest string                     `json:"selected_manifest_digest"`
	OCIConfigDigest        string                     `json:"oci_config_digest"`
	DescriptorProofDigest  string                     `json:"descriptor_proof_digest"`
	Platform               string                     `json:"platform"`
	SourceRevision         string                     `json:"source_revision"`
	SourceTreeDigest       string                     `json:"source_tree_digest"`
	ArchiveDigest          string                     `json:"archive_digest"`
	ArchiveSize            int64                      `json:"archive_size"`
	Role                   *Slice6RoleCandidateRef    `json:"role,omitempty"`
	Desktop                *Slice6DesktopCandidateRef `json:"desktop,omitempty"`
}

type Slice6RoleCandidateRef struct {
	SourceDeployment string `json:"source_deployment"`
	BuildTarget      string `json:"build_target"`
}

type Slice6DesktopCandidateRef struct {
	ProfileID string `json:"profile_id"`
}

// ReceiptDigest is SHA256 over the exact retained descriptor payload file,
// not the domain-separated semantic ImageDescriptorProofDigest and not the
// run envelope's own SHA256. Only this digest enters the raw-receipt index.
type Slice6DescriptorReceipt struct {
	Kind          string `json:"kind"`
	Subject       string `json:"subject"`
	ReceiptDigest string `json:"receipt_digest"`
}

type Slice6ProcessEvidence struct {
	DeploymentName string `json:"deployment_name"`
	Sequence       int    `json:"sequence"`
	ContainerID    string `json:"container_id"`
	CommandDigest  string `json:"command_digest"`
	ConfigDigest   string `json:"config_digest"`
	InspectDigest  string `json:"inspect_digest"`
	StartedAt      string `json:"started_at"`
	FinishedAt     string `json:"finished_at"`
	ExitCode       int    `json:"exit_code"`
	Final          bool   `json:"final"`
}

// Slice6ComponentEvidence retains an independently inspected in-container
// process, without pretending it owns a separate container lifecycle.
type Slice6ComponentEvidence struct {
	Name                     string `json:"name"`
	ParentContainerID        string `json:"parent_container_id"`
	PID                      int    `json:"pid"`
	ProcessStartTicks        uint64 `json:"process_start_ticks"`
	ProcessInspectDigest     string `json:"process_inspect_digest"`
	SocketInspectDigest      string `json:"socket_inspect_digest"`
	SessionAssociationDigest string `json:"session_association_digest"`
}

type Slice6ExternalEvidence struct {
	Name                       string                            `json:"name"`
	IdentityDigest             string                            `json:"identity_digest"`
	ContainerID                string                            `json:"container_id"`
	ImageReference             string                            `json:"image_reference"`
	RuntimeStoreImageID        string                            `json:"runtime_store_image_id"`
	RuntimeStoreDescriptor     ImageDescriptor                   `json:"runtime_store_descriptor"`
	SelectedManifestDescriptor ImageDescriptor                   `json:"selected_manifest_descriptor"`
	SelectedManifestDigest     string                            `json:"selected_manifest_digest"`
	OCIConfigDigest            string                            `json:"oci_config_digest"`
	RuntimePlatform            string                            `json:"runtime_platform"`
	DescriptorProofDigest      string                            `json:"descriptor_proof_digest"`
	ContainerInspectDigest     string                            `json:"container_inspect_digest"`
	ImageInspectDigest         string                            `json:"image_inspect_digest"`
	TLSProbeDigest             string                            `json:"tls_probe_digest"`
	ReachabilityProbeDigest    string                            `json:"reachability_probe_digest"`
	RestoreDomainSeparated     bool                              `json:"restore_domain_separated"`
	PostgresServerAuth         *Slice6PostgresServerAuthEvidence `json:"postgres_server_auth,omitempty"`
}

// Slice6PostgresServerAuthEvidence names private raw receipts retained by the
// controlled deployment gate. These digests do not prove their own origin;
// the gate must record the actual PostgreSQL process, read-only mount, file
// bytes, ordered disk parser output, reload/startup and new connections.
type Slice6PostgresServerAuthEvidence struct {
	ProfileDigest                string   `json:"profile_digest"`
	HBAArtifactID                string   `json:"hba_artifact_id"`
	HBADigest                    string   `json:"hba_digest"`
	ClientCAArtifactID           string   `json:"client_ca_artifact_id"`
	ClientCABundleDigest         string   `json:"client_ca_bundle_digest"`
	ApprovedIngressCIDR          string   `json:"approved_ingress_cidr"`
	ApprovedSourceCIDRs          []string `json:"approved_source_cidrs,omitempty"`
	ReadOnlyMountInspectDigest   string   `json:"read_only_mount_inspect_digest"`
	ServerSettingsProbeDigest    string   `json:"server_settings_probe_digest"`
	OrderedParsedRulesDigest     string   `json:"ordered_parsed_rules_digest"`
	StartupOrReloadResultDigest  string   `json:"startup_or_reload_result_digest"`
	NewConnectionResultsDigest   string   `json:"new_connection_results_digest"`
	RestartReconcileResultDigest string   `json:"restart_reconcile_result_digest"`
}

type Slice6ScenarioEvidence struct {
	Name           string   `json:"name"`
	Outcome        string   `json:"outcome"`
	Participants   []string `json:"participants"`
	EvidenceDigest string   `json:"evidence_digest"`
}

// Slice6ScenarioRequirement exposes the verifier's frozen scenario inventory
// to the independent gate without giving callers authority to change it.
type Slice6ScenarioRequirement struct {
	Name         string
	Participants []string
	Assertions   []string
}

func RequiredSlice6Scenarios() []Slice6ScenarioRequirement {
	result := make([]Slice6ScenarioRequirement, len(slice6ScenarioNames))
	for index, name := range slice6ScenarioNames {
		result[index] = Slice6ScenarioRequirement{
			Name: name, Participants: append([]string(nil), slice6RequiredParticipants[name]...),
			Assertions: append([]string(nil), slice6RequiredAssertions[name]...),
		}
	}
	return result
}

type Slice6ResourceEvidence struct {
	Name            string `json:"name"`
	Remaining       int    `json:"remaining"`
	InspectorDigest string `json:"inspector_digest"`
}

// VerifySlice6EvidenceFile checks only the closed manifest structure. It does
// not read raw receipts or prove a same-run execution. Release admission must
// additionally call VerifySlice6EvidenceBundle.
func VerifySlice6EvidenceFile(path string) (Slice6Evidence, error) {
	if path == "" {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxSlice6EvidenceSize {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	return VerifySlice6Evidence(document)
}

func VerifySlice6Evidence(document []byte) (Slice6Evidence, error) {
	if len(document) < 1 || len(document) > maxSlice6EvidenceSize || rejectDuplicateMembers(document) != nil {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	var evidence Slice6Evidence
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&evidence) != nil {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	canonical, err := json.Marshal(evidence)
	if err != nil || !bytes.Equal(canonical, document) || evidence.Validate() != nil {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	return evidence, nil
}

func (e Slice6Evidence) Validate() error {
	externalIDs := make(map[string]string, len(e.External))
	for _, service := range e.External {
		if _, exists := externalIDs[service.Name]; exists {
			return ErrInvalidSlice6Evidence
		}
		externalIDs[service.Name] = service.ContainerID
	}
	if e.ID != Slice6EvidenceID || e.Version != Slice6EvidenceVersion ||
		!slice6RunIDPattern.MatchString(e.RunID) || !digestPattern.MatchString(e.ReceiptIndexDigest) ||
		e.Scope != "same_host_local_candidate_non_release" ||
		!slice6RevisionPattern.MatchString(e.RuntimeRevision) ||
		!slice6RevisionPattern.MatchString(e.EvidenceRevision) ||
		!digestPattern.MatchString(e.RuntimeTreeDigest) ||
		!digestPattern.MatchString(e.EvidenceTreeDigest) ||
		!validSlice6Time(e.ObservedAt) || e.Profile.Validate() != nil ||
		ValidateObservationsWithExternal(e.Profile, e.Observations, externalIDs) != nil ||
		!validSlice6Candidates(e.Profile, e.Observations, e.Candidates, e.RuntimeRevision, e.RuntimeTreeDigest) ||
		!validSlice6DescriptorReceipts(e.Profile, e.DescriptorReceipts) ||
		!validSlice6Processes(e.Profile, e.Observations, e.Processes) ||
		!validSlice6Components(e.Observations, e.Components) ||
		!validSlice6External(e.Profile, e.External) ||
		!validSlice6Scenarios(e.Profile, e.Scenarios) ||
		!validSlice6Cleanup(e.Cleanup) ||
		len(e.NonClaims) != 3 || e.NonClaims[0] != "independent_host_or_platform_enforcement" ||
		e.NonClaims[1] != "complete_application_image_publication_and_signing" ||
		e.NonClaims[2] != "production_readiness" ||
		e.ManifestDigest != slice6EvidenceDigest(e) {
		return ErrInvalidSlice6Evidence
	}
	return nil
}

func validSlice6DescriptorReceipts(profile Profile, values []Slice6DescriptorReceipt) bool {
	if len(values) != len(profile.Principals)+len(profile.External) {
		return false
	}
	expected := make(map[string]bool, len(values))
	for _, principal := range profile.Principals {
		expected["container/"+principal.Name] = true
	}
	for _, external := range profile.External {
		expected["external/"+external.Name] = true
	}
	previous := ""
	for _, value := range values {
		key := value.Kind + "/" + value.Subject
		if key <= previous || !expected[key] || !digestPattern.MatchString(value.ReceiptDigest) {
			return false
		}
		previous = key
	}
	return true
}

func validSlice6Candidates(profile Profile, observations ObservationSet, values []Slice6CandidateImage, revision, treeDigest string) bool {
	type imageAuthority struct {
		config, kind, selected, imageKind, proof, target string
		deployments                                      map[string]bool
	}
	expected := make(map[string]imageAuthority)
	observed := make(map[string]ContainerObservation, len(observations.Containers))
	for _, container := range observations.Containers {
		observed[container.DeploymentName] = container
	}
	for _, principal := range profile.Principals {
		if principal.ImageLocation == "local" {
			target, err := Slice6DesiredImageTarget(principal.Name)
			if err != nil || target == Slice6BrowserPublishedImage {
				return false
			}
			if principal.ImageIdentityKind != ImageIdentityOCIManifest && principal.ImageIdentityKind != ImageIdentityOCIIndex {
				return false
			}
			selected := principal.ImageDigest
			if principal.ImageIdentityKind == ImageIdentityOCIIndex {
				selected = principal.ImageSelectedManifestDigest
			}
			kind := Slice6CandidateRepositoryRole
			if target == Slice6DesktopCandidateImage {
				kind = Slice6CandidateDesktop
			}
			observation, ok := observed[principal.Name]
			if !ok || !digestPattern.MatchString(observation.ImageDescriptorProofDigest) {
				return false
			}
			key := principal.ImageDigest + "/" + principal.ImagePlatform
			value, found := expected[key]
			if !found {
				value = imageAuthority{config: principal.ImageConfigDigest, kind: kind, selected: selected,
					imageKind: principal.ImageIdentityKind, proof: observation.ImageDescriptorProofDigest,
					target: target, deployments: make(map[string]bool)}
			} else if value.config != principal.ImageConfigDigest || value.kind != kind || value.selected != selected ||
				value.imageKind != principal.ImageIdentityKind || value.proof != observation.ImageDescriptorProofDigest ||
				value.target != target {
				return false
			}
			value.deployments[principal.Name] = true
			expected[key] = value
		}
	}
	if len(values) != len(expected) {
		return false
	}
	previous := ""
	for _, value := range values {
		key := value.RuntimeStoreImageID + "/" + value.Platform
		if key <= previous || !digestPattern.MatchString(value.RuntimeStoreImageID) ||
			!digestPattern.MatchString(value.ManifestDigest) || len(value.ManifestSchema) < 1 || len(value.ManifestSchema) > 128 ||
			!digestPattern.MatchString(value.OCIConfigDigest) || !digestPattern.MatchString(value.DescriptorProofDigest) ||
			!digestPattern.MatchString(value.SelectedManifestDigest) || !imagePlatformPattern.MatchString(value.Platform) ||
			value.SourceRevision != revision || value.SourceTreeDigest != treeDigest ||
			!digestPattern.MatchString(value.ArchiveDigest) || value.ArchiveSize < 1 || value.ArchiveSize > 8<<30 {
			return false
		}
		authority, ok := expected[key]
		if !ok || authority.config != value.OCIConfigDigest || authority.kind != value.Kind ||
			authority.selected != value.SelectedManifestDigest || authority.imageKind != value.ImageIdentityKind ||
			authority.proof != value.DescriptorProofDigest {
			return false
		}
		if value.Kind == Slice6CandidateRepositoryRole {
			if value.ManifestSchema != Slice6RoleManifestSchema || value.Role == nil || value.Desktop != nil || value.Role.BuildTarget != authority.target ||
				!authority.deployments[value.Role.SourceDeployment] {
				return false
			}
		} else if value.Kind == Slice6CandidateDesktop {
			if value.ManifestSchema != Slice6DesktopManifestSchema || value.Desktop == nil || value.Role != nil || value.Desktop.ProfileID == "" ||
				authority.target != Slice6DesktopCandidateImage {
				return false
			}
		} else {
			return false
		}
		previous = key
	}
	return true
}

func slice6EvidenceDigest(e Slice6Evidence) string {
	e.ManifestDigest = ""
	document, err := json.Marshal(e)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(append([]byte("sandbox-runtime/phase6-slice6/evidence/v3\x00"), document...))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func validSlice6Time(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.UTC().Format(time.RFC3339Nano) == value
}

func validSlice6Processes(profile Profile, observations ObservationSet, values []Slice6ProcessEvidence) bool {
	if len(values) < len(profile.Principals) || len(values) > len(profile.Principals)*8 {
		return false
	}
	observed := make(map[string]ContainerObservation, len(observations.Containers))
	for _, container := range observations.Containers {
		observed[container.DeploymentName] = container
	}
	index := 0
	usedIDs := make(map[string]struct{}, len(values))
	for _, principal := range profile.Principals {
		sequence := 0
		for index < len(values) && values[index].DeploymentName == principal.Name {
			value := values[index]
			sequence++
			started, startErr := time.Parse(time.RFC3339Nano, value.StartedAt)
			finished, finishErr := time.Parse(time.RFC3339Nano, value.FinishedAt)
			if value.Sequence != sequence || !containerIDPattern.MatchString(value.ContainerID) ||
				!digestPattern.MatchString(value.CommandDigest) || !digestPattern.MatchString(value.ConfigDigest) ||
				!digestPattern.MatchString(value.InspectDigest) || !validSlice6Time(value.StartedAt) ||
				!validSlice6Time(value.FinishedAt) || startErr != nil || finishErr != nil ||
				!finished.After(started) || value.ExitCode < 0 || value.ExitCode > 255 {
				return false
			}
			if _, duplicate := usedIDs[value.ContainerID]; duplicate {
				return false
			}
			usedIDs[value.ContainerID] = struct{}{}
			last := index+1 == len(values) || values[index+1].DeploymentName != principal.Name
			if value.Final != last || (last && (value.ContainerID != observed[principal.Name].ContainerID ||
				value.InspectDigest != observed[principal.Name].ContainerInspectDigest || value.ExitCode != 0)) {
				return false
			}
			index++
		}
		if sequence == 0 {
			return false
		}
	}
	return index == len(values)
}

func validSlice6Components(observations ObservationSet, values []Slice6ComponentEvidence) bool {
	if len(values) != len(observations.Components) {
		return false
	}
	for index, observed := range observations.Components {
		value := values[index]
		if value.Name != observed.Name || value.ParentContainerID != observed.ParentContainerID ||
			value.PID != observed.PID || value.ProcessStartTicks != observed.ProcessStartTicks ||
			value.ProcessInspectDigest != observed.ProcessInspectDigest ||
			value.SocketInspectDigest != observed.SocketInspectDigest ||
			value.SessionAssociationDigest != observed.SessionAssociationDigest {
			return false
		}
	}
	return true
}

func validSlice6External(profile Profile, values []Slice6ExternalEvidence) bool {
	if len(values) != len(profile.External) {
		return false
	}
	var clientCA TrustAnchor
	for _, anchor := range profile.TrustAnchors {
		if anchor.ID == profile.PostgresServerAuth.ClientCAAnchorID {
			clientCA = anchor
			break
		}
	}
	for index, expected := range profile.External {
		value := values[index]
		separationRequired := expected.Name == "action-history-postgres" || expected.Name == "capacity-valkey"
		selected := expected.ImageDigest
		if expected.ImageIdentityKind == ImageIdentityOCIIndex {
			selected = expected.ImageSelectedManifestDigest
		}
		if value.Name != expected.Name || value.IdentityDigest != expected.IdentityDigest ||
			!containerIDPattern.MatchString(value.ContainerID) ||
			value.ImageReference != expected.ImageReference || value.RuntimeStoreImageID != expected.ImageDigest ||
			value.RuntimeStoreDescriptor.Digest != expected.ImageDigest || value.RuntimeStoreDescriptor.Size < 1 ||
			!validStoreDescriptorMediaType(expected.ImageIdentityKind, value.RuntimeStoreDescriptor.MediaType) ||
			value.SelectedManifestDescriptor.Digest != selected || value.SelectedManifestDescriptor.Size < 1 ||
			!validStoreDescriptorMediaType(ImageIdentityOCIManifest, value.SelectedManifestDescriptor.MediaType) ||
			value.SelectedManifestDigest != selected || value.OCIConfigDigest != expected.ImageConfigDigest ||
			value.RuntimePlatform != expected.ImagePlatform || !digestPattern.MatchString(value.DescriptorProofDigest) ||
			!digestPattern.MatchString(value.ContainerInspectDigest) || !digestPattern.MatchString(value.ImageInspectDigest) ||
			!digestPattern.MatchString(value.TLSProbeDigest) ||
			!digestPattern.MatchString(value.ReachabilityProbeDigest) ||
			value.RestoreDomainSeparated != separationRequired {
			return false
		}
		if expected.Name == profile.PostgresServerAuth.ServiceName {
			proof := value.PostgresServerAuth
			if proof == nil || proof.ProfileDigest != profile.ProfileDigest ||
				proof.HBAArtifactID != profile.PostgresServerAuth.HBAArtifactID ||
				proof.HBADigest != profile.PostgresServerAuth.HBADigest ||
				proof.ClientCAArtifactID != clientCA.ArtifactID ||
				proof.ClientCABundleDigest != clientCA.BundleDigest ||
				!validSlice6PostgresIngressProof(profile.PostgresServerAuth, proof) ||
				!digestPattern.MatchString(proof.ReadOnlyMountInspectDigest) ||
				!digestPattern.MatchString(proof.ServerSettingsProbeDigest) ||
				!digestPattern.MatchString(proof.OrderedParsedRulesDigest) ||
				!digestPattern.MatchString(proof.StartupOrReloadResultDigest) ||
				!digestPattern.MatchString(proof.NewConnectionResultsDigest) ||
				!digestPattern.MatchString(proof.RestartReconcileResultDigest) {
				return false
			}
		} else if value.PostgresServerAuth != nil {
			return false
		}
	}
	return true
}

func validSlice6PostgresIngressProof(policy PostgresServerAuthPolicy, proof *Slice6PostgresServerAuthEvidence) bool {
	if proof == nil {
		return false
	}
	if policy.Scope == postgresServerAuthScope {
		return proof.ApprovedIngressCIDR == policy.IngressCIDR && len(proof.ApprovedSourceCIDRs) == 0
	}
	if policy.Scope != postgresSharedAuthScope || proof.ApprovedIngressCIDR != "" {
		return false
	}
	rules, err := Slice6DesiredFinalSharedPostgresHBARules()
	if err != nil {
		return false
	}
	wanted := make([]string, len(rules))
	for i, rule := range rules {
		wanted[i] = rule.SourceCIDR
	}
	return slices.Equal(proof.ApprovedSourceCIDRs, wanted)
}

func validSlice6Scenarios(profile Profile, values []Slice6ScenarioEvidence) bool {
	if len(values) != len(slice6ScenarioNames) {
		return false
	}
	known := make(map[string]struct{}, len(profile.Principals)+len(profile.Components)+len(profile.External))
	for _, principal := range profile.Principals {
		known[principal.Name] = struct{}{}
	}
	for _, component := range profile.Components {
		known[component.Name] = struct{}{}
	}
	for _, external := range profile.External {
		known[external.Name] = struct{}{}
	}
	for index, expected := range slice6ScenarioNames {
		value := values[index]
		if value.Name != expected || value.Outcome != "passed" || !digestPattern.MatchString(value.EvidenceDigest) ||
			len(value.Participants) < 2 || len(value.Participants) > len(known) || !sort.StringsAreSorted(value.Participants) {
			return false
		}
		previous := ""
		for _, name := range value.Participants {
			if name <= previous {
				return false
			}
			if _, exists := known[name]; !exists {
				return false
			}
			previous = name
		}
		for _, required := range slice6RequiredParticipants[expected] {
			index := sort.SearchStrings(value.Participants, required)
			if index == len(value.Participants) || value.Participants[index] != required {
				return false
			}
		}
	}
	return true
}

func validSlice6Cleanup(values []Slice6ResourceEvidence) bool {
	if len(values) != len(slice6CleanupNames) {
		return false
	}
	for index, expected := range slice6CleanupNames {
		value := values[index]
		if value.Name != expected || value.Remaining != 0 || !digestPattern.MatchString(value.InspectorDigest) {
			return false
		}
	}
	return true
}
