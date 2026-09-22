// Package productphase6slice5evidence verifies the closed aggregate evidence
// for Product v1 Phase 6 Slice 5. It binds, but does not conflate, the real
// six-role material/credential gate and the real recording Transit adapter
// gate.
package productphase6slice5evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const (
	ManifestID      = "product-v1-phase-6-slice-5"
	ManifestVersion = "1"

	VaultImage    = "docker.io/hashicorp/vault@sha256:47f14a6acb98f48d798a07df7c83f23a6e636e1cf724c5f8ff165cb32667a1e2"
	PostgresImage = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"

	RoleMaterialHarness = "phase6-slice5-role-material-credential-process-gate-v1"
	RecordingHarness    = "phase6-slice5-recording-transit-postgres-gate-v1"
	CleanupBoundary     = "after_both_independent_real_gates_to_zero_run_owned_resources"
	maxEvidenceBytes    = 2 << 20
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	agentRoles      = map[string]secretref.Role{
		"product-migration-agent":  secretref.RoleProduct,
		"provider-migration-agent": secretref.RoleProvider,
		"product-runtime-agent":    secretref.RoleProduct,
		"provider-runtime-agent":   secretref.RoleProvider,
		"gateway-agent":            secretref.RoleGateway,
		"guest-agent":              secretref.RoleGuest,
		"browser-agent":            secretref.RoleBrowser,
		"desktop-agent":            secretref.RoleDesktop,
	}
	materialScenarios = map[string]struct{}{
		"workload_credential_renewal": {}, "workload_credential_restart": {}, "material_agent_loss": {},
		"vault_loss_and_revocation": {}, "break_glass_dual_control": {},
	}
	recordingScenarios = map[string]struct{}{
		"tenant_bound_round_trip": {}, "overlap_rotation": {}, "stale_revoked_key_rejection": {},
		"restart_reconstruction": {}, "vault_loss": {}, "ciphertext_aad_substitution": {},
		"postgres_recording_lifecycle": {}, "exact_cleanup": {},
	}
	cleanupResources = map[string]struct{}{
		"role_processes": {}, "executor_backend_processes": {}, "workload_material_agent_processes": {},
		"workload_credential_controller_processes": {}, "break_glass_controller_processes": {},
		"desktop_namespace_containers": {}, "desktop_namespace_networks": {}, "postgres_containers": {},
		"chromium_containers": {}, "vault_containers": {}, "browser_gateway_images": {},
		"desktop_broker_sockets": {}, "material_agent_sockets": {}, "credential_controller_sockets": {},
		"break_glass_sockets": {}, "credential_state_files": {}, "break_glass_state_files": {},
		"guest_fixture_listeners": {},
	}
	recordingCleanupResources = map[string]struct{}{
		"vault_containers": {}, "postgres_containers": {}, "recording_directories": {},
		"database_connections": {}, "scoped_vault_tokens": {},
	}
)

type Manifest struct {
	ID                         string                         `json:"id"`
	Version                    string                         `json:"version"`
	ManifestDigest             string                         `json:"manifest_digest"`
	RuntimeGate                productphase6evidence.Manifest `json:"runtime_gate"`
	RoleMaterialAndCredentials RoleMaterialAndCredentials     `json:"role_material_and_credentials"`
	RecordingTransitAdapter    RecordingTransitEvidence       `json:"recording_transit_adapter"`
	CapabilityBoundary         CapabilityBoundary             `json:"capability_boundary"`
	FutureGates                []FutureGate                   `json:"future_gates"`
	Cleanup                    Cleanup                        `json:"cleanup"`
	NonClaims                  []string                       `json:"non_claims"`
}

type RoleMaterialAndCredentials struct {
	Harness                        string                     `json:"harness"`
	CommandDigest                  string                     `json:"command_digest"`
	ConfigDigest                   string                     `json:"config_digest"`
	VaultImage                     string                     `json:"vault_image"`
	VaultTLS                       bool                       `json:"vault_tls"`
	WorkloadMaterialProtocol       string                     `json:"workload_material_protocol"`
	WorkloadCredentialProtocol     string                     `json:"workload_credential_protocol"`
	BreakGlassProtocol             string                     `json:"break_glass_protocol"`
	ManagementCredentialTransport  string                     `json:"management_credential_transport"`
	CredentialPayloadPersisted     bool                       `json:"credential_payload_persisted"`
	CredentialControllerProcesses  int                        `json:"credential_controller_processes"`
	WorkloadMaterialAgentProcesses int                        `json:"workload_material_agent_processes"`
	CredentialTTLSeconds           int                        `json:"credential_ttl_seconds"`
	CredentialOverlapSeconds       int                        `json:"credential_overlap_seconds"`
	Agents                         []AgentEvidence            `json:"agents"`
	Scenarios                      []Scenario                 `json:"scenarios"`
	BreakGlass                     BreakGlassEvidence         `json:"break_glass"`
	PlaintextExclusion             PlaintextExclusionEvidence `json:"plaintext_exclusion"`
	EvidenceDigest                 string                     `json:"evidence_digest"`
}

type AgentEvidence struct {
	AgentID          string         `json:"agent_id"`
	Role             secretref.Role `json:"role"`
	IdentityDigest   string         `json:"identity_digest"`
	BindingDigest    string         `json:"binding_digest"`
	LeaseRecords     int            `json:"lease_records"`
	ActiveLeases     int            `json:"active_leases"`
	RevokedLeases    int            `json:"revoked_leases"`
	MaxRevision      int64          `json:"max_revision"`
	Renewable        bool           `json:"renewable"`
	Migration        bool           `json:"migration"`
	RotationObserved bool           `json:"rotation_observed"`
}

type Scenario struct {
	Name           string `json:"name"`
	Outcome        string `json:"outcome"`
	EvidenceDigest string `json:"evidence_digest"`
}

type BreakGlassEvidence struct {
	ControllerProcesses       int    `json:"controller_processes"`
	PersistentAuthority       bool   `json:"persistent_authority"`
	DistinctApproversRequired int    `json:"distinct_approvers_required"`
	MaxTTLSeconds             int    `json:"max_ttl_seconds"`
	MaxUses                   int    `json:"max_uses"`
	RequestRecords            int    `json:"request_records"`
	ConsumedRecords           int    `json:"consumed_records"`
	RevokedRecords            int    `json:"revoked_records"`
	ExpiredRecords            int    `json:"expired_records"`
	AuditEntries              int64  `json:"audit_entries"`
	AuditHead                 string `json:"audit_head"`
	LedgerDigest              string `json:"ledger_digest"`
	AuditDigest               string `json:"audit_digest"`
	HashChainedAudit          bool   `json:"hash_chained_audit"`
	ReasonTicketDigestOnly    bool   `json:"reason_ticket_digest_only"`
	TargetAgentBound          bool   `json:"target_agent_bound"`
	OnlineAtomicConsume       bool   `json:"online_atomic_consume"`
	MigrationDenied           bool   `json:"migration_denied"`
}

type PlaintextExclusionEvidence struct {
	Scope                      string `json:"scope"`
	KnownSecretValues          int    `json:"known_secret_values"`
	FilesScanned               int    `json:"files_scanned"`
	ProcessCommandLinesScanned int    `json:"process_command_lines_scanned"`
	ForbiddenMatches           int    `json:"forbidden_matches"`
	DistinctOSUIDEstablished   bool   `json:"distinct_os_uid_established"`
	ScanDigest                 string `json:"scan_digest"`
}

type RecordingTransitEvidence struct {
	Harness                         string            `json:"harness"`
	RuntimeImplementationRevision   string            `json:"runtime_implementation_revision"`
	RuntimeImplementationTreeDigest string            `json:"runtime_implementation_tree_digest"`
	EvidenceToolRevision            string            `json:"evidence_tool_revision"`
	EvidenceToolTreeDigest          string            `json:"evidence_tool_tree_digest"`
	ObservedAt                      string            `json:"observed_at"`
	CommandDigest                   string            `json:"command_digest"`
	ConfigDigest                    string            `json:"config_digest"`
	VaultImage                      string            `json:"vault_image"`
	PostgresImage                   string            `json:"postgres_image"`
	VaultTLS                        bool              `json:"vault_tls"`
	VaultTransitMount               string            `json:"vault_transit_mount"`
	VaultKeyIdentityDigest          string            `json:"vault_key_identity_digest"`
	BindingDigest                   string            `json:"binding_digest"`
	Purpose                         secretref.Purpose `json:"purpose"`
	Role                            secretref.Role    `json:"role"`
	StoreSchema                     string            `json:"store_schema"`
	HandleSchema                    string            `json:"handle_schema"`
	CredentialClass                 string            `json:"credential_class"`
	RootCredentialUsedByAdapter     bool              `json:"root_credential_used_by_adapter"`
	RawKeyExported                  bool              `json:"raw_key_exported"`
	FreshPostgresSchema             bool              `json:"fresh_postgres_schema"`
	Scenarios                       []Scenario        `json:"scenarios"`
	Cleanup                         []Resource        `json:"cleanup"`
	EvidenceDigest                  string            `json:"evidence_digest"`
}

type CapabilityBoundary struct {
	ProductKernelCapabilityReadiness string `json:"product_kernel_capability_readiness"`
	RecordingContentStoreComposed    bool   `json:"recording_content_store_composed"`
	RecordingContentE2E              bool   `json:"recording_content_e2e"`
	TicketEnvelopeConsumerComposed   bool   `json:"ticket_envelope_consumer_composed"`
	DataEnvelopeConsumerComposed     bool   `json:"data_envelope_consumer_composed"`
	LegacyRecordingFallback          bool   `json:"legacy_recording_fallback"`
	ProductionConfigEnablement       string `json:"production_config_enablement"`
}

type FutureGate struct {
	Slice       int    `json:"slice"`
	Requirement string `json:"requirement"`
}

type Cleanup struct {
	ZeroResources  bool       `json:"zero_resources"`
	Boundary       string     `json:"boundary"`
	Resources      []Resource `json:"resources"`
	EvidenceDigest string     `json:"evidence_digest"`
}

type Resource struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func VerifyFile(path string) (Manifest, error) {
	info, err := os.Lstat(path)
	if path == "" || err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxEvidenceBytes {
		return Manifest{}, errors.New("Slice 5 evidence must be a private bounded regular file")
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, errors.New("read Slice 5 evidence")
	}
	return Verify(document)
}

func VerifyRecordingFile(path string) (RecordingTransitEvidence, error) {
	info, err := os.Lstat(path)
	if path == "" || err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxEvidenceBytes {
		return RecordingTransitEvidence{}, errors.New("recording Transit evidence must be a private bounded regular file")
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return RecordingTransitEvidence{}, errors.New("read recording Transit evidence")
	}
	var evidence RecordingTransitEvidence
	if err := decodeCanonical(document, &evidence); err != nil || !validRecording(evidence) {
		return RecordingTransitEvidence{}, errors.New("invalid recording Transit evidence")
	}
	return evidence, nil
}

func Seal(manifest Manifest) (Manifest, error) {
	if manifest.ManifestDigest != "" {
		return Manifest{}, errors.New("Slice 5 evidence is already sealed")
	}
	manifest.ID, manifest.Version = ManifestID, ManifestVersion
	manifest.ManifestDigest = manifestDigest(manifest)
	document, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, errors.New("encode Slice 5 evidence")
	}
	return Verify(document)
}

func SealRecording(evidence RecordingTransitEvidence) (RecordingTransitEvidence, error) {
	if evidence.EvidenceDigest != "" {
		return RecordingTransitEvidence{}, errors.New("recording Transit evidence is already sealed")
	}
	evidence.EvidenceDigest = RecordingEvidenceDigest(evidence)
	if !validRecording(evidence) {
		return RecordingTransitEvidence{}, errors.New("invalid recording Transit evidence")
	}
	return evidence, nil
}

func Verify(document []byte) (Manifest, error) { //nolint:gocyclo
	if len(document) < 1 || len(document) > maxEvidenceBytes {
		return Manifest{}, errors.New("Slice 5 evidence size is invalid")
	}
	var manifest Manifest
	if err := decodeCanonical(document, &manifest); err != nil {
		return Manifest{}, errors.New("Slice 5 evidence must be closed canonical JSON")
	}
	if manifest.ID != ManifestID || manifest.Version != ManifestVersion || manifest.ManifestDigest != manifestDigest(manifest) {
		return Manifest{}, errors.New("Slice 5 evidence identity or digest is invalid")
	}
	runtimeDocument, err := json.Marshal(manifest.RuntimeGate)
	if err != nil {
		return Manifest{}, errors.New("encode embedded runtime gate")
	}
	runtimeGate, err := productphase6evidence.Verify(runtimeDocument)
	if err != nil {
		return Manifest{}, fmt.Errorf("invalid embedded runtime gate: %w", err)
	}
	if !validRoleMaterial(manifest.RoleMaterialAndCredentials) || !validRecording(manifest.RecordingTransitAdapter) {
		return Manifest{}, errors.New("Slice 5 sub-evidence is invalid")
	}
	identity := runtimeGate.Identity
	recording := manifest.RecordingTransitAdapter
	if recording.RuntimeImplementationRevision != identity.RuntimeImplementationRevision || recording.RuntimeImplementationTreeDigest != identity.RuntimeImplementationTreeDigest ||
		recording.EvidenceToolRevision != identity.EvidenceToolRevision || recording.EvidenceToolTreeDigest != identity.EvidenceToolTreeDigest {
		return Manifest{}, errors.New("Slice 5 sub-evidence revision binding mismatch")
	}
	if manifest.RoleMaterialAndCredentials.ConfigDigest != identity.ConfigDigest {
		return Manifest{}, errors.New("Slice 5 role-material configuration binding mismatch")
	}
	if !validCapabilityBoundary(manifest.CapabilityBoundary) || !validFutureGates(manifest.FutureGates) || !validCleanup(manifest.Cleanup) || !validNonClaims(manifest.NonClaims) {
		return Manifest{}, errors.New("Slice 5 claim boundary is incomplete")
	}
	return manifest, nil
}

func validRoleMaterial(value RoleMaterialAndCredentials) bool { //nolint:gocyclo
	if value.Harness != RoleMaterialHarness || !digestPattern.MatchString(value.CommandDigest) || !digestPattern.MatchString(value.ConfigDigest) ||
		value.VaultImage != VaultImage || !value.VaultTLS || value.WorkloadMaterialProtocol != "sandbox-runtime.workload-material.v1" ||
		value.WorkloadCredentialProtocol != "sandbox-runtime.workload-credential.v1" || value.BreakGlassProtocol != "sandbox-runtime.break-glass.v1" ||
		value.ManagementCredentialTransport != "inherited_fd_3" || value.CredentialPayloadPersisted || value.CredentialControllerProcesses < 2 ||
		value.WorkloadMaterialAgentProcesses < 10 || value.CredentialTTLSeconds != 30 || value.CredentialOverlapSeconds != 3 ||
		len(value.Agents) != len(agentRoles) || len(value.Scenarios) != len(materialScenarios) || value.EvidenceDigest != RoleMaterialEvidenceDigest(value) {
		return false
	}
	seen := make(map[string]struct{}, len(value.Agents))
	for _, agent := range value.Agents {
		role, ok := agentRoles[agent.AgentID]
		if !ok || role != agent.Role || !digestPattern.MatchString(agent.IdentityDigest) || !digestPattern.MatchString(agent.BindingDigest) || agent.LeaseRecords < 1 || agent.MaxRevision < 2 {
			return false
		}
		if _, duplicate := seen[agent.AgentID]; duplicate {
			return false
		}
		seen[agent.AgentID] = struct{}{}
		migration := strings.Contains(agent.AgentID, "-migration-")
		if agent.Migration != migration || agent.Renewable == migration || migration && (agent.ActiveLeases != 0 || agent.RevokedLeases < 1 || agent.RotationObserved) ||
			!migration && (agent.ActiveLeases != 1 || !agent.RotationObserved) {
			return false
		}
	}
	if !validScenarios(value.Scenarios, materialScenarios) || !validBreakGlass(value.BreakGlass) {
		return false
	}
	plaint := value.PlaintextExclusion
	return plaint.Scope == "role_configs_process_arguments_logs_control_ledgers_and_manifest" && plaint.KnownSecretValues > 0 && plaint.FilesScanned > 0 &&
		plaint.ProcessCommandLinesScanned >= 6 && plaint.ForbiddenMatches == 0 && !plaint.DistinctOSUIDEstablished && digestPattern.MatchString(plaint.ScanDigest)
}

func validBreakGlass(value BreakGlassEvidence) bool {
	return value.ControllerProcesses >= 1 && value.PersistentAuthority && value.DistinctApproversRequired == 2 && value.MaxTTLSeconds == 900 &&
		value.MaxUses == 1 && value.RequestRecords == 3 && value.ConsumedRecords == 1 && value.RevokedRecords == 1 && value.ExpiredRecords == 1 &&
		value.AuditEntries == 15 && digestPattern.MatchString(value.AuditHead) && digestPattern.MatchString(value.LedgerDigest) && digestPattern.MatchString(value.AuditDigest) &&
		value.HashChainedAudit && value.ReasonTicketDigestOnly && value.TargetAgentBound && value.OnlineAtomicConsume && value.MigrationDenied
}

func validRecording(value RecordingTransitEvidence) bool {
	if value.Harness != RecordingHarness || !revisionPattern.MatchString(value.RuntimeImplementationRevision) || !digestPattern.MatchString(value.RuntimeImplementationTreeDigest) ||
		!revisionPattern.MatchString(value.EvidenceToolRevision) || !digestPattern.MatchString(value.EvidenceToolTreeDigest) || value.RuntimeImplementationRevision == value.EvidenceToolRevision ||
		!validTime(value.ObservedAt) || !digestPattern.MatchString(value.CommandDigest) || !digestPattern.MatchString(value.ConfigDigest) || value.VaultImage != VaultImage ||
		value.PostgresImage != PostgresImage || !value.VaultTLS || value.VaultTransitMount != "transit" || !digestPattern.MatchString(value.VaultKeyIdentityDigest) ||
		!digestPattern.MatchString(value.BindingDigest) || value.Purpose != secretref.PurposeRecordingEnvelopeKey || value.Role != secretref.RoleProduct ||
		value.StoreSchema != "recordings-kms-v1" || value.HandleSchema != "rkms1" || value.CredentialClass != "vault_nonrenewable_scoped_token" ||
		value.RootCredentialUsedByAdapter || value.RawKeyExported || !value.FreshPostgresSchema || len(value.Scenarios) != len(recordingScenarios) ||
		!validScenarios(value.Scenarios, recordingScenarios) || len(value.Cleanup) != len(recordingCleanupResources) || value.EvidenceDigest != RecordingEvidenceDigest(value) {
		return false
	}
	return validResources(value.Cleanup, recordingCleanupResources)
}

func validScenarios(values []Scenario, expected map[string]struct{}) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := expected[value.Name]; !ok || value.Outcome != "passed" || !digestPattern.MatchString(value.EvidenceDigest) {
			return false
		}
		if _, duplicate := seen[value.Name]; duplicate {
			return false
		}
		seen[value.Name] = struct{}{}
	}
	return len(seen) == len(expected)
}

func validCapabilityBoundary(value CapabilityBoundary) bool {
	return value.ProductKernelCapabilityReadiness == "unavailable" && !value.RecordingContentStoreComposed && !value.RecordingContentE2E &&
		!value.TicketEnvelopeConsumerComposed && !value.DataEnvelopeConsumerComposed && !value.LegacyRecordingFallback &&
		value.ProductionConfigEnablement == "schema_absent_and_unknown_fields_rejected"
}

func validFutureGates(values []FutureGate) bool {
	want := map[int]string{
		8:  "compose KMS RecordingContentStore into the real Product or recording worker with write/read/rotation/restart/loss/integrity/cleanup evidence",
		11: "verify deployment configuration cannot enable any uncomposed recording-content capability",
		14: "run black-box encrypted recording E2E from published artifacts before release-candidate eligibility",
	}
	if len(values) != len(want) {
		return false
	}
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if want[value.Slice] != value.Requirement {
			return false
		}
		if _, duplicate := seen[value.Slice]; duplicate {
			return false
		}
		seen[value.Slice] = struct{}{}
	}
	return true
}

func validCleanup(value Cleanup) bool {
	return value.ZeroResources && value.Boundary == CleanupBoundary && len(value.Resources) == len(cleanupResources) &&
		validResources(value.Resources, cleanupResources) && value.EvidenceDigest == CleanupEvidenceDigest(value)
}

func validResources(values []Resource, expected map[string]struct{}) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := expected[value.Name]; !ok || value.Count != 0 {
			return false
		}
		if _, duplicate := seen[value.Name]; duplicate {
			return false
		}
		seen[value.Name] = struct{}{}
	}
	return len(seen) == len(expected)
}

func validNonClaims(values []string) bool {
	want := map[string]bool{
		"Product OS process has not composed the KMS RecordingContentStore":                   false,
		"public Product recording content E2E remains unproven":                               false,
		"ticket and data envelope consumers are not composed":                                 false,
		"Vault software Transit evidence is not HSM evidence":                                 false,
		"distinct OS UIDs, service accounts and platform identity federation remain unproven": false,
		"deployment, HA and production readiness remain unproven":                             false,
		"metadata and catalog behavior is not encrypted content durability":                   false,
		"the local Desktop candidate is not a published or signed artifact":                   false,
	}
	if len(values) != len(want) {
		return false
	}
	for _, value := range values {
		if _, ok := want[value]; !ok || want[value] {
			return false
		}
		want[value] = true
	}
	for _, present := range want {
		if !present {
			return false
		}
	}
	return true
}

func RoleMaterialEvidenceDigest(value RoleMaterialAndCredentials) string {
	value.EvidenceDigest = ""
	return evidenceDigest("sandbox-runtime/phase6-slice5/role-material/v1", value)
}

func RecordingEvidenceDigest(value RecordingTransitEvidence) string {
	value.EvidenceDigest = ""
	return evidenceDigest("sandbox-runtime/phase6-slice5/recording-transit/v1", value)
}

func CleanupEvidenceDigest(value Cleanup) string {
	value.EvidenceDigest = ""
	return evidenceDigest("sandbox-runtime/phase6-slice5/cleanup/v1", value)
}

func Digest(domain string, value any) string { return evidenceDigest(domain, value) }

func ScenarioNames(set string) []string {
	selected := materialScenarios
	if set == "recording" {
		selected = recordingScenarios
	}
	values := make([]string, 0, len(selected))
	for name := range selected {
		values = append(values, name)
	}
	sort.Strings(values)
	return values
}

func evidenceDigest(domain string, value any) string {
	document, _ := json.Marshal(value)
	digest := sha256.Sum256(append(append([]byte(nil), []byte(domain)...), append([]byte{0}, document...)...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func manifestDigest(value Manifest) string {
	value.ManifestDigest = ""
	return evidenceDigest("sandbox-runtime/phase6-slice5/manifest/v1", value)
}

func decodeCanonical(document []byte, target any) error {
	if len(document) < 1 || len(document) > maxEvidenceBytes {
		return errors.New("invalid evidence size")
	}
	unique := json.NewDecoder(bytes.NewReader(document))
	if err := scanUniqueJSON(unique); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing evidence JSON")
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return errors.New("non-canonical evidence JSON")
	}
	return nil
}

func scanUniqueJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	var scan func(json.Token) error
	scan = func(value json.Token) error {
		delimiter, ok := value.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON member")
				}
				if _, duplicate := seen[key]; duplicate {
					return errors.New("duplicate JSON member")
				}
				seen[key] = struct{}{}
				next, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				if err := scan(next); err != nil {
					return err
				}
			}
			_, tokenErr := decoder.Token()
			return tokenErr
		case '[':
			for decoder.More() {
				next, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				if err := scan(next); err != nil {
					return err
				}
			}
			_, tokenErr := decoder.Token()
			return tokenErr
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := scan(token); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func validTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero() && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}
