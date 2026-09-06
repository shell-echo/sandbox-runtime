package lock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
	browserimage "github.com/shell-echo/sandbox-runtime/profiles/browser/image"
)

const (
	DownstreamFencingLockPath = "e2e/downstream-fencing.lock.json"
	DownstreamFencingProfile  = "browser-downstream-fencing-e2e-v1"

	DownstreamFencingHarnessBaseline   = "ac1fa1f7ca3ed221165b4dfd092c1da11f5aef53"
	DownstreamFencingV2HarnessBaseline = "ac1fa1f7ca3ed221165b4dfd092c1da11f5aef53"
	DownstreamFencingGatewayRevision   = "b4d41c9a32b4ccf39edaba3fb8bf5ad239c1f945"
	DownstreamFencingIngressRevision   = "b4d41c9a32b4ccf39edaba3fb8bf5ad239c1f945"
	DownstreamFencingCallerBaseline    = "074a9d4a42acef3bf7da57b1b250af8f0c1b1aa9"

	DownstreamFencingValkeyImage = "ghcr.io/valkey-io/valkey"
	DownstreamFencingValkeyIndex = "sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd"

	DownstreamFencingV2LockPath = "e2e/downstream-fencing-v2.lock.json"
	DownstreamFencingV2Profile  = "browser-downstream-fencing-e2e-v2"

	PostgresControlledRestoreLockPath        = "e2e/postgres-controlled-restore.lock.json"
	PostgresControlledRestoreProfile         = "browser-postgres-controlled-restore-e2e-v1"
	PostgresControlledRestoreHarnessBaseline = "9c235dc7c95c6fb2ae79c46b28b3e1626ab28928"
	PostgresWitnessImage                     = "postgres"
	PostgresWitnessIndex                     = "sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
	PostgresWitnessResolvedTag               = "17.6-alpine3.22"
	PostgresWitnessMigrationPath             = "gateway/capacity/redis/migrations/0001_action_history_witness.sql"

	DownstreamFencingServerConfig = "bind 0.0.0.0\n" +
		"protected-mode no\n" +
		"port 6379\n" +
		"appendonly no\n" +
		"save \"\"\n" +
		"maxmemory-policy noeviction\n"
	DownstreamFencingACLTemplate = "user default off\n" +
		"user e2e on >${PASSWORD} ~sandbox-runtime:{${CAPACITY_NAMESPACE_SHA256}}:capacity:* " +
		"~sandbox-runtime:{${REVOCATION_NAMESPACE_SHA256}}:revocation:* " +
		"+ping +type +zcard +zscore +set +get +hset +hlen +hget +time +pttl +zremrangebyscore " +
		"+zrange +incr +zadd +pexpireat +zrem +evalsha +eval\n"
	DownstreamFencingV2ACLTemplate = "user default off\n" +
		"user e2e on >${RUNTIME_PASSWORD} ~sandbox-runtime:{${CAPACITY_NAMESPACE_SHA256}}:capacity:* " +
		"~sandbox-runtime:{${REVOCATION_NAMESPACE_SHA256}}:revocation:* " +
		"+ping +type +zcard +zscore +set +get +hset +hlen +hget +hgetall +time +pttl +zremrangebyscore " +
		"+zrange +incr +zadd +pexpireat +zrem +evalsha +eval\n" +
		"user orchestrator on >${ORCHESTRATOR_PASSWORD} ~sandbox-runtime:{${CAPACITY_NAMESPACE_SHA256}}:capacity:* " +
		"+ping +type +exists +get +set +hget +hmget +hgetall +hset +hdel +zcard +zrange +pttl +dump +restore +del\n"
)

var downstreamFencingScenarioInventory = [...]string{
	"ordinary bounded real-CDP mutation through the unique ingress",
	"Gateway A SIGSTOP beyond its confirmed capacity lease",
	"Gateway B acquires and activates a higher fence",
	"resumed Gateway A queued stale mutation is rejected before Chromium with no partial action",
	"Gateway B distinct real-CDP mutation succeeds",
	"pre-action lease loss is rejected before Chromium",
	"higher-fence activation replaces the active old stream",
	"replaced lower-fence Gateway closes terminally without reconnect",
	"another Browser session and tenant remain active",
	"Valkey outage fails closed and retained-state recovery succeeds",
	"ingress reconstruction retains high-water and rejects a stale claim",
	"no Gateway bypass exists and all owned runtime resources are cleaned",
	"sanitized evidence pins every locked identity without private material",
}

var downstreamFencingV2ScenarioInventory = [...]string{
	"ordinary bounded real-CDP mutation through the unique ingress",
	"Gateway A SIGSTOP beyond its confirmed capacity lease",
	"Gateway B acquires and activates a higher fence",
	"resumed Gateway A queued stale mutation is rejected before Chromium with no partial action",
	"Gateway B distinct real-CDP mutation succeeds",
	"pre-action lease loss is rejected before Chromium",
	"higher-fence activation replaces the active old stream",
	"replaced lower-fence Gateway closes terminally without reconnect",
	"another Browser session and tenant remain active",
	"Valkey outage fails closed and retained-state recovery succeeds",
	"single retained session-field deletion rejects before Chromium without a new upstream dial",
	"complete action-state deletion rejects before Chromium without a new upstream dial",
	"pre-activation snapshot restore reuses the numerical capacity fence and fails closed",
	"ingress and file-witness reconstruction reject the restored older action state",
	"exact Redis-ahead-one interrupted witness CAS recovers conservatively",
	"behind divergent and more-than-one-ahead checkpoints remain unavailable",
	"no Gateway bypass exists and all owned runtime resources are cleaned",
	"sanitized v2 evidence pins identities and records Contract Suite as unexercised",
}

var postgresControlledRestoreScenarioInventory = [...]string{
	"ordinary bounded real-CDP mutation through the unique ingress",
	"Gateway A SIGSTOP beyond its confirmed capacity lease",
	"Gateway B acquires and activates a higher fence",
	"resumed Gateway A queued stale mutation is rejected before Chromium with no partial action",
	"Gateway B distinct real-CDP mutation succeeds",
	"pre-action lease loss is rejected before Chromium",
	"higher-fence activation replaces the active old stream",
	"replaced lower-fence Gateway closes terminally without reconnect",
	"another Browser session and tenant remain active",
	"Valkey outage fails closed and retained-state recovery succeeds",
	"unique ingress is quarantined before restore and Gateways have no bypass",
	"orchestrator-only control restores an older Redis snapshot without restoring PostgreSQL",
	"strict restored-state verification rejects the older snapshot without advancing PostgreSQL or opening listeners",
	"orchestrator restores the exact current Redis state while ingress remains quarantined",
	"strict restored-state verification accepts exact state before listeners resume",
	"post-resume real-CDP mutation succeeds through the unique ingress",
	"no Gateway bypass exists and all owned runtime resources are cleaned",
	"sanitized PostgreSQL restore evidence records its same-runner boundary and unexercised Contract Suite",
}

type DownstreamFencingV2BaseLock struct {
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	EvidenceProfile string `json:"evidence_profile"`
}

type DownstreamFencingV2Sources struct {
	ProviderRevision       string                           `json:"provider_revision"`
	HarnessBaseline        string                           `json:"harness_baseline"`
	GatewayComponent       DownstreamFencingComponentSource `json:"gateway_component"`
	IngressComponent       DownstreamFencingComponentSource `json:"ingress_component"`
	ActionHistoryComponent DownstreamFencingComponentSource `json:"action_history_component"`
	CallerSubstrate        DownstreamFencingBaselineSource  `json:"caller_substrate"`
}

type DownstreamFencingV2Witness struct {
	Kind                       string `json:"kind"`
	RequiredMode               string `json:"required_mode"`
	OutsideValkeyRestoreDomain bool   `json:"outside_valkey_restore_domain"`
	LifetimeExclusiveLock      bool   `json:"lifetime_exclusive_lock"`
	Reconstructed              bool   `json:"reconstructed"`
}

type DownstreamFencingV2RestoreControl struct {
	Owner               string `json:"owner"`
	Mechanism           string `json:"mechanism"`
	ExposedToGateways   bool   `json:"exposed_to_gateways"`
	ExposedToCallers    bool   `json:"exposed_to_callers"`
	SeparateCredential  bool   `json:"separate_credential"`
	RestoresWitness     bool   `json:"restores_witness"`
	ReusesCapacityFence bool   `json:"reuses_capacity_fence"`
}

type DownstreamFencingV2Lock struct {
	SchemaVersion     int                                            `json:"schema_version"`
	EvidenceProfile   string                                         `json:"evidence_profile"`
	Sources           DownstreamFencingV2Sources                     `json:"sources"`
	BaseLock          DownstreamFencingV2BaseLock                    `json:"base_lock"`
	Contract          DownstreamFencingContract                      `json:"contract"`
	ActionFence       rediscapacity.WitnessedActionFencingDescriptor `json:"action_fence"`
	Witness           DownstreamFencingV2Witness                     `json:"witness"`
	RestoreControl    DownstreamFencingV2RestoreControl              `json:"restore_control"`
	ACLTemplateSHA256 string                                         `json:"acl_template_sha256"`
	Scenarios         []string                                       `json:"scenarios"`

	Base DownstreamFencingLock `json:"-"`
}

func DownstreamFencingV2ScenarioNames() []string {
	return append([]string(nil), downstreamFencingV2ScenarioInventory[:]...)
}

type PostgresControlledRestoreImage struct {
	Image                    string   `json:"image"`
	IndexDigest              string   `json:"index_digest"`
	ResolvedTag              string   `json:"resolved_tag"`
	Platforms                []string `json:"platforms"`
	Database                 string   `json:"database"`
	RuntimeRole              string   `json:"runtime_role"`
	MigrationPath            string   `json:"migration_path"`
	MigrationSHA256          string   `json:"migration_sha256"`
	ProvenanceNotEstablished bool     `json:"provenance_not_established"`
	SameRunner               bool     `json:"same_runner"`
	IndependentFailureDomain bool     `json:"independent_failure_domain"`

	SelectedPlatform string `json:"-"`
}

type PostgresControlledRestoreWitness struct {
	Kind                          string   `json:"kind"`
	OperationTimeoutMillis        int64    `json:"operation_timeout_millis"`
	RuntimePrivileges             []string `json:"runtime_privileges"`
	RuntimeOwnsSchemaOrTable      bool     `json:"runtime_owns_schema_or_table"`
	RuntimeHasDDLOrDestructiveDML bool     `json:"runtime_has_ddl_or_destructive_dml"`
	CredentialsExposedToGateways  bool     `json:"credentials_exposed_to_gateways"`
	CredentialsExposedToCallers   bool     `json:"credentials_exposed_to_callers"`
}

type PostgresControlledRestoreControl struct {
	Owner                       string `json:"owner"`
	Mechanism                   string `json:"mechanism"`
	IngressQuarantine           string `json:"ingress_quarantine"`
	Verification                string `json:"verification"`
	SeparateRedisCredential     bool   `json:"separate_redis_credential"`
	RestoreCredentialToGateways bool   `json:"restore_credential_to_gateways"`
	RestoreCredentialToCallers  bool   `json:"restore_credential_to_callers"`
	RestoresWitness             bool   `json:"restores_witness"`
	VerificationMutatesWitness  bool   `json:"verification_mutates_witness"`
	ResumeRequiresExactMatch    bool   `json:"resume_requires_exact_match"`
}

type PostgresControlledRestoreLock struct {
	SchemaVersion   int                                            `json:"schema_version"`
	EvidenceProfile string                                         `json:"evidence_profile"`
	Sources         DownstreamFencingV2Sources                     `json:"sources"`
	BaseLock        DownstreamFencingV2BaseLock                    `json:"base_lock"`
	Contract        DownstreamFencingContract                      `json:"contract"`
	ActionFence     rediscapacity.WitnessedActionFencingDescriptor `json:"action_fence"`
	PostgreSQL      PostgresControlledRestoreImage                 `json:"postgresql"`
	Witness         PostgresControlledRestoreWitness               `json:"witness"`
	RestoreControl  PostgresControlledRestoreControl               `json:"restore_control"`
	Scenarios       []string                                       `json:"scenarios"`

	Base DownstreamFencingV2Lock `json:"-"`
}

func PostgresControlledRestoreScenarioNames() []string {
	return append([]string(nil), postgresControlledRestoreScenarioInventory[:]...)
}

type DownstreamFencingComponentSource struct {
	Path     string `json:"path"`
	Revision string `json:"revision"`
}

type DownstreamFencingBaselineSource struct {
	Path             string `json:"path"`
	BaselineRevision string `json:"baseline_revision"`
}

// DownstreamFencingSources distinguishes implemented component revisions from
// the commit on which the new harness is being built. HarnessBaseline and the
// caller substrate do not claim that the downstream-fencing runner existed at
// those revisions.
type DownstreamFencingSources struct {
	ProviderRevision string                           `json:"provider_revision"`
	HarnessBaseline  string                           `json:"harness_baseline"`
	GatewayComponent DownstreamFencingComponentSource `json:"gateway_component"`
	IngressComponent DownstreamFencingComponentSource `json:"ingress_component"`
	CallerSubstrate  DownstreamFencingBaselineSource  `json:"caller_substrate"`
}

type DownstreamFencingContract struct {
	Namespace            string `json:"namespace"`
	Revision             string `json:"revision"`
	Tree                 string `json:"tree"`
	SuiteCases           int    `json:"suite_cases"`
	SuiteExercised       bool   `json:"suite_exercised"`
	ContractMetadataOnly bool   `json:"contract_metadata_only"`
}

type DownstreamFencingProvenance struct {
	Established   bool   `json:"established"`
	SourceCommit  string `json:"source_commit"`
	Workflow      string `json:"workflow"`
	RunID         int64  `json:"run_id"`
	AttestationID int64  `json:"attestation_id"`
	RunnerPolicy  string `json:"runner_policy"`
}

type DownstreamFencingBrowserImage struct {
	Repository       string                      `json:"repository"`
	IndexDigest      string                      `json:"index_digest"`
	ImmutableTag     string                      `json:"immutable_tag"`
	PlatformDigests  map[string]string           `json:"platform_digests"`
	RuntimeProfileID string                      `json:"runtime_profile_id"`
	SeccompDigest    string                      `json:"seccomp_digest"`
	Provenance       DownstreamFencingProvenance `json:"provenance"`

	SelectedPlatform string `json:"-"`
	SelectedDigest   string `json:"-"`
}

type DownstreamFencingValkey struct {
	Image                    string            `json:"image"`
	IndexDigest              string            `json:"index_digest"`
	PlatformDigests          map[string]string `json:"platform_digests"`
	DatabaseIndex            int               `json:"database_index"`
	ServerConfigSHA256       string            `json:"server_config_sha256"`
	ACLTemplateSHA256        string            `json:"acl_template_sha256"`
	ProvenanceNotEstablished bool              `json:"provenance_not_established"`

	SelectedPlatform string `json:"-"`
	SelectedDigest   string `json:"-"`
}

type DownstreamFencingWire struct {
	Protocol                       string   `json:"protocol"`
	Version                        int      `json:"version"`
	ResolvePath                    string   `json:"resolve_path"`
	ConnectPath                    string   `json:"connect_path"`
	TLSMinVersion                  string   `json:"tls_min_version"`
	TLSMaxVersion                  string   `json:"tls_max_version"`
	ALPN                           []string `json:"alpn"`
	WebSocketSubprotocol           string   `json:"websocket_subprotocol"`
	MutualTLSRequired              bool     `json:"mutual_tls_required"`
	IngressURIIdentity             string   `json:"ingress_uri_identity"`
	GatewayURIIdentities           []string `json:"gateway_uri_identities"`
	ResolveRequestMaxBytes         int64    `json:"resolve_request_max_bytes"`
	ResolveRequestStrictJSON       bool     `json:"resolve_request_strict_json"`
	EndpointMetadataMaxBytes       int64    `json:"endpoint_metadata_max_bytes"`
	EndpointMetadataStrictJSON     bool     `json:"endpoint_metadata_strict_json"`
	ResolveAdvancesHighWater       bool     `json:"resolve_advances_high_water"`
	ResolveMetadataOnly            bool     `json:"resolve_metadata_only"`
	HighWaterActivationOnly        bool     `json:"high_water_activation_only"`
	ConnectFreshResolve            bool     `json:"connect_fresh_resolve"`
	ConnectOpensIngress            bool     `json:"connect_opens_ingress"`
	ActivationMessageType          string   `json:"activation_message_type"`
	ActivationMaxBytes             int64    `json:"activation_max_bytes"`
	ActivationStrictJSON           bool     `json:"activation_strict_json"`
	ActionMessageTypes             []string `json:"action_message_types"`
	ActionMaxBytes                 int64    `json:"action_max_bytes"`
	CompleteMessageRequired        bool     `json:"complete_message_required"`
	ActionACKMessageType           string   `json:"action_ack_message_type"`
	ActionACKPayloadSHA256         string   `json:"action_ack_payload_sha256"`
	ActionACKAfterSend             bool     `json:"action_ack_after_send"`
	ErrorCodes                     []string `json:"error_codes"`
	URLQueryAllowed                bool     `json:"url_query_allowed"`
	URLFragmentAllowed             bool     `json:"url_fragment_allowed"`
	URLUserinfoAllowed             bool     `json:"url_userinfo_allowed"`
	PrivateMaterialInURLHeader     bool     `json:"private_material_in_url_or_header"`
	ActionFenceClaimActivationOnly bool     `json:"action_fence_claim_activation_only"`
	ExactURLPathsRequired          bool     `json:"exact_url_paths_required"`
}

type DownstreamFencingTopology struct {
	GatewayProcesses                    int  `json:"gateway_processes"`
	ProviderIngressProcesses            int  `json:"provider_ingress_processes"`
	CallerProcesses                     int  `json:"caller_processes"`
	ValkeyProcesses                     int  `json:"valkey_processes"`
	SessionCapacityLimit                int  `json:"session_capacity_limit"`
	PrivateIngressesPerSession          int  `json:"private_ingresses_per_session"`
	ChromiumUpstreamsPerSession         int  `json:"chromium_upstreams_per_session"`
	IngressOwnsBrowserResolver          bool `json:"ingress_owns_browser_resolver"`
	GatewayAccessesIngressOnly          bool `json:"gateway_accesses_ingress_only"`
	IngressIsOnlyChromiumPath           bool `json:"ingress_is_only_chromium_path"`
	GatewayDirectChromiumAccess         bool `json:"gateway_direct_chromium_access"`
	GatewayDirectProviderAttacherAccess bool `json:"gateway_direct_provider_attacher_access"`
}

type DownstreamFencingIngress struct {
	ActionTimeoutMillis     int64 `json:"action_timeout_millis"`
	CloseTimeoutMillis      int64 `json:"close_timeout_millis"`
	MaxSessions             int   `json:"max_sessions"`
	MaxActionBytes          int64 `json:"max_action_bytes"`
	MaxConnections          int   `json:"max_connections"`
	ReadHeaderTimeoutMillis int64 `json:"read_header_timeout_millis"`
	ReadTimeoutMillis       int64 `json:"read_timeout_millis"`
	WriteTimeoutMillis      int64 `json:"write_timeout_millis"`
	IdleTimeoutMillis       int64 `json:"idle_timeout_millis"`
	MaxHeaderBytes          int   `json:"max_header_bytes"`
}

type DownstreamFencingTransport struct {
	ClientResolveTimeoutMillis      int64 `json:"client_resolve_timeout_millis"`
	ClientConnectAndIOTimeoutMillis int64 `json:"client_connect_and_io_timeout_millis"`
	ServerResolveTotalTimeoutMillis int64 `json:"server_resolve_total_timeout_millis"`
	ServerActivationIOTimeoutMillis int64 `json:"server_activation_and_io_timeout_millis"`
}

type DownstreamFencingAdapterDescriptors struct {
	Capacity    rediscapacity.Descriptor              `json:"capacity"`
	ActionFence rediscapacity.ActionFencingDescriptor `json:"action_fence"`
	Revocation  redisrevocation.Descriptor            `json:"revocation"`
}

// DownstreamFencingLock is the immutable input plan for the independent ADR
// 0033 caller gate. Loading this file is not evidence that the runner exists or
// that any scenario has executed.
type DownstreamFencingLock struct {
	SchemaVersion    int                                 `json:"schema_version"`
	EvidenceProfile  string                              `json:"evidence_profile"`
	Sources          DownstreamFencingSources            `json:"sources"`
	Contract         DownstreamFencingContract           `json:"contract"`
	BrowserImage     DownstreamFencingBrowserImage       `json:"browser_image"`
	Valkey           DownstreamFencingValkey             `json:"valkey"`
	CapacityPolicy   SharedCapacityPolicy                `json:"capacity_policy"`
	RevocationPolicy DurableRevocationPolicy             `json:"revocation_policy"`
	Adapters         DownstreamFencingAdapterDescriptors `json:"adapters"`
	PrivateWire      DownstreamFencingWire               `json:"private_wire"`
	Topology         DownstreamFencingTopology           `json:"topology"`
	Ingress          DownstreamFencingIngress            `json:"ingress"`
	Transport        DownstreamFencingTransport          `json:"transport"`
	Scenarios        []string                            `json:"scenarios"`
}

func DownstreamFencingScenarioNames() []string {
	return append([]string(nil), downstreamFencingScenarioInventory[:]...)
}

// LoadDownstreamFencing validates the lock and selects immutable platform
// children. It performs no network, Docker, Chromium, or shared-store work.
func LoadDownstreamFencing(providerRoot, platform string) (DownstreamFencingLock, error) {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return DownstreamFencingLock{}, fmt.Errorf("resolve Provider root: %w", err)
	}
	lockPath := filepath.Join(root, DownstreamFencingLockPath)
	if err := requireDownstreamFencingFields(lockPath); err != nil {
		return DownstreamFencingLock{}, err
	}
	var locked DownstreamFencingLock
	if err := decodeStrictFile(lockPath, &locked); err != nil {
		return DownstreamFencingLock{}, err
	}
	if err := validateDownstreamFencingLock(locked); err != nil {
		return DownstreamFencingLock{}, err
	}
	valkeyDigest, ok := locked.Valkey.PlatformDigests[platform]
	if !ok {
		return DownstreamFencingLock{}, fmt.Errorf("downstream-fencing platform %q is not locked", platform)
	}
	browserPlatform := platform
	if platform == "linux/arm64" {
		browserPlatform = "linux/arm64/v8"
	}
	browserDigest, ok := locked.BrowserImage.PlatformDigests[browserPlatform]
	if !ok {
		return DownstreamFencingLock{}, fmt.Errorf("downstream-fencing Browser platform %q is not locked", browserPlatform)
	}
	locked.Valkey.SelectedPlatform, locked.Valkey.SelectedDigest = platform, valkeyDigest
	locked.BrowserImage.SelectedPlatform, locked.BrowserImage.SelectedDigest = browserPlatform, browserDigest
	return locked, nil
}

// LoadDownstreamFencingV2 validates the explicit ADR 0034 successor and its
// content-bound v1 transport/topology substrate without changing the v1 lock.
func LoadDownstreamFencingV2(providerRoot, platform string) (DownstreamFencingV2Lock, error) {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return DownstreamFencingV2Lock{}, fmt.Errorf("resolve Provider root: %w", err)
	}
	base, err := LoadDownstreamFencing(root, platform)
	if err != nil {
		return DownstreamFencingV2Lock{}, err
	}
	lockPath := filepath.Join(root, DownstreamFencingV2LockPath)
	if err := requireDownstreamFencingV2Fields(lockPath); err != nil {
		return DownstreamFencingV2Lock{}, err
	}
	var locked DownstreamFencingV2Lock
	if err := decodeStrictFile(lockPath, &locked); err != nil {
		return DownstreamFencingV2Lock{}, err
	}
	baseContent, err := os.ReadFile(filepath.Join(root, DownstreamFencingLockPath))
	if err != nil {
		return DownstreamFencingV2Lock{}, err
	}
	if err := validateDownstreamFencingV2Lock(locked, normalizedSHA256(string(baseContent)), base); err != nil {
		return DownstreamFencingV2Lock{}, err
	}
	locked.Base = base
	return locked, nil
}

func LoadPostgresControlledRestore(providerRoot, platform string) (PostgresControlledRestoreLock, error) {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return PostgresControlledRestoreLock{}, fmt.Errorf("resolve Provider root: %w", err)
	}
	base, err := LoadDownstreamFencingV2(root, platform)
	if err != nil {
		return PostgresControlledRestoreLock{}, err
	}
	lockPath := filepath.Join(root, PostgresControlledRestoreLockPath)
	if err := requirePostgresControlledRestoreFields(lockPath); err != nil {
		return PostgresControlledRestoreLock{}, err
	}
	var locked PostgresControlledRestoreLock
	if err := decodeStrictFile(lockPath, &locked); err != nil {
		return PostgresControlledRestoreLock{}, err
	}
	baseContent, err := os.ReadFile(filepath.Join(root, DownstreamFencingV2LockPath))
	if err != nil {
		return PostgresControlledRestoreLock{}, err
	}
	migrationContent, err := os.ReadFile(filepath.Join(root, PostgresWitnessMigrationPath))
	if err != nil {
		return PostgresControlledRestoreLock{}, err
	}
	if err := validatePostgresControlledRestoreLock(
		locked, normalizedSHA256(string(baseContent)), normalizedSHA256(string(migrationContent)), base,
	); err != nil {
		return PostgresControlledRestoreLock{}, err
	}
	if !containsExactString(locked.PostgreSQL.Platforms, platform) {
		return PostgresControlledRestoreLock{}, fmt.Errorf("PostgreSQL controlled-restore platform %q is not locked", platform)
	}
	locked.PostgreSQL.SelectedPlatform = platform
	locked.Base = base
	return locked, nil
}

// VerifyDownstreamFencing verifies only the lock, clean Git checkout, Provider
// identity, and source baselines. It does not assert that the E2E runner is
// implemented or that the scenarios are executable.
func VerifyDownstreamFencing(providerRoot, platform string) error {
	if err := Verify(providerRoot); err != nil {
		return err
	}
	locked, err := LoadDownstreamFencing(providerRoot, platform)
	if err != nil {
		return err
	}
	return verifyDownstreamFencingSources(providerRoot, locked.Sources)
}

func VerifyDownstreamFencingV2(providerRoot, platform string) error {
	if err := Verify(providerRoot); err != nil {
		return err
	}
	locked, err := LoadDownstreamFencingV2(providerRoot, platform)
	if err != nil {
		return err
	}
	return verifyDownstreamFencingV2Sources(providerRoot, locked.Sources)
}

func VerifyPostgresControlledRestore(providerRoot, platform string) error {
	if err := Verify(providerRoot); err != nil {
		return err
	}
	locked, err := LoadPostgresControlledRestore(providerRoot, platform)
	if err != nil {
		return err
	}
	return verifyPostgresControlledRestoreSources(providerRoot, locked.Sources)
}

func validatePostgresControlledRestoreLock(
	locked PostgresControlledRestoreLock,
	baseDigest string,
	migrationDigest string,
	base DownstreamFencingV2Lock,
) error {
	if locked.SchemaVersion != 1 || locked.EvidenceProfile != PostgresControlledRestoreProfile {
		return errors.New("PostgreSQL controlled-restore lock identity is invalid")
	}
	expectedSources := DownstreamFencingV2Sources{
		ProviderRevision: ProviderCommit, HarnessBaseline: PostgresControlledRestoreHarnessBaseline,
		GatewayComponent:       DownstreamFencingComponentSource{Path: "gateway/composition/browser.go", Revision: DownstreamFencingGatewayRevision},
		IngressComponent:       DownstreamFencingComponentSource{Path: "gateway/cdpfence", Revision: DownstreamFencingIngressRevision},
		ActionHistoryComponent: DownstreamFencingComponentSource{Path: "gateway/capacity/redis", Revision: ProviderCommit},
		CallerSubstrate:        DownstreamFencingBaselineSource{Path: "e2e/internal/caller", BaselineRevision: DownstreamFencingCallerBaseline},
	}
	if locked.Sources != expectedSources {
		return errors.New("PostgreSQL controlled-restore sources differ from the locked component baselines")
	}
	expectedBase := DownstreamFencingV2BaseLock{
		Path: DownstreamFencingV2LockPath, SHA256: baseDigest, EvidenceProfile: DownstreamFencingV2Profile,
	}
	if locked.BaseLock != expectedBase || base.EvidenceProfile != DownstreamFencingV2Profile ||
		locked.Contract != base.Contract || locked.ActionFence != base.ActionFence || locked.Contract.SuiteExercised {
		return errors.New("PostgreSQL controlled-restore base identity differs from the ADR 0034 substrate")
	}
	expectedPostgres := PostgresControlledRestoreImage{
		Image: PostgresWitnessImage, IndexDigest: PostgresWitnessIndex, ResolvedTag: PostgresWitnessResolvedTag,
		Platforms: []string{"linux/amd64", "linux/arm64"}, Database: "witness", RuntimeRole: "sandbox_runtime_witness",
		MigrationPath: PostgresWitnessMigrationPath, MigrationSHA256: migrationDigest,
		ProvenanceNotEstablished: true, SameRunner: true,
	}
	if !reflect.DeepEqual(locked.PostgreSQL, expectedPostgres) {
		return errors.New("PostgreSQL controlled-restore image, migration, or evidence boundary differs from the lock")
	}
	expectedWitness := PostgresControlledRestoreWitness{
		Kind: "postgresql-action-history-witness-v1", OperationTimeoutMillis: 200,
		RuntimePrivileges: []string{"CONNECT", "USAGE", "SELECT", "INSERT_COLUMNS", "UPDATE_COLUMNS"},
	}
	if !reflect.DeepEqual(locked.Witness, expectedWitness) {
		return errors.New("PostgreSQL controlled-restore witness role differs from the least-privilege lock")
	}
	expectedRestore := PostgresControlledRestoreControl{
		Owner: "orchestrator-only", Mechanism: "redis-dump-restore-v1",
		IngressQuarantine: "provider-private-ingress-process-stop", Verification: "VerifyRestoredState",
		SeparateRedisCredential: true, ResumeRequiresExactMatch: true,
	}
	if locked.RestoreControl != expectedRestore {
		return errors.New("PostgreSQL controlled-restore procedure differs from the ADR 0036 gate")
	}
	if !reflect.DeepEqual(locked.Scenarios, postgresControlledRestoreScenarioInventory[:]) {
		return errors.New("PostgreSQL controlled-restore scenario inventory differs from the ADR 0036 gate")
	}
	return nil
}

func validateDownstreamFencingV2Lock(
	locked DownstreamFencingV2Lock,
	baseDigest string,
	base DownstreamFencingLock,
) error {
	if locked.SchemaVersion != 1 {
		return fmt.Errorf("downstream-fencing-v2 schema version = %d, want 1", locked.SchemaVersion)
	}
	if locked.EvidenceProfile != DownstreamFencingV2Profile {
		return fmt.Errorf("downstream-fencing-v2 evidence profile = %q, want %q", locked.EvidenceProfile, DownstreamFencingV2Profile)
	}
	expectedSources := DownstreamFencingV2Sources{
		ProviderRevision: ProviderCommit, HarnessBaseline: DownstreamFencingV2HarnessBaseline,
		GatewayComponent:       DownstreamFencingComponentSource{Path: "gateway/composition/browser.go", Revision: DownstreamFencingGatewayRevision},
		IngressComponent:       DownstreamFencingComponentSource{Path: "gateway/cdpfence", Revision: DownstreamFencingIngressRevision},
		ActionHistoryComponent: DownstreamFencingComponentSource{Path: "gateway/capacity/redis", Revision: ProviderCommit},
		CallerSubstrate:        DownstreamFencingBaselineSource{Path: "e2e/internal/caller", BaselineRevision: DownstreamFencingCallerBaseline},
	}
	if locked.Sources != expectedSources {
		return fmt.Errorf("downstream-fencing-v2 sources = %#v, want %#v", locked.Sources, expectedSources)
	}
	expectedBase := DownstreamFencingV2BaseLock{
		Path: DownstreamFencingLockPath, SHA256: baseDigest, EvidenceProfile: DownstreamFencingProfile,
	}
	if locked.BaseLock != expectedBase || base.EvidenceProfile != DownstreamFencingProfile {
		return errors.New("downstream-fencing-v2 base lock identity differs from the v1 substrate")
	}
	if locked.Contract != base.Contract || locked.Contract.SuiteExercised || locked.Contract.ContractMetadataOnly {
		return errors.New("downstream-fencing-v2 Contract metadata differs from its unexercised locked identity")
	}
	descriptor, err := currentDownstreamFencingV2Descriptor(base.CapacityPolicy)
	if err != nil {
		return err
	}
	if locked.ActionFence != descriptor {
		return fmt.Errorf("downstream-fencing-v2 action descriptor = %#v, want %#v", locked.ActionFence, descriptor)
	}
	expectedWitness := DownstreamFencingV2Witness{
		Kind: "single-process-file-v1", RequiredMode: "0600", OutsideValkeyRestoreDomain: true,
		LifetimeExclusiveLock: true, Reconstructed: true,
	}
	if locked.Witness != expectedWitness {
		return errors.New("downstream-fencing-v2 witness boundary differs from the ADR 0034 gate")
	}
	expectedRestore := DownstreamFencingV2RestoreControl{
		Owner: "orchestrator-only", Mechanism: "redis-dump-restore-v1", SeparateCredential: true,
		ReusesCapacityFence: true,
	}
	if locked.RestoreControl != expectedRestore {
		return errors.New("downstream-fencing-v2 restore control differs from the ADR 0034 gate")
	}
	wantACL := normalizedSHA256(DownstreamFencingV2ACLTemplate)
	if locked.ACLTemplateSHA256 != wantACL {
		return fmt.Errorf("downstream-fencing-v2 ACL template = %q, want %q", locked.ACLTemplateSHA256, wantACL)
	}
	if !reflect.DeepEqual(locked.Scenarios, downstreamFencingV2ScenarioInventory[:]) {
		return errors.New("downstream-fencing-v2 scenario inventory differs from the ADR 0034 gate")
	}
	return nil
}

func validateDownstreamFencingLock(locked DownstreamFencingLock) error {
	if locked.SchemaVersion != 1 {
		return fmt.Errorf("downstream-fencing schema version = %d, want 1", locked.SchemaVersion)
	}
	if locked.EvidenceProfile != DownstreamFencingProfile {
		return fmt.Errorf("downstream-fencing evidence profile = %q, want %q", locked.EvidenceProfile, DownstreamFencingProfile)
	}
	expectedSources := DownstreamFencingSources{
		ProviderRevision: ProviderCommit,
		HarnessBaseline:  DownstreamFencingHarnessBaseline,
		GatewayComponent: DownstreamFencingComponentSource{Path: "gateway/composition/browser.go", Revision: DownstreamFencingGatewayRevision},
		IngressComponent: DownstreamFencingComponentSource{Path: "gateway/cdpfence", Revision: DownstreamFencingIngressRevision},
		CallerSubstrate:  DownstreamFencingBaselineSource{Path: "e2e/internal/caller", BaselineRevision: DownstreamFencingCallerBaseline},
	}
	if locked.Sources != expectedSources {
		return fmt.Errorf("downstream-fencing sources = %#v, want %#v", locked.Sources, expectedSources)
	}
	expectedContract := DownstreamFencingContract{
		Namespace: ContractNS, Revision: ContractRevision, Tree: ContractTree, SuiteCases: SuiteCases,
		SuiteExercised: false, ContractMetadataOnly: false,
	}
	if locked.Contract != expectedContract {
		return fmt.Errorf("downstream-fencing Contract metadata = %#v, want %#v", locked.Contract, expectedContract)
	}
	if err := validateDownstreamFencingBrowserImage(locked.BrowserImage); err != nil {
		return err
	}
	if err := validateDownstreamFencingValkey(locked.Valkey); err != nil {
		return err
	}
	expectedPolicy := SharedCapacityPolicy{
		MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1,
		LeaseTTLMillis: 3000, RenewIntervalMillis: 400,
		RenewalSafetyMarginMillis: 500, OperationTimeoutMillis: 200,
	}
	if locked.CapacityPolicy != expectedPolicy {
		return fmt.Errorf("downstream-fencing capacity policy = %#v, want %#v", locked.CapacityPolicy, expectedPolicy)
	}
	expectedRevocation := DurableRevocationPolicy{
		MaxGrantLifetimeMillis: 900_000,
		PollIntervalMillis:     100,
		OperationTimeoutMillis: 100,
	}
	if locked.RevocationPolicy != expectedRevocation {
		return fmt.Errorf("downstream-fencing revocation policy = %#v, want %#v", locked.RevocationPolicy, expectedRevocation)
	}
	descriptors, err := currentDownstreamFencingDescriptors(expectedPolicy, expectedRevocation)
	if err != nil {
		return err
	}
	if locked.Adapters != descriptors {
		return fmt.Errorf("downstream-fencing adapter descriptors = %#v, want %#v", locked.Adapters, descriptors)
	}
	expectedWire := downstreamFencingWireBaseline()
	if !reflect.DeepEqual(locked.PrivateWire, expectedWire) {
		return fmt.Errorf("downstream-fencing private wire = %#v, want %#v", locked.PrivateWire, expectedWire)
	}
	expectedTopology := DownstreamFencingTopology{
		GatewayProcesses: 2, ProviderIngressProcesses: 1, CallerProcesses: 2, ValkeyProcesses: 1,
		SessionCapacityLimit: 1, PrivateIngressesPerSession: 1, ChromiumUpstreamsPerSession: 1,
		IngressOwnsBrowserResolver: true, GatewayAccessesIngressOnly: true, IngressIsOnlyChromiumPath: true,
	}
	if locked.Topology != expectedTopology {
		return fmt.Errorf("downstream-fencing topology = %#v, want %#v", locked.Topology, expectedTopology)
	}
	expectedIngress := DownstreamFencingIngress{
		ActionTimeoutMillis: 1000, CloseTimeoutMillis: 5000, MaxSessions: 4, MaxActionBytes: 64 << 10,
		MaxConnections: 32, ReadHeaderTimeoutMillis: 1000, ReadTimeoutMillis: 30000,
		WriteTimeoutMillis: 30000, IdleTimeoutMillis: 60000, MaxHeaderBytes: 16 << 10,
	}
	if locked.Ingress != expectedIngress {
		return fmt.Errorf("downstream-fencing ingress bounds = %#v, want %#v", locked.Ingress, expectedIngress)
	}
	expectedTransport := DownstreamFencingTransport{
		ClientResolveTimeoutMillis: 1000, ClientConnectAndIOTimeoutMillis: 2000,
		ServerResolveTotalTimeoutMillis: 1000, ServerActivationIOTimeoutMillis: 2000,
	}
	if locked.Transport != expectedTransport {
		return fmt.Errorf("downstream-fencing transport bounds = %#v, want %#v", locked.Transport, expectedTransport)
	}
	if locked.Transport.ClientConnectAndIOTimeoutMillis <= locked.Ingress.ActionTimeoutMillis ||
		locked.Transport.ServerActivationIOTimeoutMillis <= locked.Ingress.ActionTimeoutMillis {
		return errors.New("downstream-fencing transport I/O timeouts must exceed the ingress action budget")
	}
	availableWindow := locked.CapacityPolicy.LeaseTTLMillis - locked.CapacityPolicy.RenewIntervalMillis -
		locked.CapacityPolicy.RenewalSafetyMarginMillis - locked.CapacityPolicy.OperationTimeoutMillis
	if locked.Ingress.ActionTimeoutMillis >= availableWindow {
		return fmt.Errorf("downstream-fencing action timeout = %dms, must be below %dms capacity safety window",
			locked.Ingress.ActionTimeoutMillis, availableWindow)
	}
	if !reflect.DeepEqual(locked.Scenarios, downstreamFencingScenarioInventory[:]) {
		return errors.New("downstream-fencing scenario inventory differs from the ADR 0033 gate")
	}
	return nil
}

func validateDownstreamFencingBrowserImage(locked DownstreamFencingBrowserImage) error {
	publication := browserimage.LockedPublication()
	expectedPlatforms := map[string]string{
		"linux/amd64":    "sha256:5e68861696218355998a552800908fd9ef26698435010761f9f7265145a3c746",
		"linux/arm64/v8": "sha256:93ddabde08132c50650d141cf47403263622fe72a5fad1ffaffbf69a94e35591",
	}
	expectedProvenance := DownstreamFencingProvenance{
		Established: true, SourceCommit: publication.SourceCommit, Workflow: publication.Workflow,
		RunID: publication.RunID, AttestationID: publication.AttestationID, RunnerPolicy: publication.RunnerPolicy,
	}
	if locked.Repository != publication.Repository || locked.IndexDigest != publication.Digest ||
		locked.ImmutableTag != publication.Tag || !reflect.DeepEqual(locked.PlatformDigests, expectedPlatforms) ||
		locked.RuntimeProfileID != publication.RuntimeProfileID || locked.SeccompDigest != publication.SeccompDigest ||
		locked.Provenance != expectedProvenance {
		return errors.New("downstream-fencing Browser image or provenance differs from the signed publication baseline")
	}
	return nil
}

func validateDownstreamFencingValkey(locked DownstreamFencingValkey) error {
	expectedPlatforms := map[string]string{
		"linux/amd64": "sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478",
		"linux/arm64": "sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e",
	}
	if locked.Image != DownstreamFencingValkeyImage || locked.IndexDigest != DownstreamFencingValkeyIndex ||
		!reflect.DeepEqual(locked.PlatformDigests, expectedPlatforms) || locked.DatabaseIndex != 0 ||
		locked.ServerConfigSHA256 != normalizedSHA256(DownstreamFencingServerConfig) ||
		locked.ACLTemplateSHA256 != normalizedSHA256(DownstreamFencingACLTemplate) || !locked.ProvenanceNotEstablished {
		return errors.New("downstream-fencing Valkey identity, configuration, or provenance boundary differs from the baseline")
	}
	for platform, digest := range locked.PlatformDigests {
		if (platform != "linux/amd64" && platform != "linux/arm64") || !digestPattern.MatchString(digest) {
			return fmt.Errorf("downstream-fencing Valkey platform descriptor %q=%q is invalid", platform, digest)
		}
	}
	return nil
}

func downstreamFencingWireBaseline() DownstreamFencingWire {
	return DownstreamFencingWire{
		Protocol: wire.ProtocolName, Version: wire.ProtocolVersion,
		ResolvePath: wire.ResolvePath, ConnectPath: wire.ConnectPath,
		TLSMinVersion: "1.3", TLSMaxVersion: "1.3", ALPN: []string{"http/1.1"}, WebSocketSubprotocol: wire.ProtocolName,
		MutualTLSRequired: true, IngressURIIdentity: wire.IngressRoleURI,
		GatewayURIIdentities:   []string{wire.GatewayARoleURI, wire.GatewayBRoleURI},
		ResolveRequestMaxBytes: wire.MaxResolutionBytes, ResolveRequestStrictJSON: true,
		EndpointMetadataMaxBytes: wire.MaxResolutionBytes, EndpointMetadataStrictJSON: true,
		ResolveMetadataOnly: true, HighWaterActivationOnly: true,
		ConnectFreshResolve: true, ConnectOpensIngress: true,
		ActivationMessageType: "text", ActivationMaxBytes: wire.MaxActivationBytes, ActivationStrictJSON: true,
		ActionMessageTypes: []string{"text", "binary"}, ActionMaxBytes: wire.MaxMessageBytes, CompleteMessageRequired: true,
		ActionACKMessageType:           "pong",
		ActionACKPayloadSHA256:         normalizedSHA256(wire.ActionACKPayload),
		ActionACKAfterSend:             true,
		ErrorCodes:                     []string{wire.ErrorInvalidActivation, wire.ErrorUnavailable, wire.ErrorFenceLost},
		ActionFenceClaimActivationOnly: true, ExactURLPathsRequired: true,
	}
}

func requireDownstreamFencingFields(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxLockBytes {
		return fmt.Errorf("decode %s: lock exceeds %d bytes", path, maxLockBytes)
	}
	if err := requireJSONStructFields(content, reflect.TypeOf(DownstreamFencingLock{}), "$"); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func requireDownstreamFencingV2Fields(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxLockBytes {
		return fmt.Errorf("decode %s: lock exceeds %d bytes", path, maxLockBytes)
	}
	if err := requireJSONStructFields(content, reflect.TypeOf(DownstreamFencingV2Lock{}), "$"); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func requirePostgresControlledRestoreFields(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxLockBytes {
		return fmt.Errorf("decode %s: lock exceeds %d bytes", path, maxLockBytes)
	}
	if err := requireJSONStructFields(content, reflect.TypeOf(PostgresControlledRestoreLock{}), "$"); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func requireJSONStructFields(encoded []byte, objectType reflect.Type, path string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		return err
	}
	for index := 0; index < objectType.NumField(); index++ {
		field := objectType.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		value, exists := object[name]
		if !exists {
			return fmt.Errorf("missing required field %s.%s", path, name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("required field %s.%s is null", path, name)
		}
		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType.Kind() == reflect.Struct {
			if err := requireJSONStructFields(value, fieldType, path+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func currentDownstreamFencingDescriptors(
	policy SharedCapacityPolicy,
	revocationPolicy DurableRevocationPolicy,
) (DownstreamFencingAdapterDescriptors, error) {
	timeout := time.Duration(policy.OperationTimeoutMillis) * time.Millisecond
	client := goredis.NewClient(&goredis.Options{
		Addr: "127.0.0.1:1", MaxRetries: -1, ContextTimeoutEnabled: true,
		Protocol: 2, DisableIdentity: true, DialTimeout: timeout, ReadTimeout: timeout,
		WriteTimeout: timeout, PoolTimeout: timeout,
	})
	defer func() { _ = client.Close() }()
	capacity, err := rediscapacity.New(rediscapacity.Options{
		Client: client, Namespace: "downstream-fencing-lock-descriptor",
		MaxTotal: policy.MaxTotal, MaxPerTenant: policy.MaxPerTenant, MaxPerSession: policy.MaxPerSession,
		LeaseTTL:            time.Duration(policy.LeaseTTLMillis) * time.Millisecond,
		RenewInterval:       time.Duration(policy.RenewIntervalMillis) * time.Millisecond,
		RenewalSafetyMargin: time.Duration(policy.RenewalSafetyMarginMillis) * time.Millisecond,
		OperationTimeout:    timeout,
	})
	if err != nil {
		return DownstreamFencingAdapterDescriptors{}, fmt.Errorf("construct downstream-fencing capacity descriptor: %w", err)
	}
	fencer, err := rediscapacity.NewActionFencer(capacity)
	if err != nil {
		return DownstreamFencingAdapterDescriptors{}, fmt.Errorf("construct downstream-fencing action descriptor: %w", err)
	}
	revocationTimeout := time.Duration(revocationPolicy.OperationTimeoutMillis) * time.Millisecond
	revocationClient := goredis.NewClient(&goredis.Options{
		Addr: "127.0.0.1:1", MaxRetries: -1, ContextTimeoutEnabled: true,
		Protocol: 2, DisableIdentity: true, DialTimeout: revocationTimeout, ReadTimeout: revocationTimeout,
		WriteTimeout: revocationTimeout, PoolTimeout: revocationTimeout,
	})
	defer func() { _ = revocationClient.Close() }()
	revocations, err := redisrevocation.New(redisrevocation.Options{
		Client: revocationClient, Namespace: "downstream-fencing-lock-revocation-descriptor",
		MaxGrantLifetime: time.Duration(revocationPolicy.MaxGrantLifetimeMillis) * time.Millisecond,
		PollInterval:     time.Duration(revocationPolicy.PollIntervalMillis) * time.Millisecond,
		OperationTimeout: time.Duration(revocationPolicy.OperationTimeoutMillis) * time.Millisecond,
	})
	if err != nil {
		return DownstreamFencingAdapterDescriptors{}, fmt.Errorf("construct downstream-fencing revocation descriptor: %w", err)
	}
	return DownstreamFencingAdapterDescriptors{
		Capacity: capacity.Descriptor(), ActionFence: fencer.Descriptor(), Revocation: revocations.Descriptor(),
	}, nil
}

type descriptorActionHistoryWitness struct{}

func (descriptorActionHistoryWitness) Load(context.Context, string) (rediscapacity.ActionHistoryCheckpoint, error) {
	return rediscapacity.ActionHistoryCheckpoint{}, rediscapacity.ErrActionHistoryUnavailable
}

func (descriptorActionHistoryWitness) Provision(context.Context, string, rediscapacity.ActionHistoryCheckpoint) error {
	return rediscapacity.ErrActionHistoryUnavailable
}

func (descriptorActionHistoryWitness) CompareAndSwap(
	context.Context,
	string,
	rediscapacity.ActionHistoryCheckpoint,
	rediscapacity.ActionHistoryCheckpoint,
) error {
	return rediscapacity.ErrActionHistoryUnavailable
}

func currentDownstreamFencingV2Descriptor(
	policy SharedCapacityPolicy,
) (rediscapacity.WitnessedActionFencingDescriptor, error) {
	timeout := time.Duration(policy.OperationTimeoutMillis) * time.Millisecond
	client := goredis.NewClient(&goredis.Options{
		Addr: "127.0.0.1:1", MaxRetries: -1, ContextTimeoutEnabled: true,
		Protocol: 2, DisableIdentity: true, DialTimeout: timeout, ReadTimeout: timeout,
		WriteTimeout: timeout, PoolTimeout: timeout,
	})
	defer func() { _ = client.Close() }()
	capacity, err := rediscapacity.New(rediscapacity.Options{
		Client: client, Namespace: "downstream-fencing-v2-lock-descriptor",
		MaxTotal: policy.MaxTotal, MaxPerTenant: policy.MaxPerTenant, MaxPerSession: policy.MaxPerSession,
		LeaseTTL:            time.Duration(policy.LeaseTTLMillis) * time.Millisecond,
		RenewInterval:       time.Duration(policy.RenewIntervalMillis) * time.Millisecond,
		RenewalSafetyMargin: time.Duration(policy.RenewalSafetyMarginMillis) * time.Millisecond,
		OperationTimeout:    timeout,
	})
	if err != nil {
		return rediscapacity.WitnessedActionFencingDescriptor{}, fmt.Errorf("construct downstream-fencing-v2 capacity descriptor: %w", err)
	}
	fencer, err := rediscapacity.NewWitnessedActionFencer(capacity, descriptorActionHistoryWitness{})
	if err != nil {
		return rediscapacity.WitnessedActionFencingDescriptor{}, fmt.Errorf("construct downstream-fencing-v2 action descriptor: %w", err)
	}
	return fencer.Descriptor(), nil
}

func verifyDownstreamFencingSources(providerRoot string, sources DownstreamFencingSources) error {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return fmt.Errorf("resolve Provider root: %w", err)
	}
	if _, err := HarnessRevision(root); err != nil {
		return err
	}
	if err := verifyAncestor(root, sources.HarnessBaseline, "downstream-fencing harness baseline"); err != nil {
		return err
	}
	changed, err := git(root, "diff", "--name-only", sources.HarnessBaseline, "HEAD")
	if err != nil {
		return err
	}
	for _, path := range strings.Fields(changed) {
		if !downstreamFencingHarnessPath(path) {
			return fmt.Errorf("downstream-fencing harness differs from baseline at disallowed path %s", path)
		}
	}
	for name, source := range map[string]DownstreamFencingComponentSource{
		"Gateway": sources.GatewayComponent,
		"ingress": sources.IngressComponent,
	} {
		if err := verifyExactComponentSource(root, name, source.Path, source.Revision); err != nil {
			return err
		}
	}
	if err := verifyExactComponentSource(root, "caller substrate", sources.CallerSubstrate.Path, sources.CallerSubstrate.BaselineRevision); err != nil {
		return err
	}
	return nil
}

func verifyDownstreamFencingV2Sources(providerRoot string, sources DownstreamFencingV2Sources) error {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return fmt.Errorf("resolve Provider root: %w", err)
	}
	if _, err := HarnessRevision(root); err != nil {
		return err
	}
	if err := verifyAncestor(root, sources.HarnessBaseline, "downstream-fencing-v2 harness baseline"); err != nil {
		return err
	}
	changed, err := git(root, "diff", "--name-only", sources.HarnessBaseline, "HEAD")
	if err != nil {
		return err
	}
	for _, path := range strings.Fields(changed) {
		if !downstreamFencingV2HarnessPath(path) {
			return fmt.Errorf("downstream-fencing-v2 harness differs from baseline at disallowed path %s", path)
		}
	}
	for name, source := range map[string]DownstreamFencingComponentSource{
		"Gateway": sources.GatewayComponent, "ingress": sources.IngressComponent,
		"action history": sources.ActionHistoryComponent,
	} {
		if err := verifyExactComponentSource(root, name, source.Path, source.Revision); err != nil {
			return err
		}
	}
	return verifyExactComponentSource(root, "caller substrate", sources.CallerSubstrate.Path, sources.CallerSubstrate.BaselineRevision)
}

func verifyPostgresControlledRestoreSources(providerRoot string, sources DownstreamFencingV2Sources) error {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return fmt.Errorf("resolve Provider root: %w", err)
	}
	if _, err := HarnessRevision(root); err != nil {
		return err
	}
	if err := verifyAncestor(root, sources.HarnessBaseline, "PostgreSQL controlled-restore harness baseline"); err != nil {
		return err
	}
	changed, err := git(root, "diff", "--name-only", sources.HarnessBaseline, "HEAD")
	if err != nil {
		return err
	}
	for _, path := range strings.Fields(changed) {
		if !postgresControlledRestoreHarnessPath(path) {
			return fmt.Errorf("PostgreSQL controlled-restore harness differs from baseline at disallowed path %s", path)
		}
	}
	for name, source := range map[string]DownstreamFencingComponentSource{
		"Gateway": sources.GatewayComponent, "ingress": sources.IngressComponent,
		"action history": sources.ActionHistoryComponent,
	} {
		if err := verifyExactComponentSource(root, name, source.Path, source.Revision); err != nil {
			return err
		}
	}
	return verifyExactComponentSource(root, "caller substrate", sources.CallerSubstrate.Path, sources.CallerSubstrate.BaselineRevision)
}

func verifyAncestor(root, revision, name string) error {
	if !commitPattern.MatchString(revision) {
		return fmt.Errorf("%s revision is invalid", name)
	}
	if _, err := git(root, "merge-base", "--is-ancestor", revision, "HEAD"); err != nil {
		return fmt.Errorf("%s %s is not an ancestor of HEAD: %w", name, revision, err)
	}
	return nil
}

func verifyExactComponentSource(root, name, path, revision string) error {
	if filepath.ToSlash(filepath.Clean(path)) != path || path == "." || strings.HasPrefix(path, "../") {
		return fmt.Errorf("downstream-fencing %s path %q is invalid", name, path)
	}
	if err := verifyAncestor(root, revision, "downstream-fencing "+name); err != nil {
		return err
	}
	if _, err := git(root, "cat-file", "-e", revision+":"+path); err != nil {
		return fmt.Errorf("downstream-fencing %s source is absent: %w", name, err)
	}
	changed, err := git(root, "diff", "--name-only", revision, "HEAD", "--", path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(changed) != "" {
		return fmt.Errorf("downstream-fencing %s source differs from revision %s", name, revision)
	}
	return nil
}

func downstreamFencingHarnessPath(path string) bool {
	if filepath.ToSlash(filepath.Clean(path)) != path {
		return false
	}
	return path == "README.md" || path == "e2e" || strings.HasPrefix(path, "e2e/") || path == "docs" || strings.HasPrefix(path, "docs/") ||
		path == ".github/workflows/downstream-fencing-e2e.yml" ||
		path == ".github/workflows/downstream-fencing-v2-e2e.yml" ||
		path == ".github/workflows/postgres-controlled-restore-e2e.yml"
}

func downstreamFencingV2HarnessPath(path string) bool {
	if filepath.ToSlash(filepath.Clean(path)) != path {
		return false
	}
	return path == "README.md" || path == "e2e" || strings.HasPrefix(path, "e2e/") ||
		path == "docs" || strings.HasPrefix(path, "docs/") ||
		path == ".github/workflows/downstream-fencing-v2-e2e.yml" ||
		path == ".github/workflows/postgres-controlled-restore-e2e.yml"
}

func postgresControlledRestoreHarnessPath(path string) bool {
	if filepath.ToSlash(filepath.Clean(path)) != path {
		return false
	}
	return path == "README.md" || path == "e2e" || strings.HasPrefix(path, "e2e/") ||
		path == "docs" || strings.HasPrefix(path, "docs/") ||
		path == ".github/workflows/postgres-controlled-restore-e2e.yml"
}

func containsExactString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
