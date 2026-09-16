package lock

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
	goredis "github.com/redis/go-redis/v9"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
)

const (
	ProviderCommit   = "9532a9ca58610c12c62675102d09474ce44c35f6"
	ContractNS       = "urn:shell-echo:sandbox-runtime:provider-v1"
	ContractRevision = "22ba6987ea5fbc37d53942720133c0acad199edd"
	ContractTree     = "c9a7054d7c8e7f4b6e32f38175ceedddc48c2d38"

	SuiteID            = "sandbox-provider"
	SuiteVersion       = "1.0.0"
	SuiteDigest        = "sha256:b40c932643f4a1e5fd6681e3abf9b64a607609866a6254456970f8b8034cf2a8"
	SuiteDigestProfile = "rfc8785-full-document-excluding-suite-digest-v1"
	SuiteProfile       = "sandbox-runtime-provider-v1"
	SuiteCases         = 53

	RemoteSuiteID            = "sandbox-provider-remote"
	RemoteSuiteVersion       = "1.0.0"
	RemoteSuiteDigest        = "sha256:167922d972229a97a64bf22bc6a36ee20d4de19a023395d9f004f00c54cc49d0"
	RemoteSuiteDigestProfile = "rfc8785-full-document-excluding-suite-digest-v1"
	RemoteSuiteProfile       = "sandbox-runtime-provider-remote-discovery-v1"
	RemoteSuiteCases         = 6

	SharedCapacityLockPath        = "e2e/shared-capacity.lock.json"
	SharedCapacityEvidenceProfile = "browser-shared-capacity-e2e-v1"
	SharedCapacityValkeyImage     = "ghcr.io/valkey-io/valkey"
	SharedCapacityValkeyIndex     = "sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd"
	DurableRevocationLockPath     = "e2e/durable-revocation.lock.json"
	DurableRevocationProfile      = "browser-durable-revocation-e2e-v1"
	DurableRevocationValkeyImage  = "ghcr.io/valkey-io/valkey"
	DurableRevocationValkeyIndex  = "sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd"

	SharedCapacityServerConfig = "bind 0.0.0.0\n" +
		"protected-mode no\n" +
		"port 6379\n" +
		"appendonly no\n" +
		"save \"\"\n" +
		"maxmemory-policy noeviction\n"
	SharedCapacityACLTemplate = "user default off\n" +
		"user e2e on >${PASSWORD} ~sandbox-runtime:{${NAMESPACE_SHA256}}:capacity:* " +
		"+ping +type +zcard +set +get +hset +hlen +hget +time +zremrangebyscore " +
		"+zrange +incr +zadd +pexpireat +zrem +evalsha +eval\n"
	DurableRevocationServerConfig = "bind 0.0.0.0\n" +
		"protected-mode no\n" +
		"port 6379\n" +
		"appendonly no\n" +
		"save \"\"\n" +
		"maxmemory-policy noeviction\n"
	DurableRevocationACLTemplate = "user default off\n" +
		"user e2e on >${PASSWORD} ~sandbox-runtime:{${NAMESPACE_SHA256}}:revocation:* " +
		"+ping +type +hset +hlen +hget +time +get +set +pttl +pexpireat +evalsha +eval\n"

	maxLockBytes = 64 << 10
)

var (
	errDirtyHarness = errors.New("external caller harness has worktree changes")
	commitPattern   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

var sharedCapacityScenarioInventory = [10]string{
	"cross-process session limit after WebSocket upgrade",
	"cross-process tenant limit and unaffected tenant",
	"cross-process global limit",
	"renewal beyond three lease TTLs",
	"confirmed lease loss closes without reconnect",
	"Gateway crash TTL reclamation",
	"stale owner and fence cannot affect successor",
	"renew and release race does not resurrect",
	"store outage fails closed and retained-state recovery",
	"sensitive values absent from evidence",
}

var durableRevocationScenarioInventory = [7]string{
	"independent revoker disconnects the same exact active grant on both Gateways within bound",
	"pre-revoked exact grant is rejected before authorized resolve and dial on both Gateways",
	"retained revocation survives both Gateway process reconstructions",
	"exact grant scope leaves another same-session grant and another tenant active",
	"retained-store outage closes active connections and rejects new work before resolution",
	"store recovery does not resurrect revoked grants and fresh grants recover",
	"sensitive values are absent from evidence",
}

// SharedCapacityScenarios supports fixed-index scenario execution. Validation
// uses a private copy so consumers cannot mutate the lock authority.
var SharedCapacityScenarios = sharedCapacityScenarioInventory

// DurableRevocationScenarios supports fixed-index scenario execution.
// Validation uses a private copy so consumers cannot mutate lock authority.
var DurableRevocationScenarios = durableRevocationScenarioInventory

type SharedCapacityPolicy struct {
	MaxTotal                  int   `json:"max_total"`
	MaxPerTenant              int   `json:"max_per_tenant"`
	MaxPerSession             int   `json:"max_per_session"`
	LeaseTTLMillis            int64 `json:"lease_ttl_millis"`
	RenewIntervalMillis       int64 `json:"renew_interval_millis"`
	RenewalSafetyMarginMillis int64 `json:"renewal_safety_margin_millis"`
	OperationTimeoutMillis    int64 `json:"operation_timeout_millis"`
}

// SharedCapacityValkey identifies the immutable server inputs selected for a
// run. SelectedPlatform and SelectedChildDigest are derived during loading.
type SharedCapacityValkey struct {
	Image               string            `json:"image"`
	IndexDigest         string            `json:"index_digest"`
	PlatformDigests     map[string]string `json:"platform_digests"`
	ServerConfigSHA256  string            `json:"server_config_sha256"`
	ACLTemplateSHA256   string            `json:"acl_template_sha256"`
	SelectedPlatform    string            `json:"-"`
	SelectedChildDigest string            `json:"-"`
}

// SharedCapacityAdapterDescriptor is the adapter's stable, non-sensitive
// policy and Lua program identity.
type SharedCapacityAdapterDescriptor = rediscapacity.Descriptor

// SharedCapacityLock is the validated shared-capacity evidence configuration.
type SharedCapacityLock struct {
	SchemaVersion    int                             `json:"schema_version"`
	EvidenceProfile  string                          `json:"evidence_profile"`
	ProviderCommit   string                          `json:"provider_commit"`
	Valkey           SharedCapacityValkey            `json:"valkey"`
	CapacityPolicy   SharedCapacityPolicy            `json:"capacity_policy"`
	GatewayProcesses int                             `json:"gateway_processes"`
	Scenarios        []string                        `json:"scenarios"`
	Adapter          SharedCapacityAdapterDescriptor `json:"adapter"`
}

type DurableRevocationContract struct {
	Namespace                string `json:"namespace"`
	Revision                 string `json:"revision"`
	Tree                     string `json:"tree"`
	SuiteID                  string `json:"suite_id"`
	SuiteVersion             string `json:"suite_version"`
	SuiteDigest              string `json:"suite_digest"`
	SuiteDigestProfile       string `json:"suite_digest_profile"`
	SuiteProfile             string `json:"suite_profile"`
	SuiteCases               int    `json:"suite_cases"`
	RemoteSuiteID            string `json:"remote_suite_id"`
	RemoteSuiteVersion       string `json:"remote_suite_version"`
	RemoteSuiteDigest        string `json:"remote_suite_digest"`
	RemoteSuiteDigestProfile string `json:"remote_suite_digest_profile"`
	RemoteSuiteProfile       string `json:"remote_suite_profile"`
	RemoteSuiteCases         int    `json:"remote_suite_cases"`
	SuiteExercised           bool   `json:"suite_exercised"`
	RemoteSuiteExercised     bool   `json:"remote_suite_exercised"`
}

// DurableRevocationValkey identifies the immutable retained backend selected
// for a run. SelectedPlatform and SelectedChildDigest are derived while loading.
type DurableRevocationValkey struct {
	Image               string            `json:"image"`
	IndexDigest         string            `json:"index_digest"`
	PlatformDigests     map[string]string `json:"platform_digests"`
	ServerConfigSHA256  string            `json:"server_config_sha256"`
	ACLTemplateSHA256   string            `json:"acl_template_sha256"`
	SelectedPlatform    string            `json:"-"`
	SelectedChildDigest string            `json:"-"`
}

type DurableRevocationProcesses struct {
	Gateways int `json:"gateways"`
	Callers  int `json:"callers"`
	Revokers int `json:"revokers"`
}

type DurableRevocationPolicy struct {
	MaxGrantLifetimeMillis int64 `json:"max_grant_lifetime_millis"`
	PollIntervalMillis     int64 `json:"poll_interval_millis"`
	OperationTimeoutMillis int64 `json:"operation_timeout_millis"`
}

type DurableRevocationBounds struct {
	GrantLifetimeMillis int64 `json:"grant_lifetime_millis"`
	PropagationMillis   int64 `json:"propagation_millis"`
	OutageMillis        int64 `json:"outage_millis"`
}

type DurableRevocationLocalCapacity struct {
	MaxTotal      int `json:"max_total"`
	MaxPerTenant  int `json:"max_per_tenant"`
	MaxPerSession int `json:"max_per_session"`
}

type DurableRevocationReconnect struct {
	MaxReconnects          int   `json:"max_reconnects"`
	ReconnectBackoffMillis int64 `json:"reconnect_backoff_millis"`
}

type DurableRevocationAdapterDescriptor = redisrevocation.Descriptor

// DurableRevocationLock is the validated black-box durable-revocation evidence
// configuration. Contract metadata is pinned for provenance but not exercised.
type DurableRevocationLock struct {
	SchemaVersion   int                                `json:"schema_version"`
	EvidenceProfile string                             `json:"evidence_profile"`
	ProviderCommit  string                             `json:"provider_commit"`
	Contract        DurableRevocationContract          `json:"contract"`
	Valkey          DurableRevocationValkey            `json:"valkey"`
	Processes       DurableRevocationProcesses         `json:"processes"`
	Policy          DurableRevocationPolicy            `json:"revocation_policy"`
	Bounds          DurableRevocationBounds            `json:"bounds"`
	LocalCapacity   DurableRevocationLocalCapacity     `json:"local_capacity"`
	Reconnect       DurableRevocationReconnect         `json:"reconnect"`
	Scenarios       []string                           `json:"scenarios"`
	Adapter         DurableRevocationAdapterDescriptor `json:"adapter"`
}

// SharedCapacityScenarioNames returns the exact ordered scenario inventory.
func SharedCapacityScenarioNames() []string {
	return append([]string(nil), sharedCapacityScenarioInventory[:]...)
}

// DurableRevocationScenarioNames returns the exact ordered scenario inventory.
func DurableRevocationScenarioNames() []string {
	return append([]string(nil), durableRevocationScenarioInventory[:]...)
}

// SuiteCheckSummary returns the complete local and remote Suite identities for
// concise, consistent -check output. Callers supply only the execution claims.
func SuiteCheckSummary(suiteExercised, remoteSuiteExercised bool) string {
	return fmt.Sprintf(
		"suite_id=%s suite_version=%s suite_profile=%s suite_digest_profile=%s suite_digest=%s suite_cases=%d suite_exercised=%t "+
			"remote_suite_id=%s remote_suite_version=%s remote_suite_profile=%s remote_suite_digest_profile=%s remote_suite_digest=%s remote_suite_cases=%d remote_suite_exercised=%t",
		SuiteID, SuiteVersion, SuiteProfile, SuiteDigestProfile, SuiteDigest, SuiteCases, suiteExercised,
		RemoteSuiteID, RemoteSuiteVersion, RemoteSuiteProfile, RemoteSuiteDigestProfile, RemoteSuiteDigest, RemoteSuiteCases, remoteSuiteExercised,
	)
}

type providerLock struct {
	FormatVersion int `json:"format_version"`
	Source        struct {
		Revision     string `json:"revision"`
		ContractTree string `json:"contract_tree"`
	} `json:"source"`
	Contract struct {
		Namespace string `json:"namespace"`
	} `json:"contract"`
	SandboxSuite        providerSuiteLock `json:"sandbox_suite"`
	ProviderRemoteSuite providerSuiteLock `json:"provider_remote_suite"`
}

type providerSuiteLock struct {
	Path               string `json:"path"`
	SuiteID            string `json:"suite_id"`
	SuiteVersion       string `json:"suite_version"`
	SuiteDigest        string `json:"suite_digest"`
	SuiteDigestProfile string `json:"suite_digest_profile"`
	RequiredProfile    string `json:"required_profile"`
}

type suite struct {
	SuiteID            string `json:"suite_id"`
	SuiteVersion       string `json:"suite_version"`
	SuiteDigestProfile string `json:"suite_digest_profile"`
	Profiles           []struct {
		ProfileID          string   `json:"profile_id"`
		ExecutionMode      string   `json:"execution_mode"`
		MutationsPerformed *bool    `json:"mutations_performed,omitempty"`
		Tests              []string `json:"tests"`
	} `json:"profiles"`
	SuiteDigest string `json:"suite_digest"`
}

type e2eProviderLock struct {
	SchemaVersion int `json:"schema_version"`
	Provider      struct {
		Repository string `json:"repository"`
		Commit     string `json:"commit"`
	} `json:"provider"`
	Contract struct {
		Namespace                string `json:"namespace"`
		Revision                 string `json:"revision"`
		Tree                     string `json:"tree"`
		SuiteID                  string `json:"suite_id"`
		SuiteVersion             string `json:"suite_version"`
		SuiteDigest              string `json:"suite_digest"`
		SuiteDigestProfile       string `json:"suite_digest_profile"`
		SuiteProfile             string `json:"suite_profile"`
		SuiteCases               int    `json:"suite_cases"`
		RemoteSuiteID            string `json:"remote_suite_id"`
		RemoteSuiteVersion       string `json:"remote_suite_version"`
		RemoteSuiteDigest        string `json:"remote_suite_digest"`
		RemoteSuiteDigestProfile string `json:"remote_suite_digest_profile"`
		RemoteSuiteProfile       string `json:"remote_suite_profile"`
		RemoteSuiteCases         int    `json:"remote_suite_cases"`
		SuiteExercised           bool   `json:"suite_exercised"`
		RemoteSuiteExercised     bool   `json:"remote_suite_exercised"`
	} `json:"contract"`
}

// Verify rejects a checkout whose implementation or locked Contract differs
// from the evidence baseline. Documentation and the co-located harness paths
// are allowed so evidence maintenance does not invalidate the implementation
// lock.
func Verify(providerRoot string) error {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return fmt.Errorf("resolve Provider root: %w", err)
	}
	if dirty, err := git(root, "status", "--porcelain", "--untracked-files=no"); err != nil {
		return err
	} else if strings.TrimSpace(dirty) != "" {
		return errors.New("Provider checkout has tracked worktree changes")
	}
	if err := verifyE2EProviderLock(root); err != nil {
		return err
	}
	if _, err := git(root, "merge-base", "--is-ancestor", ProviderCommit, "HEAD"); err != nil {
		return fmt.Errorf("Provider baseline %s is not an ancestor of HEAD: %w", ProviderCommit, err)
	}
	changed, err := git(root, "diff", "--name-only", ProviderCommit, "HEAD")
	if err != nil {
		return err
	}
	for _, path := range strings.Fields(changed) {
		if !providerChangePath(path) {
			return fmt.Errorf("Provider implementation differs from %s at %s", ProviderCommit, path)
		}
	}
	actualTree, err := git(root, "rev-parse", "HEAD:contract")
	if err != nil {
		return err
	}
	if strings.TrimSpace(actualTree) != ContractTree {
		return fmt.Errorf("Provider Contract tree = %s, want %s", strings.TrimSpace(actualTree), ContractTree)
	}

	var locked providerLock
	if err := decodeFile(filepath.Join(root, "compatibility/sandbox-runtime/contract.lock.json"), &locked); err != nil {
		return err
	}
	if locked.FormatVersion != 2 || locked.Source.Revision != ContractRevision || locked.Source.ContractTree != ContractTree || locked.Contract.Namespace != ContractNS {
		return errors.New("Provider Contract lock identity differs from the E2E lock")
	}
	if err := verifyProviderSuite(root, "local", locked.SandboxSuite, expectedLocalSuiteLock(), "repository-go-test", SuiteCases, false); err != nil {
		return err
	}
	if err := verifyProviderSuite(root, "remote", locked.ProviderRemoteSuite, expectedRemoteSuiteLock(), "remote-http-black-box", RemoteSuiteCases, true); err != nil {
		return err
	}
	return nil
}

func verifyE2EProviderLock(providerRoot string) error {
	lockPath := filepath.Join(providerRoot, "e2e/contract.lock.json")
	var locked e2eProviderLock
	if _, err := decodeRequiredStrictFile(lockPath, reflect.TypeOf(e2eProviderLock{}), &locked); err != nil {
		return err
	}
	if locked.SchemaVersion != 2 || locked.Provider.Repository != "github.com/shell-echo/sandbox-runtime" ||
		locked.Provider.Commit != ProviderCommit || locked.Contract.Namespace != ContractNS ||
		locked.Contract.Revision != ContractRevision || locked.Contract.Tree != ContractTree ||
		locked.Contract.SuiteID != SuiteID || locked.Contract.SuiteVersion != SuiteVersion ||
		locked.Contract.SuiteDigest != SuiteDigest || locked.Contract.SuiteDigestProfile != SuiteDigestProfile ||
		locked.Contract.SuiteProfile != SuiteProfile || locked.Contract.SuiteCases != SuiteCases ||
		locked.Contract.RemoteSuiteID != RemoteSuiteID || locked.Contract.RemoteSuiteVersion != RemoteSuiteVersion ||
		locked.Contract.RemoteSuiteDigest != RemoteSuiteDigest || locked.Contract.RemoteSuiteDigestProfile != RemoteSuiteDigestProfile ||
		locked.Contract.RemoteSuiteProfile != RemoteSuiteProfile || locked.Contract.RemoteSuiteCases != RemoteSuiteCases ||
		locked.Contract.SuiteExercised || locked.Contract.RemoteSuiteExercised {
		return errors.New("E2E Provider lock identity differs from the compiled evidence baseline")
	}
	return nil
}

func expectedLocalSuiteLock() providerSuiteLock {
	return providerSuiteLock{
		Path: "contract/conformance/provider-v1/suite.json", SuiteID: SuiteID, SuiteVersion: SuiteVersion,
		SuiteDigest: SuiteDigest, SuiteDigestProfile: SuiteDigestProfile, RequiredProfile: SuiteProfile,
	}
}

func expectedRemoteSuiteLock() providerSuiteLock {
	return providerSuiteLock{
		Path: "contract/conformance/provider-remote-v1/suite.json", SuiteID: RemoteSuiteID, SuiteVersion: RemoteSuiteVersion,
		SuiteDigest: RemoteSuiteDigest, SuiteDigestProfile: RemoteSuiteDigestProfile, RequiredProfile: RemoteSuiteProfile,
	}
}

func verifyProviderSuite(
	root, name string,
	locked, expected providerSuiteLock,
	executionMode string,
	expectedCases int,
	requireMutationBoundary bool,
) error {
	return verifyProviderSuiteWithReader(
		root, name, locked, expected, executionMode, expectedCases, requireMutationBoundary, readBoundedFile,
	)
}

func verifyProviderSuiteWithReader(
	root, name string,
	locked, expected providerSuiteLock,
	executionMode string,
	expectedCases int,
	requireMutationBoundary bool,
	readFile func(string) ([]byte, error),
) error {
	if locked != expected {
		return fmt.Errorf("Provider %s Suite lock identity differs from the E2E lock", name)
	}
	suitePath := filepath.Join(root, locked.Path)
	content, err := readFile(suitePath)
	if err != nil {
		return fmt.Errorf("read Provider %s Suite: %w", name, err)
	}
	var document suite
	if err := decodeStrict(content, &document); err != nil {
		return fmt.Errorf("decode %s: %w", suitePath, err)
	}
	if document.SuiteID != locked.SuiteID || document.SuiteVersion != locked.SuiteVersion ||
		document.SuiteDigest != locked.SuiteDigest || document.SuiteDigestProfile != locked.SuiteDigestProfile {
		return fmt.Errorf("Provider %s Suite document identity differs from the E2E lock", name)
	}
	computedDigest, err := computeProviderSuiteDigest(content)
	if err != nil {
		return fmt.Errorf("compute Provider %s Suite digest: %w", name, err)
	}
	if computedDigest != locked.SuiteDigest {
		return fmt.Errorf("Provider %s Suite content digest = %s, want %s", name, computedDigest, locked.SuiteDigest)
	}
	matched := 0
	caseCount := 0
	for _, profile := range document.Profiles {
		if profile.ProfileID != locked.RequiredProfile {
			continue
		}
		matched++
		caseCount = len(profile.Tests)
		if profile.ExecutionMode != executionMode {
			return fmt.Errorf("Provider %s Suite execution mode = %q, want %q", name, profile.ExecutionMode, executionMode)
		}
		if requireMutationBoundary {
			if profile.MutationsPerformed == nil || *profile.MutationsPerformed {
				return fmt.Errorf("Provider %s Suite must explicitly prohibit mutations", name)
			}
		} else if profile.MutationsPerformed != nil {
			return fmt.Errorf("Provider %s Suite unexpectedly declares a mutation boundary", name)
		}
	}
	if matched != 1 {
		return fmt.Errorf("Provider %s Suite required profile matches = %d, want 1", name, matched)
	}
	if caseCount != expectedCases {
		return fmt.Errorf("Provider %s Suite case count = %d, want %d", name, caseCount, expectedCases)
	}
	return nil
}

func computeProviderSuiteDigest(content []byte) (string, error) {
	canonical, err := jcs.Transform(content)
	if err != nil {
		return "", err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		return "", err
	}
	if _, exists := members["suite_digest"]; !exists {
		return "", errors.New("Suite digest member is required")
	}
	delete(members, "suite_digest")
	withoutDigest, err := json.Marshal(members)
	if err != nil {
		return "", err
	}
	canonicalWithoutDigest, err := jcs.Transform(withoutDigest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonicalWithoutDigest)
	return fmt.Sprintf("sha256:%x", digest), nil
}

func providerDocumentationPath(path string) bool {
	return path == "README.md" || path == "compatibility/sandbox-runtime/README.md" || strings.HasPrefix(path, "docs/")
}

func providerChangePath(changedPath string) bool {
	if pathpkg.Clean(changedPath) != changedPath {
		return false
	}
	return providerDocumentationPath(changedPath) || changedPath == ".github/workflows/reference-e2e.yml" ||
		changedPath == ".github/workflows/platform-candidate-e2e.yml" ||
		changedPath == ".github/workflows/browser-e2e.yml" ||
		changedPath == ".github/workflows/shared-capacity-e2e.yml" ||
		changedPath == ".github/workflows/durable-revocation-e2e.yml" ||
		changedPath == ".github/workflows/downstream-fencing-e2e.yml" ||
		changedPath == ".github/workflows/downstream-fencing-v2-e2e.yml" ||
		changedPath == ".github/workflows/postgres-controlled-restore-e2e.yml" ||
		changedPath == ".github/workflows/postgres-witness-integration.yml" ||
		changedPath == "e2e" || strings.HasPrefix(changedPath, "e2e/")
}

// LoadDurableRevocation returns the exact durable-revocation evidence lock for
// one explicitly supported runner platform.
func LoadDurableRevocation(providerRoot, platform string) (DurableRevocationLock, error) {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return DurableRevocationLock{}, fmt.Errorf("resolve Provider root: %w", err)
	}
	lockPath := filepath.Join(root, DurableRevocationLockPath)
	var locked DurableRevocationLock
	if _, err := decodeRequiredStrictFile(lockPath, reflect.TypeOf(DurableRevocationLock{}), &locked); err != nil {
		return DurableRevocationLock{}, err
	}
	if err := validateDurableRevocationLock(locked); err != nil {
		return DurableRevocationLock{}, err
	}
	child, ok := locked.Valkey.PlatformDigests[platform]
	if !ok {
		return DurableRevocationLock{}, fmt.Errorf("durable-revocation platform %q is not locked", platform)
	}
	locked.Valkey.SelectedPlatform = platform
	locked.Valkey.SelectedChildDigest = child
	return locked, nil
}

// VerifyDurableRevocation additionally proves that the clean Provider checkout
// matches the implementation and Contract baseline consumed by the lock.
func VerifyDurableRevocation(providerRoot, platform string) error {
	if err := Verify(providerRoot); err != nil {
		return err
	}
	_, err := LoadDurableRevocation(providerRoot, platform)
	return err
}

func validateDurableRevocationLock(locked DurableRevocationLock) error {
	if locked.SchemaVersion != 2 {
		return fmt.Errorf("durable-revocation schema version = %d, want 2", locked.SchemaVersion)
	}
	if locked.EvidenceProfile != DurableRevocationProfile {
		return fmt.Errorf("durable-revocation evidence profile = %q, want %q", locked.EvidenceProfile, DurableRevocationProfile)
	}
	if locked.ProviderCommit != ProviderCommit {
		return fmt.Errorf("durable-revocation Provider commit = %q, want %q", locked.ProviderCommit, ProviderCommit)
	}
	expectedContract := DurableRevocationContract{
		Namespace: ContractNS, Revision: ContractRevision, Tree: ContractTree,
		SuiteID: SuiteID, SuiteVersion: SuiteVersion, SuiteDigest: SuiteDigest,
		SuiteDigestProfile: SuiteDigestProfile, SuiteProfile: SuiteProfile, SuiteCases: SuiteCases,
		RemoteSuiteID: RemoteSuiteID, RemoteSuiteVersion: RemoteSuiteVersion, RemoteSuiteDigest: RemoteSuiteDigest,
		RemoteSuiteDigestProfile: RemoteSuiteDigestProfile, RemoteSuiteProfile: RemoteSuiteProfile, RemoteSuiteCases: RemoteSuiteCases,
		SuiteExercised: false, RemoteSuiteExercised: false,
	}
	if locked.Contract != expectedContract {
		return fmt.Errorf("durable-revocation Contract metadata = %#v, want %#v", locked.Contract, expectedContract)
	}
	if locked.Valkey.Image != DurableRevocationValkeyImage || locked.Valkey.IndexDigest != DurableRevocationValkeyIndex {
		return errors.New("durable-revocation Valkey image or index digest differs from the evidence baseline")
	}
	expectedPlatforms := map[string]string{
		"linux/amd64": "sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478",
		"linux/arm64": "sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e",
	}
	if !reflect.DeepEqual(locked.Valkey.PlatformDigests, expectedPlatforms) {
		return errors.New("durable-revocation Valkey platform digests differ from the evidence baseline")
	}
	for platform, digest := range locked.Valkey.PlatformDigests {
		if platform != "linux/amd64" && platform != "linux/arm64" {
			return fmt.Errorf("durable-revocation Valkey platform %q is not supported", platform)
		}
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("durable-revocation Valkey digest for %s is invalid", platform)
		}
	}
	expectedServerConfig := normalizedSHA256(DurableRevocationServerConfig)
	expectedACLTemplate := normalizedSHA256(DurableRevocationACLTemplate)
	if locked.Valkey.ServerConfigSHA256 != expectedServerConfig || locked.Valkey.ACLTemplateSHA256 != expectedACLTemplate {
		return fmt.Errorf("durable-revocation Valkey normalized configuration digests = %q/%q, want %q/%q",
			locked.Valkey.ServerConfigSHA256, locked.Valkey.ACLTemplateSHA256, expectedServerConfig, expectedACLTemplate)
	}
	expectedProcesses := DurableRevocationProcesses{Gateways: 2, Callers: 2, Revokers: 1}
	if locked.Processes != expectedProcesses {
		return fmt.Errorf("durable-revocation process topology = %#v, want %#v", locked.Processes, expectedProcesses)
	}
	expectedPolicy := DurableRevocationPolicy{
		MaxGrantLifetimeMillis: 900000, PollIntervalMillis: 100, OperationTimeoutMillis: 100,
	}
	if locked.Policy != expectedPolicy {
		return fmt.Errorf("durable-revocation policy = %#v, want %#v", locked.Policy, expectedPolicy)
	}
	expectedBounds := DurableRevocationBounds{
		GrantLifetimeMillis: 600000, PropagationMillis: 2000, OutageMillis: 2000,
	}
	if locked.Bounds != expectedBounds {
		return fmt.Errorf("durable-revocation bounds = %#v, want %#v", locked.Bounds, expectedBounds)
	}
	expectedLocalCapacity := DurableRevocationLocalCapacity{MaxTotal: 16, MaxPerTenant: 8, MaxPerSession: 4}
	if locked.LocalCapacity != expectedLocalCapacity {
		return fmt.Errorf("durable-revocation local capacity = %#v, want %#v", locked.LocalCapacity, expectedLocalCapacity)
	}
	expectedReconnect := DurableRevocationReconnect{MaxReconnects: 1, ReconnectBackoffMillis: 10}
	if locked.Reconnect != expectedReconnect {
		return fmt.Errorf("durable-revocation reconnect policy = %#v, want %#v", locked.Reconnect, expectedReconnect)
	}
	if !reflect.DeepEqual(locked.Scenarios, durableRevocationScenarioInventory[:]) {
		return errors.New("durable-revocation scenario inventory differs from the evidence baseline")
	}
	descriptor, err := currentDurableRevocationDescriptor(locked.Policy)
	if err != nil {
		return err
	}
	if locked.Adapter != descriptor {
		return fmt.Errorf("durable-revocation adapter descriptor = %#v, want %#v", locked.Adapter, descriptor)
	}
	return nil
}

func currentDurableRevocationDescriptor(policy DurableRevocationPolicy) (DurableRevocationAdapterDescriptor, error) {
	timeout := time.Duration(policy.OperationTimeoutMillis) * time.Millisecond
	client := goredis.NewClient(&goredis.Options{
		Addr: "127.0.0.1:1", MaxRetries: -1, ContextTimeoutEnabled: true,
		Protocol: 2, DisableIdentity: true, DialTimeout: timeout, ReadTimeout: timeout,
		WriteTimeout: timeout, PoolTimeout: timeout,
	})
	defer func() { _ = client.Close() }()
	revocations, err := redisrevocation.New(redisrevocation.Options{
		Client: client, Namespace: "durable-revocation-lock-descriptor",
		MaxGrantLifetime: time.Duration(policy.MaxGrantLifetimeMillis) * time.Millisecond,
		PollInterval:     time.Duration(policy.PollIntervalMillis) * time.Millisecond,
		OperationTimeout: timeout,
	})
	if err != nil {
		return DurableRevocationAdapterDescriptor{}, fmt.Errorf("construct durable-revocation adapter descriptor: %w", err)
	}
	return revocations.Descriptor(), nil
}

// LoadSharedCapacity returns the exact shared-capacity evidence lock for one
// explicitly supported runner platform. It validates the immutable Provider,
// Valkey, policy, adapter, and scenario identities before returning them.
func LoadSharedCapacity(providerRoot, platform string) (SharedCapacityLock, error) {
	root, err := filepath.Abs(providerRoot)
	if err != nil {
		return SharedCapacityLock{}, fmt.Errorf("resolve Provider root: %w", err)
	}
	var locked SharedCapacityLock
	if err := decodeStrictFile(filepath.Join(root, SharedCapacityLockPath), &locked); err != nil {
		return SharedCapacityLock{}, err
	}
	if err := validateSharedCapacityLock(root, locked); err != nil {
		return SharedCapacityLock{}, err
	}
	child, ok := locked.Valkey.PlatformDigests[platform]
	if !ok {
		return SharedCapacityLock{}, fmt.Errorf("shared-capacity platform %q is not locked", platform)
	}
	locked.Valkey.SelectedPlatform = platform
	locked.Valkey.SelectedChildDigest = child
	return locked, nil
}

// VerifySharedCapacity additionally proves that the clean Provider checkout
// matches the implementation and Contract baseline consumed by the lock.
func VerifySharedCapacity(providerRoot, platform string) error {
	if err := Verify(providerRoot); err != nil {
		return err
	}
	_, err := LoadSharedCapacity(providerRoot, platform)
	return err
}

func validateSharedCapacityLock(providerRoot string, locked SharedCapacityLock) error {
	if locked.SchemaVersion != 1 {
		return fmt.Errorf("shared-capacity schema version = %d, want 1", locked.SchemaVersion)
	}
	if locked.EvidenceProfile != SharedCapacityEvidenceProfile {
		return fmt.Errorf("shared-capacity evidence profile = %q, want %q", locked.EvidenceProfile, SharedCapacityEvidenceProfile)
	}
	if locked.ProviderCommit != ProviderCommit {
		return fmt.Errorf("shared-capacity Provider commit = %q, want %q", locked.ProviderCommit, ProviderCommit)
	}
	if locked.Valkey.Image != SharedCapacityValkeyImage || locked.Valkey.IndexDigest != SharedCapacityValkeyIndex {
		return errors.New("shared-capacity Valkey image or index digest differs from the evidence baseline")
	}
	expectedPlatforms := map[string]string{
		"linux/amd64": "sha256:dd021e69e0a204fbb25b39c332c3dd61d51853d0a67e34f523cf1e1ab15fe478",
		"linux/arm64": "sha256:d31209ff403ca1d95218612dd936405d84837a90bc00e3b631ebc6373b91830e",
	}
	if !reflect.DeepEqual(locked.Valkey.PlatformDigests, expectedPlatforms) {
		return errors.New("shared-capacity Valkey platform digests differ from the evidence baseline")
	}
	for platform, digest := range locked.Valkey.PlatformDigests {
		if platform != "linux/amd64" && platform != "linux/arm64" {
			return fmt.Errorf("shared-capacity Valkey platform %q is not supported", platform)
		}
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("shared-capacity Valkey digest for %s is invalid", platform)
		}
	}
	if locked.Valkey.ServerConfigSHA256 != normalizedSHA256(SharedCapacityServerConfig) ||
		locked.Valkey.ACLTemplateSHA256 != normalizedSHA256(SharedCapacityACLTemplate) {
		return errors.New("shared-capacity Valkey normalized configuration digest differs from the evidence baseline")
	}
	expectedPolicy := SharedCapacityPolicy{
		MaxTotal: 4, MaxPerTenant: 2, MaxPerSession: 1,
		LeaseTTLMillis: 2000, RenewIntervalMillis: 400,
		RenewalSafetyMarginMillis: 500, OperationTimeoutMillis: 200,
	}
	if locked.CapacityPolicy != expectedPolicy {
		return fmt.Errorf("shared-capacity policy = %#v, want %#v", locked.CapacityPolicy, expectedPolicy)
	}
	if locked.GatewayProcesses != 2 {
		return fmt.Errorf("shared-capacity Gateway process count = %d, want 2", locked.GatewayProcesses)
	}
	if !reflect.DeepEqual(locked.Scenarios, sharedCapacityScenarioInventory[:]) {
		return errors.New("shared-capacity scenario inventory differs from the evidence baseline")
	}
	descriptor, err := currentSharedCapacityDescriptor(providerRoot, locked.CapacityPolicy)
	if err != nil {
		return err
	}
	if locked.Adapter != descriptor {
		return fmt.Errorf("shared-capacity adapter descriptor = %#v, want %#v", locked.Adapter, descriptor)
	}
	return nil
}

func currentSharedCapacityDescriptor(providerRoot string, policy SharedCapacityPolicy) (SharedCapacityAdapterDescriptor, error) {
	scripts, err := sharedCapacityScriptHashes(filepath.Join(providerRoot, "gateway/capacity/redis/scripts.go"))
	if err != nil {
		return SharedCapacityAdapterDescriptor{}, err
	}
	policyFormat, err := sharedCapacityPolicyFormat(filepath.Join(providerRoot, "gateway/capacity/redis/capacity.go"))
	if err != nil {
		return SharedCapacityAdapterDescriptor{}, err
	}
	policyInput := fmt.Sprintf("%s|%d|%d|%d|%d|%d|%d|%d|%s|%s|%s|%s", policyFormat,
		policy.MaxTotal, policy.MaxPerTenant, policy.MaxPerSession, policy.LeaseTTLMillis,
		policy.RenewIntervalMillis, policy.RenewalSafetyMarginMillis, policy.OperationTimeoutMillis,
		scripts["provisionScript"], scripts["acquireScript"], scripts["renewScript"], scripts["releaseScript"])
	policyDigest := sha256.Sum256([]byte(policyInput))
	return SharedCapacityAdapterDescriptor{
		PolicyFormat: policyFormat, PolicyFingerprint: fmt.Sprintf("%x", policyDigest),
		ProvisionScript: scripts["provisionScript"], AcquireScript: scripts["acquireScript"],
		RenewScript: scripts["renewScript"], ReleaseScript: scripts["releaseScript"],
	}, nil
}

func sharedCapacityScriptHashes(path string) (map[string]string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse shared-capacity scripts: %w", err)
	}
	wanted := map[string]bool{
		"provisionScript": true,
		"acquireScript":   true,
		"renewScript":     true,
		"releaseScript":   true,
	}
	hashes := make(map[string]string, len(wanted))
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, specification := range general.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || !wanted[value.Names[0].Name] || len(value.Values) != 1 {
				continue
			}
			call, ok := value.Values[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return nil, fmt.Errorf("shared-capacity script %s is not one literal", value.Names[0].Name)
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			literal, literalOK := call.Args[0].(*ast.BasicLit)
			if !ok || selector.Sel.Name != "NewScript" || !literalOK || literal.Kind != token.STRING {
				return nil, fmt.Errorf("shared-capacity script %s has an unsupported declaration", value.Names[0].Name)
			}
			source, err := strconv.Unquote(literal.Value)
			if err != nil {
				return nil, fmt.Errorf("decode shared-capacity script %s: %w", value.Names[0].Name, err)
			}
			digest := sha1.Sum([]byte(source))
			hashes[value.Names[0].Name] = fmt.Sprintf("%x", digest)
		}
	}
	if len(hashes) != len(wanted) {
		return nil, fmt.Errorf("found %d shared-capacity scripts, want %d", len(hashes), len(wanted))
	}
	return hashes, nil
}

func sharedCapacityPolicyFormat(path string) (string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return "", fmt.Errorf("parse shared-capacity adapter: %w", err)
	}
	for _, declaration := range parsed.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, specification := range general.Specs {
			value, ok := specification.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "capacityPolicyFormat" || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return "", errors.New("shared-capacity policy format is not one string literal")
			}
			format, err := strconv.Unquote(literal.Value)
			if err != nil || format == "" {
				return "", errors.New("shared-capacity policy format is invalid")
			}
			return format, nil
		}
	}
	return "", errors.New("shared-capacity policy format was not found")
}

func normalizedSHA256(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", digest)
}

// HarnessRevision returns the exact independently versioned caller revision.
// Evidence runs refuse tracked or untracked source changes; ignored ephemeral
// evidence, runtime state, and secrets remain outside Git status.
func HarnessRevision(moduleRoot string) (string, error) {
	root, err := filepath.Abs(moduleRoot)
	if err != nil {
		return "", fmt.Errorf("resolve harness root: %w", err)
	}
	dirty, err := git(root, "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(dirty) != "" {
		return "", errDirtyHarness
	}
	revision, err := git(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil {
		return "", err
	}
	revision = strings.TrimSpace(revision)
	if !commitPattern.MatchString(revision) {
		return "", errors.New("external caller harness revision is invalid")
	}
	return revision, nil
}

func decodeFile(path string, target any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func decodeStrictFile(path string, target any) error {
	content, err := readBoundedFile(path)
	if err != nil {
		return err
	}
	if err := decodeStrict(content, target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func decodeRequiredStrictFile(path string, objectType reflect.Type, target any) ([]byte, error) {
	content, err := readBoundedFile(path)
	if err != nil {
		return nil, err
	}
	if err := requireJSONStructFields(content, objectType, "$"); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := decodeStrict(content, target); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return content, nil
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer func() { _ = file.Close() }()
	content, err := io.ReadAll(io.LimitReader(file, maxLockBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(content) > maxLockBytes {
		return nil, fmt.Errorf("decode %s: lock exceeds %d bytes", path, maxLockBytes)
	}
	return content, nil
}

func decodeStrict(content []byte, target any) error {
	if err := rejectDuplicateJSONFields(content); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing input: %w", err)
	}
	return nil
}

func rejectDuplicateJSONFields(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := walkUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return fmt.Errorf("trailing input: %w", err)
	}
	return nil
}

func walkUniqueJSONValue(decoder *json.Decoder) error {
	value, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := value.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		fields := make(map[string]struct{})
		for decoder.More() {
			fieldValue, err := decoder.Token()
			if err != nil {
				return err
			}
			field, ok := fieldValue.(string)
			if !ok {
				return errors.New("object field is not a string")
			}
			if _, exists := fields[field]; exists {
				return fmt.Errorf("duplicate JSON field %q", field)
			}
			fields[field] = struct{}{}
			if err := walkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := walkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func git(root string, args ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
