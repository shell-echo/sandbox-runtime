//go:build darwin || linux

package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	goredis "github.com/redis/go-redis/v9"
	providercaller "github.com/shell-echo/sandbox-runtime-e2e/internal/caller"
	downstreamcaller "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/gatewaystack"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/provisioning"
	downstreamstack "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/stack"
	downstreamtransport "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
	downstreamwire "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/wire"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	basestack "github.com/shell-echo/sandbox-runtime-e2e/internal/stack"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
	"github.com/shell-echo/sandbox-runtime/gateway"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
)

const (
	downstreamFencingEvidenceName = "Browser downstream CDP action-fencing external-caller evidence"
	downstreamFencingNamespace    = "downstream-fencing-e2e"
	downstreamFencingController   = "downstream-fencing-e2e-controller"
	downstreamCommandTimeout      = 5 * time.Second
	downstreamRecordMaximum       = 512
	downstreamFileMaximum         = 16 << 20
)

var downstreamEvidenceFiles = []string{
	"gateway-audit-a.jsonl",
	"gateway-audit-b.jsonl",
	"ingress-observations.jsonl",
	"manifest.json",
	"report.json",
}

var errDownstreamEvidenceChanged = errors.New("downstream-fencing evidence changed while reading")

var restoreDownstreamStaleMemberScript = goredis.NewScript(`
local lease_type = redis.call('TYPE', KEYS[1]).ok
local fence_type = redis.call('TYPE', KEYS[2]).ok
if (lease_type ~= 'none' and lease_type ~= 'zset') or fence_type ~= 'string' or
   redis.call('ZCARD', KEYS[1]) ~= 0 then
  return 0
end
local counter = redis.call('GET', KEYS[2])
local stale_fence = tonumber(ARGV[2])
local retained_fence = tonumber(ARGV[3])
local lease_ttl = tonumber(ARGV[4])
local bound_expiry = tonumber(ARGV[5])
local required_window = tonumber(ARGV[6])
if not counter or not (counter == '0' or string.match(counter, '^[1-9][0-9]*$')) or
   string.len(counter) > 15 or not stale_fence or not retained_fence or
   not lease_ttl or not bound_expiry or not required_window or
   tonumber(counter) ~= retained_fence or tonumber(counter) <= stale_fence then
  return 0
end
local clock = redis.call('TIME')
local now = (clock[1] * 1000) + math.floor(clock[2] / 1000)
local expiry = now + lease_ttl
if expiry > bound_expiry then
  expiry = bound_expiry
end
if expiry - now < required_window + 500 then
  return 0
end
if redis.call('ZADD', KEYS[1], 'NX', expiry, ARGV[1]) ~= 1 then
  return 0
end
redis.call('PEXPIREAT', KEYS[1], expiry)
return expiry
`)

var validateDownstreamStaleMemberScript = goredis.NewScript(`
if redis.call('TYPE', KEYS[1]).ok ~= 'zset' or
   redis.call('TYPE', KEYS[2]).ok ~= 'string' or
   redis.call('ZCARD', KEYS[1]) ~= 1 then
  return 0
end
local exact = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
if #exact ~= 2 or exact[1] ~= ARGV[1] then
  return 0
end
local score = tonumber(exact[2])
local bound_expiry = tonumber(ARGV[2])
local required_window = tonumber(ARGV[3])
local counter = redis.call('GET', KEYS[2])
local stale_fence = tonumber(ARGV[4])
local retained_fence = tonumber(ARGV[5])
if not score or score ~= math.floor(score) or not bound_expiry or
   not required_window or not counter or
   not (counter == '0' or string.match(counter, '^[1-9][0-9]*$')) or
   string.len(counter) > 15 or not stale_fence or not retained_fence or
   tonumber(counter) ~= retained_fence or tonumber(counter) <= stale_fence then
  return 0
end
local clock = redis.call('TIME')
local now = (clock[1] * 1000) + math.floor(clock[2] / 1000)
local remaining = score - now
local lease_ttl = redis.call('PTTL', KEYS[1])
if score > bound_expiry or remaining < required_window or
   bound_expiry - now < required_window or not lease_ttl or
   lease_ttl < remaining - 2 or lease_ttl > remaining then
  return 0
end
return 1
`)

type DownstreamFencingResult struct {
	EvidenceDirectory string
	Scenarios         int
	Platform          string
}

type downstreamFencingReport struct {
	EvidenceName    string                      `json:"evidence_name"`
	EvidenceProfile string                      `json:"evidence_profile"`
	Scenarios       []downstreamFencingScenario `json:"scenarios"`
}

type downstreamFencingScenario struct {
	Name           string `json:"name"`
	Status         string `json:"status"`
	DurationMillis int64  `json:"duration_millis"`
}

type downstreamFencingRunner struct {
	report downstreamFencingReport
}

func (r *downstreamFencingRunner) run(ctx context.Context, name string, scenario func(context.Context) error) error {
	started := time.Now()
	err := scenario(ctx)
	status := "passed"
	if err != nil {
		status = "failed"
	}
	r.report.Scenarios = append(r.report.Scenarios, downstreamFencingScenario{
		Name: name, Status: status, DurationMillis: time.Since(started).Milliseconds(),
	})
	if err != nil {
		return fmt.Errorf("downstream-fencing scenario %q: %w", name, err)
	}
	return nil
}

type downstreamFencingManifest struct {
	CreatedAt              string                                   `json:"created_at"`
	EvidenceName           string                                   `json:"evidence_name"`
	EvidenceProfile        string                                   `json:"evidence_profile"`
	HarnessCommit          string                                   `json:"harness_commit"`
	Sources                lock.DownstreamFencingSources            `json:"sources"`
	Contract               downstreamFencingContractEvidence        `json:"contract"`
	BrowserImage           downstreamFencingBrowserEvidence         `json:"browser_image"`
	Valkey                 downstreamFencingValkeyEvidence          `json:"valkey"`
	CapacityPolicy         lock.SharedCapacityPolicy                `json:"capacity_policy"`
	RevocationPolicy       lock.DurableRevocationPolicy             `json:"revocation_policy"`
	Adapters               lock.DownstreamFencingAdapterDescriptors `json:"adapters"`
	PrivateWire            lock.DownstreamFencingWire               `json:"private_wire"`
	Topology               lock.DownstreamFencingTopology           `json:"topology"`
	Ingress                lock.DownstreamFencingIngress            `json:"ingress"`
	Transport              lock.DownstreamFencingTransport          `json:"transport"`
	BinaryDigests          downstreamFencingBinaryDigests           `json:"binary_digests"`
	ConfigDigests          downstreamFencingConfigDigests           `json:"config_digests"`
	ProcessReconstructions int                                      `json:"provider_ingress_process_reconstructions"`
	Reports                []string                                 `json:"reports"`
	Audits                 []string                                 `json:"audits"`
	Observations           []string                                 `json:"observations"`
	Commands               []string                                 `json:"commands"`
	Faults                 []string                                 `json:"faults"`
	Sanitization           downstreamFencingSanitization            `json:"sanitization"`
	Cleanup                downstreamFencingCleanup                 `json:"cleanup"`
	NonTargets             []string                                 `json:"non_targets"`
	EvidenceBoundary       string                                   `json:"evidence_boundary"`
}

type downstreamFencingContractEvidence struct {
	lock.DownstreamFencingContract
	ProviderRoutesExercised []string `json:"provider_routes_exercised"`
}

type downstreamFencingBrowserEvidence struct {
	Repository       string                           `json:"repository"`
	IndexDigest      string                           `json:"index_digest"`
	ImmutableTag     string                           `json:"immutable_tag"`
	SelectedPlatform string                           `json:"selected_platform"`
	SelectedDigest   string                           `json:"selected_platform_digest"`
	LocalImageID     string                           `json:"local_image_id"`
	RuntimeProfileID string                           `json:"runtime_profile_id"`
	SeccompDigest    string                           `json:"seccomp_digest"`
	Provenance       lock.DownstreamFencingProvenance `json:"provenance"`
}

type downstreamFencingValkeyEvidence struct {
	Image                    string `json:"image"`
	IndexDigest              string `json:"index_digest"`
	SelectedPlatform         string `json:"selected_platform"`
	SelectedDigest           string `json:"selected_platform_digest"`
	LocalImageID             string `json:"local_image_id"`
	DatabaseIndex            int    `json:"database_index"`
	ServerConfigSHA256       string `json:"server_config_sha256"`
	ACLTemplateSHA256        string `json:"acl_template_sha256"`
	ProvenanceNotEstablished bool   `json:"provenance_not_established"`
}

type downstreamFencingBinaryDigests struct {
	ProviderIngress string `json:"provider_ingress_sha256"`
	Gateway         string `json:"gateway_sha256"`
	Caller          string `json:"caller_sha256"`
	BrowserEgress   string `json:"browser_egress_sha256"`
	Verifier        string `json:"verifier_sha256"`
}

type downstreamFencingConfigDigests struct {
	ProviderIngress    string   `json:"provider_ingress"`
	Gateways           []string `json:"gateways"`
	CallerBootstraps   []string `json:"caller_bootstraps"`
	ProviderBootstraps []string `json:"provider_bootstraps"`
	FinalCallers       []string `json:"final_callers"`
}

type downstreamFencingSanitization struct {
	ExactFileSet          bool `json:"exact_file_set"`
	PrivateMaterialScan   bool `json:"private_material_scan"`
	AuditRecordsValidated bool `json:"audit_records_validated"`
}

type downstreamFencingCleanup struct {
	CallersStopped          bool `json:"callers_stopped"`
	GatewaysStopped         bool `json:"gateways_stopped"`
	ProviderIngressStopped  bool `json:"provider_ingress_stopped"`
	ValkeyRemoved           bool `json:"valkey_removed"`
	BrowserResourcesRemoved bool `json:"browser_resources_removed"`
	SupportImageRemoved     bool `json:"support_image_removed"`
}

type downstreamFencingObservation struct {
	Sequence    uint64                                     `json:"sequence"`
	Type        downstreamtransport.ObservationType        `json:"type"`
	Timestamp   string                                     `json:"timestamp"`
	Result      downstreamtransport.ObservationResult      `json:"result"`
	MessageType downstreamtransport.ObservationMessageType `json:"message_type"`
	Bytes       uint64                                     `json:"bytes"`
}

type downstreamObservations []downstreamFencingObservation

type downstreamGatewayAudit struct {
	Sequence   uint64 `json:"sequence"`
	Type       string `json:"type"`
	Timestamp  string `json:"timestamp"`
	Attempt    int    `json:"attempt"`
	Frames     uint64 `json:"frames"`
	Bytes      uint64 `json:"bytes"`
	ReasonCode string `json:"reason_code"`
}

type downstreamFencingIdentity struct {
	name              string
	controller        testenv.Identity
	principal         downstreamcaller.Principal
	endpointTemplate  downstreamcaller.BootstrapEndpointTemplate
	grantTemplate     downstreamcaller.BootstrapGrantBinding
	providerBootstrap providercaller.BrowserBootstrapConfig
	request           provisioning.Request
	bootstrapConfig   downstreamcaller.BootstrapCallerConfig
	envelope          provisioning.EndpointEnvelope
}

// RunDownstreamFencing executes the locked ADR 0033 external-caller profile.
// It composes independently started caller and Gateway processes around one
// Provider/private-ingress process, one retained Valkey process, and the exact
// signed Browser image running real Chromium.
func RunDownstreamFencing(ctx context.Context, options Options) (_ DownstreamFencingResult, resultErr error) {
	moduleRoot, err := filepath.Abs(options.ModuleRoot)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	providerRoot, err := filepath.Abs(options.ProviderRoot)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	platform, err := dockerServerPlatform(ctx)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	if err := lock.VerifyDownstreamFencing(providerRoot, platform); err != nil {
		return DownstreamFencingResult{}, err
	}
	locked, err := lock.LoadDownstreamFencing(providerRoot, platform)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	harnessCommit, err := lock.HarnessRevision(moduleRoot)
	if err != nil {
		return DownstreamFencingResult{}, err
	}

	evidenceRoot, err := filepath.Abs(options.EvidenceRoot)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	evidenceDirectory := filepath.Join(evidenceRoot, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		return DownstreamFencingResult{}, err
	}
	temporaryRoot := filepath.Join(moduleRoot, "tmp")
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		return DownstreamFencingResult{}, err
	}
	runRoot, err := os.MkdirTemp(temporaryRoot, runRootPrefix)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupRunRoot(temporaryRoot, runRoot)) }()
	if err := os.Chmod(runRoot, 0o700); err != nil {
		return DownstreamFencingResult{}, err
	}

	dockerClient, err := client.New(client.FromEnv)
	if err != nil {
		return DownstreamFencingResult{}, fmt.Errorf("create Docker client: %w", err)
	}
	defer dockerClient.Close()
	architecture := strings.TrimPrefix(platform, "linux/")
	if architecture == platform {
		return DownstreamFencingResult{}, errors.New("downstream-fencing Docker platform is invalid")
	}
	if err := cleanupBrowserResources(ctx, dockerClient, downstreamFencingNamespace); err != nil {
		return DownstreamFencingResult{}, err
	}

	binRoot := filepath.Join(runRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o700); err != nil {
		return DownstreamFencingResult{}, err
	}
	goCache := filepath.Join(runRoot, "go-cache")
	ingressBinary := filepath.Join(binRoot, "downstream-fencing-ingress")
	gatewayBinary := filepath.Join(binRoot, "downstream-fencing-gateway")
	callerBinary := filepath.Join(binRoot, "downstream-fencing-caller")
	browserGatewayBinary := filepath.Join(binRoot, "browser-egress-gateway")
	for _, target := range []struct{ output, packagePath string }{
		{ingressBinary, "./cmd/downstream-fencing-ingress"},
		{gatewayBinary, "./cmd/downstream-fencing-gateway"},
		{callerBinary, "./cmd/downstream-fencing-caller"},
	} {
		if err := build(ctx, moduleRoot, goCache, nil, target.output, target.packagePath); err != nil {
			return DownstreamFencingResult{}, err
		}
	}
	if err := build(ctx, providerRoot, goCache, []string{"GOOS=linux", "GOARCH=" + architecture, "CGO_ENABLED=0"}, browserGatewayBinary, "./cmd/browser-egress-gateway"); err != nil {
		return DownstreamFencingResult{}, err
	}
	ingressBinaryDigest, err := fileSHA256(ingressBinary)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	gatewayBinaryDigest, err := fileSHA256(gatewayBinary)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	callerBinaryDigest, err := fileSHA256(callerBinary)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	browserGatewayBinaryDigest, err := fileSHA256(browserGatewayBinary)
	if err != nil {
		return DownstreamFencingResult{}, err
	}

	browserReference := locked.BrowserImage.Repository + "@" + locked.BrowserImage.IndexDigest
	if err := ensureBrowserImage(ctx, dockerClient, browserReference, architecture); err != nil {
		return DownstreamFencingResult{}, err
	}
	browserInspection, err := dockerClient.ImageInspect(ctx, browserReference)
	if err != nil {
		return DownstreamFencingResult{}, fmt.Errorf("inspect locked Browser image: %w", err)
	}
	browserGatewayImage, cleanupGatewayImage, err := prepareBrowserGatewayImage(ctx, dockerClient, runRoot, browserGatewayBinary, architecture)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	gatewayImageRemoved := false
	defer func() {
		if gatewayImageRemoved {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupGatewayImage(cleanupCtx))
	}()
	uplinkName, cleanupUplink, err := createBrowserUplink(ctx, dockerClient, downstreamFencingNamespace)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	uplinkRemoved := false
	defer func() {
		if uplinkRemoved {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupUplink(cleanupCtx))
	}()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, cleanupBrowserResources(cleanupCtx, dockerClient, downstreamFencingNamespace))
	}()

	ghPath, ghDigest, err := provenanceExecutable()
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	capacityNamespace, revocationNamespace, password, err := downstreamAuthoritySecrets()
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	acl := downstreamAuthorityACL(password, capacityNamespace, revocationNamespace)
	valkeyImage := locked.Valkey.Image + "@" + locked.Valkey.IndexDigest
	valkey, err := startSharedValkey(ctx, runRoot, valkeyImage, platform, locked.Valkey.SelectedDigest,
		lock.DownstreamFencingServerConfig, acl, "e2e", password)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	valkeyRemoved := false
	storePaused := false
	defer func() {
		if storePaused {
			unpauseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resultErr = errors.Join(resultErr, valkey.unpause(unpauseCtx))
			cancel()
		}
		if !valkeyRemoved {
			closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			resultErr = errors.Join(resultErr, valkey.close(closeCtx))
			cancel()
		}
	}()
	operationTimeout := time.Duration(locked.RevocationPolicy.OperationTimeoutMillis) * time.Millisecond
	redisClient, err := newSharedRedisClient(valkey.redisURL, operationTimeout)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	redisClosed := false
	defer func() {
		if !redisClosed {
			resultErr = errors.Join(resultErr, redisClient.Close())
		}
	}()
	if err := waitForSharedRedis(ctx, redisClient, 10*time.Second); err != nil {
		return DownstreamFencingResult{}, err
	}
	if err := provisionDownstreamAuthorities(ctx, redisClient, capacityNamespace, revocationNamespace, locked); err != nil {
		return DownstreamFencingResult{}, err
	}

	secretsRoot := filepath.Join(runRoot, "secrets")
	material, err := testenv.GeneratePKI(secretsRoot, time.Now().UTC())
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	addresses, err := allocateDistinctAddresses(4)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	providerAddress, ingressAddress := addresses[0], addresses[1]
	gatewayAddressA, gatewayAddressB := addresses[2], addresses[3]
	stateRoot := filepath.Join(runRoot, "state")
	logRoot := filepath.Join(runRoot, "logs")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return DownstreamFencingResult{}, err
	}
	if err := os.MkdirAll(logRoot, 0o700); err != nil {
		return DownstreamFencingResult{}, err
	}
	observationPath := filepath.Join(stateRoot, "ingress-observations.jsonl")
	providerRevisionID := "provider-revision-downstream-fencing-e2e-v1"
	providerAudience := "urn:shell-echo:sandbox-runtime:provider-instance:downstream-fencing-e2e"
	providerConfig := downstreamProviderConfig(
		providerAddress, ingressAddress, stateRoot, runRoot, providerRoot, browserReference, browserGatewayImage, uplinkName,
		architecture, ghPath, ghDigest, valkey.redisURL, capacityNamespace, locked, material, observationPath,
	)
	providerConfigPath := filepath.Join(secretsRoot, "provider-ingress.json")
	providerConfigDigest, err := writeJSON(providerConfigPath, providerConfig)
	if err != nil {
		return DownstreamFencingResult{}, err
	}

	ingressProcess, err := startStack(ingressBinary, providerConfigPath, filepath.Join(logRoot, "provider-ingress-initial.log"))
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	ingressStopped := false
	defer func() {
		if ingressProcess != nil && !ingressStopped {
			resultErr = errors.Join(resultErr, ingressProcess.Stop())
		}
	}()
	if err := waitForListenersWithin(ctx, ingressProcess, browserListenerReadinessTimeout, providerAddress, ingressAddress); err != nil {
		return DownstreamFencingResult{}, err
	}

	gatewayURLs := map[string]string{
		"gateway-a": "https://" + gatewayAddressA,
		"gateway-b": "https://" + gatewayAddressB,
	}
	identities, sensitive, err := downstreamIdentities(
		material, gatewayURLs, "https://"+providerAddress, providerRevisionID, providerAudience,
		locked.BrowserImage.Repository, locked.BrowserImage.IndexDigest, architecture,
	)
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	callerBootstrapDigests := make([]string, 2)
	providerBootstrapDigests := make([]string, 2)
	callerBootstrapPaths := make([]string, 2)
	providerBootstrapPaths := make([]string, 2)
	for index := range identities {
		callerBootstrapPaths[index] = filepath.Join(secretsRoot, "caller-"+identities[index].name+"-bootstrap.json")
		providerBootstrapPaths[index] = filepath.Join(secretsRoot, "caller-"+identities[index].name+"-provider.json")
		callerBootstrapDigests[index], err = writeJSON(callerBootstrapPaths[index], identities[index].bootstrapConfig)
		if err != nil {
			return DownstreamFencingResult{}, err
		}
		providerBootstrapDigests[index], err = writeJSON(providerBootstrapPaths[index], identities[index].providerBootstrap)
		if err != nil {
			return DownstreamFencingResult{}, err
		}
	}

	callers := make([]*downstreamCallerProcess, 2)
	callersStopped := false
	defer func() {
		if callersStopped {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, process := range callers {
			resultErr = errors.Join(resultErr, process.shutdown(shutdownCtx))
		}
	}()
	for index := range identities {
		callers[index], identities[index].envelope, err = startDownstreamCaller(
			ctx, callerBinary, callerBootstrapPaths[index], providerBootstrapPaths[index],
			filepath.Join(logRoot, "caller-"+identities[index].name+".log"), identities[index].request,
		)
		if err != nil {
			return DownstreamFencingResult{}, err
		}
	}

	principals, endpoints, bindings := downstreamGatewayBindings(identities)
	gatewayConfigA := downstreamGatewayConfig(
		"gateway-a", gatewayAddressA, ingressAddress, capacityNamespace, revocationNamespace,
		valkey.redisURL, filepath.Join(stateRoot, "gateway-a-audit.jsonl"), material.GatewayA,
		locked, material, principals, endpoints, bindings,
	)
	gatewayConfigB := downstreamGatewayConfig(
		"gateway-b", gatewayAddressB, ingressAddress, capacityNamespace, revocationNamespace,
		valkey.redisURL, filepath.Join(stateRoot, "gateway-b-audit.jsonl"), material.GatewayB,
		locked, material, principals, endpoints, bindings,
	)
	gatewayConfigPaths := []string{filepath.Join(secretsRoot, "gateway-a.json"), filepath.Join(secretsRoot, "gateway-b.json")}
	gatewayConfigDigests := make([]string, 2)
	for index, config := range []gatewaystack.Config{gatewayConfigA, gatewayConfigB} {
		gatewayConfigDigests[index], err = writeJSON(gatewayConfigPaths[index], config)
		if err != nil {
			return DownstreamFencingResult{}, err
		}
	}

	gatewayA, err := startStack(gatewayBinary, gatewayConfigPaths[0], filepath.Join(logRoot, "gateway-a.log"))
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	gatewayAStopped := false
	gatewayAPaused := false
	defer func() {
		if gatewayAPaused {
			resultErr = errors.Join(resultErr, signalSharedGateway(gatewayA, syscall.SIGCONT))
		}
		if gatewayA != nil && !gatewayAStopped {
			resultErr = errors.Join(resultErr, gatewayA.Stop())
		}
	}()
	gatewayB, err := startStack(gatewayBinary, gatewayConfigPaths[1], filepath.Join(logRoot, "gateway-b.log"))
	if err != nil {
		return DownstreamFencingResult{}, errors.Join(err, gatewayA.Stop())
	}
	gatewayBStopped := false
	gatewayBPaused := false
	defer func() {
		if gatewayBPaused {
			resultErr = errors.Join(resultErr, signalSharedGateway(gatewayB, syscall.SIGCONT))
		}
		if gatewayB != nil && !gatewayBStopped {
			resultErr = errors.Join(resultErr, gatewayB.Stop())
		}
	}()
	if err := waitForListenersWithin(ctx, gatewayA, 15*time.Second, gatewayAddressA); err != nil {
		return DownstreamFencingResult{}, err
	}
	if err := waitForListenersWithin(ctx, gatewayB, 15*time.Second, gatewayAddressB); err != nil {
		return DownstreamFencingResult{}, err
	}

	finalCallerConfigs := make([]downstreamcaller.Config, 2)
	finalCallerDigests := make([]string, 2)
	for index := range identities {
		finalCallerConfigs[index] = downstreamFinalCallerConfig(identities[index])
		finalCallerDigests[index], err = downstreamJSONDigest(finalCallerConfigs[index])
		if err != nil {
			return DownstreamFencingResult{}, err
		}
		commitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = callers[index].commit(commitCtx, finalCallerConfigs[index])
		cancel()
		if err != nil {
			return DownstreamFencingResult{}, err
		}
		if err := downstreamCallerReady(ctx, callers[index]); err != nil {
			return DownstreamFencingResult{}, err
		}
	}

	for _, identity := range identities {
		sensitive = append(sensitive, downstreamIdentityPrivateValues(identity)...)
	}
	sensitive = append(sensitive,
		capacityNamespace, revocationNamespace, password, valkey.redisURL, runRoot,
		providerAddress, ingressAddress, gatewayAddressA, gatewayAddressB,
		"https://"+providerAddress, "https://"+gatewayAddressA, "https://"+gatewayAddressB,
		providerConfigPath, callerBootstrapPaths[0], callerBootstrapPaths[1],
		providerBootstrapPaths[0], providerBootstrapPaths[1], gatewayConfigPaths[0], gatewayConfigPaths[1],
	)

	baselineMarker, err := randomSecret("baseline-marker-")
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	staleMarker, err := randomSecret("stale-marker-")
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	replacementMarker, err := randomSecret("replacement-marker-")
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	preActionMarker, err := randomSecret("pre-action-marker-")
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	outageMarker, err := randomSecret("outage-marker-")
	if err != nil {
		return DownstreamFencingResult{}, err
	}
	sensitive = append(sensitive, baselineMarker, staleMarker, replacementMarker, preActionMarker, outageMarker)

	runner := &downstreamFencingRunner{report: downstreamFencingReport{
		EvidenceName: downstreamFencingEvidenceName, EvidenceProfile: locked.EvidenceProfile,
	}}
	leaseTTL := time.Duration(locked.CapacityPolicy.LeaseTTLMillis) * time.Millisecond
	var staleLease, replacementLease sharedLeaseRecord
	var targetID, ownerSession, replacementSession string
	var ownerA, replacementB *downstreamCDPClient

	if err := runner.run(ctx, locked.Scenarios[0], func(ctx context.Context) error {
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := downstreamOpen(ctx, callers[0], "owner-a", "gateway-a", identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		ownerA, err = newDownstreamCDPClient(callers[0], "owner-a")
		if err != nil {
			return err
		}
		if err := ownerA.browserVersion(ctx, downstreamCommandTimeout); err != nil {
			return err
		}
		targetID, err = ownerA.createTarget(ctx, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		ownerSession, err = ownerA.attachTarget(ctx, targetID, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, targetID, ownerSession)
		got, err := ownerA.evaluateString(ctx, ownerSession, downstreamSetExpression(baselineMarker), downstreamCommandTimeout)
		if err != nil || got != baselineMarker {
			return errors.Join(err, errors.New("ordinary real-CDP mutation did not persist"))
		}
		after, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(before, after, "activation", "succeeded", 1); err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(before, after, "upstream_dial", "succeeded", 1); err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(before, after, "action_read", "complete", 4); err != nil {
			return err
		}
		return assertDownstreamObservationDelta(before, after, "action_forwarded", "succeeded", 4)
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[1], func(ctx context.Context) error {
		initial, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil {
			return err
		}
		staleLease, err = waitForSingleSharedLeaseRenewal(ctx, redisClient, capacityNamespace, initial, leaseTTL)
		if err != nil {
			return err
		}
		if err := signalSharedGateway(gatewayA, syscall.SIGSTOP); err != nil {
			return err
		}
		gatewayAPaused = true
		if err := waitForSharedGatewayStopped(ctx, gatewayA, time.Second); err != nil {
			return err
		}
		return waitForDownstreamLeaseExpiry(ctx, redisClient, capacityNamespace, staleLease, leaseTTL+time.Second)
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[2], func(ctx context.Context) error {
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := downstreamOpen(ctx, callers[0], "replacement-b", "gateway-b", identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		replacementB, err = newDownstreamCDPClient(callers[0], "replacement-b")
		if err != nil {
			return err
		}
		if err := replacementB.browserVersion(ctx, downstreamCommandTimeout); err != nil {
			return err
		}
		replacementSession, err = replacementB.attachTarget(ctx, targetID, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, replacementSession)
		replacementLease, err = singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil || replacementLease.fence <= staleLease.fence || replacementLease.member == staleLease.member {
			return errors.Join(err, errors.New("replacement did not acquire a distinct higher fence"))
		}
		after, err := waitForDownstreamObservation(
			ctx, observationPath, before, downstreamtransport.ObservationStreamTerminated,
			downstreamtransport.ObservationResultFenceLost, 1, downstreamCommandTimeout,
		)
		if err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(before, after, "activation", "succeeded", 1); err != nil {
			return err
		}
		return assertDownstreamObservationDelta(before, after, "upstream_dial", "succeeded", 1)
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[3], func(ctx context.Context) error {
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		command, payloadBytes, err := ownerA.prepareEvaluation(
			ownerSession, downstreamSetExpression(staleMarker), downstreamcaller.ActionQueueCDP, downstreamCommandTimeout,
		)
		if err != nil {
			return err
		}
		queueResult := make(chan error, 1)
		go func() { queueResult <- downstreamQueue(ctx, callers[0], command, payloadBytes) }()
		queueTimer := time.NewTimer(time.Second)
		defer queueTimer.Stop()
		select {
		case err := <-queueResult:
			if err != nil {
				return err
			}
		case <-queueTimer.C:
			return errors.New("stale CDP action was not queued while Gateway A remained suspended")
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := signalSharedGateway(gatewayA, syscall.SIGCONT); err != nil {
			return err
		}
		gatewayAPaused = false
		if err := downstreamExpectedClosed(ctx, callers[0], "owner-a", leaseTTL); err != nil {
			return err
		}
		after, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := assertQueuedStaleActionRejected(before, after, uint64(payloadBytes)); err != nil {
			return err
		}
		got, err := replacementB.evaluateString(ctx, replacementSession, downstreamReadExpression(), downstreamCommandTimeout)
		if err != nil || got != baselineMarker || got == staleMarker {
			return errors.Join(err, errors.New("queued stale mutation changed Chromium state"))
		}
		return nil
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[4], func(ctx context.Context) error {
		got, err := replacementB.evaluateString(ctx, replacementSession, downstreamSetExpression(replacementMarker), downstreamCommandTimeout)
		if err != nil || got != replacementMarker {
			return errors.Join(err, errors.New("replacement real-CDP mutation did not persist"))
		}
		got, err = replacementB.evaluateString(ctx, replacementSession, downstreamReadExpression(), downstreamCommandTimeout)
		if err != nil || got != replacementMarker || got == staleMarker {
			return errors.Join(err, errors.New("replacement could not observe its distinct mutation"))
		}
		return nil
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[5], func(ctx context.Context) error {
		current, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil {
			return err
		}
		current, err = waitForSingleSharedLeaseRenewal(ctx, redisClient, capacityNamespace, current, leaseTTL)
		if err != nil {
			return err
		}
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := removeSharedLease(ctx, redisClient, capacityNamespace, current.member); err != nil {
			return err
		}
		command, payloadBytes, err := replacementB.prepareEvaluation(
			replacementSession, downstreamSetExpression(preActionMarker), downstreamcaller.ActionQueueCDP, downstreamCommandTimeout,
		)
		if err != nil {
			return err
		}
		if err := downstreamQueue(ctx, callers[0], command, payloadBytes); err != nil {
			return err
		}
		after, err := waitForDownstreamObservation(ctx, observationPath, before, "action_failed", "fence_lost", 1, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		if err := assertDownstreamActionRejected(before, after, downstreamtransport.ObservationResultFenceLost); err != nil {
			return err
		}
		return downstreamExpectedClosed(ctx, callers[0], "replacement-b", leaseTTL)
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	var activeA *downstreamCDPClient
	var activeASession string
	var lowerReconnectBefore downstreamObservations
	if err := runner.run(ctx, locked.Scenarios[6], func(ctx context.Context) error {
		if err := waitForSharedCardinality(ctx, redisClient, capacityNamespace, 0, leaseTTL); err != nil {
			return err
		}
		if err := downstreamOpen(ctx, callers[0], "lower-b", "gateway-b", identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		lowerB, err := newDownstreamCDPClient(callers[0], "lower-b")
		if err != nil {
			return err
		}
		if err := lowerB.browserVersion(ctx, downstreamCommandTimeout); err != nil {
			return err
		}
		oldLease, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil {
			return err
		}
		oldLease, err = waitForSingleSharedLeaseRenewal(ctx, redisClient, capacityNamespace, oldLease, leaseTTL)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, oldLease.member)
		if err := signalSharedGateway(gatewayB, syscall.SIGSTOP); err != nil {
			return err
		}
		gatewayBPaused = true
		if err := waitForSharedGatewayStopped(ctx, gatewayB, time.Second); err != nil {
			return err
		}
		if err := waitForDownstreamLeaseExpiry(ctx, redisClient, capacityNamespace, oldLease, leaseTTL+time.Second); err != nil {
			return err
		}
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := downstreamOpen(ctx, callers[0], "active-a", "gateway-a", identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		activeA, err = newDownstreamCDPClient(callers[0], "active-a")
		if err != nil {
			return err
		}
		activeASession, err = activeA.attachTarget(ctx, targetID, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, activeASession)
		newLease, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil || newLease.fence <= oldLease.fence {
			return errors.Join(err, errors.New("higher-fence activation did not replace the active old stream"))
		}
		after, err := waitForDownstreamObservation(
			ctx, observationPath, before, downstreamtransport.ObservationStreamTerminated,
			downstreamtransport.ObservationResultFenceLost, 1, downstreamCommandTimeout,
		)
		if err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(before, after, "activation", "succeeded", 1); err != nil {
			return err
		}
		lowerReconnectBefore = after
		return nil
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[7], func(ctx context.Context) error {
		auditBefore, err := readDownstreamGatewayAudit(filepath.Join(stateRoot, "gateway-b-audit.jsonl"))
		if err != nil {
			return err
		}
		if err := signalSharedGateway(gatewayB, syscall.SIGCONT); err != nil {
			return err
		}
		gatewayBPaused = false
		if err := downstreamExpectedClosed(ctx, callers[0], "lower-b", leaseTTL); err != nil {
			return err
		}
		if _, err := waitForDownstreamTerminalAudit(
			ctx, filepath.Join(stateRoot, "gateway-b-audit.jsonl"), auditBefore, downstreamCommandTimeout,
		); err != nil {
			return err
		}
		closed, err := waitForDownstreamObservationsUnchanged(
			ctx, observationPath, lowerReconnectBefore, 100*time.Millisecond,
		)
		if err != nil {
			return err
		}
		if !downstreamObservationsEqual(lowerReconnectBefore, closed) {
			return errors.New("replaced lower-fence Gateway attempted an automatic reconnect")
		}
		return nil
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[8], func(ctx context.Context) error {
		if err := downstreamOpen(ctx, callers[1], "unaffected-b", "gateway-b", identities[1].envelope.GrantBinding.ID); err != nil {
			return err
		}
		unaffected, err := newDownstreamCDPClient(callers[1], "unaffected-b")
		if err != nil {
			return err
		}
		if err := unaffected.browserVersion(ctx, downstreamCommandTimeout); err != nil {
			return err
		}
		unaffectedTarget, err := unaffected.createTarget(ctx, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		unaffectedSession, err := unaffected.attachTarget(ctx, unaffectedTarget, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, unaffectedTarget, unaffectedSession)
		unaffectedMarker, err := randomSecret("unaffected-marker-")
		if err != nil {
			return err
		}
		sensitive = append(sensitive, unaffectedMarker)
		got, err := unaffected.evaluateString(ctx, unaffectedSession, downstreamSetExpression(unaffectedMarker), downstreamCommandTimeout)
		if err != nil || got != unaffectedMarker {
			return errors.Join(err, errors.New("unaffected tenant Browser session did not remain active"))
		}
		got, err = activeA.evaluateString(ctx, activeASession, downstreamReadExpression(), downstreamCommandTimeout)
		if err != nil || got != replacementMarker {
			return errors.Join(err, errors.New("primary Browser session was disturbed by the unaffected tenant"))
		}
		if err := downstreamClose(ctx, callers[1], "unaffected-b"); err != nil {
			return err
		}
		return waitForSharedCardinality(ctx, redisClient, capacityNamespace, 1, leaseTTL)
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[9], func(ctx context.Context) error {
		current, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil {
			return err
		}
		current, err = waitForSingleSharedLeaseRenewal(ctx, redisClient, capacityNamespace, current, leaseTTL)
		if err != nil {
			return err
		}
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := valkey.pause(ctx); err != nil {
			return err
		}
		storePaused = true
		command, payloadBytes, err := activeA.prepareEvaluation(
			activeASession, downstreamSetExpression(outageMarker), downstreamcaller.ActionQueueCDP, downstreamCommandTimeout,
		)
		if err != nil {
			return err
		}
		if err := downstreamQueue(ctx, callers[0], command, payloadBytes); err != nil {
			return err
		}
		after, err := waitForDownstreamObservation(ctx, observationPath, before, "action_failed", "unavailable", 1, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		if err := assertDownstreamActionRejected(before, after, downstreamtransport.ObservationResultUnavailable); err != nil {
			return err
		}
		if err := downstreamExpectedClosed(ctx, callers[0], "active-a", leaseTTL); err != nil {
			return err
		}
		if err := valkey.unpause(ctx); err != nil {
			return err
		}
		storePaused = false
		if err := waitForSharedRedis(ctx, redisClient, 5*time.Second); err != nil {
			return err
		}
		if err := waitForDownstreamLeaseExpiry(ctx, redisClient, capacityNamespace, current, leaseTTL+time.Second); err != nil {
			return err
		}
		if err := downstreamOpen(ctx, callers[0], "recovered-b", "gateway-b", identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		recovered, err := newDownstreamCDPClient(callers[0], "recovered-b")
		if err != nil {
			return err
		}
		recoveredSession, err := recovered.attachTarget(ctx, targetID, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, recoveredSession)
		recoveredLease, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil || recoveredLease.fence <= current.fence {
			return errors.Join(err, errors.New("retained-state recovery did not acquire a higher fence"))
		}
		got, err := recovered.evaluateString(ctx, recoveredSession, downstreamReadExpression(), downstreamCommandTimeout)
		if err != nil || got != replacementMarker || got == outageMarker {
			return errors.Join(err, errors.New("retained-state recovery observed a faulted mutation"))
		}
		return downstreamClose(ctx, callers[0], "recovered-b")
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	if err := runner.run(ctx, locked.Scenarios[10], func(ctx context.Context) error {
		if err := waitForSharedCardinality(ctx, redisClient, capacityNamespace, 0, leaseTTL); err != nil {
			return err
		}
		if err := downstreamOpen(ctx, callers[0], "reconstruct-stale-a", "gateway-a", identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		staleReconstruct, err := newDownstreamCDPClient(callers[0], "reconstruct-stale-a")
		if err != nil {
			return err
		}
		if err := staleReconstruct.browserVersion(ctx, downstreamCommandTimeout); err != nil {
			return err
		}
		oldLease, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil {
			return err
		}
		oldLease, err = waitForSingleSharedLeaseRenewal(ctx, redisClient, capacityNamespace, oldLease, leaseTTL)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, oldLease.member)
		if err := signalSharedGateway(gatewayA, syscall.SIGSTOP); err != nil {
			return err
		}
		gatewayAPaused = true
		if err := waitForSharedGatewayStopped(ctx, gatewayA, time.Second); err != nil {
			return err
		}
		if err := waitForDownstreamLeaseExpiry(ctx, redisClient, capacityNamespace, oldLease, leaseTTL+time.Second); err != nil {
			return err
		}
		activationBefore, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := downstreamOpen(ctx, callers[0], "reconstruct-current-b", "gateway-b", identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		currentB, err := newDownstreamCDPClient(callers[0], "reconstruct-current-b")
		if err != nil {
			return err
		}
		if err := currentB.browserVersion(ctx, downstreamCommandTimeout); err != nil {
			return err
		}
		currentSession, err := currentB.attachTarget(ctx, targetID, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, currentSession)
		activationAfter, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(activationBefore, activationAfter, "activation", "succeeded", 1); err != nil {
			return err
		}
		newLease, err := singleSharedLease(ctx, redisClient, capacityNamespace)
		if err != nil || newLease.fence <= oldLease.fence {
			return errors.Join(err, errors.New("reconstruction setup did not retain a higher fence"))
		}
		highWaterBefore, err := downstreamHighWaterSnapshot(ctx, redisClient, capacityNamespace, identities[0])
		if err != nil {
			return err
		}
		if err := downstreamClose(ctx, callers[0], "reconstruct-current-b"); err != nil {
			return err
		}
		if err := ingressProcess.Stop(); err != nil {
			return err
		}
		ingressStopped = true
		ingressProcess, err = startStack(ingressBinary, providerConfigPath, filepath.Join(logRoot, "provider-ingress-reconstructed.log"))
		if err != nil {
			return err
		}
		ingressStopped = false
		if err := waitForListenersWithin(ctx, ingressProcess, browserListenerReadinessTimeout, providerAddress, ingressAddress); err != nil {
			return err
		}
		highWaterAfter, err := downstreamHighWaterSnapshot(ctx, redisClient, capacityNamespace, identities[0])
		if err != nil || highWaterAfter != highWaterBefore {
			return errors.Join(err, errors.New("retained action high-water changed across ingress reconstruction"))
		}
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if err := signalSharedGateway(gatewayA, syscall.SIGCONT); err != nil {
			return err
		}
		gatewayAPaused = false
		if err := downstreamExpectedClosed(ctx, callers[0], "reconstruct-stale-a", leaseTTL); err != nil {
			return err
		}
		if err := gatewayA.Stop(); err != nil {
			return err
		}
		gatewayAStopped = true
		closed, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if !downstreamObservationsEqual(before, closed) {
			return errors.New("reconstructed ingress received an automatic reconnect from the terminated stale Gateway")
		}
		if err := waitForSharedCardinality(ctx, redisClient, capacityNamespace, 0, leaseTTL); err != nil {
			return err
		}
		claim, err := downstreamStaleFenceClaim(oldLease)
		if err != nil {
			return err
		}
		sensitive = append(sensitive, claim.Opaque())
		requiredWindow := time.Duration(locked.Ingress.ActionTimeoutMillis) * time.Millisecond
		if err := downstreamStaleActivationProbe(ctx, gatewayConfigA, identities[0], claim, func() error {
			return restoreDownstreamStaleMember(
				ctx, redisClient, capacityNamespace, oldLease, newLease, leaseTTL, requiredWindow,
			)
		}); err != nil {
			return err
		}
		if err := validateDownstreamStaleMember(
			ctx, redisClient, capacityNamespace, oldLease, newLease, requiredWindow,
		); err != nil {
			return err
		}
		// Server time only advances. A still-valid exact member after rejection
		// excludes the earlier absent, expired, and insufficient-window loss paths.
		after, err := waitForDownstreamObservation(ctx, observationPath, before, "activation", "fence_lost", 1, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(before, after, "upstream_dial", "succeeded", 0); err != nil {
			return err
		}
		highWaterFinal, err := downstreamHighWaterSnapshot(ctx, redisClient, capacityNamespace, identities[0])
		if err != nil || highWaterFinal != highWaterBefore {
			return errors.Join(err, errors.New("stale reconstruction probe changed retained action high-water"))
		}
		return removeSharedLease(ctx, redisClient, capacityNamespace, oldLease.member)
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	cleanupState := downstreamFencingCleanup{}
	if err := runner.run(ctx, locked.Scenarios[11], func(ctx context.Context) error {
		if err := ingressProcess.Stop(); err != nil {
			return err
		}
		ingressStopped = true
		before, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		openCtx, cancel := context.WithTimeout(ctx, downstreamCommandTimeout+time.Second)
		response, requestErr := callers[1].request(openCtx, downstreamcaller.Command{
			Action: downstreamcaller.ActionOpen, ConnectionID: "no-bypass-b", GatewayID: "gateway-b",
			GrantBindingID: identities[1].envelope.GrantBinding.ID, TimeoutMillis: downstreamCommandTimeout.Milliseconds(),
		})
		cancel()
		if requestErr != nil {
			return requestErr
		}
		if response.OK {
			if response.Outcome != downstreamcaller.OutcomeOpened || !response.Upgraded || response.ErrorCode != "" {
				return errors.New("no-bypass probe returned an invalid open response")
			}
			if err := downstreamExpectedClosed(ctx, callers[1], "no-bypass-b", downstreamCommandTimeout); err != nil {
				return err
			}
		} else if response.ErrorCode != downstreamcaller.ErrorNotUpgraded && response.ErrorCode != downstreamcaller.ErrorUpgradeFailed {
			return errors.New("no-bypass probe did not fail closed")
		}
		after, err := downstreamObservationSnapshot(observationPath)
		if err != nil {
			return err
		}
		if !downstreamObservationsEqual(before, after) {
			return errors.New("Gateway reached a private downstream path after ingress shutdown")
		}
		ingressProcess, err = startStack(ingressBinary, providerConfigPath, filepath.Join(logRoot, "provider-ingress-cleanup.log"))
		if err != nil {
			return err
		}
		ingressStopped = false
		if err := waitForListenersWithin(ctx, ingressProcess, browserListenerReadinessTimeout, providerAddress, ingressAddress); err != nil {
			return err
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 10*time.Second)
		for _, process := range callers {
			if err := process.shutdown(shutdownCtx); err != nil {
				shutdownCancel()
				return err
			}
		}
		shutdownCancel()
		callersStopped = true
		cleanupState.CallersStopped = true
		if !gatewayAStopped {
			if err := gatewayA.Stop(); err != nil {
				return err
			}
			gatewayAStopped = true
		}
		if err := gatewayB.Stop(); err != nil {
			return err
		}
		gatewayBStopped = true
		cleanupState.GatewaysStopped = true
		if err := waitForDownstreamHandoffExpiry(ctx, identities); err != nil {
			return err
		}
		if err := ingressProcess.Stop(); err != nil {
			return err
		}
		ingressStopped = true
		cleanupState.ProviderIngressStopped = true
		if err := assertBrowserRuntimeResourcesAbsent(ctx, dockerClient, downstreamFencingNamespace, downstreamFencingController); err != nil {
			return err
		}
		if err := redisClient.Close(); err != nil {
			return err
		}
		redisClosed = true
		valkeyID := valkey.containerID
		if err := valkey.close(ctx); err != nil {
			return err
		}
		valkeyRemoved = true
		if _, err := dockerClient.ContainerInspect(ctx, valkeyID, client.ContainerInspectOptions{}); err == nil {
			return errors.New("owned Valkey container remains after cleanup")
		} else if !cerrdefs.IsNotFound(err) {
			return errors.New("confirm owned Valkey container cleanup")
		}
		cleanupState.ValkeyRemoved = true
		if err := cleanupUplink(ctx); err != nil {
			return err
		}
		uplinkRemoved = true
		if err := cleanupGatewayImage(ctx); err != nil {
			return err
		}
		gatewayImageRemoved = true
		cleanupState.SupportImageRemoved = true
		if err := assertBrowserManagedResourcesAbsent(ctx, dockerClient, downstreamFencingNamespace); err != nil {
			return err
		}
		cleanupState.BrowserResourcesRemoved = true
		return nil
	}); err != nil {
		return DownstreamFencingResult{}, err
	}

	manifest := downstreamFencingManifest{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), EvidenceName: downstreamFencingEvidenceName,
		EvidenceProfile: locked.EvidenceProfile, HarnessCommit: harnessCommit, Sources: locked.Sources,
		Contract: downstreamFencingContractEvidence{
			DownstreamFencingContract: locked.Contract,
			ProviderRoutesExercised: []string{
				"GET /v1/capabilities", "POST /v1/sandboxes", "GET /v1/sandboxes/{sandbox_id}",
				"GET /v1/operations/{operation_id}", "POST /v1/sandboxes/{sandbox_id}/browser/sessions",
				"GET /v1/sandboxes/{sandbox_id}/browser/sessions/{browser_session_id}",
			},
		},
		BrowserImage: downstreamFencingBrowserEvidence{
			Repository: locked.BrowserImage.Repository, IndexDigest: locked.BrowserImage.IndexDigest,
			ImmutableTag: locked.BrowserImage.ImmutableTag, SelectedPlatform: locked.BrowserImage.SelectedPlatform,
			SelectedDigest: locked.BrowserImage.SelectedDigest, LocalImageID: browserInspection.ID,
			RuntimeProfileID: locked.BrowserImage.RuntimeProfileID, SeccompDigest: locked.BrowserImage.SeccompDigest,
			Provenance: locked.BrowserImage.Provenance,
		},
		Valkey: downstreamFencingValkeyEvidence{
			Image: locked.Valkey.Image, IndexDigest: locked.Valkey.IndexDigest,
			SelectedPlatform: locked.Valkey.SelectedPlatform, SelectedDigest: locked.Valkey.SelectedDigest,
			LocalImageID: valkey.imageID, DatabaseIndex: locked.Valkey.DatabaseIndex,
			ServerConfigSHA256: locked.Valkey.ServerConfigSHA256, ACLTemplateSHA256: locked.Valkey.ACLTemplateSHA256,
			ProvenanceNotEstablished: locked.Valkey.ProvenanceNotEstablished,
		},
		CapacityPolicy: locked.CapacityPolicy, RevocationPolicy: locked.RevocationPolicy, Adapters: locked.Adapters,
		PrivateWire: locked.PrivateWire, Topology: locked.Topology, Ingress: locked.Ingress, Transport: locked.Transport,
		BinaryDigests: downstreamFencingBinaryDigests{
			ProviderIngress: ingressBinaryDigest, Gateway: gatewayBinaryDigest, Caller: callerBinaryDigest,
			BrowserEgress: browserGatewayBinaryDigest, Verifier: ghDigest,
		},
		ConfigDigests: downstreamFencingConfigDigests{
			ProviderIngress: providerConfigDigest, Gateways: gatewayConfigDigests,
			CallerBootstraps: callerBootstrapDigests, ProviderBootstraps: providerBootstrapDigests,
			FinalCallers: finalCallerDigests,
		},
		ProcessReconstructions: 2, Reports: []string{"report.json"},
		Audits:       []string{"gateway-audit-a.jsonl", "gateway-audit-b.jsonl"},
		Observations: []string{"ingress-observations.jsonl"},
		Commands: []string{
			"go build ./cmd/downstream-fencing-ingress", "go build ./cmd/downstream-fencing-gateway",
			"go build ./cmd/downstream-fencing-caller", "GOOS=linux GOARCH=<locked> go build ./cmd/browser-egress-gateway",
			"two caller FD 3/4/5 provisioning handshakes", "two caller JSONL control streams",
			"controller-owned mTLS stale-claim activation probe",
		},
		Faults: []string{
			"Gateway A SIGSTOP/SIGCONT after retained-store-time lease expiry",
			"Gateway B SIGSTOP/SIGCONT terminal replacement", "exact active lease removal before a complete action",
			"retained Valkey pause/unpause", "Provider/private-ingress process reconstruction",
			"controlled unique stale exact-member restoration below retained high-water",
			"private-ingress shutdown no-bypass probe",
		},
		Cleanup: cleanupState,
		NonTargets: []string{
			"CDP exactly-once behavior", "transparent replay or reconnect safety", "command-result certainty after disconnect",
			"revocation of an already admitted or executed action", "arbitrary suspension safety for the ingress",
			"downstream grant-revocation fencing", "Valkey provenance", "HA/failover or restored-snapshot consistency",
			"Provider multi-controller reliability", "hostile multi-tenant isolation", "real Agent Platform compatibility",
			"aggregate conformance", "production advertisement", "deployment readiness", "production readiness",
		},
		EvidenceBoundary: "ADR 0033 two-Gateway, two-independent-caller, unique Provider/private-ingress, retained-Valkey, signed-real-Chromium downstream action-fencing external-caller E2E only",
	}

	if err := runner.run(ctx, locked.Scenarios[12], func(context.Context) error {
		if err := copyDownstreamEvidence(stateRoot, evidenceDirectory); err != nil {
			return err
		}
		provisional := runner.report
		provisional.Scenarios = append(append([]downstreamFencingScenario(nil), provisional.Scenarios...), downstreamFencingScenario{
			Name: locked.Scenarios[12], Status: "pending", DurationMillis: 0,
		})
		if _, err := writeJSON(filepath.Join(evidenceDirectory, "report.json"), provisional); err != nil {
			return err
		}
		manifest.Sanitization = downstreamFencingSanitization{}
		if _, err := writeJSON(filepath.Join(evidenceDirectory, "manifest.json"), manifest); err != nil {
			return err
		}
		if err := assertDownstreamExactFiles(evidenceDirectory, downstreamEvidenceFiles); err != nil {
			return err
		}
		observations, err := readDownstreamObservations(filepath.Join(evidenceDirectory, "ingress-observations.jsonl"), false)
		if err != nil || len(observations) == 0 {
			return errors.Join(err, errors.New("sanitized downstream-fencing observations are unavailable"))
		}
		for _, name := range []string{"gateway-audit-a.jsonl", "gateway-audit-b.jsonl"} {
			records, err := readDownstreamGatewayAudit(filepath.Join(evidenceDirectory, name))
			if err != nil || len(records) == 0 {
				return errors.Join(err, errors.New("sanitized downstream-fencing Gateway audit is unavailable"))
			}
		}
		if err := assertEvidenceExcludes(evidenceDirectory, sensitive); err != nil {
			return err
		}
		manifest.Sanitization = downstreamFencingSanitization{
			ExactFileSet: true, PrivateMaterialScan: true, AuditRecordsValidated: true,
		}
		if err := validateDownstreamManifest(manifest); err != nil {
			return err
		}
		_, err = writeJSON(filepath.Join(evidenceDirectory, "manifest.json"), manifest)
		return err
	}); err != nil {
		return DownstreamFencingResult{}, err
	}
	if _, err := writeJSON(filepath.Join(evidenceDirectory, "report.json"), runner.report); err != nil {
		return DownstreamFencingResult{}, err
	}
	if err := validateDownstreamReport(runner.report, locked.Scenarios); err != nil {
		return DownstreamFencingResult{}, err
	}
	if err := assertDownstreamExactFiles(evidenceDirectory, downstreamEvidenceFiles); err != nil {
		return DownstreamFencingResult{}, err
	}
	if err := assertEvidenceExcludes(evidenceDirectory, sensitive); err != nil {
		return DownstreamFencingResult{}, err
	}
	return DownstreamFencingResult{EvidenceDirectory: evidenceDirectory, Scenarios: len(runner.report.Scenarios), Platform: platform}, nil
}

func downstreamAuthoritySecrets() (string, string, string, error) {
	capacityToken, err := randomSecret("")
	if err != nil {
		return "", "", "", err
	}
	revocationToken, err := randomSecret("")
	if err != nil {
		return "", "", "", err
	}
	password, err := randomSecret("")
	if err != nil {
		return "", "", "", err
	}
	return "downstream-capacity-" + capacityToken[:24], "downstream-revocation-" + revocationToken[:24], password, nil
}

func waitForDownstreamHandoffExpiry(ctx context.Context, identities []downstreamFencingIdentity) error {
	if len(identities) != 2 {
		return errors.New("downstream-fencing Provider handoff set is invalid")
	}
	var latest time.Time
	for _, identity := range identities {
		expiresAt, err := time.Parse(time.RFC3339Nano, identity.envelope.HandoffExpiresAt)
		if err != nil || expiresAt.IsZero() || identity.envelope.HandoffExpiresAt != expiresAt.UTC().Format(time.RFC3339Nano) {
			return errors.New("downstream-fencing Provider handoff expiry is invalid")
		}
		if expiresAt.After(latest) {
			latest = expiresAt
		}
	}
	wait := time.Until(latest.Add(100 * time.Millisecond))
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func downstreamHighWaterSnapshot(
	ctx context.Context,
	client *goredis.Client,
	namespace string,
	identity downstreamFencingIdentity,
) (string, error) {
	if ctx == nil || client == nil {
		return "", errors.New("retained action high-water authority is unavailable")
	}
	key, err := downstreamHighWaterKey(namespace, identity)
	if err != nil {
		return "", err
	}
	operationCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	value, err := client.Get(operationCtx, key).Bytes()
	if err != nil || len(value) == 0 || len(value) > downstreamRecordMaximum {
		return "", errors.New("retained action high-water is unavailable")
	}
	ttl, err := client.PTTL(operationCtx, key).Result()
	if err != nil || ttl <= 0 {
		return "", errors.New("retained action high-water expiry is unavailable")
	}
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:]), nil
}

func downstreamHighWaterKey(namespace string, identity downstreamFencingIdentity) (string, error) {
	endpoint := identity.envelope.Endpoint
	if namespace == "" || endpoint.TenantID == "" || endpoint.SandboxID == "" || endpoint.BrowserSessionID == "" {
		return "", errors.New("retained action high-water subject is invalid")
	}
	namespaceDigest := sha256.Sum256([]byte(namespace))
	sessionDigest := downstreamDigestParts(endpoint.TenantID, endpoint.SandboxID, "browser", endpoint.BrowserSessionID)
	return "sandbox-runtime:{" + hex.EncodeToString(namespaceDigest[:]) + "}:capacity:action-fence:high-water:" + sessionDigest, nil
}

func downstreamDigestParts(parts ...string) string {
	hash := sha256.New()
	var length [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func downstreamProviderConfig(
	providerAddress, ingressAddress, stateRoot, runRoot, providerRoot, browserReference, browserGatewayImage, uplinkName,
	architecture, provenancePath, provenanceDigest, redisURL, capacityNamespace string,
	locked lock.DownstreamFencingLock,
	material testenv.Material,
	observationPath string,
) downstreamstack.Config {
	return downstreamstack.Config{
		Provider: basestack.BrowserProviderConfig{
			ProviderAddress: providerAddress, ProviderCertificateFile: material.ProviderCertificateFile,
			ProviderPrivateKeyFile: material.ProviderPrivateKeyFile, ClientCAFile: material.CAFile,
			AllowedClientURIs: []string{material.ControllerA.URI, material.ControllerB.URI},
			TrustedJWSKeys: []basestack.TrustedJWSKey{
				{ID: material.ControllerA.JWSKeyID, Algorithm: "EdDSA", Path: material.ControllerA.JWSPublicFile},
				{ID: material.ControllerB.JWSKeyID, Algorithm: "EdDSA", Path: material.ControllerB.JWSPublicFile},
			},
			ProviderRevisionID: "provider-revision-downstream-fencing-e2e-v1",
			StateRoot:          filepath.Join(stateRoot, "provider"), RuntimeDataRoot: filepath.Join(runRoot, "browser-runtime"),
			RuntimeImage: browserReference, RuntimeControllerID: downstreamFencingController,
			Browser: &basestack.BrowserConfig{
				GatewayImage: browserGatewayImage, UplinkNetwork: uplinkName, Namespace: downstreamFencingNamespace,
				RuntimeArchitecture:      architecture,
				ManifestPath:             filepath.Join(providerRoot, "profiles/browser/image/manifest.json"),
				SeccompPath:              filepath.Join(providerRoot, "profiles/browser/image/chromium-seccomp.json"),
				ProvenanceExecutablePath: provenancePath, ProvenanceExecutableDigest: provenanceDigest,
				NetworkPolicyReference: "browser-egress-policy-1", AllowedHosts: []string{"example.com"},
			},
		},
		Ingress: downstreamstack.IngressConfig{
			Address: ingressAddress, ServerCertificateFile: material.IngressCertificateFile,
			ServerPrivateKeyFile: material.IngressPrivateKeyFile, ClientCAFile: material.CAFile,
			AllowedGatewayURIs:      append([]string(nil), locked.PrivateWire.GatewayURIIdentities...),
			ResolveTimeoutMillis:    locked.Transport.ServerResolveTotalTimeoutMillis,
			ActivationTimeoutMillis: locked.Transport.ServerActivationIOTimeoutMillis,
			ActionTimeoutMillis:     locked.Ingress.ActionTimeoutMillis, CloseTimeoutMillis: locked.Ingress.CloseTimeoutMillis,
			MaxSessions: locked.Ingress.MaxSessions, MaxActionBytes: locked.Ingress.MaxActionBytes,
			MaxConnections: locked.Ingress.MaxConnections, ReadHeaderTimeoutMillis: locked.Ingress.ReadHeaderTimeoutMillis,
			ReadTimeoutMillis: locked.Ingress.ReadTimeoutMillis, WriteTimeoutMillis: locked.Ingress.WriteTimeoutMillis,
			IdleTimeoutMillis: locked.Ingress.IdleTimeoutMillis, MaxHeaderBytes: locked.Ingress.MaxHeaderBytes,
		},
		Authority: downstreamstack.AuthorityConfig{
			RedisURL: redisURL, CapacityNamespace: capacityNamespace,
			CapacityPolicy: downstreamstack.CapacityPolicy{
				MaxTotal: locked.CapacityPolicy.MaxTotal, MaxPerTenant: locked.CapacityPolicy.MaxPerTenant,
				MaxPerSession:             locked.CapacityPolicy.MaxPerSession,
				LeaseTTLMillis:            locked.CapacityPolicy.LeaseTTLMillis,
				RenewIntervalMillis:       locked.CapacityPolicy.RenewIntervalMillis,
				RenewalSafetyMarginMillis: locked.CapacityPolicy.RenewalSafetyMarginMillis,
				OperationTimeoutMillis:    locked.CapacityPolicy.OperationTimeoutMillis,
			},
		},
		ObservationFile: observationPath,
	}
}

func downstreamIdentities(
	material testenv.Material,
	gatewayURLs map[string]string,
	providerURL, providerRevisionID, providerAudience, imageReference, imageDigest, architecture string,
) ([]downstreamFencingIdentity, []string, error) {
	controllers := []testenv.Identity{material.ControllerA, material.ControllerB}
	identities := make([]downstreamFencingIdentity, 2)
	sensitive := make([]string, 0, 64)
	for index, controller := range controllers {
		name := string(rune('a' + index))
		token, err := randomSecret("")
		if err != nil {
			return nil, nil, err
		}
		nonce, err := randomSecret("")
		if err != nil {
			return nil, nil, err
		}
		short := nonce[:20]
		principal := downstreamcaller.Principal{
			ID: "principal-" + name, Token: token, CallerID: "downstream-caller-" + name + "-" + short,
			TenantID: "downstream-tenant-" + name + "-" + short,
		}
		endpoint := downstreamcaller.BootstrapEndpointTemplate{
			ID: "endpoint-" + name, TenantID: principal.TenantID,
			SandboxID:           "downstream-sandbox-" + name + "-" + short,
			BrowserSessionID:    "downstream-browser-" + name + "-" + short,
			CapabilityProfileID: "browser-v1",
		}
		grant := downstreamcaller.BootstrapGrantBinding{
			ID: "binding-" + name, GrantID: "downstream-grant-" + name + "-" + short,
			PrincipalID: principal.ID, EndpointID: endpoint.ID, LifetimeMillis: int64((3 * time.Minute) / time.Millisecond),
		}
		provider := providercaller.BrowserBootstrapConfig{
			ProviderBaseURL: providerURL, CAFile: material.CAFile,
			ProviderRevisionID: providerRevisionID, ProviderInstanceAudience: providerAudience,
			RuntimeImageReference: imageReference, RuntimeImageDigest: imageDigest, RuntimeArchitecture: architecture,
			Controller: providercaller.BrowserBootstrapController{
				ControllerSubject: controller.URI, CertificateFile: controller.CertificateFile,
				PrivateKeyFile: controller.PrivateKeyFile, JWSPrivateKeyFile: controller.JWSPrivateFile,
				JWSKeyID: controller.JWSKeyID,
			},
			TenantID: principal.TenantID, WorkOrderID: "downstream-work-order-" + name + "-" + short,
			SandboxID: endpoint.SandboxID, WorkspaceID: "downstream-workspace-" + name + "-" + short,
			WorkspaceRevisionID:     "downstream-workspace-revision-" + name + "-" + short,
			WorkspaceRevisionDigest: "sha256:" + strings.Repeat(string('a'+rune(index)), 64),
			BranchID:                "downstream-branch-" + name + "-" + short,
			ProviderResolutionID:    "downstream-resolution-" + name + "-" + short,
			NetworkPolicyReference:  "browser-egress-policy-1",
			CreateOperationID:       "downstream-create-operation-" + name + "-" + short,
			CreateAttemptID:         "downstream-create-attempt-" + name + "-" + short,
			CreateFencingToken:      int64(11 + index*10), CreateIdempotencyKey: "downstream-create-key-" + name + "-" + short,
			OpenOperationID:  "downstream-open-operation-" + name + "-" + short,
			OpenAttemptID:    "downstream-open-attempt-" + name + "-" + short,
			OpenFencingToken: int64(12 + index*10), OpenIdempotencyKey: "downstream-open-key-" + name + "-" + short,
			BrowserSessionID: endpoint.BrowserSessionID, PollTimeoutMillis: int64((5 * time.Minute) / time.Millisecond),
		}
		requestID := "provision-" + name + "-" + short
		bootstrap := downstreamcaller.BootstrapCallerConfig{
			CAFile:    material.CAFile,
			Gateways:  map[string]string{"gateway-a": gatewayURLs["gateway-a"], "gateway-b": gatewayURLs["gateway-b"]},
			Principal: principal, Endpoint: endpoint, GrantBinding: grant,
		}
		identities[index] = downstreamFencingIdentity{
			name: name, controller: controller, principal: principal, endpointTemplate: endpoint, grantTemplate: grant,
			providerBootstrap: provider, bootstrapConfig: bootstrap,
			request: provisioning.Request{
				Version: provisioning.ProtocolVersion, RequestID: requestID, ControllerSubject: controller.URI,
				TenantID: endpoint.TenantID, SandboxID: endpoint.SandboxID,
				BrowserSessionID: endpoint.BrowserSessionID, CapabilityProfileID: endpoint.CapabilityProfileID,
			},
		}
		sensitive = append(sensitive,
			token, nonce, principal.CallerID, principal.TenantID, endpoint.SandboxID, endpoint.BrowserSessionID,
			grant.GrantID, provider.WorkOrderID, provider.WorkspaceID, provider.WorkspaceRevisionID,
			provider.BranchID, provider.ProviderResolutionID, provider.CreateOperationID, provider.CreateAttemptID,
			provider.CreateIdempotencyKey, provider.OpenOperationID, provider.OpenAttemptID, provider.OpenIdempotencyKey,
			requestID,
		)
	}
	return identities, sensitive, nil
}

func downstreamIdentityPrivateValues(identity downstreamFencingIdentity) []string {
	envelope := identity.envelope
	return []string{
		envelope.Endpoint.ID, envelope.Endpoint.TenantID, envelope.Endpoint.SandboxID,
		envelope.Endpoint.BrowserSessionID, envelope.Endpoint.HandoffReference,
		envelope.GrantBinding.ID, envelope.GrantBinding.GrantID, envelope.GrantBinding.PrincipalID,
		envelope.GrantBinding.EndpointID, envelope.GrantBinding.ExpiresAt, envelope.HandoffExpiresAt,
	}
}

func downstreamGatewayBindings(identities []downstreamFencingIdentity) (
	[]gatewaystack.Principal,
	[]gatewaystack.Endpoint,
	[]gatewaystack.GrantBinding,
) {
	principals := make([]gatewaystack.Principal, 0, len(identities))
	endpoints := make([]gatewaystack.Endpoint, 0, len(identities))
	bindings := make([]gatewaystack.GrantBinding, 0, len(identities))
	for _, identity := range identities {
		envelope := identity.envelope
		principals = append(principals, gatewaystack.Principal{
			ID: identity.principal.ID, Token: identity.principal.Token,
			CallerID: identity.principal.CallerID, TenantID: identity.principal.TenantID,
		})
		endpoints = append(endpoints, gatewaystack.Endpoint{
			ID: envelope.Endpoint.ID, TenantID: envelope.Endpoint.TenantID, SandboxID: envelope.Endpoint.SandboxID,
			BrowserSessionID:     envelope.Endpoint.BrowserSessionID,
			CapabilityProfileID:  envelope.Endpoint.CapabilityProfileID,
			HandoffReference:     envelope.Endpoint.HandoffReference,
			ConnectionGeneration: envelope.Endpoint.ConnectionGeneration,
		})
		bindings = append(bindings, gatewaystack.GrantBinding{
			ID: envelope.GrantBinding.ID, GrantID: envelope.GrantBinding.GrantID,
			PrincipalID: envelope.GrantBinding.PrincipalID, EndpointID: envelope.GrantBinding.EndpointID,
			ExpiresAt: envelope.GrantBinding.ExpiresAt,
		})
	}
	return principals, endpoints, bindings
}

func downstreamGatewayConfig(
	gatewayID, address, ingressAddress, capacityNamespace, revocationNamespace, redisURL, auditPath string,
	privateIdentity testenv.TLSIdentity,
	locked lock.DownstreamFencingLock,
	material testenv.Material,
	principals []gatewaystack.Principal,
	endpoints []gatewaystack.Endpoint,
	bindings []gatewaystack.GrantBinding,
) gatewaystack.Config {
	return gatewaystack.Config{
		GatewayID: gatewayID, Address: address,
		ServerCertificateFile: material.GatewayCertificateFile,
		ServerPrivateKeyFile:  material.GatewayPrivateKeyFile, AuditFile: auditPath,
		Authority: gatewaystack.AuthorityConfig{
			RedisURL: redisURL, CapacityNamespace: capacityNamespace, RevocationNamespace: revocationNamespace,
			CapacityPolicy: gatewaystack.CapacityPolicy{
				MaxTotal: locked.CapacityPolicy.MaxTotal, MaxPerTenant: locked.CapacityPolicy.MaxPerTenant,
				MaxPerSession:             locked.CapacityPolicy.MaxPerSession,
				LeaseTTLMillis:            locked.CapacityPolicy.LeaseTTLMillis,
				RenewIntervalMillis:       locked.CapacityPolicy.RenewIntervalMillis,
				RenewalSafetyMarginMillis: locked.CapacityPolicy.RenewalSafetyMarginMillis,
				OperationTimeoutMillis:    locked.CapacityPolicy.OperationTimeoutMillis,
			},
			RevocationPolicy: gatewaystack.RevocationPolicy{
				MaxGrantLifetimeMillis: locked.RevocationPolicy.MaxGrantLifetimeMillis,
				PollIntervalMillis:     locked.RevocationPolicy.PollIntervalMillis,
				OperationTimeoutMillis: locked.RevocationPolicy.OperationTimeoutMillis,
			},
		},
		PrivateIngress: gatewaystack.PrivateIngressConfig{
			Address: ingressAddress, ServerName: "localhost",
			ClientCertificateFile: privateIdentity.CertificateFile,
			ClientPrivateKeyFile:  privateIdentity.PrivateKeyFile, ServerCAFile: material.CAFile,
			GatewayRoleURI:            privateIdentity.URI,
			ResolveTimeoutMillis:      locked.Transport.ClientResolveTimeoutMillis,
			ConnectAndIOTimeoutMillis: locked.Transport.ClientConnectAndIOTimeoutMillis,
			MaxMessageBytes:           locked.PrivateWire.ActionMaxBytes,
		},
		Principals:    append([]gatewaystack.Principal(nil), principals...),
		Endpoints:     append([]gatewaystack.Endpoint(nil), endpoints...),
		GrantBindings: append([]gatewaystack.GrantBinding(nil), bindings...),
	}
}

func downstreamFinalCallerConfig(identity downstreamFencingIdentity) downstreamcaller.Config {
	envelope := identity.envelope
	return downstreamcaller.Config{
		CAFile: identity.bootstrapConfig.CAFile,
		Gateways: map[string]string{
			"gateway-a": identity.bootstrapConfig.Gateways["gateway-a"],
			"gateway-b": identity.bootstrapConfig.Gateways["gateway-b"],
		},
		Principals: []downstreamcaller.Principal{identity.principal},
		Endpoints: []downstreamcaller.Endpoint{{
			ID: envelope.Endpoint.ID, TenantID: envelope.Endpoint.TenantID,
			SandboxID: envelope.Endpoint.SandboxID, BrowserSessionID: envelope.Endpoint.BrowserSessionID,
			CapabilityProfileID:  envelope.Endpoint.CapabilityProfileID,
			HandoffReference:     envelope.Endpoint.HandoffReference,
			ConnectionGeneration: envelope.Endpoint.ConnectionGeneration,
		}},
		GrantBindings: []downstreamcaller.GrantBinding{{
			ID: envelope.GrantBinding.ID, GrantID: envelope.GrantBinding.GrantID,
			PrincipalID: envelope.GrantBinding.PrincipalID, EndpointID: envelope.GrantBinding.EndpointID,
			ExpiresAt: envelope.GrantBinding.ExpiresAt,
		}},
	}
}

func downstreamAuthorityACL(password, capacityNamespace, revocationNamespace string) string {
	capacityDigest := sha256.Sum256([]byte(capacityNamespace))
	revocationDigest := sha256.Sum256([]byte(revocationNamespace))
	result := strings.ReplaceAll(lock.DownstreamFencingACLTemplate, "${PASSWORD}", password)
	result = strings.ReplaceAll(result, "${CAPACITY_NAMESPACE_SHA256}", hex.EncodeToString(capacityDigest[:]))
	return strings.ReplaceAll(result, "${REVOCATION_NAMESPACE_SHA256}", hex.EncodeToString(revocationDigest[:]))
}

func provisionDownstreamAuthorities(
	ctx context.Context,
	redisClient *goredis.Client,
	capacityNamespace, revocationNamespace string,
	locked lock.DownstreamFencingLock,
) error {
	capacity, err := sharedCapacityFromLock(redisClient, capacityNamespace, locked.CapacityPolicy)
	if err != nil {
		return err
	}
	fencer, err := rediscapacity.NewActionFencer(capacity)
	if err != nil {
		return err
	}
	revocations, err := durableRevocationFromLock(redisClient, revocationNamespace, locked.RevocationPolicy)
	if err != nil {
		return err
	}
	provisionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := capacity.Provision(provisionCtx); err != nil {
		return errors.New("provision downstream-fencing capacity authority")
	}
	if err := fencer.Provision(provisionCtx); err != nil {
		return errors.New("provision downstream-fencing action authority")
	}
	if err := revocations.Provision(provisionCtx); err != nil {
		return errors.New("provision downstream-fencing revocation authority")
	}
	if err := capacity.Verify(provisionCtx); err != nil {
		return errors.New("verify downstream-fencing capacity authority")
	}
	if err := fencer.Verify(provisionCtx); err != nil {
		return errors.New("verify downstream-fencing action authority")
	}
	if err := revocations.Verify(provisionCtx); err != nil {
		return errors.New("verify downstream-fencing revocation authority")
	}
	return nil
}

func allocateDistinctAddresses(count int) ([]string, error) {
	if count < 1 || count > 16 {
		return nil, errors.New("invalid downstream-fencing listener count")
	}
	result := make([]string, 0, count)
	seen := map[string]bool{}
	for len(result) < count {
		address, err := allocateAddress()
		if err != nil {
			return nil, err
		}
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	return result, nil
}

func downstreamJSONDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func downstreamCallerReady(ctx context.Context, process *downstreamCallerProcess) error {
	requestCtx, cancel := context.WithTimeout(ctx, downstreamCommandTimeout)
	defer cancel()
	response, err := process.request(requestCtx, downstreamcaller.Command{
		Action: downstreamcaller.ActionReadCDP, ConnectionID: "readiness-probe", TimeoutMillis: 100,
	})
	if err != nil || response.OK || response.ErrorCode != downstreamcaller.ErrorConnectionNotFound || response.Outcome != "" {
		return errors.New("downstream-fencing caller did not acknowledge its correlated final configuration")
	}
	return nil
}

func downstreamObservationSnapshot(path string) (downstreamObservations, error) {
	return readDownstreamObservations(path, true)
}

func readDownstreamObservations(path string, allowMissing bool) (downstreamObservations, error) {
	contents, err := readDownstreamEvidenceFile(path, allowMissing)
	if err != nil || contents == nil {
		return nil, err
	}
	if len(contents) == 0 {
		return downstreamObservations{}, nil
	}
	if contents[len(contents)-1] != '\n' {
		return nil, errors.New("private ingress observation file has a partial record")
	}
	lines := bytes.Split(contents[:len(contents)-1], []byte{'\n'})
	result := make(downstreamObservations, 0, len(lines))
	var last uint64
	for _, line := range lines {
		if len(line) == 0 || len(line)+1 > downstreamRecordMaximum {
			return nil, errors.New("private ingress observation record is invalid")
		}
		record, err := decodeDownstreamObservation(line)
		if err != nil || record.Sequence != last+1 {
			return nil, errors.New("private ingress observation sequence is invalid")
		}
		result = append(result, record)
		last = record.Sequence
	}
	return result, nil
}

func decodeDownstreamObservation(line []byte) (downstreamFencingObservation, error) {
	if err := validateDownstreamUniqueJSONFields(line); err != nil {
		return downstreamFencingObservation{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(line, &fields); err != nil || len(fields) != 6 {
		return downstreamFencingObservation{}, errors.New("private ingress observation fields are invalid")
	}
	for _, name := range []string{"sequence", "type", "timestamp", "result", "message_type", "bytes"} {
		if _, ok := fields[name]; !ok {
			return downstreamFencingObservation{}, errors.New("private ingress observation fields are invalid")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var record downstreamFencingObservation
	if err := decoder.Decode(&record); err != nil {
		return downstreamFencingObservation{}, errors.New("private ingress observation is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return downstreamFencingObservation{}, errors.New("private ingress observation has trailing input")
	}
	at, err := time.Parse(time.RFC3339Nano, record.Timestamp)
	if err != nil || at.IsZero() || record.Timestamp != at.UTC().Format(time.RFC3339Nano) {
		return downstreamFencingObservation{}, errors.New("private ingress observation timestamp is invalid")
	}
	if err := downstreamtransport.ValidateObservation(downstreamtransport.Observation{
		Type: record.Type, Result: record.Result, MessageType: record.MessageType, Bytes: record.Bytes,
	}); err != nil {
		return downstreamFencingObservation{}, err
	}
	return record, nil
}

func readDownstreamGatewayAudit(path string) ([]downstreamGatewayAudit, error) {
	contents, err := readDownstreamEvidenceFile(path, false)
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		return nil, errors.New("Gateway audit is empty or has a partial record")
	}
	lines := bytes.Split(contents[:len(contents)-1], []byte{'\n'})
	records := make([]downstreamGatewayAudit, 0, len(lines))
	var last uint64
	for _, line := range lines {
		if len(line) == 0 || len(line)+1 > downstreamRecordMaximum || validateDownstreamUniqueJSONFields(line) != nil {
			return nil, errors.New("Gateway audit record is invalid")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(line, &fields); err != nil || len(fields) != 7 {
			return nil, errors.New("Gateway audit fields are invalid")
		}
		for _, name := range []string{"sequence", "type", "timestamp", "attempt", "frames", "bytes", "reason_code"} {
			if _, ok := fields[name]; !ok {
				return nil, errors.New("Gateway audit fields are invalid")
			}
		}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		var record downstreamGatewayAudit
		if err := decoder.Decode(&record); err != nil || record.Sequence != last+1 || record.Attempt < 0 || record.Attempt > 3 ||
			downstreamGatewayAuditReason(record.Type) != record.ReasonCode {
			return nil, errors.New("Gateway audit record is invalid")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("Gateway audit has trailing input")
		}
		at, err := time.Parse(time.RFC3339Nano, record.Timestamp)
		if err != nil || at.IsZero() || record.Timestamp != at.UTC().Format(time.RFC3339Nano) {
			return nil, errors.New("Gateway audit timestamp is invalid")
		}
		records = append(records, record)
		last = record.Sequence
	}
	return records, nil
}

func downstreamGatewayAuditReason(kind string) string {
	switch kind {
	case "authorized", "denied", "connected", "reconnected", "backend_closed", "revoked", "expired", "client_closed",
		"reconnect_failed", "capacity_rejected", "capacity_unavailable", "capacity_lost", "capacity_release_failed",
		"revocation_unavailable", "downstream_fence_lost":
		return kind
	case "downstream_unavailable":
		return "downstream_fence_unavailable"
	default:
		return ""
	}
}

func validateDownstreamUniqueJSONFields(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := validateDownstreamUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing input")
	}
	return nil
}

func validateDownstreamUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("JSON object key is duplicated")
			}
			seen[key] = struct{}{}
			if err := validateDownstreamUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := validateDownstreamUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("JSON array is incomplete")
		}
	default:
		return errors.New("JSON delimiter is invalid")
	}
	return nil
}

func downstreamObservationDelta(
	before, after downstreamObservations,
	kind downstreamtransport.ObservationType,
	result downstreamtransport.ObservationResult,
) int {
	count := func(records downstreamObservations) int {
		var found int
		for _, record := range records {
			if record.Type == kind && record.Result == result {
				found++
			}
		}
		return found
	}
	return count(after) - count(before)
}

func waitForDownstreamObservation(
	ctx context.Context,
	path string,
	before downstreamObservations,
	kind downstreamtransport.ObservationType,
	result downstreamtransport.ObservationResult,
	want int,
	timeout time.Duration,
) (downstreamObservations, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	delta := 0
	for {
		after, err := downstreamObservationSnapshot(path)
		if err != nil && !errors.Is(err, errDownstreamEvidenceChanged) {
			return nil, err
		}
		if err == nil {
			delta = downstreamObservationDelta(before, after, kind, result)
			if delta == want {
				return after, nil
			}
			if delta > want {
				return nil, fmt.Errorf("private ingress %s:%s delta = %d, want %d", kind, result, delta, want)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("private ingress %s:%s delta = %d, want %d", kind, result, delta, want)
		case <-ticker.C:
		}
	}
}

func assertDownstreamExactFiles(root string, names []string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	got := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("downstream-fencing evidence contains a non-regular entry")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errors.New("downstream-fencing evidence contains an unsafe file")
		}
		got = append(got, entry.Name())
	}
	want := append([]string(nil), names...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		return fmt.Errorf("downstream-fencing evidence file count = %d, want %d", len(got), len(want))
	}
	for index := range got {
		if got[index] != want[index] {
			return errors.New("downstream-fencing evidence file set differs from the locked profile")
		}
	}
	return nil
}

func validateDownstreamReport(report downstreamFencingReport, names []string) error {
	if report.EvidenceName != downstreamFencingEvidenceName || report.EvidenceProfile != lock.DownstreamFencingProfile ||
		len(report.Scenarios) != len(names) {
		return errors.New("downstream-fencing report identity or scenario count is invalid")
	}
	for index, name := range names {
		if report.Scenarios[index].Name != name || report.Scenarios[index].Status != "passed" ||
			report.Scenarios[index].DurationMillis < 0 {
			return fmt.Errorf("downstream-fencing scenario %d is not an ordered pass", index+1)
		}
	}
	return nil
}

func validateDownstreamManifest(manifest downstreamFencingManifest) error {
	if manifest.EvidenceName != downstreamFencingEvidenceName || manifest.EvidenceProfile != lock.DownstreamFencingProfile ||
		manifest.Contract.SuiteExercised || manifest.Contract.ContractMetadataOnly ||
		len(manifest.Contract.ProviderRoutesExercised) == 0 || manifest.ProcessReconstructions != 2 ||
		!manifest.Sanitization.ExactFileSet || !manifest.Sanitization.PrivateMaterialScan || !manifest.Sanitization.AuditRecordsValidated ||
		!manifest.Cleanup.CallersStopped || !manifest.Cleanup.GatewaysStopped || !manifest.Cleanup.ProviderIngressStopped ||
		!manifest.Cleanup.ValkeyRemoved || !manifest.Cleanup.BrowserResourcesRemoved || !manifest.Cleanup.SupportImageRemoved {
		return errors.New("downstream-fencing manifest identity or evidence boundary is invalid")
	}
	if len(manifest.Reports) != 1 || manifest.Reports[0] != "report.json" ||
		len(manifest.Audits) != 2 || manifest.Audits[0] != "gateway-audit-a.jsonl" || manifest.Audits[1] != "gateway-audit-b.jsonl" ||
		len(manifest.Observations) != 1 || manifest.Observations[0] != "ingress-observations.jsonl" {
		return errors.New("downstream-fencing manifest evidence files are invalid")
	}
	requiredNonTargets := []string{
		"aggregate conformance", "Provider multi-controller reliability", "hostile multi-tenant isolation",
		"real Agent Platform compatibility", "deployment readiness", "production readiness",
	}
	for _, required := range requiredNonTargets {
		found := false
		for _, actual := range manifest.NonTargets {
			if actual == required {
				found = true
				break
			}
		}
		if !found {
			return errors.New("downstream-fencing manifest omits a required non-target")
		}
	}
	return nil
}

func downstreamBase64(payload []byte) string { return base64.StdEncoding.EncodeToString(payload) }

func downstreamExpectedClosed(ctx context.Context, process *downstreamCallerProcess, connection string, timeout time.Duration) error {
	requestCtx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	response, err := process.request(requestCtx, downstreamcaller.Command{
		Action: downstreamcaller.ActionExpectClosed, ConnectionID: connection, TimeoutMillis: timeout.Milliseconds(),
	})
	if err != nil || !response.OK || response.Outcome != downstreamcaller.OutcomeClosed || response.ErrorCode != "" ||
		(response.CloseCode != int(websocket.StatusNormalClosure) && response.CloseCode != int(websocket.StatusPolicyViolation) &&
			response.CloseCode != int(websocket.StatusInternalError) && response.CloseCode != int(websocket.StatusAbnormalClosure)) {
		return errors.New("downstream-fencing connection did not close with a bounded WebSocket status")
	}
	return nil
}

func downstreamStaleActivationProbe(
	ctx context.Context,
	config gatewaystack.Config,
	identity downstreamFencingIdentity,
	claim gateway.DownstreamFence,
	beforeDial func() error,
) error {
	if ctx == nil || claim.Validate() != nil || beforeDial == nil {
		return errors.New("stale downstream-fence probe input is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, identity.envelope.GrantBinding.ExpiresAt)
	if err != nil || expiresAt.IsZero() || identity.envelope.GrantBinding.ExpiresAt != expiresAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("stale downstream-fence probe expiry is invalid")
	}
	subject := gateway.DownstreamFenceSubject{
		TenantID: identity.envelope.Endpoint.TenantID, SandboxID: identity.envelope.Endpoint.SandboxID,
		BrowserSessionID:     identity.envelope.Endpoint.BrowserSessionID,
		CapabilityProfileID:  identity.envelope.Endpoint.CapabilityProfileID,
		ConnectionGeneration: identity.envelope.Endpoint.ConnectionGeneration, ExpiresAt: expiresAt.UTC(),
	}
	if subject.Validate() != nil {
		return errors.New("construct stale downstream-fence probe")
	}
	resolver, err := gatewaystack.NewPrivateResolver(config)
	if err != nil {
		return err
	}
	defer resolver.CloseIdleConnections()
	endpoint, err := resolver.ResolveFenced(ctx, identity.envelope.Endpoint.HandoffReference, subject, claim)
	if err != nil {
		return errors.New("resolve stale downstream-fence probe")
	}
	if err := beforeDial(); err != nil {
		return err
	}
	stream, err := endpoint.Dial(ctx)
	if stream != nil {
		_ = stream.Close()
		return errors.New("stale downstream-fence probe reached a private upstream")
	}
	if !errors.Is(err, gateway.ErrDownstreamFenceLost) {
		return errors.New("stale downstream-fence probe was not rejected as fence loss")
	}
	return nil
}

func downstreamStaleFenceClaim(lease sharedLeaseRecord) (gateway.DownstreamFence, error) {
	if lease.member == "" || lease.fence == 0 {
		return gateway.DownstreamFence{}, errors.New("stale downstream-fence lease is invalid")
	}
	claim, err := gateway.NewDownstreamFence("v1." + base64.RawURLEncoding.EncodeToString([]byte(lease.member)))
	if err != nil {
		return gateway.DownstreamFence{}, errors.New("construct stale downstream-fence claim")
	}
	return claim, nil
}

func restoreDownstreamStaleMember(
	ctx context.Context,
	client *goredis.Client,
	namespace string,
	stale, retained sharedLeaseRecord,
	leaseTTL, requiredWindow time.Duration,
) error {
	if ctx == nil || client == nil || namespace == "" || stale.member == "" || stale.fence == 0 ||
		retained.fence <= stale.fence || leaseTTL <= requiredWindow || requiredWindow < gateway.MinDownstreamActionWindow {
		return errors.New("controlled stale-member restoration input is invalid")
	}
	parts := strings.Split(stale.member, ":")
	if len(parts) != 5 {
		return errors.New("controlled stale member is malformed")
	}
	boundExpiry, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil || boundExpiry < 1 {
		return errors.New("controlled stale member expiry is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	score, err := restoreDownstreamStaleMemberScript.Run(
		operationCtx, client,
		[]string{sharedCapacityLeaseKey(namespace), downstreamCapacityFenceKey(namespace)},
		stale.member, stale.fence, retained.fence, leaseTTL.Milliseconds(), boundExpiry, requiredWindow.Milliseconds(),
	).Int64()
	if err != nil || score < 1 {
		return errors.Join(err, errors.New("restore controlled stale exact member"))
	}
	restored, err := singleSharedLease(operationCtx, client, namespace)
	if err != nil || restored.member != stale.member || restored.fence != stale.fence || restored.score != score {
		return errors.Join(err, errors.New("controlled stale exact member was not restored uniquely"))
	}
	return nil
}

func validateDownstreamStaleMember(
	ctx context.Context,
	client *goredis.Client,
	namespace string,
	stale, retained sharedLeaseRecord,
	requiredWindow time.Duration,
) error {
	if ctx == nil || client == nil || namespace == "" || stale.member == "" || stale.fence == 0 ||
		retained.fence <= stale.fence || requiredWindow < gateway.MinDownstreamActionWindow {
		return errors.New("controlled stale-member validation input is invalid")
	}
	parts := strings.Split(stale.member, ":")
	if len(parts) != 5 {
		return errors.New("controlled stale member is malformed")
	}
	boundExpiry, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil || boundExpiry < 1 {
		return errors.New("controlled stale member expiry is invalid")
	}
	operationCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	valid, err := validateDownstreamStaleMemberScript.Run(
		operationCtx, client,
		[]string{sharedCapacityLeaseKey(namespace), downstreamCapacityFenceKey(namespace)},
		stale.member, boundExpiry, requiredWindow.Milliseconds(), stale.fence, retained.fence,
	).Int64()
	if err != nil || valid != 1 {
		return errors.Join(err, errors.New("stale activation was not rejected against an otherwise-valid exact member"))
	}
	return nil
}

func downstreamCapacityFenceKey(namespace string) string {
	digest := sha256.Sum256([]byte(namespace))
	return "sandbox-runtime:{" + hex.EncodeToString(digest[:]) + "}:capacity:fence"
}

func downstreamOpen(
	ctx context.Context,
	process *downstreamCallerProcess,
	connection, gatewayID, bindingID string,
) error {
	requestCtx, cancel := context.WithTimeout(ctx, downstreamCommandTimeout+time.Second)
	defer cancel()
	response, err := process.request(requestCtx, downstreamcaller.Command{
		Action: downstreamcaller.ActionOpen, ConnectionID: connection, GatewayID: gatewayID,
		GrantBindingID: bindingID, TimeoutMillis: downstreamCommandTimeout.Milliseconds(),
	})
	if err != nil || !response.OK || response.Outcome != downstreamcaller.OutcomeOpened || !response.Upgraded || response.ErrorCode != "" {
		return errors.New("downstream-fencing Browser connection did not open")
	}
	return nil
}

func downstreamClose(ctx context.Context, process *downstreamCallerProcess, connection string) error {
	requestCtx, cancel := context.WithTimeout(ctx, downstreamCommandTimeout+time.Second)
	defer cancel()
	response, err := process.request(requestCtx, downstreamcaller.Command{
		Action: downstreamcaller.ActionClose, ConnectionID: connection,
		TimeoutMillis: downstreamCommandTimeout.Milliseconds(),
	})
	if err != nil || !response.OK || response.Outcome != downstreamcaller.OutcomeReleased || response.ErrorCode != "" {
		return errors.New("downstream-fencing Browser connection did not release")
	}
	return nil
}

func downstreamQueue(
	ctx context.Context,
	process *downstreamCallerProcess,
	command downstreamcaller.Command,
	wantBytes int,
) error {
	payload, err := base64.StdEncoding.DecodeString(command.PayloadBase64)
	if err != nil || len(payload) != wantBytes || wantBytes < 1 || wantBytes > downstreamCDPMaxPayloadBytes {
		return errors.New("downstream-fencing queued action is not one complete bounded CDP message")
	}
	requestCtx, cancel := context.WithTimeout(ctx, downstreamCommandTimeout+time.Second)
	defer cancel()
	response, err := process.request(requestCtx, command)
	if err != nil || !response.OK || response.Outcome != downstreamcaller.OutcomeWritten || response.ErrorCode != "" ||
		response.PayloadBase64 != "" || response.MessageType != "" {
		return errors.New("downstream-fencing caller did not queue the complete CDP message")
	}
	return nil
}

func downstreamSetExpression(value string) string {
	encoded, _ := json.Marshal(value)
	return "globalThis.__sandboxRuntimeFenceMarker = " + string(encoded) + "; String(globalThis.__sandboxRuntimeFenceMarker)"
}

func downstreamReadExpression() string {
	return "String(globalThis.__sandboxRuntimeFenceMarker || '')"
}

func waitForDownstreamLeaseExpiry(
	ctx context.Context,
	client *goredis.Client,
	namespace string,
	record sharedLeaseRecord,
	timeout time.Duration,
) error {
	if record.member == "" || record.score < 1 {
		return errors.New("downstream-fencing lease identity is unavailable")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		operationCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		score, scoreErr := client.ZScore(operationCtx, sharedCapacityLeaseKey(namespace), record.member).Result()
		serverTime, timeErr := client.Time(operationCtx).Result()
		cancel()
		if timeErr != nil || (scoreErr != nil && !errors.Is(scoreErr, goredis.Nil)) ||
			(scoreErr == nil && score != float64(record.score)) {
			return errors.New("downstream-fencing lease changed before confirmed server-time expiry")
		}
		if downstreamLeaseExpiredAt(serverTime, record.score) {
			return nil
		}
		if errors.Is(scoreErr, goredis.Nil) {
			return errors.New("downstream-fencing lease disappeared before confirmed server-time expiry")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("downstream-fencing lease did not expire by retained-store time")
		case <-ticker.C:
		}
	}
}

func downstreamLeaseExpiredAt(serverTime time.Time, score int64) bool {
	return !serverTime.IsZero() && score > 0 && serverTime.UnixMilli() >= score
}

func assertDownstreamObservationDelta(
	before, after downstreamObservations,
	kind downstreamtransport.ObservationType,
	result downstreamtransport.ObservationResult,
	want int,
) error {
	if got := downstreamObservationDelta(before, after, kind, result); got != want {
		return fmt.Errorf("private ingress %s:%s delta = %d, want %d", kind, result, got, want)
	}
	return nil
}

func assertDownstreamActionRejected(
	before, after downstreamObservations,
	result downstreamtransport.ObservationResult,
) error {
	if result != downstreamtransport.ObservationResultFenceLost && result != downstreamtransport.ObservationResultUnavailable {
		return errors.New("private ingress action rejection result is invalid")
	}
	if !downstreamObservationPrefixEqual(before, after) {
		return errors.New("private ingress observation history changed")
	}
	delta := after[len(before):]
	if downstreamObservationDelta(before, after, downstreamtransport.ObservationActionRead, downstreamtransport.ObservationResultComplete) != 1 ||
		downstreamObservationDelta(before, after, downstreamtransport.ObservationActionFailed, result) != 1 {
		return errors.New("private ingress action rejection record count is invalid")
	}
	found := false
	for index := 0; index+1 < len(delta); index++ {
		read, failed := delta[index], delta[index+1]
		if read.Type != downstreamtransport.ObservationActionRead || read.Result != downstreamtransport.ObservationResultComplete ||
			failed.Type != downstreamtransport.ObservationActionFailed || failed.Result != result {
			continue
		}
		if failed.Sequence != read.Sequence+1 || failed.MessageType != read.MessageType || failed.Bytes != read.Bytes {
			return errors.New("private ingress action rejection is not an adjacent exact-message proof")
		}
		for _, record := range delta {
			if record.Type == downstreamtransport.ObservationActionForwarded &&
				record.Result == downstreamtransport.ObservationResultSucceeded &&
				record.MessageType == read.MessageType && record.Bytes == read.Bytes {
				return errors.New("private ingress forwarded the rejected action")
			}
		}
		found = true
	}
	if !found {
		return errors.New("private ingress action rejection lacks an adjacent read/failure proof")
	}
	return nil
}

func assertDownstreamTerminalAudit(before, after []downstreamGatewayAudit) error {
	if len(after) != len(before)+1 {
		return errors.New("Gateway terminal audit delta is invalid")
	}
	for index := range before {
		if before[index] != after[index] {
			return errors.New("Gateway audit history changed")
		}
	}
	terminal := after[len(before)]
	if terminal.Sequence != uint64(len(after)) || terminal.Attempt != 0 {
		return errors.New("Gateway terminal audit metadata is invalid")
	}
	switch terminal.Type {
	case "capacity_lost", "capacity_unavailable", "downstream_fence_lost":
		return nil
	default:
		return errors.New("Gateway did not close for a fenced authority boundary")
	}
}

func waitForDownstreamTerminalAudit(
	ctx context.Context,
	path string,
	before []downstreamGatewayAudit,
	timeout time.Duration,
) ([]downstreamGatewayAudit, error) {
	if ctx == nil || path == "" || timeout <= 0 {
		return nil, errors.New("Gateway terminal audit wait input is invalid")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		after, err := readDownstreamGatewayAudit(path)
		if err != nil && !errors.Is(err, errDownstreamEvidenceChanged) {
			return nil, err
		}
		if err == nil && len(after) > len(before) {
			if err := assertDownstreamTerminalAudit(before, after); err != nil {
				return nil, err
			}
			return after, nil
		}
		if err == nil && len(after) < len(before) {
			return nil, errors.New("Gateway audit history was truncated")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("Gateway terminal audit was not recorded")
		case <-ticker.C:
		}
	}
}

func waitForDownstreamObservationsUnchanged(
	ctx context.Context,
	path string,
	want downstreamObservations,
	window time.Duration,
) (downstreamObservations, error) {
	if ctx == nil || path == "" || window <= 0 {
		return nil, errors.New("private ingress stability wait input is invalid")
	}
	notBefore := time.Now().Add(window)
	deadline := time.NewTimer(window + 500*time.Millisecond)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		current, err := downstreamObservationSnapshot(path)
		if err != nil && !errors.Is(err, errDownstreamEvidenceChanged) {
			return nil, err
		}
		if err == nil {
			if !downstreamObservationsEqual(want, current) {
				return current, errors.New("private ingress observations changed during the stability window")
			}
			if !time.Now().Before(notBefore) {
				return current, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("private ingress observations did not stabilize")
		case <-ticker.C:
		}
	}
}

func assertQueuedStaleActionRejected(before, after downstreamObservations, payloadBytes uint64) error {
	if payloadBytes == 0 || payloadBytes > downstreamwire.MaxMessageBytes {
		return errors.New("queued stale action size is invalid")
	}
	if !downstreamObservationPrefixEqual(before, after) {
		return errors.New("private ingress observation history changed")
	}
	delta := after[len(before):]
	if len(delta) == 0 {
		// The higher-fence activation already produced a stream-termination
		// witness before this scenario resumed the old Gateway. The queued public
		// frame may therefore be rejected before the old private handler reads it.
		return nil
	}
	if len(delta) != 2 {
		return errors.New("queued stale action produced an invalid ingress trace")
	}
	read, failed := delta[0], delta[1]
	if read.Type != downstreamtransport.ObservationActionRead || read.Result != downstreamtransport.ObservationResultComplete ||
		read.MessageType != downstreamtransport.ObservationMessageText || read.Bytes != payloadBytes ||
		failed.Type != downstreamtransport.ObservationActionFailed || failed.Result != downstreamtransport.ObservationResultFenceLost ||
		failed.Sequence != read.Sequence+1 || failed.MessageType != read.MessageType || failed.Bytes != read.Bytes {
		return errors.New("queued stale action lacks an exact read/fence-loss trace")
	}
	return nil
}

func downstreamObservationPrefixEqual(before, after downstreamObservations) bool {
	if len(after) < len(before) {
		return false
	}
	for index := range before {
		if before[index] != after[index] {
			return false
		}
	}
	return true
}

func downstreamObservationsEqual(left, right downstreamObservations) bool {
	return len(left) == len(right) && downstreamObservationPrefixEqual(left, right)
}

func readDownstreamEvidenceFile(path string, allowMissing bool) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if allowMissing && errors.Is(err, syscall.ENOENT) {
			return nil, nil
		}
		return nil, errors.New("open downstream-fencing evidence without following links")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open downstream-fencing evidence")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 0 || info.Size() > downstreamFileMaximum {
		return nil, errors.New("downstream-fencing evidence is not a bounded 0600 regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, downstreamFileMaximum+1))
	if err != nil || len(contents) > downstreamFileMaximum {
		return nil, errors.New("read bounded downstream-fencing evidence")
	}
	if int64(len(contents)) != info.Size() {
		return nil, errDownstreamEvidenceChanged
	}
	if contents == nil {
		contents = make([]byte, 0)
	}
	return contents, nil
}

func copyDownstreamEvidenceFile(source, destination string) (resultErr error) {
	contents, err := readDownstreamEvidenceFile(source, false)
	if err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("create downstream-fencing evidence destination")
	}
	defer func() {
		resultErr = errors.Join(resultErr, output.Close())
		if resultErr != nil {
			_ = os.Remove(destination)
		}
	}()
	written, err := io.Copy(output, bytes.NewReader(contents))
	if err != nil || written != int64(len(contents)) {
		return errors.New("copy downstream-fencing evidence exactly")
	}
	if err := output.Sync(); err != nil {
		return errors.New("sync downstream-fencing evidence")
	}
	return nil
}

func copyDownstreamEvidence(sourceRoot, evidenceRoot string) error {
	for source, destination := range map[string]string{
		filepath.Join(sourceRoot, "gateway-a-audit.jsonl"):      filepath.Join(evidenceRoot, "gateway-audit-a.jsonl"),
		filepath.Join(sourceRoot, "gateway-b-audit.jsonl"):      filepath.Join(evidenceRoot, "gateway-audit-b.jsonl"),
		filepath.Join(sourceRoot, "ingress-observations.jsonl"): filepath.Join(evidenceRoot, "ingress-observations.jsonl"),
	} {
		if err := copyDownstreamEvidenceFile(source, destination); err != nil {
			return err
		}
	}
	return nil
}
