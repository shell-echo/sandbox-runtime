package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/sharedcapacity/wire"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
)

const sharedCapacityEvidenceName = "Browser Gateway shared-capacity black-box evidence"

type SharedCapacityResult struct {
	EvidenceDirectory string
	Scenarios         int
	Platform          string
}

type sharedCapacityManifest struct {
	CreatedAt            string                    `json:"created_at"`
	EvidenceName         string                    `json:"evidence_name"`
	EvidenceProfile      string                    `json:"evidence_profile"`
	HarnessCommit        string                    `json:"harness_commit"`
	ProviderCommit       string                    `json:"provider_commit"`
	GatewaySourceCommit  string                    `json:"gateway_source_commit"`
	GatewayBinarySHA256  string                    `json:"gateway_binary_sha256"`
	CallerBinarySHA256   string                    `json:"caller_binary_sha256"`
	GatewayProcesses     int                       `json:"gateway_processes"`
	Valkey               sharedCapacityValkeyInfo  `json:"valkey"`
	CapacityPolicy       lock.SharedCapacityPolicy `json:"capacity_policy"`
	Adapter              rediscapacity.Descriptor  `json:"adapter"`
	GatewayConfigDigests []string                  `json:"gateway_config_digests"`
	CallerConfigDigest   string                    `json:"caller_config_digest"`
	Contract             sharedContractInfo        `json:"contract"`
	Reports              []string                  `json:"reports"`
	Audits               []string                  `json:"audits"`
	Observations         []string                  `json:"observations"`
	Faults               []string                  `json:"faults"`
	Commands             []string                  `json:"commands"`
	EvidenceBoundary     string                    `json:"evidence_boundary"`
}

type sharedCapacityValkeyInfo struct {
	Image                    string `json:"image"`
	IndexDigest              string `json:"index_digest"`
	SelectedPlatform         string `json:"selected_platform"`
	SelectedPlatformDigest   string `json:"selected_platform_digest"`
	LocalImageID             string `json:"local_image_id"`
	ServerConfigSHA256       string `json:"server_config_sha256"`
	ACLTemplateSHA256        string `json:"acl_template_sha256"`
	ProvenanceNotEstablished bool   `json:"provenance_not_established"`
}

type sharedContractInfo struct {
	Namespace  string `json:"namespace"`
	Revision   string `json:"revision"`
	Tree       string `json:"tree"`
	SuiteCases int    `json:"suite_cases"`
	Exercised  bool   `json:"exercised"`
}

type sharedScenarioRunner struct {
	report wire.Report
}

func (r *sharedScenarioRunner) run(ctx context.Context, name string, scenario func(context.Context) error) error {
	started := time.Now()
	err := scenario(ctx)
	status := "passed"
	if err != nil {
		status = "failed"
	}
	r.report.Scenarios = append(r.report.Scenarios, wire.Scenario{
		Name: name, Status: status, DurationMillis: time.Since(started).Milliseconds(), GatewayProcesses: 2,
	})
	if err != nil {
		return fmt.Errorf("shared-capacity scenario %q: %w", name, err)
	}
	return nil
}

// RunSharedCapacity launches two Gateway OS processes, one pinned retained
// Valkey authority, and independent network caller processes.
func RunSharedCapacity(ctx context.Context, options Options) (_ SharedCapacityResult, resultErr error) {
	moduleRoot, err := filepath.Abs(options.ModuleRoot)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	providerRoot, err := filepath.Abs(options.ProviderRoot)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	if err := lock.Verify(providerRoot); err != nil {
		return SharedCapacityResult{}, err
	}
	harnessCommit, err := lock.HarnessRevision(moduleRoot)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	platform, err := dockerServerPlatform(ctx)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	sharedLock, err := lock.LoadSharedCapacity(providerRoot, platform)
	if err != nil {
		return SharedCapacityResult{}, err
	}

	evidenceRoot, err := filepath.Abs(options.EvidenceRoot)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	evidenceDirectory := filepath.Join(evidenceRoot, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		return SharedCapacityResult{}, err
	}
	temporaryRoot := filepath.Join(moduleRoot, "tmp")
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		return SharedCapacityResult{}, err
	}
	runRoot, err := os.MkdirTemp(temporaryRoot, runRootPrefix)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupRunRoot(temporaryRoot, runRoot)) }()

	binRoot := filepath.Join(runRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o700); err != nil {
		return SharedCapacityResult{}, err
	}
	goCache := filepath.Join(runRoot, "go-cache")
	gatewayBinary := filepath.Join(binRoot, "shared-capacity-gateway")
	callerBinary := filepath.Join(binRoot, "shared-capacity-caller")
	if err := build(ctx, moduleRoot, goCache, nil, gatewayBinary, "./cmd/shared-capacity-gateway"); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := build(ctx, moduleRoot, goCache, nil, callerBinary, "./cmd/shared-capacity-caller"); err != nil {
		return SharedCapacityResult{}, err
	}
	gatewayBinaryDigest, err := fileSHA256(gatewayBinary)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	callerBinaryDigest, err := fileSHA256(callerBinary)
	if err != nil {
		return SharedCapacityResult{}, err
	}

	namespaceToken, err := randomSecret("")
	if err != nil {
		return SharedCapacityResult{}, err
	}
	namespace := "shared-capacity-e2e-" + namespaceToken[:24]
	namespaceDigest := sha256.Sum256([]byte(namespace))
	password, err := randomSecret("")
	if err != nil {
		return SharedCapacityResult{}, err
	}
	acl := strings.ReplaceAll(lock.SharedCapacityACLTemplate, "${PASSWORD}", password)
	acl = strings.ReplaceAll(acl, "${NAMESPACE_SHA256}", hex.EncodeToString(namespaceDigest[:]))
	image := sharedLock.Valkey.Image + "@" + sharedLock.Valkey.IndexDigest
	valkey, err := startSharedValkey(ctx, runRoot, image, platform, sharedLock.Valkey.SelectedChildDigest,
		lock.SharedCapacityServerConfig, acl, "e2e", password)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	storePaused := false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if storePaused {
			resultErr = errors.Join(resultErr, valkey.unpause(cleanupCtx))
		}
		resultErr = errors.Join(resultErr, valkey.close(cleanupCtx))
	}()

	redisClient, err := newSharedRedisClient(valkey.redisURL, time.Duration(sharedLock.CapacityPolicy.OperationTimeoutMillis)*time.Millisecond)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	defer redisClient.Close()
	if err := waitForSharedRedis(ctx, redisClient, 10*time.Second); err != nil {
		return SharedCapacityResult{}, err
	}
	capacity, err := sharedCapacityFromLock(redisClient, namespace, sharedLock.CapacityPolicy)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	provisionCtx, cancelProvision := context.WithTimeout(ctx, 3*time.Second)
	err = capacity.Provision(provisionCtx)
	cancelProvision()
	if err != nil {
		return SharedCapacityResult{}, errors.New("provision shared-capacity authority")
	}

	material, err := testenv.GeneratePKI(filepath.Join(runRoot, "secrets"), time.Now().UTC())
	if err != nil {
		return SharedCapacityResult{}, err
	}
	gatewayAddressA, err := allocateAddress()
	if err != nil {
		return SharedCapacityResult{}, err
	}
	gatewayAddressB, err := allocateAddress()
	if err != nil {
		return SharedCapacityResult{}, err
	}
	for gatewayAddressB == gatewayAddressA {
		gatewayAddressB, err = allocateAddress()
		if err != nil {
			return SharedCapacityResult{}, err
		}
	}
	principals, endpoints, sensitive, err := sharedCapacityIdentities()
	if err != nil {
		return SharedCapacityResult{}, err
	}
	for _, principal := range principals {
		sensitive = append(sensitive, principal.Token, principal.CallerID, principal.TenantID)
	}
	for _, endpoint := range endpoints {
		sensitive = append(sensitive, endpoint.TenantID, endpoint.SandboxID, endpoint.BrowserSessionID, endpoint.HandoffReference)
	}
	sensitive = append(sensitive, namespace, valkey.redisURL, password)

	policy := wire.CapacityPolicy{
		MaxTotal: sharedLock.CapacityPolicy.MaxTotal, MaxPerTenant: sharedLock.CapacityPolicy.MaxPerTenant,
		MaxPerSession: sharedLock.CapacityPolicy.MaxPerSession, LeaseTTLMillis: sharedLock.CapacityPolicy.LeaseTTLMillis,
		RenewIntervalMillis:       sharedLock.CapacityPolicy.RenewIntervalMillis,
		RenewalSafetyMarginMillis: sharedLock.CapacityPolicy.RenewalSafetyMarginMillis,
		OperationTimeoutMillis:    sharedLock.CapacityPolicy.OperationTimeoutMillis,
	}
	auditA := filepath.Join(runRoot, "gateway-a-audit.jsonl")
	auditB := filepath.Join(runRoot, "gateway-b-audit.jsonl")
	observationA := filepath.Join(runRoot, "gateway-a-observations.jsonl")
	observationB := filepath.Join(runRoot, "gateway-b-observations.jsonl")
	gatewayConfigA := wire.GatewayConfig{
		Address: gatewayAddressA, ServerCertificateFile: material.GatewayCertificateFile,
		ServerPrivateKeyFile: material.GatewayPrivateKeyFile, RedisURL: valkey.redisURL,
		CapacityNamespace: namespace, AuditFile: auditA, ObservationFile: observationA,
		Policy: policy, Principals: principals, Endpoints: endpoints,
	}
	gatewayConfigB := gatewayConfigA
	gatewayConfigB.Address = gatewayAddressB
	gatewayConfigB.AuditFile = auditB
	gatewayConfigB.ObservationFile = observationB
	gatewayConfigPathA := filepath.Join(runRoot, "secrets", "gateway-a.json")
	gatewayConfigPathB := filepath.Join(runRoot, "secrets", "gateway-b.json")
	gatewayConfigDigestA, err := writeJSON(gatewayConfigPathA, gatewayConfigA)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	gatewayConfigDigestB, err := writeJSON(gatewayConfigPathB, gatewayConfigB)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	callerConfig := wire.CallerConfig{
		CAFile:     material.CAFile,
		Gateways:   map[string]string{"a": "https://" + gatewayAddressA, "b": "https://" + gatewayAddressB},
		Principals: principals, Endpoints: endpoints,
	}
	callerConfigPath := filepath.Join(runRoot, "secrets", "caller.json")
	callerConfigDigest, err := writeJSON(callerConfigPath, callerConfig)
	if err != nil {
		return SharedCapacityResult{}, err
	}
	logRoot := filepath.Join(runRoot, "logs")
	if err := os.MkdirAll(logRoot, 0o700); err != nil {
		return SharedCapacityResult{}, err
	}

	gatewayA, err := startStack(gatewayBinary, gatewayConfigPathA, filepath.Join(logRoot, "gateway-a-initial.log"))
	if err != nil {
		return SharedCapacityResult{}, err
	}
	gatewayAStopped := false
	gatewayASuspended := false
	defer func() {
		if gatewayA == nil || gatewayAStopped {
			return
		}
		if gatewayASuspended {
			resultErr = errors.Join(resultErr, signalSharedGateway(gatewayA, syscall.SIGCONT))
		}
		resultErr = errors.Join(resultErr, gatewayA.Stop())
	}()
	gatewayB, err := startStack(gatewayBinary, gatewayConfigPathB, filepath.Join(logRoot, "gateway-b.log"))
	if err != nil {
		stopErr := gatewayA.Stop()
		gatewayAStopped = stopErr == nil
		return SharedCapacityResult{}, errors.Join(err, stopErr)
	}
	gatewayBStopped := false
	defer func() {
		if gatewayB != nil && !gatewayBStopped {
			resultErr = errors.Join(resultErr, gatewayB.Stop())
		}
	}()
	if err := waitForListenersWithin(ctx, gatewayA, 15*time.Second, gatewayAddressA); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := waitForListenersWithin(ctx, gatewayB, 15*time.Second, gatewayAddressB); err != nil {
		return SharedCapacityResult{}, err
	}

	callers := make([]*sharedCallerProcess, 6)
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
	for index := range callers {
		callers[index], err = startSharedCaller(callerBinary, callerConfigPath,
			filepath.Join(logRoot, fmt.Sprintf("caller-%d.log", index+1)))
		if err != nil {
			return SharedCapacityResult{}, err
		}
	}

	runner := &sharedScenarioRunner{report: wire.Report{EvidenceName: sharedCapacityEvidenceName}}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[0], func(ctx context.Context) error {
		before, err := combinedRecordCount(observationA, observationB, "resolve")
		if err != nil {
			return err
		}
		beforeRejected, err := combinedRecordCount(auditA, auditB, "capacity_rejected")
		if err != nil {
			return err
		}
		attempts := []sharedOpenAttempt{
			{caller: callers[0], connection: "session-a", gateway: "a", principal: "a", endpoint: "a1"},
			{caller: callers[1], connection: "session-b", gateway: "b", principal: "a", endpoint: "a1"},
		}
		accepted, rejected, err := runConcurrentContention(ctx, attempts, 1)
		if err != nil {
			return err
		}
		defer closeAttempts(context.Background(), accepted)
		if err := assertRejectedNormalClosure(ctx, rejected); err != nil {
			return err
		}
		after, err := combinedRecordCount(observationA, observationB, "resolve")
		if err != nil {
			return err
		}
		if after-before != 1 {
			return fmt.Errorf("session contention resolver delta = %d, want 1", after-before)
		}
		return waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_rejected", beforeRejected, 1, 2*time.Second)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[1], func(ctx context.Context) error {
		beforeRejected, err := combinedRecordCount(auditA, auditB, "capacity_rejected")
		if err != nil {
			return err
		}
		attempts := []sharedOpenAttempt{
			{caller: callers[0], connection: "tenant-a1", gateway: "a", principal: "a", endpoint: "a1"},
			{caller: callers[1], connection: "tenant-a2", gateway: "b", principal: "a", endpoint: "a2"},
			{caller: callers[2], connection: "tenant-a3", gateway: "a", principal: "a", endpoint: "a3"},
			{caller: callers[3], connection: "tenant-b1", gateway: "b", principal: "b", endpoint: "b1"},
		}
		accepted, rejected, err := runConcurrentContention(ctx, attempts, 3)
		if err != nil {
			return err
		}
		defer closeAttempts(context.Background(), accepted)
		if err := assertRejectedNormalClosure(ctx, rejected); err != nil {
			return err
		}
		acceptedB := false
		for _, attempt := range accepted {
			if attempt.principal == "b" {
				acceptedB = true
			}
		}
		if !acceptedB {
			return errors.New("unaffected tenant did not retain service")
		}
		return waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_rejected", beforeRejected, 1, 2*time.Second)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[2], func(ctx context.Context) error {
		before, err := combinedRecordCount(observationA, observationB, "dial")
		if err != nil {
			return err
		}
		beforeRejected, err := combinedRecordCount(auditA, auditB, "capacity_rejected")
		if err != nil {
			return err
		}
		attempts := []sharedOpenAttempt{
			{caller: callers[0], connection: "global-a1", gateway: "a", principal: "a", endpoint: "a1"},
			{caller: callers[1], connection: "global-a2", gateway: "b", principal: "a", endpoint: "a2"},
			{caller: callers[2], connection: "global-b1", gateway: "a", principal: "b", endpoint: "b1"},
			{caller: callers[3], connection: "global-b2", gateway: "b", principal: "b", endpoint: "b2"},
			{caller: callers[4], connection: "global-c1", gateway: "a", principal: "c", endpoint: "c1"},
			{caller: callers[5], connection: "global-c2", gateway: "b", principal: "c", endpoint: "c2"},
		}
		accepted, rejected, err := runConcurrentContention(ctx, attempts, 4)
		if err != nil {
			return err
		}
		defer closeAttempts(context.Background(), accepted)
		if err := assertRejectedNormalClosure(ctx, rejected); err != nil {
			return err
		}
		after, err := combinedRecordCount(observationA, observationB, "dial")
		if err != nil {
			return err
		}
		if after-before != 4 {
			return fmt.Errorf("global contention dial delta = %d, want 4", after-before)
		}
		return waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_rejected", beforeRejected, 2, 2*time.Second)
	}); err != nil {
		return SharedCapacityResult{}, err
	}

	leaseTTL := time.Duration(policy.LeaseTTLMillis) * time.Millisecond
	renewInterval := time.Duration(policy.RenewIntervalMillis) * time.Millisecond
	if err := runner.run(ctx, lock.SharedCapacityScenarios[3], func(ctx context.Context) error {
		attempt := sharedOpenAttempt{caller: callers[0], connection: "renewal", gateway: "a", principal: "a", endpoint: "a1"}
		if err := openHealthy(ctx, attempt); err != nil {
			return err
		}
		defer closeAttempt(context.Background(), attempt)
		if err := waitForSharedDuration(ctx, 3*leaseTTL+renewInterval); err != nil {
			return err
		}
		return roundTrip(ctx, attempt)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[4], func(ctx context.Context) error {
		attempt := sharedOpenAttempt{caller: callers[0], connection: "loss-old", gateway: "a", principal: "a", endpoint: "a1"}
		if err := openHealthy(ctx, attempt); err != nil {
			return err
		}
		beforeLost, err := combinedRecordCount(auditA, auditB, "capacity_lost")
		if err != nil {
			return err
		}
		beforeResolve, err := countSanitizedRecords(observationA, "resolve")
		if err != nil {
			return err
		}
		if err := removeSingleSharedLease(ctx, redisClient, namespace); err != nil {
			return err
		}
		if err := expectClosed(ctx, attempt, int(websocket.StatusNormalClosure), leaseTTL); err != nil {
			return err
		}
		afterResolve, err := countSanitizedRecords(observationA, "resolve")
		if err != nil {
			return err
		}
		if afterResolve != beforeResolve {
			return errors.New("lost capacity lease triggered resolver reconnect")
		}
		return waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_lost", beforeLost, 1, 2*time.Second)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[5], func(ctx context.Context) error {
		attempt := sharedOpenAttempt{caller: callers[0], connection: "crash-old", gateway: "a", principal: "a", endpoint: "a1"}
		if err := openHealthy(ctx, attempt); err != nil {
			return err
		}
		if err := killSharedGateway(gatewayA); err != nil {
			return err
		}
		gatewayAStopped = true
		if err := expectClosed(ctx, attempt, int(websocket.StatusAbnormalClosure), 3*time.Second); err != nil {
			return err
		}
		contender := sharedOpenAttempt{caller: callers[1], connection: "crash-contender", gateway: "b", principal: "a", endpoint: "a1"}
		beforeRejected, err := combinedRecordCount(auditA, auditB, "capacity_rejected")
		if err != nil {
			return err
		}
		if err := openUpgraded(ctx, contender); err != nil {
			return err
		}
		if err := expectClosed(ctx, contender, int(websocket.StatusNormalClosure), time.Second); err != nil {
			return errors.New("crashed owner was reclaimed before its TTL")
		}
		if err := waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_rejected", beforeRejected, 1, 2*time.Second); err != nil {
			return err
		}
		if err := waitForSharedDuration(ctx, leaseTTL+300*time.Millisecond); err != nil {
			return err
		}
		successor := sharedOpenAttempt{caller: callers[1], connection: "crash-successor", gateway: "b", principal: "a", endpoint: "a1"}
		if err := openHealthy(ctx, successor); err != nil {
			return err
		}
		if err := closeAttempt(ctx, successor); err != nil {
			return err
		}
		gatewayA, err = startStack(gatewayBinary, gatewayConfigPathA, filepath.Join(logRoot, "gateway-a-restarted.log"))
		if err != nil {
			return err
		}
		gatewayAStopped = false
		return waitForListenersWithin(ctx, gatewayA, 15*time.Second, gatewayAddressA)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[6], func(ctx context.Context) error {
		stale := sharedOpenAttempt{caller: callers[0], connection: "stale-owner", gateway: "a", principal: "a", endpoint: "a1"}
		if err := openHealthy(ctx, stale); err != nil {
			return err
		}
		beforeLost, err := combinedRecordCount(auditA, auditB, "capacity_lost")
		if err != nil {
			return err
		}
		if err := signalSharedGateway(gatewayA, syscall.SIGSTOP); err != nil {
			return err
		}
		gatewayASuspended = true
		defer func() {
			if gatewayASuspended {
				if signalSharedGateway(gatewayA, syscall.SIGCONT) == nil {
					gatewayASuspended = false
				}
			}
		}()
		if err := waitForSharedDuration(ctx, leaseTTL+300*time.Millisecond); err != nil {
			return err
		}
		successor := sharedOpenAttempt{caller: callers[1], connection: "stale-successor", gateway: "b", principal: "a", endpoint: "a1"}
		if err := openHealthy(ctx, successor); err != nil {
			return err
		}
		defer closeAttempt(context.Background(), successor)
		if err := signalSharedGateway(gatewayA, syscall.SIGCONT); err != nil {
			return err
		}
		gatewayASuspended = false
		if err := expectClosed(ctx, stale, int(websocket.StatusNormalClosure), leaseTTL); err != nil {
			return err
		}
		if err := waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_lost", beforeLost, 1, 2*time.Second); err != nil {
			return err
		}
		return roundTrip(ctx, successor)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[7], func(ctx context.Context) error {
		for index := 0; index < 6; index++ {
			gateway := "a"
			if index%2 == 1 {
				gateway = "b"
			}
			attempt := sharedOpenAttempt{
				caller: callers[index%len(callers)], connection: fmt.Sprintf("release-race-%d", index),
				gateway: gateway, principal: "a", endpoint: "a1",
			}
			if err := openHealthy(ctx, attempt); err != nil {
				return err
			}
			beforeClosed, err := combinedRecordCount(auditA, auditB, "client_closed")
			if err != nil {
				return err
			}
			beforeUnavailable, err := combinedRecordCount(auditA, auditB, "capacity_unavailable")
			if err != nil {
				return err
			}
			if err := valkey.pause(ctx); err != nil {
				return err
			}
			storePaused = true
			// Keep the real store paused past the scheduled renewal so Close races
			// an in-flight renewal rather than relying on scheduler coincidence.
			if err := waitForSharedDuration(ctx, renewInterval+50*time.Millisecond); err != nil {
				return err
			}
			raceCtx, cancelRace := context.WithTimeout(ctx, 3*time.Second)
			closed := make(chan error, 1)
			go func() { closed <- closeAttempt(raceCtx, attempt) }()
			if err := waitForCombinedRecordDelta(raceCtx, auditA, auditB, "client_closed", beforeClosed, 1, time.Second); err != nil {
				cancelRace()
				return err
			}
			if err := valkey.unpause(raceCtx); err != nil {
				cancelRace()
				return err
			}
			storePaused = false
			select {
			case err := <-closed:
				cancelRace()
				if err != nil {
					return err
				}
			case <-raceCtx.Done():
				cancelRace()
				return raceCtx.Err()
			}
			if err := waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_unavailable", beforeUnavailable, 0, 100*time.Millisecond); err != nil {
				return errors.New("renew/release race emitted capacity unavailability")
			}
			if err := assertSharedCardinality(ctx, redisClient, namespace, 0); err != nil {
				return err
			}
		}
		if err := waitForSharedDuration(ctx, renewInterval+time.Duration(policy.OperationTimeoutMillis)*time.Millisecond+100*time.Millisecond); err != nil {
			return err
		}
		return assertSharedCardinality(ctx, redisClient, namespace, 0)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[8], func(ctx context.Context) error {
		active := sharedOpenAttempt{caller: callers[0], connection: "outage-active", gateway: "a", principal: "a", endpoint: "a1"}
		if err := openHealthy(ctx, active); err != nil {
			return err
		}
		beforeUnavailable, err := combinedRecordCount(auditA, auditB, "capacity_unavailable")
		if err != nil {
			return err
		}
		beforeResolve, err := countSanitizedRecords(observationB, "resolve")
		if err != nil {
			return err
		}
		if err := valkey.pause(ctx); err != nil {
			return err
		}
		storePaused = true
		pausedAt := time.Now()
		contender := sharedOpenAttempt{caller: callers[1], connection: "outage-new", gateway: "b", principal: "b", endpoint: "b1"}
		if err := openUpgraded(ctx, contender); err != nil {
			return err
		}
		if err := expectClosed(ctx, contender, int(websocket.StatusNormalClosure), leaseTTL); err != nil {
			return err
		}
		if err := expectClosed(ctx, active, int(websocket.StatusNormalClosure), leaseTTL+500*time.Millisecond); err != nil {
			return err
		}
		if time.Since(pausedAt) > leaseTTL+250*time.Millisecond {
			return errors.New("active lease exceeded its confirmed safety boundary")
		}
		afterResolve, err := countSanitizedRecords(observationB, "resolve")
		if err != nil {
			return err
		}
		if afterResolve != beforeResolve {
			return errors.New("store-outage acquisition reached resolver")
		}
		if err := waitForCombinedRecordDelta(ctx, auditA, auditB, "capacity_unavailable", beforeUnavailable, 2, 2*time.Second); err != nil {
			return err
		}
		if err := valkey.unpause(ctx); err != nil {
			return err
		}
		storePaused = false
		if err := waitForSharedRedis(ctx, redisClient, 5*time.Second); err != nil {
			return err
		}
		if err := waitForSharedDuration(ctx, leaseTTL+300*time.Millisecond); err != nil {
			return err
		}
		recovery := sharedOpenAttempt{caller: callers[1], connection: "outage-recovery", gateway: "b", principal: "b", endpoint: "b1"}
		if err := openHealthy(ctx, recovery); err != nil {
			return err
		}
		return closeAttempt(ctx, recovery)
	}); err != nil {
		return SharedCapacityResult{}, err
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(ctx, 15*time.Second)
	for _, process := range callers {
		if err := process.shutdown(shutdownCtx); err != nil {
			cancelShutdown()
			return SharedCapacityResult{}, err
		}
	}
	cancelShutdown()
	callersStopped = true
	if err := gatewayA.Stop(); err != nil {
		return SharedCapacityResult{}, err
	}
	gatewayAStopped = true
	if err := gatewayB.Stop(); err != nil {
		return SharedCapacityResult{}, err
	}
	gatewayBStopped = true

	auditNames := []string{"gateway-a-audit.jsonl", "gateway-b-audit.jsonl"}
	observationNames := []string{"gateway-a-observations.jsonl", "gateway-b-observations.jsonl"}
	for source, destination := range map[string]string{
		auditA: auditNames[0], auditB: auditNames[1], observationA: observationNames[0], observationB: observationNames[1],
	} {
		if err := copyFile(source, filepath.Join(evidenceDirectory, destination)); err != nil {
			return SharedCapacityResult{}, err
		}
	}
	if err := runner.run(ctx, lock.SharedCapacityScenarios[9], func(context.Context) error {
		if err := assertSanitizedSharedRecords(evidenceDirectory, auditNames, observationNames); err != nil {
			return err
		}
		for kind, want := range map[string]int{
			"capacity_rejected":    5,
			"capacity_lost":        2,
			"capacity_unavailable": 2,
		} {
			got, err := combinedRecordCount(filepath.Join(evidenceDirectory, auditNames[0]), filepath.Join(evidenceDirectory, auditNames[1]), kind)
			if err != nil {
				return err
			}
			if got != want {
				return fmt.Errorf("final %s audit count = %d, want %d", kind, got, want)
			}
		}
		return assertEvidenceExcludes(evidenceDirectory, sensitive)
	}); err != nil {
		return SharedCapacityResult{}, err
	}
	reportPath := filepath.Join(evidenceDirectory, "report.json")
	if _, err := writeJSON(reportPath, runner.report); err != nil {
		return SharedCapacityResult{}, err
	}
	manifest := sharedCapacityManifest{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), EvidenceName: sharedCapacityEvidenceName,
		EvidenceProfile: sharedLock.EvidenceProfile, HarnessCommit: harnessCommit, ProviderCommit: lock.ProviderCommit,
		GatewaySourceCommit: harnessCommit, GatewayBinarySHA256: gatewayBinaryDigest,
		CallerBinarySHA256: callerBinaryDigest, GatewayProcesses: sharedLock.GatewayProcesses,
		Valkey: sharedCapacityValkeyInfo{
			Image: image, IndexDigest: sharedLock.Valkey.IndexDigest,
			SelectedPlatform: platform, SelectedPlatformDigest: sharedLock.Valkey.SelectedChildDigest,
			LocalImageID: valkey.imageID, ServerConfigSHA256: sharedLock.Valkey.ServerConfigSHA256,
			ACLTemplateSHA256: sharedLock.Valkey.ACLTemplateSHA256, ProvenanceNotEstablished: true,
		},
		CapacityPolicy: sharedLock.CapacityPolicy, Adapter: sharedLock.Adapter,
		GatewayConfigDigests: []string{gatewayConfigDigestA, gatewayConfigDigestB}, CallerConfigDigest: callerConfigDigest,
		Contract: sharedContractInfo{
			Namespace: lock.ContractNS, Revision: lock.ContractRevision, Tree: lock.ContractTree,
			SuiteCases: lock.SuiteCases, Exercised: false,
		},
		Reports: []string{filepath.Base(reportPath)}, Audits: auditNames, Observations: observationNames,
		Faults: []string{"single lease removal", "SIGKILL owning Gateway", "SIGSTOP/SIGCONT stale owner", "retained Valkey pause/unpause"},
		Commands: []string{
			"go build ./cmd/shared-capacity-gateway", "go build ./cmd/shared-capacity-caller",
			"shared-capacity-gateway -config <ephemeral> (two independent processes)",
			"shared-capacity-caller -config <ephemeral> (independent network processes)",
		},
		EvidenceBoundary: "real shared-capacity adapter and two-independent-Gateway Browser black-box evidence only; Contract identity is pinned but Provider protocol is not exercised; not Valkey production deployment or HA failover, distributed durable revocation, downstream fencing, arbitrary suspension safety, Provider multi-controller reliability, hostile multi-tenant isolation, real Agent Platform compatibility, aggregate conformance, deployment readiness, or production readiness",
	}
	if _, err := writeJSON(filepath.Join(evidenceDirectory, "manifest.json"), manifest); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := assertEvidenceFileSet(evidenceDirectory, append([]string{"manifest.json", filepath.Base(reportPath)}, append(auditNames, observationNames...)...)); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := assertSanitizedSharedRecords(evidenceDirectory, auditNames, observationNames); err != nil {
		return SharedCapacityResult{}, err
	}
	if err := assertEvidenceExcludes(evidenceDirectory, sensitive); err != nil {
		return SharedCapacityResult{}, err
	}
	return SharedCapacityResult{EvidenceDirectory: evidenceDirectory, Scenarios: len(runner.report.Scenarios), Platform: platform}, nil
}

type sharedOpenAttempt struct {
	caller     *sharedCallerProcess
	connection string
	gateway    string
	principal  string
	endpoint   string
}

func runConcurrentContention(ctx context.Context, attempts []sharedOpenAttempt, wantAccepted int) ([]sharedOpenAttempt, []sharedOpenAttempt, error) {
	start := make(chan struct{})
	responses := make([]wire.Response, len(attempts))
	errorsByAttempt := make([]error, len(attempts))
	var wait sync.WaitGroup
	for index := range attempts {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			responses[index], errorsByAttempt[index] = sendSharedCommand(ctx, attempts[index].caller, wire.Command{
				Action: wire.ActionOpen, ConnectionID: attempts[index].connection,
				GatewayID: attempts[index].gateway, PrincipalID: attempts[index].principal,
				EndpointID: attempts[index].endpoint, GrantTTLMillis: 30_000, TimeoutMillis: 5_000,
			})
		}(index)
	}
	close(start)
	wait.Wait()
	for index := range attempts {
		if errorsByAttempt[index] != nil || !responses[index].OK || responses[index].Outcome != wire.OutcomeOpened || !responses[index].Upgraded {
			return nil, nil, errors.New("a concurrent Browser connection was not upgraded")
		}
	}
	if err := waitForSharedDuration(ctx, 100*time.Millisecond); err != nil {
		return nil, nil, err
	}
	accepted := make([]sharedOpenAttempt, 0, wantAccepted)
	rejected := make([]sharedOpenAttempt, 0, len(attempts)-wantAccepted)
	for _, attempt := range attempts {
		response, err := sendSharedCommand(ctx, attempt.caller, wire.Command{
			Action: wire.ActionRoundTrip, ConnectionID: attempt.connection, TimeoutMillis: 750,
		})
		if err != nil {
			return nil, nil, err
		}
		if response.OK && response.Outcome == wire.OutcomeEchoed {
			accepted = append(accepted, attempt)
		} else if !response.OK {
			rejected = append(rejected, attempt)
		} else {
			return nil, nil, errors.New("concurrent Browser connection returned an invalid outcome")
		}
	}
	if len(accepted) != wantAccepted || len(accepted)+len(rejected) != len(attempts) {
		return nil, nil, fmt.Errorf("concurrent contention accepted=%d rejected=%d, want accepted=%d", len(accepted), len(rejected), wantAccepted)
	}
	return accepted, rejected, nil
}

func openHealthy(ctx context.Context, attempt sharedOpenAttempt) error {
	if err := openUpgraded(ctx, attempt); err != nil {
		return err
	}
	if err := waitForSharedDuration(ctx, 50*time.Millisecond); err != nil {
		return err
	}
	return roundTrip(ctx, attempt)
}

func openUpgraded(ctx context.Context, attempt sharedOpenAttempt) error {
	response, err := sendSharedCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionOpen, ConnectionID: attempt.connection, GatewayID: attempt.gateway,
		PrincipalID: attempt.principal, EndpointID: attempt.endpoint,
		GrantTTLMillis: 30_000, TimeoutMillis: 5_000,
	})
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeOpened || !response.Upgraded {
		return errors.New("Browser connection did not complete its WebSocket upgrade")
	}
	return nil
}

func roundTrip(ctx context.Context, attempt sharedOpenAttempt) error {
	response, err := sendSharedCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionRoundTrip, ConnectionID: attempt.connection, TimeoutMillis: 3_000,
	})
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeEchoed {
		return errors.New("Browser private echo round trip failed")
	}
	return nil
}

func expectClosed(ctx context.Context, attempt sharedOpenAttempt, wantCode int, timeout time.Duration) error {
	response, err := sendSharedCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionExpectClosed, ConnectionID: attempt.connection, TimeoutMillis: timeout.Milliseconds(),
	})
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeClosed || response.CloseCode != wantCode {
		return fmt.Errorf("Browser close projection code = %d, want %d", response.CloseCode, wantCode)
	}
	return nil
}

func closeAttempt(ctx context.Context, attempt sharedOpenAttempt) error {
	response, err := sendSharedCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionClose, ConnectionID: attempt.connection, TimeoutMillis: 3_000,
	})
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeReleased {
		return errors.New("Browser connection release failed")
	}
	return nil
}

func closeAttempts(ctx context.Context, attempts []sharedOpenAttempt) {
	for _, attempt := range attempts {
		closeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		_ = closeAttempt(closeCtx, attempt)
		cancel()
	}
}

func assertRejectedNormalClosure(ctx context.Context, attempts []sharedOpenAttempt) error {
	for _, attempt := range attempts {
		if err := expectClosed(ctx, attempt, int(websocket.StatusNormalClosure), 2*time.Second); err != nil {
			return err
		}
	}
	return nil
}

func sendSharedCommand(ctx context.Context, caller *sharedCallerProcess, command wire.Command) (wire.Response, error) {
	timeout := time.Duration(command.TimeoutMillis)*time.Millisecond + 2*time.Second
	if timeout < 3*time.Second {
		timeout = 3 * time.Second
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return caller.request(commandCtx, command)
}

func sharedCapacityIdentities() ([]wire.Principal, []wire.Endpoint, []string, error) {
	tokens := make([]string, 3)
	for index := range tokens {
		var err error
		tokens[index], err = randomSecret("shared-capacity-token-")
		if err != nil {
			return nil, nil, nil, err
		}
	}
	principals := []wire.Principal{
		{ID: "a", Token: tokens[0], CallerID: "shared-caller-sensitive-a", TenantID: "tenant-sensitive-a"},
		{ID: "b", Token: tokens[1], CallerID: "shared-caller-sensitive-b", TenantID: "tenant-sensitive-b"},
		{ID: "c", Token: tokens[2], CallerID: "shared-caller-sensitive-c", TenantID: "tenant-sensitive-c"},
	}
	type endpointInput struct{ id, tenant, sandbox, session string }
	inputs := []endpointInput{
		{"a1", principals[0].TenantID, "sandbox-sensitive-a1", "browser-sensitive-a1"},
		{"a2", principals[0].TenantID, "sandbox-sensitive-a2", "browser-sensitive-a2"},
		{"a3", principals[0].TenantID, "sandbox-sensitive-a3", "browser-sensitive-a3"},
		{"b1", principals[1].TenantID, "sandbox-sensitive-b1", "browser-sensitive-b1"},
		{"b2", principals[1].TenantID, "sandbox-sensitive-b2", "browser-sensitive-b2"},
		{"c1", principals[2].TenantID, "sandbox-sensitive-c1", "browser-sensitive-c1"},
		{"c2", principals[2].TenantID, "sandbox-sensitive-c2", "browser-sensitive-c2"},
	}
	endpoints := make([]wire.Endpoint, 0, len(inputs))
	for _, input := range inputs {
		token, err := randomSecret("")
		if err != nil {
			return nil, nil, nil, err
		}
		digest := sha256.Sum256([]byte(token))
		endpoints = append(endpoints, wire.Endpoint{
			ID: input.id, TenantID: input.tenant, SandboxID: input.sandbox,
			BrowserSessionID: input.session, CapabilityProfileID: "browser-v1",
			HandoffReference: "ref:browser-session:" + hex.EncodeToString(digest[:16]), ConnectionGeneration: 1,
		})
	}
	return principals, endpoints, tokens, nil
}

func newSharedRedisClient(endpoint string, timeout time.Duration) (*goredis.Client, error) {
	options, err := goredis.ParseURL(endpoint)
	if err != nil {
		return nil, errors.New("parse shared-capacity store configuration")
	}
	options.Protocol = 2
	options.MaxRetries = -1
	options.ContextTimeoutEnabled = true
	options.DisableIdentity = true
	options.DialTimeout = timeout
	options.ReadTimeout = timeout
	options.WriteTimeout = timeout
	options.PoolTimeout = timeout
	return goredis.NewClient(options), nil
}

func waitForSharedRedis(ctx context.Context, client *goredis.Client, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		err := client.Ping(pingCtx).Err()
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("shared-capacity store did not become ready")
		case <-ticker.C:
		}
	}
}

func sharedCapacityFromLock(client *goredis.Client, namespace string, policy lock.SharedCapacityPolicy) (*rediscapacity.Capacity, error) {
	return rediscapacity.New(rediscapacity.Options{
		Client: client, Namespace: namespace,
		MaxTotal: policy.MaxTotal, MaxPerTenant: policy.MaxPerTenant, MaxPerSession: policy.MaxPerSession,
		LeaseTTL:            time.Duration(policy.LeaseTTLMillis) * time.Millisecond,
		RenewInterval:       time.Duration(policy.RenewIntervalMillis) * time.Millisecond,
		RenewalSafetyMargin: time.Duration(policy.RenewalSafetyMarginMillis) * time.Millisecond,
		OperationTimeout:    time.Duration(policy.OperationTimeoutMillis) * time.Millisecond,
	})
}

func sharedCapacityLeaseKey(namespace string) string {
	digest := sha256.Sum256([]byte(namespace))
	return "sandbox-runtime:{" + hex.EncodeToString(digest[:]) + "}:capacity:leases"
}

func removeSingleSharedLease(ctx context.Context, client *goredis.Client, namespace string) error {
	key := sharedCapacityLeaseKey(namespace)
	members, err := client.ZRange(ctx, key, 0, -1).Result()
	if err != nil || len(members) != 1 {
		return errors.Join(err, fmt.Errorf("shared-capacity lease cardinality = %d, want 1", len(members)))
	}
	removed, err := client.ZRem(ctx, key, members[0]).Result()
	if err != nil || removed != 1 {
		return errors.Join(err, errors.New("remove exact shared-capacity lease failed"))
	}
	return nil
}

func assertSharedCardinality(ctx context.Context, client *goredis.Client, namespace string, want int64) error {
	count, err := client.ZCard(ctx, sharedCapacityLeaseKey(namespace)).Result()
	if err != nil {
		return err
	}
	if count != want {
		return fmt.Errorf("shared-capacity cardinality = %d, want %d", count, want)
	}
	return nil
}

func combinedRecordCount(first, second, kind string) (int, error) {
	left, err := countSanitizedRecords(first, kind)
	if err != nil {
		return 0, err
	}
	right, err := countSanitizedRecords(second, kind)
	return left + right, err
}

func waitForCombinedRecordDelta(ctx context.Context, first, second, kind string, before, want int, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		after, err := combinedRecordCount(first, second, kind)
		if err != nil {
			return err
		}
		delta := after - before
		if want > 0 && delta == want {
			return nil
		}
		if delta > want {
			return fmt.Errorf("%s audit delta = %d, want %d", kind, delta, want)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			if delta == want {
				return nil
			}
			return fmt.Errorf("%s audit delta = %d, want %d", kind, delta, want)
		case <-ticker.C:
		}
	}
}

func assertSanitizedSharedRecords(root string, audits, observations []string) error {
	for _, name := range audits {
		if err := validateSanitizedAudit(filepath.Join(root, name)); err != nil {
			return err
		}
	}
	for _, name := range observations {
		if err := validateSanitizedObservation(filepath.Join(root, name)); err != nil {
			return err
		}
	}
	return nil
}

func assertEvidenceFileSet(root string, names []string) error {
	expected := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "" || filepath.Base(name) != name || expected[name] {
			return errors.New("shared-capacity evidence allowlist is invalid")
		}
		expected[name] = true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("shared-capacity evidence file count = %d, want %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !expected[entry.Name()] || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("shared-capacity evidence file %q is not allowed", entry.Name())
		}
	}
	return nil
}

func validateSanitizedAudit(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		"authorized": true, "denied": true, "connected": true, "reconnected": true,
		"backend_closed": true, "revoked": true, "expired": true, "client_closed": true,
		"reconnect_failed": true, "capacity_rejected": true, "capacity_unavailable": true,
		"capacity_lost": true, "capacity_release_failed": true,
	}
	var expectedSequence uint64
	for line, record := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if record == "" {
			return fmt.Errorf("sanitized audit line %d is empty", line+1)
		}
		var value struct {
			Sequence   uint64 `json:"sequence"`
			Type       string `json:"type"`
			Timestamp  string `json:"timestamp"`
			Attempt    int    `json:"attempt"`
			Frames     uint64 `json:"frames"`
			Bytes      uint64 `json:"bytes"`
			ReasonCode string `json:"reason_code,omitempty"`
		}
		decoder := json.NewDecoder(strings.NewReader(record))
		decoder.DisallowUnknownFields()
		expectedSequence++
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("sanitized audit line %d is invalid", line+1)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return fmt.Errorf("sanitized audit line %d has trailing content", line+1)
		}
		if _, err := time.Parse(time.RFC3339Nano, value.Timestamp); err != nil || value.Sequence != expectedSequence ||
			!allowed[value.Type] || value.ReasonCode != value.Type || value.Attempt < 0 {
			return fmt.Errorf("sanitized audit line %d is invalid", line+1)
		}
	}
	if expectedSequence == 0 {
		return errors.New("sanitized audit is empty")
	}
	return nil
}

func validateSanitizedObservation(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var expectedSequence uint64
	for line, record := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		if record == "" {
			return fmt.Errorf("sanitized observation line %d is empty", line+1)
		}
		var value struct {
			Sequence uint64 `json:"sequence"`
			Kind     string `json:"kind"`
		}
		decoder := json.NewDecoder(strings.NewReader(record))
		decoder.DisallowUnknownFields()
		expectedSequence++
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("sanitized observation line %d is invalid", line+1)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return fmt.Errorf("sanitized observation line %d has trailing content", line+1)
		}
		if value.Sequence != expectedSequence || (value.Kind != "resolve" && value.Kind != "dial") {
			return fmt.Errorf("sanitized observation line %d is invalid", line+1)
		}
	}
	if expectedSequence == 0 {
		return errors.New("sanitized observation is empty")
	}
	return nil
}

func waitForSharedDuration(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
