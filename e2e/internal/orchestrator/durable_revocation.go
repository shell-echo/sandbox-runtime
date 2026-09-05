package orchestrator

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/testenv"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
)

const durableRevocationEvidenceName = "Browser Gateway durable distributed revocation black-box evidence"

type DurableRevocationResult struct {
	EvidenceDirectory string
	Scenarios         int
	Platform          string
}

type durableRevocationManifest struct {
	CreatedAt              string                                  `json:"created_at"`
	EvidenceName           string                                  `json:"evidence_name"`
	EvidenceProfile        string                                  `json:"evidence_profile"`
	HarnessCommit          string                                  `json:"harness_commit"`
	ProviderCommit         string                                  `json:"provider_commit"`
	GatewaySourceCommit    string                                  `json:"gateway_source_commit"`
	BinaryDigests          durableRevocationBinaryDigests          `json:"binary_digests"`
	ConfigDigests          durableRevocationConfigDigests          `json:"config_digests"`
	Processes              lock.DurableRevocationProcesses         `json:"processes"`
	ProcessReconstructions int                                     `json:"gateway_process_reconstructions"`
	Valkey                 durableRevocationValkeyInfo             `json:"valkey"`
	RevocationPolicy       lock.DurableRevocationPolicy            `json:"revocation_policy"`
	Bounds                 lock.DurableRevocationBounds            `json:"bounds"`
	LocalCapacity          lock.DurableRevocationLocalCapacity     `json:"local_capacity"`
	Reconnect              lock.DurableRevocationReconnect         `json:"reconnect"`
	Adapter                lock.DurableRevocationAdapterDescriptor `json:"adapter"`
	Contract               lock.DurableRevocationContract          `json:"contract"`
	Reports                []string                                `json:"reports"`
	Audits                 []string                                `json:"audits"`
	Observations           []string                                `json:"observations"`
	ControlLogs            []string                                `json:"control_logs"`
	Faults                 []string                                `json:"faults"`
	Commands               []string                                `json:"commands"`
	NonTargets             []string                                `json:"non_targets"`
	EvidenceBoundary       string                                  `json:"evidence_boundary"`
}

type durableRevocationBinaryDigests struct {
	Gateway string `json:"gateway_sha256"`
	Caller  string `json:"caller_sha256"`
	Revoker string `json:"revoker_sha256"`
}

type durableRevocationConfigDigests struct {
	Gateways []string `json:"gateways"`
	Callers  []string `json:"callers"`
	Revoker  string   `json:"revoker"`
}

type durableRevocationValkeyInfo struct {
	Image                    string `json:"image"`
	IndexDigest              string `json:"index_digest"`
	SelectedPlatform         string `json:"selected_platform"`
	SelectedPlatformDigest   string `json:"selected_platform_digest"`
	LocalImageID             string `json:"local_image_id"`
	ServerConfigSHA256       string `json:"server_config_sha256"`
	ACLTemplateSHA256        string `json:"acl_template_sha256"`
	ProvenanceNotEstablished bool   `json:"provenance_not_established"`
	ACLRoleSeparation        bool   `json:"acl_role_separation_established"`
}

type durableScenarioRunner struct {
	report wire.Report
}

func (r *durableScenarioRunner) run(ctx context.Context, name string, scenario func(context.Context) error) error {
	return r.runMeasured(ctx, name, func(ctx context.Context) ([]wire.Measurement, error) {
		return nil, scenario(ctx)
	})
}

func (r *durableScenarioRunner) runMeasured(ctx context.Context, name string, scenario func(context.Context) ([]wire.Measurement, error)) error {
	started := time.Now()
	measurements, err := scenario(ctx)
	status := "passed"
	if err != nil {
		status = "failed"
	}
	r.report.Scenarios = append(r.report.Scenarios, wire.Scenario{
		Name: name, Status: status, DurationMillis: time.Since(started).Milliseconds(),
		GatewayProcesses: 2, Measurements: measurements,
	})
	if err != nil {
		return fmt.Errorf("durable-revocation scenario %q: %w", name, err)
	}
	return nil
}

// RunDurableRevocation executes the separately locked two-Gateway, two-caller,
// one-revoker retained-state black-box profile. It exercises no Provider route
// or Contract case and uses a fixture echo backend instead of a real Browser.
func RunDurableRevocation(ctx context.Context, options Options) (_ DurableRevocationResult, resultErr error) {
	moduleRoot, err := filepath.Abs(options.ModuleRoot)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	providerRoot, err := filepath.Abs(options.ProviderRoot)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	platform, err := dockerServerPlatform(ctx)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	if err := lock.VerifyDurableRevocation(providerRoot, platform); err != nil {
		return DurableRevocationResult{}, err
	}
	locked, err := lock.LoadDurableRevocation(providerRoot, platform)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	harnessCommit, err := lock.HarnessRevision(moduleRoot)
	if err != nil {
		return DurableRevocationResult{}, err
	}

	evidenceRoot, err := filepath.Abs(options.EvidenceRoot)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	evidenceDirectory := filepath.Join(evidenceRoot, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		return DurableRevocationResult{}, err
	}
	temporaryRoot := filepath.Join(moduleRoot, "tmp")
	if err := os.MkdirAll(temporaryRoot, 0o700); err != nil {
		return DurableRevocationResult{}, err
	}
	runRoot, err := os.MkdirTemp(temporaryRoot, runRootPrefix)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, cleanupRunRoot(temporaryRoot, runRoot)) }()

	binRoot := filepath.Join(runRoot, "bin")
	if err := os.MkdirAll(binRoot, 0o700); err != nil {
		return DurableRevocationResult{}, err
	}
	goCache := filepath.Join(runRoot, "go-cache")
	gatewayBinary := filepath.Join(binRoot, "durable-revocation-gateway")
	callerBinary := filepath.Join(binRoot, "durable-revocation-caller")
	revokerBinary := filepath.Join(binRoot, "durable-revocation-revoker")
	for _, target := range []struct{ output, packagePath string }{
		{gatewayBinary, "./cmd/durable-revocation-gateway"},
		{callerBinary, "./cmd/durable-revocation-caller"},
		{revokerBinary, "./cmd/durable-revocation-revoker"},
	} {
		if err := build(ctx, moduleRoot, goCache, nil, target.output, target.packagePath); err != nil {
			return DurableRevocationResult{}, err
		}
	}
	gatewayBinaryDigest, err := fileSHA256(gatewayBinary)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	callerBinaryDigest, err := fileSHA256(callerBinary)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	revokerBinaryDigest, err := fileSHA256(revokerBinary)
	if err != nil {
		return DurableRevocationResult{}, err
	}

	namespaceToken, err := randomSecret("")
	if err != nil {
		return DurableRevocationResult{}, err
	}
	namespace := "durable-revocation-e2e-" + namespaceToken[:24]
	namespaceDigest := sha256.Sum256([]byte(namespace))
	password, err := randomSecret("")
	if err != nil {
		return DurableRevocationResult{}, err
	}
	acl := strings.ReplaceAll(lock.DurableRevocationACLTemplate, "${PASSWORD}", password)
	acl = strings.ReplaceAll(acl, "${NAMESPACE_SHA256}", hex.EncodeToString(namespaceDigest[:]))
	image := locked.Valkey.Image + "@" + locked.Valkey.IndexDigest
	valkey, err := startSharedValkey(ctx, runRoot, image, platform, locked.Valkey.SelectedChildDigest,
		lock.DurableRevocationServerConfig, acl, "e2e", password)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	storePaused := false
	defer func() {
		if storePaused {
			unpauseCtx, cancelUnpause := context.WithTimeout(context.Background(), 5*time.Second)
			resultErr = errors.Join(resultErr, valkey.unpause(unpauseCtx))
			cancelUnpause()
		}
		closeCtx, cancelClose := context.WithTimeout(context.Background(), 15*time.Second)
		resultErr = errors.Join(resultErr, valkey.close(closeCtx))
		cancelClose()
	}()

	operationTimeout := time.Duration(locked.Policy.OperationTimeoutMillis) * time.Millisecond
	adminClient, err := newSharedRedisClient(valkey.redisURL, operationTimeout)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	if err := waitForSharedRedis(ctx, adminClient, 10*time.Second); err != nil {
		_ = adminClient.Close()
		return DurableRevocationResult{}, err
	}
	adminAuthority, err := durableRevocationFromLock(adminClient, namespace, locked.Policy)
	if err != nil {
		_ = adminClient.Close()
		return DurableRevocationResult{}, err
	}
	provisionCtx, cancelProvision := context.WithTimeout(ctx, 3*time.Second)
	err = adminAuthority.Provision(provisionCtx)
	if err == nil {
		err = adminAuthority.Verify(provisionCtx)
	}
	cancelProvision()
	closeAdminErr := adminClient.Close()
	if err != nil || closeAdminErr != nil {
		return DurableRevocationResult{}, errors.Join(errors.New("provision durable-revocation authority"), err, closeAdminErr)
	}

	secretsRoot := filepath.Join(runRoot, "secrets")
	material, err := testenv.GeneratePKI(secretsRoot, time.Now().UTC())
	if err != nil {
		return DurableRevocationResult{}, err
	}
	gatewayAddressA, err := allocateAddress()
	if err != nil {
		return DurableRevocationResult{}, err
	}
	gatewayAddressB, err := allocateAddress()
	if err != nil {
		return DurableRevocationResult{}, err
	}
	for gatewayAddressB == gatewayAddressA {
		gatewayAddressB, err = allocateAddress()
		if err != nil {
			return DurableRevocationResult{}, err
		}
	}
	expiresAt := time.Now().UTC().Add(time.Duration(locked.Bounds.GrantLifetimeMillis) * time.Millisecond)
	principals, endpoints, bindings, sensitive, err := durableRevocationIdentities(expiresAt)
	if err != nil {
		return DurableRevocationResult{}, err
	}

	stateRoot := filepath.Join(runRoot, "state")
	logRoot := filepath.Join(runRoot, "logs")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		return DurableRevocationResult{}, err
	}
	if err := os.MkdirAll(logRoot, 0o700); err != nil {
		return DurableRevocationResult{}, err
	}
	auditA := filepath.Join(stateRoot, "gateway-a-audit.jsonl")
	auditB := filepath.Join(stateRoot, "gateway-b-audit.jsonl")
	observationA := filepath.Join(stateRoot, "gateway-a-observations.jsonl")
	observationB := filepath.Join(stateRoot, "gateway-b-observations.jsonl")
	controlLog := filepath.Join(stateRoot, "revoker-control.jsonl")
	policy := wire.RevocationPolicy{
		MaxGrantLifetimeMillis: locked.Policy.MaxGrantLifetimeMillis,
		PollIntervalMillis:     locked.Policy.PollIntervalMillis,
		OperationTimeoutMillis: locked.Policy.OperationTimeoutMillis,
	}
	localCapacity := wire.LocalCapacityPolicy{
		MaxTotal: locked.LocalCapacity.MaxTotal, MaxPerTenant: locked.LocalCapacity.MaxPerTenant,
		MaxPerSession: locked.LocalCapacity.MaxPerSession,
	}
	reconnect := wire.ReconnectPolicy{
		MaxReconnects: locked.Reconnect.MaxReconnects, BackoffMillis: locked.Reconnect.ReconnectBackoffMillis,
	}
	gatewayConfigA := wire.GatewayConfig{
		Address: gatewayAddressA, ServerCertificateFile: material.GatewayCertificateFile,
		ServerPrivateKeyFile: material.GatewayPrivateKeyFile, RedisURL: valkey.redisURL,
		RevocationNamespace: namespace, RevocationPolicy: policy, AuditFile: auditA,
		ObservationFile: observationA, LocalCapacity: localCapacity, ReconnectPolicy: reconnect,
		Principals: principals, Endpoints: endpoints, GrantBindings: bindings,
	}
	gatewayConfigB := gatewayConfigA
	gatewayConfigB.Address = gatewayAddressB
	gatewayConfigB.AuditFile = auditB
	gatewayConfigB.ObservationFile = observationB
	gatewayConfigPathA := filepath.Join(secretsRoot, "gateway-a.json")
	gatewayConfigPathB := filepath.Join(secretsRoot, "gateway-b.json")
	gatewayConfigDigestA, err := writeJSON(gatewayConfigPathA, gatewayConfigA)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	gatewayConfigDigestB, err := writeJSON(gatewayConfigPathB, gatewayConfigB)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	callerConfigA := wire.CallerConfig{
		CAFile: material.CAFile, Gateways: map[string]string{"a": "https://" + gatewayAddressA},
		Principals: principals, Endpoints: endpoints, GrantBindings: bindings,
	}
	callerConfigB := wire.CallerConfig{
		CAFile: material.CAFile, Gateways: map[string]string{"b": "https://" + gatewayAddressB},
		Principals: principals, Endpoints: endpoints, GrantBindings: bindings,
	}
	callerConfigPathA := filepath.Join(secretsRoot, "caller-a.json")
	callerConfigPathB := filepath.Join(secretsRoot, "caller-b.json")
	callerConfigDigestA, err := writeJSON(callerConfigPathA, callerConfigA)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	callerConfigDigestB, err := writeJSON(callerConfigPathB, callerConfigB)
	if err != nil {
		return DurableRevocationResult{}, err
	}
	revokerConfig := wire.RevokerConfig{
		RedisURL: valkey.redisURL, RevocationNamespace: namespace, RevocationPolicy: policy,
		ControlLogFile: controlLog, GrantBindings: bindings,
	}
	revokerConfigPath := filepath.Join(secretsRoot, "revoker.json")
	revokerConfigDigest, err := writeJSON(revokerConfigPath, revokerConfig)
	if err != nil {
		return DurableRevocationResult{}, err
	}

	sensitive = append(sensitive,
		namespace, valkey.redisURL, password, gatewayAddressA, gatewayAddressB,
		"https://"+gatewayAddressA, "https://"+gatewayAddressB, runRoot,
		gatewayConfigPathA, gatewayConfigPathB, callerConfigPathA, callerConfigPathB, revokerConfigPath,
		material.CAFile, material.GatewayCertificateFile, material.GatewayPrivateKeyFile,
	)
	for sequence := 1; sequence <= 64; sequence++ {
		sensitive = append(sensitive, "durable-revocation:"+strconv.Itoa(sequence))
	}

	gatewayA, err := startStack(gatewayBinary, gatewayConfigPathA, filepath.Join(logRoot, "gateway-a-initial.log"))
	if err != nil {
		return DurableRevocationResult{}, err
	}
	gatewayAStopped := false
	defer func() {
		if gatewayA != nil && !gatewayAStopped {
			resultErr = errors.Join(resultErr, gatewayA.Stop())
		}
	}()
	gatewayB, err := startStack(gatewayBinary, gatewayConfigPathB, filepath.Join(logRoot, "gateway-b-initial.log"))
	if err != nil {
		stopErr := gatewayA.Stop()
		gatewayAStopped = stopErr == nil
		return DurableRevocationResult{}, errors.Join(err, stopErr)
	}
	gatewayBStopped := false
	defer func() {
		if gatewayB != nil && !gatewayBStopped {
			resultErr = errors.Join(resultErr, gatewayB.Stop())
		}
	}()
	if err := waitForListenersWithin(ctx, gatewayA, 15*time.Second, gatewayAddressA); err != nil {
		return DurableRevocationResult{}, err
	}
	if err := waitForListenersWithin(ctx, gatewayB, 15*time.Second, gatewayAddressB); err != nil {
		return DurableRevocationResult{}, err
	}

	callers := make([]*durableControlProcess, 2)
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
	callers[0], err = startDurableControl("caller-a", callerBinary, callerConfigPathA, filepath.Join(logRoot, "caller-a.log"))
	if err != nil {
		return DurableRevocationResult{}, err
	}
	callers[1], err = startDurableControl("caller-b", callerBinary, callerConfigPathB, filepath.Join(logRoot, "caller-b.log"))
	if err != nil {
		return DurableRevocationResult{}, err
	}
	revokerProcess, err := startDurableControl("revoker", revokerBinary, revokerConfigPath, filepath.Join(logRoot, "revoker.log"))
	if err != nil {
		return DurableRevocationResult{}, err
	}
	revokerStopped := false
	defer func() {
		if revokerStopped {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, revokerProcess.shutdown(shutdownCtx))
	}()

	commandTimeout := time.Duration(locked.Bounds.PropagationMillis) * time.Millisecond
	runner := &durableScenarioRunner{report: wire.Report{EvidenceName: durableRevocationEvidenceName}}
	if err := runner.runMeasured(ctx, lock.DurableRevocationScenarios[0], func(ctx context.Context) ([]wire.Measurement, error) {
		activeA := durableOpenAttempt{caller: callers[0], connection: "active-a", gateway: "a", binding: "active-target"}
		activeB := durableOpenAttempt{caller: callers[1], connection: "active-b", gateway: "b", binding: "active-target"}
		if err := openDurableHealthy(ctx, activeA, commandTimeout); err != nil {
			return nil, err
		}
		if err := openDurableHealthy(ctx, activeB, commandTimeout); err != nil {
			return nil, err
		}
		beforeAuditA, err := durableAuditCounts(auditA)
		if err != nil {
			return nil, err
		}
		beforeAuditB, err := durableAuditCounts(auditB)
		if err != nil {
			return nil, err
		}
		beforeObservationA, err := durableObservationCounts(observationA)
		if err != nil {
			return nil, err
		}
		beforeObservationB, err := durableObservationCounts(observationB)
		if err != nil {
			return nil, err
		}
		acknowledgedAt, err := revokeDurableAndConfirm(ctx, revokerProcess, "active-target", commandTimeout, controlLog)
		if err != nil {
			return nil, err
		}
		measurements, err := observeDurableCloses(ctx, acknowledgedAt, commandTimeout, activeA, activeB)
		if err != nil {
			return nil, err
		}
		if err := waitForDurableRecordDelta(ctx, auditA, "revoked", beforeAuditA["revoked"], 1, commandTimeout); err != nil {
			return nil, err
		}
		if err := waitForDurableRecordDelta(ctx, auditB, "revoked", beforeAuditB["revoked"], 1, commandTimeout); err != nil {
			return nil, err
		}
		afterAuditA, err := durableAuditCounts(auditA)
		if err != nil {
			return nil, err
		}
		afterAuditB, err := durableAuditCounts(auditB)
		if err != nil {
			return nil, err
		}
		afterObservationA, err := durableObservationCounts(observationA)
		if err != nil {
			return nil, err
		}
		afterObservationB, err := durableObservationCounts(observationB)
		if err != nil {
			return nil, err
		}
		if err := assertOnlyDurableAuditDelta(beforeAuditA, afterAuditA, "revoked", 1); err != nil {
			return nil, fmt.Errorf("Gateway A active-revoke audit: %w", err)
		}
		if err := assertOnlyDurableAuditDelta(beforeAuditB, afterAuditB, "revoked", 1); err != nil {
			return nil, fmt.Errorf("Gateway B active-revoke audit: %w", err)
		}
		if !equalStringIntMap(beforeObservationA, afterObservationA) || !equalStringIntMap(beforeObservationB, afterObservationB) {
			return nil, errors.New("active revoke triggered reconnect, resolve, or dial")
		}
		return measurements, nil
	}); err != nil {
		return DurableRevocationResult{}, err
	}

	if err := runner.run(ctx, lock.DurableRevocationScenarios[1], func(ctx context.Context) error {
		if _, err := revokeDurableAndConfirm(ctx, revokerProcess, "pre-revoked", commandTimeout, controlLog); err != nil {
			return err
		}
		return proveDurablePreResolutionRejection(ctx, commandTimeout,
			durableOpenAttempt{caller: callers[0], connection: "pre-a", gateway: "a", binding: "pre-revoked"},
			durableOpenAttempt{caller: callers[1], connection: "pre-b", gateway: "b", binding: "pre-revoked"},
			auditA, auditB, observationA, observationB)
	}); err != nil {
		return DurableRevocationResult{}, err
	}

	if err := runner.run(ctx, lock.DurableRevocationScenarios[2], func(ctx context.Context) error {
		if err := gatewayA.Stop(); err != nil {
			return err
		}
		gatewayAStopped = true
		if err := gatewayB.Stop(); err != nil {
			return err
		}
		gatewayBStopped = true
		gatewayA, err = startStack(gatewayBinary, gatewayConfigPathA, filepath.Join(logRoot, "gateway-a-reconstructed.log"))
		if err != nil {
			return err
		}
		gatewayAStopped = false
		gatewayB, err = startStack(gatewayBinary, gatewayConfigPathB, filepath.Join(logRoot, "gateway-b-reconstructed.log"))
		if err != nil {
			return err
		}
		gatewayBStopped = false
		if err := waitForListenersWithin(ctx, gatewayA, 15*time.Second, gatewayAddressA); err != nil {
			return err
		}
		if err := waitForListenersWithin(ctx, gatewayB, 15*time.Second, gatewayAddressB); err != nil {
			return err
		}
		return proveDurablePreResolutionRejection(ctx, commandTimeout,
			durableOpenAttempt{caller: callers[0], connection: "retained-a", gateway: "a", binding: "pre-revoked"},
			durableOpenAttempt{caller: callers[1], connection: "retained-b", gateway: "b", binding: "pre-revoked"},
			auditA, auditB, observationA, observationB)
	}); err != nil {
		return DurableRevocationResult{}, err
	}

	if err := runner.run(ctx, lock.DurableRevocationScenarios[3], func(ctx context.Context) error {
		target := durableOpenAttempt{caller: callers[0], connection: "scope-target", gateway: "a", binding: "scope-target"}
		sameSession := durableOpenAttempt{caller: callers[0], connection: "same-session", gateway: "a", binding: "same-session-other"}
		otherTenant := durableOpenAttempt{caller: callers[1], connection: "other-tenant", gateway: "b", binding: "other-tenant"}
		if err := openDurableHealthy(ctx, target, commandTimeout); err != nil {
			return err
		}
		if err := openDurableHealthy(ctx, sameSession, commandTimeout); err != nil {
			return err
		}
		if err := openDurableHealthy(ctx, otherTenant, commandTimeout); err != nil {
			return err
		}
		beforeAuditA, err := durableAuditCounts(auditA)
		if err != nil {
			return err
		}
		beforeAuditB, err := durableAuditCounts(auditB)
		if err != nil {
			return err
		}
		beforeObservationA, err := durableObservationCounts(observationA)
		if err != nil {
			return err
		}
		beforeObservationB, err := durableObservationCounts(observationB)
		if err != nil {
			return err
		}
		if _, err := revokeDurableAndConfirm(ctx, revokerProcess, "scope-target", commandTimeout, controlLog); err != nil {
			return err
		}
		if err := expectDurableClosed(ctx, target, commandTimeout); err != nil {
			return err
		}
		if err := roundTripDurable(ctx, sameSession, commandTimeout); err != nil {
			return err
		}
		if err := roundTripDurable(ctx, otherTenant, commandTimeout); err != nil {
			return err
		}
		afterAuditA, err := durableAuditCounts(auditA)
		if err != nil {
			return err
		}
		afterAuditB, err := durableAuditCounts(auditB)
		if err != nil {
			return err
		}
		afterObservationA, err := durableObservationCounts(observationA)
		if err != nil {
			return err
		}
		afterObservationB, err := durableObservationCounts(observationB)
		if err != nil {
			return err
		}
		if err := assertOnlyDurableAuditDelta(beforeAuditA, afterAuditA, "revoked", 1); err != nil {
			return fmt.Errorf("same-session scope audit: %w", err)
		}
		if err := assertOnlyDurableAuditDelta(beforeAuditB, afterAuditB, "", 0); err != nil {
			return fmt.Errorf("other-tenant scope audit: %w", err)
		}
		if !equalStringIntMap(beforeObservationA, afterObservationA) || !equalStringIntMap(beforeObservationB, afterObservationB) {
			return errors.New("exact-grant revoke triggered reconnect, resolve, or dial")
		}
		return closeDurableAttempts(ctx, commandTimeout, sameSession, otherTenant)
	}); err != nil {
		return DurableRevocationResult{}, err
	}

	if err := runner.run(ctx, lock.DurableRevocationScenarios[4], func(ctx context.Context) error {
		activeA := durableOpenAttempt{caller: callers[0], connection: "outage-active-a", gateway: "a", binding: "outage-active-a"}
		activeB := durableOpenAttempt{caller: callers[1], connection: "outage-active-b", gateway: "b", binding: "outage-active-b"}
		if err := openDurableHealthy(ctx, activeA, commandTimeout); err != nil {
			return err
		}
		if err := openDurableHealthy(ctx, activeB, commandTimeout); err != nil {
			return err
		}
		beforeAuditA, err := durableAuditCounts(auditA)
		if err != nil {
			return err
		}
		beforeAuditB, err := durableAuditCounts(auditB)
		if err != nil {
			return err
		}
		beforeObservationA, err := durableObservationCounts(observationA)
		if err != nil {
			return err
		}
		beforeObservationB, err := durableObservationCounts(observationB)
		if err != nil {
			return err
		}
		beforeControl, err := durableControlCount(controlLog)
		if err != nil {
			return err
		}
		if err := valkey.pause(ctx); err != nil {
			return err
		}
		storePaused = true
		outageCtx, cancelOutage := context.WithTimeout(ctx, time.Duration(locked.Bounds.OutageMillis)*time.Millisecond)
		defer cancelOutage()
		if err := rejectDurablePair(outageCtx, commandTimeout,
			durableOpenAttempt{caller: callers[0], connection: "outage-fresh-a", gateway: "a", binding: "outage-fresh-a"},
			durableOpenAttempt{caller: callers[1], connection: "outage-fresh-b", gateway: "b", binding: "outage-fresh-b"}); err != nil {
			return err
		}
		if _, err := observeDurableCloses(outageCtx, time.Time{}, commandTimeout, activeA, activeB); err != nil {
			return err
		}
		for attempt := 0; attempt < 2; attempt++ {
			if err := expectDurableRevokerUnavailable(outageCtx, revokerProcess, "outage-probe", commandTimeout); err != nil {
				return err
			}
		}
		if err := waitForDurableRecordDelta(outageCtx, auditA, "revocation_unavailable", beforeAuditA["revocation_unavailable"], 2, commandTimeout); err != nil {
			return err
		}
		if err := waitForDurableRecordDelta(outageCtx, auditB, "revocation_unavailable", beforeAuditB["revocation_unavailable"], 2, commandTimeout); err != nil {
			return err
		}
		afterAuditA, err := durableAuditCounts(auditA)
		if err != nil {
			return err
		}
		afterAuditB, err := durableAuditCounts(auditB)
		if err != nil {
			return err
		}
		if err := assertOnlyDurableAuditDelta(beforeAuditA, afterAuditA, "revocation_unavailable", 2); err != nil {
			return fmt.Errorf("Gateway A outage audit: %w", err)
		}
		if err := assertOnlyDurableAuditDelta(beforeAuditB, afterAuditB, "revocation_unavailable", 2); err != nil {
			return fmt.Errorf("Gateway B outage audit: %w", err)
		}
		afterObservationA, err := durableObservationCounts(observationA)
		if err != nil {
			return err
		}
		afterObservationB, err := durableObservationCounts(observationB)
		if err != nil {
			return err
		}
		if !equalStringIntMap(beforeObservationA, afterObservationA) || !equalStringIntMap(beforeObservationB, afterObservationB) {
			return errors.New("store-outage fresh work reached resolve or dial")
		}
		afterControl, err := durableControlCount(controlLog)
		if err != nil {
			return err
		}
		if afterControl != beforeControl {
			return errors.New("unavailable revoker reported a committed revocation")
		}
		if err := outageCtx.Err(); err != nil {
			return errors.New("retained-store outage exceeded its locked bound")
		}
		if err := valkey.unpause(outageCtx); err != nil {
			return err
		}
		storePaused = false
		probeClient, err := newSharedRedisClient(valkey.redisURL, operationTimeout)
		if err != nil {
			return err
		}
		defer probeClient.Close()
		return waitForSharedRedis(ctx, probeClient, 5*time.Second)
	}); err != nil {
		return DurableRevocationResult{}, err
	}

	if err := runner.run(ctx, lock.DurableRevocationScenarios[5], func(ctx context.Context) error {
		if err := proveDurablePreResolutionRejection(ctx, commandTimeout,
			durableOpenAttempt{caller: callers[0], connection: "recovery-retained-a", gateway: "a", binding: "pre-revoked"},
			durableOpenAttempt{caller: callers[1], connection: "recovery-retained-b", gateway: "b", binding: "pre-revoked"},
			auditA, auditB, observationA, observationB); err != nil {
			return err
		}
		freshA := durableOpenAttempt{caller: callers[0], connection: "recovery-fresh-a", gateway: "a", binding: "recovery-fresh-a"}
		freshB := durableOpenAttempt{caller: callers[1], connection: "recovery-fresh-b", gateway: "b", binding: "recovery-fresh-b"}
		if err := openDurableHealthy(ctx, freshA, commandTimeout); err != nil {
			return err
		}
		if err := openDurableHealthy(ctx, freshB, commandTimeout); err != nil {
			return err
		}
		return closeDurableAttempts(ctx, commandTimeout, freshA, freshB)
	}); err != nil {
		return DurableRevocationResult{}, err
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(ctx, 15*time.Second)
	for _, process := range callers {
		if err := process.shutdown(shutdownCtx); err != nil {
			cancelShutdown()
			return DurableRevocationResult{}, err
		}
	}
	callersStopped = true
	if err := revokerProcess.shutdown(shutdownCtx); err != nil {
		cancelShutdown()
		return DurableRevocationResult{}, err
	}
	revokerStopped = true
	cancelShutdown()
	if err := gatewayA.Stop(); err != nil {
		return DurableRevocationResult{}, err
	}
	gatewayAStopped = true
	if err := gatewayB.Stop(); err != nil {
		return DurableRevocationResult{}, err
	}
	gatewayBStopped = true

	auditNames := []string{"gateway-a-audit.jsonl", "gateway-b-audit.jsonl"}
	observationNames := []string{"gateway-a-observations.jsonl", "gateway-b-observations.jsonl"}
	controlName := "revoker-control.jsonl"
	for source, destination := range map[string]string{
		auditA: auditNames[0], auditB: auditNames[1], observationA: observationNames[0],
		observationB: observationNames[1], controlLog: controlName,
	} {
		if err := copyFile(source, filepath.Join(evidenceDirectory, destination)); err != nil {
			return DurableRevocationResult{}, err
		}
	}
	if err := runner.run(ctx, lock.DurableRevocationScenarios[6], func(context.Context) error {
		return validateDurableEvidenceRecords(evidenceDirectory, auditNames, observationNames, controlName)
	}); err != nil {
		return DurableRevocationResult{}, err
	}
	if err := validateDurableReport(runner.report, locked.Bounds); err != nil {
		return DurableRevocationResult{}, err
	}
	reportPath := filepath.Join(evidenceDirectory, "report.json")
	if _, err := writeJSON(reportPath, runner.report); err != nil {
		return DurableRevocationResult{}, err
	}
	manifest := durableRevocationManifest{
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), EvidenceName: durableRevocationEvidenceName,
		EvidenceProfile: locked.EvidenceProfile, HarnessCommit: harnessCommit, ProviderCommit: locked.ProviderCommit,
		GatewaySourceCommit: harnessCommit,
		BinaryDigests:       durableRevocationBinaryDigests{Gateway: gatewayBinaryDigest, Caller: callerBinaryDigest, Revoker: revokerBinaryDigest},
		ConfigDigests: durableRevocationConfigDigests{
			Gateways: []string{gatewayConfigDigestA, gatewayConfigDigestB},
			Callers:  []string{callerConfigDigestA, callerConfigDigestB}, Revoker: revokerConfigDigest,
		},
		Processes: locked.Processes, ProcessReconstructions: 2,
		Valkey: durableRevocationValkeyInfo{
			Image: image, IndexDigest: locked.Valkey.IndexDigest, SelectedPlatform: platform,
			SelectedPlatformDigest: locked.Valkey.SelectedChildDigest, LocalImageID: valkey.imageID,
			ServerConfigSHA256: locked.Valkey.ServerConfigSHA256, ACLTemplateSHA256: locked.Valkey.ACLTemplateSHA256,
			ProvenanceNotEstablished: true, ACLRoleSeparation: false,
		},
		RevocationPolicy: locked.Policy, Bounds: locked.Bounds, LocalCapacity: locked.LocalCapacity,
		Reconnect: locked.Reconnect, Adapter: locked.Adapter, Contract: locked.Contract,
		Reports: []string{filepath.Base(reportPath)}, Audits: auditNames, Observations: observationNames,
		ControlLogs: []string{controlName},
		Faults:      []string{"both Gateway process reconstructions", "retained Valkey pause/unpause"},
		Commands: []string{
			"go build ./cmd/durable-revocation-gateway", "go build ./cmd/durable-revocation-caller",
			"go build ./cmd/durable-revocation-revoker",
			"durable-revocation-gateway -config <ephemeral> (two independent processes)",
			"durable-revocation-caller -config <ephemeral> (two independent processes)",
			"durable-revocation-revoker -config <ephemeral> (one independent process)",
		},
		NonTargets: []string{
			"Provider protocol or Contract conformance", "real Browser runtime or downstream CDP fencing",
			"Valkey provenance, HA, failover, persistence, backup, or production deployment",
			"ACL role separation or least-privilege control-plane isolation", "real Agent Platform compatibility",
			"Provider multi-controller reliability", "hostile multi-tenant isolation", "deployment or production readiness",
		},
		EvidenceBoundary: "durable exact-grant revocation against one pinned retained Valkey process, two independent Gateway OS processes, two independent black-box caller OS processes, and one independent revoker OS process only; Contract identity is pinned but exercised=false; ACL role separation is not established; fixture echo streams are not a real Browser; not Provider protocol, Contract conformance, downstream CDP fencing, Valkey provenance or HA/failover, real Agent Platform compatibility, Provider multi-controller reliability, hostile multi-tenant isolation, deployment readiness, or production readiness",
	}
	if _, err := writeJSON(filepath.Join(evidenceDirectory, "manifest.json"), manifest); err != nil {
		return DurableRevocationResult{}, err
	}
	exactFiles := []string{"manifest.json", "report.json", auditNames[0], auditNames[1], observationNames[0], observationNames[1], controlName}
	if err := assertEvidenceFileSet(evidenceDirectory, exactFiles); err != nil {
		return DurableRevocationResult{}, err
	}
	if err := validateDurableEvidenceRecords(evidenceDirectory, auditNames, observationNames, controlName); err != nil {
		return DurableRevocationResult{}, err
	}
	if err := assertEvidenceExcludes(evidenceDirectory, sensitive); err != nil {
		return DurableRevocationResult{}, err
	}
	return DurableRevocationResult{EvidenceDirectory: evidenceDirectory, Scenarios: len(runner.report.Scenarios), Platform: platform}, nil
}

func durableRevocationFromLock(client *goredis.Client, namespace string, policy lock.DurableRevocationPolicy) (*redisrevocation.Revocations, error) {
	return redisrevocation.New(redisrevocation.Options{
		Client: client, Namespace: namespace,
		MaxGrantLifetime: time.Duration(policy.MaxGrantLifetimeMillis) * time.Millisecond,
		PollInterval:     time.Duration(policy.PollIntervalMillis) * time.Millisecond,
		OperationTimeout: time.Duration(policy.OperationTimeoutMillis) * time.Millisecond,
	})
}

type durableOpenAttempt struct {
	caller     *durableControlProcess
	connection string
	gateway    string
	binding    string
}

func openDurableHealthy(ctx context.Context, attempt durableOpenAttempt, timeout time.Duration) error {
	if err := openDurable(ctx, attempt, timeout); err != nil {
		return err
	}
	return roundTripDurable(ctx, attempt, timeout)
}

func openDurable(ctx context.Context, attempt durableOpenAttempt, timeout time.Duration) error {
	response, err := sendDurableCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionOpen, ConnectionID: attempt.connection, GatewayID: attempt.gateway,
		GrantBindingID: attempt.binding, TimeoutMillis: timeout.Milliseconds(),
	}, timeout)
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeOpened || !response.Upgraded || response.ErrorCode != "" {
		return errors.New("durable-revocation Browser connection was not upgraded")
	}
	return nil
}

func roundTripDurable(ctx context.Context, attempt durableOpenAttempt, timeout time.Duration) error {
	response, err := sendDurableCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionRoundTrip, ConnectionID: attempt.connection, TimeoutMillis: timeout.Milliseconds(),
	}, timeout)
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeEchoed || response.ErrorCode != "" {
		return errors.New("durable-revocation Browser echo failed")
	}
	return nil
}

func expectDurableClosed(ctx context.Context, attempt durableOpenAttempt, timeout time.Duration) error {
	response, err := sendDurableCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionExpectClosed, ConnectionID: attempt.connection, TimeoutMillis: timeout.Milliseconds(),
	}, timeout)
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeClosed || response.ErrorCode != "" ||
		response.CloseCode != int(websocket.StatusNormalClosure) {
		return errors.New("durable-revocation Browser connection did not close normally")
	}
	return nil
}

func closeDurable(ctx context.Context, attempt durableOpenAttempt, timeout time.Duration) error {
	response, err := sendDurableCommand(ctx, attempt.caller, wire.Command{
		Action: wire.ActionClose, ConnectionID: attempt.connection, TimeoutMillis: timeout.Milliseconds(),
	}, timeout)
	if err != nil {
		return err
	}
	if !response.OK || response.Outcome != wire.OutcomeReleased || response.ErrorCode != "" {
		return errors.New("durable-revocation Browser connection did not release")
	}
	return nil
}

func closeDurableAttempts(ctx context.Context, timeout time.Duration, attempts ...durableOpenAttempt) error {
	for _, attempt := range attempts {
		if err := closeDurable(ctx, attempt, timeout); err != nil {
			return err
		}
	}
	return nil
}

func sendDurableCommand(ctx context.Context, process *durableControlProcess, command wire.Command, timeout time.Duration) (wire.Response, error) {
	operationCtx, cancel := context.WithTimeout(ctx, timeout+time.Second)
	defer cancel()
	return process.request(operationCtx, command)
}

func revokeDurable(ctx context.Context, process *durableControlProcess, binding string, timeout time.Duration) (time.Time, error) {
	response, err := sendDurableCommand(ctx, process, wire.Command{
		Action: wire.ActionRevoke, GrantBindingID: binding, TimeoutMillis: timeout.Milliseconds(),
	}, timeout)
	acknowledgedAt := time.Now()
	if err != nil {
		return time.Time{}, err
	}
	if !response.OK || response.Outcome != wire.OutcomeRevoked || response.ErrorCode != "" {
		return time.Time{}, fmt.Errorf("durable-revocation control failed with %q", response.ErrorCode)
	}
	return acknowledgedAt, nil
}

func revokeDurableAndConfirm(ctx context.Context, process *durableControlProcess, binding string, timeout time.Duration, controlLog string) (time.Time, error) {
	before, err := durableControlCount(controlLog)
	if err != nil {
		return time.Time{}, err
	}
	acknowledgedAt, err := revokeDurable(ctx, process, binding, timeout)
	if err != nil {
		return time.Time{}, err
	}
	if err := assertLatestDurableCommit(controlLog, before, acknowledgedAt); err != nil {
		return time.Time{}, err
	}
	return acknowledgedAt, nil
}

func expectDurableRevokerUnavailable(ctx context.Context, process *durableControlProcess, binding string, timeout time.Duration) error {
	response, err := sendDurableCommand(ctx, process, wire.Command{
		Action: wire.ActionRevoke, GrantBindingID: binding, TimeoutMillis: timeout.Milliseconds(),
	}, timeout)
	if err != nil {
		return err
	}
	if response.OK || response.Outcome != "" || response.ErrorCode != wire.ErrorRevocationUnavailable {
		return fmt.Errorf("faulted revoker returned %q instead of stable revocation_unavailable", response.ErrorCode)
	}
	return nil
}

func observeDurableCloses(ctx context.Context, acknowledgedAt time.Time, timeout time.Duration, attempts ...durableOpenAttempt) ([]wire.Measurement, error) {
	type result struct {
		index int
		at    time.Time
		err   error
	}
	results := make(chan result, len(attempts))
	var wait sync.WaitGroup
	for index, attempt := range attempts {
		wait.Add(1)
		go func(index int, attempt durableOpenAttempt) {
			defer wait.Done()
			err := expectDurableClosed(ctx, attempt, timeout)
			results <- result{index: index, at: time.Now(), err: err}
		}(index, attempt)
	}
	wait.Wait()
	close(results)
	measurements := make([]wire.Measurement, len(attempts))
	for result := range results {
		if result.err != nil {
			return nil, result.err
		}
		if acknowledgedAt.IsZero() {
			continue
		}
		elapsed := result.at.Sub(acknowledgedAt)
		if elapsed < 0 || elapsed > timeout {
			return nil, errors.New("revocation propagation exceeded its locked bound")
		}
		measurements[result.index] = wire.Measurement{
			GatewayID: attempts[result.index].gateway, AckToCloseMillis: elapsed.Milliseconds(),
		}
	}
	if acknowledgedAt.IsZero() {
		return nil, nil
	}
	return measurements, nil
}

func rejectDurablePair(ctx context.Context, timeout time.Duration, attempts ...durableOpenAttempt) error {
	if len(attempts) != 2 {
		return errors.New("durable-revocation pair must contain two attempts")
	}
	errorsByAttempt := make([]error, len(attempts))
	var wait sync.WaitGroup
	for index, attempt := range attempts {
		wait.Add(1)
		go func(index int, attempt durableOpenAttempt) {
			defer wait.Done()
			if err := openDurable(ctx, attempt, timeout); err != nil {
				errorsByAttempt[index] = err
				return
			}
			errorsByAttempt[index] = expectDurableClosed(ctx, attempt, timeout)
		}(index, attempt)
	}
	wait.Wait()
	return errors.Join(errorsByAttempt...)
}

func proveDurablePreResolutionRejection(
	ctx context.Context,
	timeout time.Duration,
	attemptA, attemptB durableOpenAttempt,
	auditA, auditB, observationA, observationB string,
) error {
	beforeAuditA, err := durableAuditCounts(auditA)
	if err != nil {
		return err
	}
	beforeAuditB, err := durableAuditCounts(auditB)
	if err != nil {
		return err
	}
	beforeObservationA, err := durableObservationCounts(observationA)
	if err != nil {
		return err
	}
	beforeObservationB, err := durableObservationCounts(observationB)
	if err != nil {
		return err
	}
	if err := rejectDurablePair(ctx, timeout, attemptA, attemptB); err != nil {
		return err
	}
	if err := waitForDurableRecordDelta(ctx, auditA, "revoked", beforeAuditA["revoked"], 1, timeout); err != nil {
		return err
	}
	if err := waitForDurableRecordDelta(ctx, auditB, "revoked", beforeAuditB["revoked"], 1, timeout); err != nil {
		return err
	}
	afterAuditA, err := durableAuditCounts(auditA)
	if err != nil {
		return err
	}
	afterAuditB, err := durableAuditCounts(auditB)
	if err != nil {
		return err
	}
	afterObservationA, err := durableObservationCounts(observationA)
	if err != nil {
		return err
	}
	afterObservationB, err := durableObservationCounts(observationB)
	if err != nil {
		return err
	}
	if err := assertOnlyDurableAuditDelta(beforeAuditA, afterAuditA, "revoked", 1); err != nil {
		return fmt.Errorf("Gateway A pre-resolution audit: %w", err)
	}
	if err := assertOnlyDurableAuditDelta(beforeAuditB, afterAuditB, "revoked", 1); err != nil {
		return fmt.Errorf("Gateway B pre-resolution audit: %w", err)
	}
	if !equalStringIntMap(beforeObservationA, afterObservationA) || !equalStringIntMap(beforeObservationB, afterObservationB) {
		return errors.New("pre-revoked work reached resolve or dial")
	}
	return nil
}

func durableRevocationIdentities(expiresAt time.Time) ([]wire.Principal, []wire.Endpoint, []wire.GrantBinding, []string, error) {
	callerA, err := randomSecret("caller-")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	callerB, err := randomSecret("caller-")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tenantA, err := randomSecret("tenant-")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tenantB, err := randomSecret("tenant-")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tokenA, err := randomSecret("")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	tokenB, err := randomSecret("")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	principals := []wire.Principal{
		{ID: "principal-a", Token: tokenA, CallerID: callerA, TenantID: tenantA},
		{ID: "principal-b", Token: tokenB, CallerID: callerB, TenantID: tenantB},
	}
	endpointA, err := durableEndpoint("endpoint-a", tenantA)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	endpointB, err := durableEndpoint("endpoint-b", tenantB)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	endpoints := []wire.Endpoint{endpointA, endpointB}
	expiry := expiresAt.UTC().Format(time.RFC3339Nano)
	inputs := []struct {
		id, principal, endpoint string
	}{
		{"active-target", "principal-a", "endpoint-a"},
		{"pre-revoked", "principal-a", "endpoint-a"},
		{"scope-target", "principal-a", "endpoint-a"},
		{"same-session-other", "principal-a", "endpoint-a"},
		{"other-tenant", "principal-b", "endpoint-b"},
		{"outage-active-a", "principal-a", "endpoint-a"},
		{"outage-active-b", "principal-b", "endpoint-b"},
		{"outage-fresh-a", "principal-a", "endpoint-a"},
		{"outage-fresh-b", "principal-b", "endpoint-b"},
		{"outage-probe", "principal-a", "endpoint-a"},
		{"recovery-fresh-a", "principal-a", "endpoint-a"},
		{"recovery-fresh-b", "principal-b", "endpoint-b"},
	}
	bindings := make([]wire.GrantBinding, 0, len(inputs))
	sensitive := []string{"principal-a", "principal-b", callerA, callerB, tenantA, tenantB, tokenA, tokenB, expiry}
	for _, input := range inputs {
		grant, err := randomSecret("grant-")
		if err != nil {
			return nil, nil, nil, nil, err
		}
		bindings = append(bindings, wire.GrantBinding{
			ID: input.id, GrantID: grant, PrincipalID: input.principal, EndpointID: input.endpoint, ExpiresAt: expiry,
		})
		sensitive = append(sensitive, grant)
	}
	for _, endpoint := range endpoints {
		sensitive = append(sensitive, endpoint.ID, endpoint.TenantID, endpoint.SandboxID,
			endpoint.BrowserSessionID, endpoint.HandoffReference)
	}
	return principals, endpoints, bindings, sensitive, nil
}

func durableEndpoint(id, tenant string) (wire.Endpoint, error) {
	sandbox, err := randomSecret("sandbox-")
	if err != nil {
		return wire.Endpoint{}, err
	}
	session, err := randomSecret("session-")
	if err != nil {
		return wire.Endpoint{}, err
	}
	reference, err := randomSecret("")
	if err != nil {
		return wire.Endpoint{}, err
	}
	return wire.Endpoint{
		ID: id, TenantID: tenant, SandboxID: sandbox, BrowserSessionID: session,
		CapabilityProfileID: "browser-v1", HandoffReference: "ref:browser-session:" + reference[:32],
		ConnectionGeneration: 1,
	}, nil
}

type durableAuditRecord struct {
	Sequence   uint64 `json:"sequence"`
	Type       string `json:"type"`
	Timestamp  string `json:"timestamp"`
	Attempt    int    `json:"attempt"`
	Frames     uint64 `json:"frames"`
	Bytes      uint64 `json:"bytes"`
	ReasonCode string `json:"reason_code"`
}

var durableAuditTypes = map[string]bool{
	"authorized": true, "denied": true, "connected": true, "reconnected": true,
	"backend_closed": true, "revoked": true, "expired": true, "client_closed": true,
	"reconnect_failed": true, "capacity_rejected": true, "capacity_unavailable": true,
	"capacity_lost": true, "capacity_release_failed": true, "revocation_unavailable": true,
}

func durableAuditCounts(path string) (map[string]int, error) {
	records, err := readDurableAudit(path, true)
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int)
	for _, record := range records {
		counts[record.Type]++
	}
	return counts, nil
}

func durableRecordCount(path, kind string) (int, error) {
	counts, err := durableAuditCounts(path)
	if err != nil {
		return 0, err
	}
	return counts[kind], nil
}

func readDurableAudit(path string, allowMissing bool) ([]durableAuditRecord, error) {
	file, err := os.Open(path)
	if allowMissing && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxDurableRevocationRecordBytes)
	var records []durableAuditRecord
	var expectedSequence uint64
	for scanner.Scan() {
		var record durableAuditRecord
		if err := decodeDurableLine(scanner.Bytes(), &record); err != nil {
			return nil, errors.New("durable-revocation audit is invalid")
		}
		expectedSequence++
		at, err := time.Parse(time.RFC3339Nano, record.Timestamp)
		if err != nil || at.UTC().Format(time.RFC3339Nano) != record.Timestamp || record.Sequence != expectedSequence ||
			!durableAuditTypes[record.Type] || record.ReasonCode != record.Type || record.Attempt < 0 {
			return nil, errors.New("durable-revocation audit is invalid")
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func waitForDurableRecordDelta(ctx context.Context, path, kind string, before, want int, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		after, err := durableRecordCount(path, kind)
		if err != nil {
			return err
		}
		delta := after - before
		if delta == want {
			return nil
		}
		if delta > want {
			return fmt.Errorf("%s audit delta = %d, want %d", kind, delta, want)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("%s audit delta = %d, want %d", kind, delta, want)
		case <-ticker.C:
		}
	}
}

func assertOnlyDurableAuditDelta(before, after map[string]int, expected string, want int) error {
	for kind := range durableAuditTypes {
		delta := after[kind] - before[kind]
		expectedDelta := 0
		if kind == expected {
			expectedDelta = want
		}
		if delta != expectedDelta {
			return fmt.Errorf("%s audit delta = %d, want %d", kind, delta, expectedDelta)
		}
	}
	return nil
}

type durableObservationRecord struct {
	Sequence uint64 `json:"sequence"`
	Kind     string `json:"kind"`
}

func durableObservationCounts(path string) (map[string]int, error) {
	records, err := readDurableObservations(path, true)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{"resolve": 0, "dial": 0}
	for _, record := range records {
		counts[record.Kind]++
	}
	return counts, nil
}

func readDurableObservations(path string, allowMissing bool) ([]durableObservationRecord, error) {
	file, err := os.Open(path)
	if allowMissing && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxDurableRevocationRecordBytes)
	var records []durableObservationRecord
	var expectedSequence uint64
	for scanner.Scan() {
		var record durableObservationRecord
		if err := decodeDurableLine(scanner.Bytes(), &record); err != nil {
			return nil, errors.New("durable-revocation observation is invalid")
		}
		expectedSequence++
		if record.Sequence != expectedSequence || (record.Kind != "resolve" && record.Kind != "dial") {
			return nil, errors.New("durable-revocation observation is invalid")
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func equalStringIntMap(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

type durableControlRecord struct {
	Sequence       uint64 `json:"sequence"`
	Type           string `json:"type"`
	Timestamp      string `json:"timestamp"`
	DurationMillis int64  `json:"duration_millis"`
}

func durableControlCount(path string) (int, error) {
	records, err := readDurableControl(path, true)
	return len(records), err
}

func assertLatestDurableCommit(path string, before int, acknowledgedAt time.Time) error {
	records, err := readDurableControl(path, false)
	if err != nil {
		return err
	}
	if len(records) != before+1 {
		return fmt.Errorf("revoker control log count = %d, want %d", len(records), before+1)
	}
	committedAt, err := time.Parse(time.RFC3339Nano, records[len(records)-1].Timestamp)
	if err != nil || committedAt.After(acknowledgedAt) {
		return errors.New("revoker control acknowledgement ordering is invalid")
	}
	return nil
}

func readDurableControl(path string, allowMissing bool) ([]durableControlRecord, error) {
	file, err := os.Open(path)
	if allowMissing && errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), maxDurableRevocationRecordBytes)
	var records []durableControlRecord
	var expectedSequence uint64
	var previous time.Time
	for scanner.Scan() {
		var record durableControlRecord
		if err := decodeDurableLine(scanner.Bytes(), &record); err != nil {
			return nil, errors.New("durable-revocation control log is invalid")
		}
		expectedSequence++
		at, err := time.Parse(time.RFC3339Nano, record.Timestamp)
		if err != nil || at.UTC().Format(time.RFC3339Nano) != record.Timestamp || record.Sequence != expectedSequence ||
			record.Type != "revoke_committed" || record.DurationMillis < 0 || (!previous.IsZero() && at.Before(previous)) {
			return nil, errors.New("durable-revocation control log is invalid")
		}
		previous = at
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func decodeDurableLine(content []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("durable-revocation JSONL record has trailing content")
	}
	return nil
}

func validateDurableEvidenceRecords(root string, audits, observations []string, control string) error {
	for _, name := range audits {
		records, err := readDurableAudit(filepath.Join(root, name), false)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return errors.New("durable-revocation audit is empty")
		}
	}
	for _, name := range observations {
		records, err := readDurableObservations(filepath.Join(root, name), false)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			return errors.New("durable-revocation observation is empty")
		}
	}
	controlRecords, err := readDurableControl(filepath.Join(root, control), false)
	if err != nil {
		return err
	}
	if len(controlRecords) != 3 {
		return fmt.Errorf("durable-revocation committed control count = %d, want 3", len(controlRecords))
	}
	return nil
}

func validateDurableReport(report wire.Report, bounds lock.DurableRevocationBounds) error {
	if report.EvidenceName != durableRevocationEvidenceName {
		return errors.New("durable-revocation report evidence name is invalid")
	}
	expected := lock.DurableRevocationScenarioNames()
	if len(report.Scenarios) != len(expected) {
		return fmt.Errorf("durable-revocation report scenarios = %d, want %d", len(report.Scenarios), len(expected))
	}
	for index, scenario := range report.Scenarios {
		if scenario.Name != expected[index] || scenario.Status != "passed" || scenario.DurationMillis < 0 || scenario.GatewayProcesses != 2 {
			return fmt.Errorf("durable-revocation report scenario %d is invalid", index+1)
		}
		if index != 0 && len(scenario.Measurements) != 0 {
			return fmt.Errorf("durable-revocation report scenario %d has unexpected measurements", index+1)
		}
	}
	measurements := report.Scenarios[0].Measurements
	if len(measurements) != 2 || measurements[0].GatewayID != "a" || measurements[1].GatewayID != "b" {
		return errors.New("durable-revocation propagation measurements do not identify both Gateways")
	}
	for _, measurement := range measurements {
		if measurement.AckToCloseMillis < 0 || measurement.AckToCloseMillis > bounds.PropagationMillis {
			return errors.New("durable-revocation propagation measurement exceeds its locked bound")
		}
	}
	return nil
}
