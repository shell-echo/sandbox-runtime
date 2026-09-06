//go:build darwin || linux

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	downstreamcaller "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
)

type downstreamPostgresRestoreScenarioInput struct {
	Runner                   *downstreamFencingRunner
	Scenarios                []string
	RedisClient              *goredis.Client
	OrchestratorRedisClient  *goredis.Client
	CapacityNamespace        string
	ObservationPath          string
	Callers                  []*downstreamCallerProcess
	Identities               []downstreamFencingIdentity
	TargetID                 string
	ExpectedMarker           string
	LeaseTTL                 time.Duration
	IngressProcess           **childProcess
	IngressStopped           *bool
	IngressBinary            string
	StrictProviderConfigPath string
	LogRoot                  string
	ProviderAddress          string
	IngressAddress           string
	Locked                   lock.DownstreamFencingLock
	LockedPostgres           lock.PostgresControlledRestoreLock
	PostgresPool             *pgxpool.Pool
	Sensitive                *[]string
}

func runDownstreamPostgresRestoreScenarios(ctx context.Context, input downstreamPostgresRestoreScenarioInput) error {
	if err := validateDownstreamPostgresRestoreScenarioInput(ctx, input); err != nil {
		return err
	}
	capacity, err := sharedCapacityFromLock(input.RedisClient, input.CapacityNamespace, input.Locked.CapacityPolicy)
	if err != nil {
		return err
	}
	witness, err := rediscapacity.NewPostgresActionHistoryWitness(rediscapacity.PostgresActionHistoryWitnessOptions{
		Capacity: capacity, Pool: input.PostgresPool,
		OperationTimeout: time.Duration(input.LockedPostgres.Witness.OperationTimeoutMillis) * time.Millisecond,
	})
	if err != nil {
		return errors.New("construct PostgreSQL restore witness probe")
	}
	policyFingerprint := input.LockedPostgres.ActionFence.PolicyFingerprint
	stateKey := downstreamActionStateKey(input.CapacityNamespace)
	fenceKey := downstreamCapacityFenceKey(input.CapacityNamespace)
	leaseKey := sharedCapacityLeaseKey(input.CapacityNamespace)
	downstreamPostgresSensitive(input, stateKey, fenceKey, leaseKey)

	var olderSnapshot, currentSnapshot downstreamRedisSnapshot
	var currentCheckpoint rediscapacity.ActionHistoryCheckpoint
	resumeMarker, err := randomSecret("postgres-restore-marker-")
	if err != nil {
		return err
	}
	downstreamPostgresSensitive(input, resumeMarker)

	if err := input.Runner.run(ctx, input.Scenarios[10], func(ctx context.Context) error {
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		olderSnapshot, err = captureDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, stateKey, fenceKey, leaseKey)
		if err != nil {
			return err
		}
		olderCheckpoint, err := witness.Load(ctx, policyFingerprint)
		if err != nil {
			return errors.New("load PostgreSQL checkpoint before restore setup")
		}
		downstreamPostgresSensitive(input, olderCheckpoint.OpaqueToken())
		tokens, err := downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
		if err != nil {
			return err
		}
		downstreamPostgresSensitive(input, tokens...)
		if err := downstreamOpen(ctx, input.Callers[0], "postgres-current-a", "gateway-a", input.Identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		client, err := newDownstreamCDPClient(input.Callers[0], "postgres-current-a")
		if err != nil {
			return err
		}
		session, err := client.attachTarget(ctx, input.TargetID, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		downstreamPostgresSensitive(input, session)
		got, err := client.evaluateString(ctx, session, downstreamSetExpression(resumeMarker), downstreamCommandTimeout)
		if err != nil || got != resumeMarker {
			return errors.Join(err, errors.New("controlled-restore setup mutation did not reach Chromium"))
		}
		if err := downstreamClose(ctx, input.Callers[0], "postgres-current-a"); err != nil {
			return err
		}
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		currentSnapshot, err = captureDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, stateKey, fenceKey, leaseKey)
		if err != nil {
			return err
		}
		currentCheckpoint, err = witness.Load(ctx, policyFingerprint)
		if err != nil || currentCheckpoint.Sequence() != olderCheckpoint.Sequence()+1 || currentCheckpoint.Equal(olderCheckpoint) {
			return errors.Join(err, errors.New("controlled-restore setup did not advance PostgreSQL exactly once"))
		}
		downstreamPostgresSensitive(input, currentCheckpoint.OpaqueToken())
		tokens, err = downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
		if err != nil {
			return err
		}
		downstreamPostgresSensitive(input, tokens...)
		if err := (*input.IngressProcess).Stop(); err != nil {
			return err
		}
		*input.IngressStopped = true
		if err := assertDownstreamListenersUnavailable(input.ProviderAddress, input.IngressAddress); err != nil {
			return err
		}
		return probeDownstreamNoBypass(ctx, input, "postgres-quarantine-no-bypass-b")
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[11], func(ctx context.Context) error {
		if !*input.IngressStopped {
			return errors.New("controlled Redis restore began without ingress quarantine")
		}
		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, olderSnapshot); err != nil {
			return err
		}
		checkpoint, err := witness.Load(ctx, policyFingerprint)
		if err != nil || !checkpoint.Equal(currentCheckpoint) {
			return errors.Join(err, errors.New("Redis restore changed the retained PostgreSQL checkpoint"))
		}
		return assertDownstreamListenersUnavailable(input.ProviderAddress, input.IngressAddress)
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[12], func(ctx context.Context) error {
		failed, err := startStack(
			input.IngressBinary, input.StrictProviderConfigPath,
			filepath.Join(input.LogRoot, "provider-ingress-postgres-old-restore-rejected.log"),
		)
		if err != nil {
			return err
		}
		if err := expectDownstreamStackStartupRejected(
			ctx, failed, 5*time.Second, input.ProviderAddress, input.IngressAddress,
		); err != nil {
			return err
		}
		checkpoint, err := witness.Load(ctx, policyFingerprint)
		if err != nil || !checkpoint.Equal(currentCheckpoint) {
			return errors.Join(err, errors.New("strict rejected-state verification advanced PostgreSQL"))
		}
		return assertDownstreamListenersUnavailable(input.ProviderAddress, input.IngressAddress)
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[13], func(ctx context.Context) error {
		if !*input.IngressStopped {
			return errors.New("exact Redis repair began without ingress quarantine")
		}
		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, currentSnapshot); err != nil {
			return err
		}
		checkpoint, err := witness.Load(ctx, policyFingerprint)
		if err != nil || !checkpoint.Equal(currentCheckpoint) {
			return errors.Join(err, errors.New("exact Redis repair changed PostgreSQL"))
		}
		return assertDownstreamListenersUnavailable(input.ProviderAddress, input.IngressAddress)
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[14], func(ctx context.Context) error {
		process, err := startStack(
			input.IngressBinary, input.StrictProviderConfigPath,
			filepath.Join(input.LogRoot, "provider-ingress-postgres-exact-restore-resumed.log"),
		)
		if err != nil {
			return err
		}
		*input.IngressProcess = process
		*input.IngressStopped = false
		if err := waitForListenersWithin(
			ctx, process, browserListenerReadinessTimeout, input.ProviderAddress, input.IngressAddress,
		); err != nil {
			return err
		}
		checkpoint, err := witness.Load(ctx, policyFingerprint)
		if err != nil || !checkpoint.Equal(currentCheckpoint) {
			return errors.Join(err, errors.New("successful strict restore verification advanced PostgreSQL"))
		}
		return nil
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[15], func(ctx context.Context) error {
		if err := downstreamOpen(ctx, input.Callers[0], "postgres-resumed-b", "gateway-b", input.Identities[0].envelope.GrantBinding.ID); err != nil {
			return err
		}
		client, err := newDownstreamCDPClient(input.Callers[0], "postgres-resumed-b")
		if err != nil {
			return err
		}
		session, err := client.attachTarget(ctx, input.TargetID, downstreamCommandTimeout)
		if err != nil {
			return err
		}
		downstreamPostgresSensitive(input, session)
		got, err := client.evaluateString(ctx, session, downstreamReadExpression(), downstreamCommandTimeout)
		if err != nil || got != resumeMarker || got == input.ExpectedMarker {
			return errors.Join(err, errors.New("resumed Chromium did not retain the exact current state"))
		}
		postResumeMarker, err := randomSecret("postgres-post-resume-marker-")
		if err != nil {
			return err
		}
		downstreamPostgresSensitive(input, postResumeMarker)
		got, err = client.evaluateString(ctx, session, downstreamSetExpression(postResumeMarker), downstreamCommandTimeout)
		if err != nil || got != postResumeMarker {
			return errors.Join(err, errors.New("post-resume real-CDP mutation failed"))
		}
		return downstreamClose(ctx, input.Callers[0], "postgres-resumed-b")
	}); err != nil {
		return err
	}
	return nil
}

func validateDownstreamPostgresRestoreScenarioInput(ctx context.Context, input downstreamPostgresRestoreScenarioInput) error {
	if ctx == nil || input.Runner == nil || len(input.Scenarios) != 18 || input.RedisClient == nil ||
		input.OrchestratorRedisClient == nil || input.CapacityNamespace == "" || input.ObservationPath == "" ||
		len(input.Callers) != 2 || input.Callers[0] == nil || input.Callers[1] == nil || len(input.Identities) != 2 ||
		input.TargetID == "" || input.ExpectedMarker == "" || input.LeaseTTL <= 0 || input.IngressProcess == nil ||
		*input.IngressProcess == nil || input.IngressStopped == nil || input.IngressBinary == "" ||
		input.StrictProviderConfigPath == "" || input.LogRoot == "" || input.ProviderAddress == "" ||
		input.IngressAddress == "" || input.PostgresPool == nil || input.Sensitive == nil ||
		input.LockedPostgres.EvidenceProfile != lock.PostgresControlledRestoreProfile {
		return errors.New("PostgreSQL controlled-restore scenario input is invalid")
	}
	return nil
}

func probeDownstreamNoBypass(ctx context.Context, input downstreamPostgresRestoreScenarioInput, connectionID string) error {
	before, err := downstreamObservationSnapshot(input.ObservationPath)
	if err != nil {
		return err
	}
	openCtx, cancel := context.WithTimeout(ctx, downstreamCommandTimeout+time.Second)
	response, requestErr := input.Callers[1].request(openCtx, downstreamcaller.Command{
		Action: downstreamcaller.ActionOpen, ConnectionID: connectionID, GatewayID: "gateway-b",
		GrantBindingID: input.Identities[1].envelope.GrantBinding.ID, TimeoutMillis: downstreamCommandTimeout.Milliseconds(),
	})
	cancel()
	if requestErr != nil {
		return requestErr
	}
	if response.OK {
		if response.Outcome != downstreamcaller.OutcomeOpened || !response.Upgraded || response.ErrorCode != "" {
			return errors.New("quarantine no-bypass probe returned an invalid open response")
		}
		if err := downstreamExpectedClosed(ctx, input.Callers[1], connectionID, downstreamCommandTimeout); err != nil {
			return err
		}
	} else if response.ErrorCode != downstreamcaller.ErrorNotUpgraded && response.ErrorCode != downstreamcaller.ErrorUpgradeFailed {
		return errors.New("quarantine no-bypass probe did not fail closed")
	}
	after, err := downstreamObservationSnapshot(input.ObservationPath)
	if err != nil {
		return err
	}
	if !downstreamObservationsEqual(before, after) {
		return errors.New("Gateway reached a private downstream path during ingress quarantine")
	}
	return nil
}

func assertDownstreamListenersUnavailable(addresses ...string) error {
	if len(addresses) == 0 {
		return errors.New("listener quarantine addresses are unavailable")
	}
	for _, address := range addresses {
		connection, err := net.DialTimeout("tcp4", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return fmt.Errorf("quarantined listener %s remained reachable", address)
		}
	}
	return nil
}

func downstreamPostgresSensitive(input downstreamPostgresRestoreScenarioInput, values ...string) {
	if input.Sensitive != nil {
		*input.Sensitive = append(*input.Sensitive, values...)
	}
}
