//go:build darwin || linux

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	goredis "github.com/redis/go-redis/v9"
	downstreamcaller "github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/caller"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/lock"
	"github.com/shell-echo/sandbox-runtime/gateway"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
)

type downstreamFencingV2ScenarioInput struct {
	Runner                  *downstreamFencingRunner
	Scenarios               []string
	RedisClient             *goredis.Client
	OrchestratorRedisClient *goredis.Client
	CapacityNamespace       string
	WitnessPath             string
	ObservationPath         string
	Callers                 []*downstreamCallerProcess
	Identities              []downstreamFencingIdentity
	TargetID                string
	ExpectedMarker          string
	LeaseTTL                time.Duration
	IngressProcess          **childProcess
	IngressStopped          *bool
	IngressBinary           string
	ProviderConfigPath      string
	LogRoot                 string
	ProviderAddress         string
	IngressAddress          string
	Locked                  lock.DownstreamFencingLock
	LockedV2                lock.DownstreamFencingV2Lock
	Sensitive               *[]string
}

func runDownstreamFencingV2Scenarios(ctx context.Context, input downstreamFencingV2ScenarioInput) error {
	if err := validateDownstreamFencingV2ScenarioInput(ctx, input); err != nil {
		return err
	}
	stateKey := downstreamActionStateKey(input.CapacityNamespace)
	leaseKey := sharedCapacityLeaseKey(input.CapacityNamespace)
	fenceKey := downstreamCapacityFenceKey(input.CapacityNamespace)
	sessionField, err := downstreamActionSessionField(input.Identities[0])
	if err != nil {
		return err
	}
	downstreamV2Sensitive(input, stateKey, leaseKey, fenceKey, sessionField)

	fieldDeletionMarker, err := randomSecret("field-deletion-marker-")
	if err != nil {
		return err
	}
	stateDeletionMarker, err := randomSecret("state-deletion-marker-")
	if err != nil {
		return err
	}
	rollbackMarker, err := randomSecret("rollback-marker-")
	if err != nil {
		return err
	}
	downstreamV2Sensitive(input, fieldDeletionMarker, stateDeletionMarker, rollbackMarker)

	if err := input.Runner.run(ctx, input.Scenarios[10], func(ctx context.Context) error {
		return runDownstreamFencingV2DeletionScenario(
			ctx, input, stateKey, "v2-delete-field-a", "v2-field-repair-b", fieldDeletionMarker,
			func(ctx context.Context) error {
				removed, err := input.OrchestratorRedisClient.HDel(ctx, stateKey, sessionField).Result()
				if err != nil || removed != 1 {
					return errors.New("delete one retained action-history session field")
				}
				return nil
			},
		)
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[11], func(ctx context.Context) error {
		return runDownstreamFencingV2DeletionScenario(
			ctx, input, stateKey, "v2-delete-state-a", "v2-state-repair-b", stateDeletionMarker,
			func(ctx context.Context) error {
				removed, err := input.OrchestratorRedisClient.Del(ctx, stateKey).Result()
				if err != nil || removed != 1 {
					return errors.New("delete complete action-history state")
				}
				return nil
			},
		)
	}); err != nil {
		return err
	}

	var preActivationSnapshot, currentSnapshot downstreamRedisSnapshot
	if err := input.Runner.run(ctx, input.Scenarios[12], func(ctx context.Context) error {
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		preActivationSnapshot, err = captureDownstreamRedisSnapshot(
			ctx, input.OrchestratorRedisClient, stateKey, fenceKey, leaseKey,
		)
		if err != nil {
			return err
		}
		tokens, err := downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
		if err != nil {
			return err
		}
		downstreamV2Sensitive(input, tokens...)
		beforeFence, err := downstreamCapacityFence(ctx, input.OrchestratorRedisClient, input.CapacityNamespace)
		if err != nil {
			return err
		}
		current, currentSession, err := downstreamV2OpenTarget(
			ctx, input, "v2-rollback-current-a", "gateway-a",
		)
		if err != nil {
			return err
		}
		got, err := current.evaluateString(
			ctx, currentSession, downstreamSetExpression(rollbackMarker), downstreamCommandTimeout,
		)
		if err != nil || got != rollbackMarker {
			return errors.Join(err, errors.New("rollback setup mutation did not reach Chromium"))
		}
		lease, err := singleSharedLease(ctx, input.RedisClient, input.CapacityNamespace)
		if err != nil || lease.fence != beforeFence+1 {
			return errors.Join(err, errors.New("rollback setup did not advance the numerical capacity fence once"))
		}
		if err := downstreamClose(ctx, input.Callers[0], "v2-rollback-current-a"); err != nil {
			return err
		}
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		currentSnapshot, err = captureDownstreamRedisSnapshot(
			ctx, input.OrchestratorRedisClient, stateKey, fenceKey, leaseKey,
		)
		if err != nil {
			return err
		}
		tokens, err = downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
		if err != nil {
			return err
		}
		downstreamV2Sensitive(input, tokens...)
		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, preActivationSnapshot); err != nil {
			return err
		}
		before, err := downstreamObservationSnapshot(input.ObservationPath)
		if err != nil {
			return err
		}
		if err := downstreamOpen(
			ctx, input.Callers[0], "v2-restored-old-b", "gateway-b", input.Identities[0].envelope.GrantBinding.ID,
		); err != nil {
			return err
		}
		after, err := waitForDownstreamObservation(
			ctx, input.ObservationPath, before, "activation", "unavailable", 1, downstreamCommandTimeout,
		)
		if err != nil {
			return err
		}
		if err := assertDownstreamObservationDelta(before, after, "upstream_dial", "succeeded", 0); err != nil {
			return err
		}
		if err := downstreamExpectedClosed(ctx, input.Callers[0], "v2-restored-old-b", input.LeaseTTL); err != nil {
			return err
		}
		reusedFence, err := downstreamCapacityFence(ctx, input.OrchestratorRedisClient, input.CapacityNamespace)
		if err != nil || reusedFence != lease.fence {
			return errors.Join(err, errors.New("restored capacity counter did not reproduce the same numerical fence"))
		}
		return nil
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[13], func(ctx context.Context) error {
		if err := (*input.IngressProcess).Stop(); err != nil {
			return err
		}
		*input.IngressStopped = true
		failed, err := startStack(
			input.IngressBinary, input.ProviderConfigPath,
			filepath.Join(input.LogRoot, "provider-ingress-v2-rollback-rejected.log"),
		)
		if err != nil {
			return err
		}
		if err := expectDownstreamStackStartupRejected(ctx, failed, 5*time.Second, input.IngressAddress); err != nil {
			return err
		}
		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, currentSnapshot); err != nil {
			return err
		}
		if err := downstreamV2RestartIngress(ctx, input, "provider-ingress-v2-rollback-repaired.log"); err != nil {
			return err
		}
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		repaired, repairedSession, err := downstreamV2OpenTarget(ctx, input, "v2-rollback-repaired-a", "gateway-a")
		if err != nil {
			return err
		}
		got, err := repaired.evaluateString(ctx, repairedSession, downstreamReadExpression(), downstreamCommandTimeout)
		if err != nil || got != rollbackMarker {
			return errors.Join(err, errors.New("current state did not recover after rejected rollback"))
		}
		return downstreamClose(ctx, input.Callers[0], "v2-rollback-repaired-a")
	}); err != nil {
		return err
	}

	var beforeAheadSnapshot downstreamRedisSnapshot
	if err := input.Runner.run(ctx, input.Scenarios[14], func(ctx context.Context) error {
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		beforeAheadSnapshot, err = captureDownstreamRedisSnapshot(
			ctx, input.OrchestratorRedisClient, stateKey, fenceKey, leaseKey,
		)
		if err != nil {
			return err
		}
		tokens, err := downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
		if err != nil {
			return err
		}
		downstreamV2Sensitive(input, tokens...)
		if err := (*input.IngressProcess).Stop(); err != nil {
			return err
		}
		*input.IngressStopped = true
		capacity, err := sharedCapacityFromLock(input.RedisClient, input.CapacityNamespace, input.Locked.CapacityPolicy)
		if err != nil {
			return err
		}
		subject, err := downstreamFenceSubject(input.Identities[0])
		if err != nil {
			return err
		}
		lease, err := capacity.Acquire(ctx, gateway.CapacitySubject{
			TenantID: subject.TenantID, SandboxID: subject.SandboxID, BrowserSessionID: subject.BrowserSessionID,
			CapabilityProfileID: subject.CapabilityProfileID, ExpiresAt: subject.ExpiresAt,
		})
		if err != nil {
			return errors.New("acquire interrupted-CAS setup lease")
		}
		leaseReleased := false
		defer func() {
			if !leaseReleased {
				_ = lease.Release(context.Background())
			}
		}()
		fenced, ok := lease.(gateway.FencedConnectionLease)
		if !ok {
			return errors.New("interrupted-CAS setup lease lacks a downstream fence")
		}
		claim, err := fenced.DownstreamFence()
		if err != nil {
			return err
		}
		downstreamV2Sensitive(input, claim.Opaque())
		witness, err := rediscapacity.OpenFileActionHistoryWitness(input.WitnessPath)
		if err != nil {
			return errors.New("open interrupted-CAS witness")
		}
		failing := &failBeforeWitnessAdvance{ActionHistoryWitness: witness, fail: true}
		fencer, err := rediscapacity.NewWitnessedActionFencer(capacity, failing)
		if err != nil {
			_ = witness.Close()
			return err
		}
		decision, authorizeErr := fencer.AuthorizeAction(
			ctx, subject, claim, time.Duration(input.Locked.Ingress.ActionTimeoutMillis)*time.Millisecond,
		)
		closeErr := witness.Close()
		if decision.Activated || !errors.Is(authorizeErr, gateway.ErrDownstreamUnavailable) || closeErr != nil || failing.fail {
			return errors.New("interrupted witness CAS did not leave an exact unreported Redis step")
		}
		tokens, err = downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
		if err != nil {
			return err
		}
		downstreamV2Sensitive(input, tokens...)
		if err := lease.Release(ctx); err != nil {
			return err
		}
		leaseReleased = true
		if err := downstreamV2RestartIngress(ctx, input, "provider-ingress-v2-ahead-one-recovered.log"); err != nil {
			return err
		}
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		recovered, recoveredSession, err := downstreamV2OpenTarget(ctx, input, "v2-ahead-recovered-b", "gateway-b")
		if err != nil {
			return err
		}
		got, err := recovered.evaluateString(ctx, recoveredSession, downstreamReadExpression(), downstreamCommandTimeout)
		if err != nil || got != rollbackMarker {
			return errors.Join(err, errors.New("exact-ahead-one recovery did not preserve Chromium state"))
		}
		return downstreamClose(ctx, input.Callers[0], "v2-ahead-recovered-b")
	}); err != nil {
		return err
	}

	if err := input.Runner.run(ctx, input.Scenarios[15], func(ctx context.Context) error {
		if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
			return err
		}
		current, err := captureDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, stateKey, fenceKey, leaseKey)
		if err != nil {
			return err
		}
		tokens, err := downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
		if err != nil {
			return err
		}
		downstreamV2Sensitive(input, tokens...)
		if err := (*input.IngressProcess).Stop(); err != nil {
			return err
		}
		*input.IngressStopped = true
		capacity, err := sharedCapacityFromLock(input.RedisClient, input.CapacityNamespace, input.Locked.CapacityPolicy)
		if err != nil {
			return err
		}
		witness, err := rediscapacity.OpenFileActionHistoryWitness(input.WitnessPath)
		if err != nil {
			return err
		}
		checkpoint, loadErr := witness.Load(ctx, input.LockedV2.ActionFence.PolicyFingerprint)
		closeErr := witness.Close()
		if loadErr != nil || closeErr != nil || checkpoint.Sequence() < 2 {
			return errors.Join(loadErr, closeErr, errors.New("read current witnessed checkpoint"))
		}
		downstreamV2Sensitive(input, checkpoint.OpaqueToken())

		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, beforeAheadSnapshot); err != nil {
			return err
		}
		if err := verifyDownstreamWitnessedStateUnavailable(ctx, capacity, input.WitnessPath); err != nil {
			return fmt.Errorf("behind checkpoint: %w", err)
		}
		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, current); err != nil {
			return err
		}
		divergentToken := downstreamCheckpointToken(checkpoint.OpaqueToken() + "-divergent")
		downstreamV2Sensitive(input, divergentToken)
		if err := input.OrchestratorRedisClient.HSet(ctx, stateKey, "token", divergentToken).Err(); err != nil {
			return errors.New("install divergent checkpoint")
		}
		if err := verifyDownstreamWitnessedStateUnavailable(ctx, capacity, input.WitnessPath); err != nil {
			return fmt.Errorf("divergent checkpoint: %w", err)
		}
		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, current); err != nil {
			return err
		}
		intermediateToken := downstreamCheckpointToken(checkpoint.OpaqueToken() + "-intermediate")
		aheadToken := downstreamCheckpointToken(checkpoint.OpaqueToken() + "-ahead")
		downstreamV2Sensitive(input, intermediateToken, aheadToken)
		if err := input.OrchestratorRedisClient.HSet(ctx, stateKey,
			"sequence", checkpoint.Sequence()+2, "token", aheadToken,
			"previous_sequence", checkpoint.Sequence()+1, "previous_token", intermediateToken,
		).Err(); err != nil {
			return errors.New("install more-than-one-ahead checkpoint")
		}
		if err := verifyDownstreamWitnessedStateUnavailable(ctx, capacity, input.WitnessPath); err != nil {
			return fmt.Errorf("more-than-one-ahead checkpoint: %w", err)
		}
		if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, current); err != nil {
			return err
		}
		return downstreamV2RestartIngress(ctx, input, "provider-ingress-v2-checkpoint-repaired.log")
	}); err != nil {
		return err
	}
	return nil
}

func runDownstreamFencingV2DeletionScenario(
	ctx context.Context,
	input downstreamFencingV2ScenarioInput,
	stateKey string,
	connectionID string,
	repairConnectionID string,
	marker string,
	remove func(context.Context) error,
) error {
	if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
		return err
	}
	client, session, err := downstreamV2OpenTarget(ctx, input, connectionID, "gateway-a")
	if err != nil {
		return err
	}
	snapshot, err := captureDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, stateKey)
	if err != nil {
		return err
	}
	tokens, err := downstreamWitnessTokens(ctx, input.OrchestratorRedisClient, stateKey)
	if err != nil {
		return err
	}
	downstreamV2Sensitive(input, tokens...)
	if err := remove(ctx); err != nil {
		return err
	}
	before, err := downstreamObservationSnapshot(input.ObservationPath)
	if err != nil {
		return err
	}
	command, payloadBytes, err := client.prepareEvaluation(
		session, downstreamSetExpression(marker), downstreamcaller.ActionQueueCDP, downstreamCommandTimeout,
	)
	if err != nil {
		return err
	}
	if err := downstreamQueue(ctx, input.Callers[0], command, payloadBytes); err != nil {
		return err
	}
	after, err := waitForDownstreamObservation(
		ctx, input.ObservationPath, before, "action_failed", "unavailable", 1, downstreamCommandTimeout,
	)
	if err != nil {
		return err
	}
	if err := assertDownstreamActionRejected(before, after, "unavailable"); err != nil {
		return err
	}
	if err := assertDownstreamObservationDelta(before, after, "upstream_dial", "succeeded", 0); err != nil {
		return err
	}
	if err := downstreamExpectedClosed(ctx, input.Callers[0], connectionID, input.LeaseTTL); err != nil {
		return err
	}
	if err := restoreDownstreamRedisSnapshot(ctx, input.OrchestratorRedisClient, snapshot); err != nil {
		return err
	}
	if err := waitForSharedCardinality(ctx, input.RedisClient, input.CapacityNamespace, 0, input.LeaseTTL+time.Second); err != nil {
		return err
	}
	repaired, repairedSession, err := downstreamV2OpenTarget(ctx, input, repairConnectionID, "gateway-b")
	if err != nil {
		return err
	}
	got, err := repaired.evaluateString(ctx, repairedSession, downstreamReadExpression(), downstreamCommandTimeout)
	if err != nil || got != input.ExpectedMarker || got == marker {
		return errors.Join(err, errors.New("deleted action-history state reached Chromium"))
	}
	return downstreamClose(ctx, input.Callers[0], repairConnectionID)
}

func downstreamV2OpenTarget(
	ctx context.Context,
	input downstreamFencingV2ScenarioInput,
	connectionID string,
	gatewayID string,
) (*downstreamCDPClient, string, error) {
	if err := downstreamOpen(ctx, input.Callers[0], connectionID, gatewayID, input.Identities[0].envelope.GrantBinding.ID); err != nil {
		return nil, "", err
	}
	client, err := newDownstreamCDPClient(input.Callers[0], connectionID)
	if err != nil {
		return nil, "", err
	}
	session, err := client.attachTarget(ctx, input.TargetID, downstreamCommandTimeout)
	if err != nil {
		return nil, "", err
	}
	downstreamV2Sensitive(input, session)
	return client, session, nil
}

func downstreamV2RestartIngress(ctx context.Context, input downstreamFencingV2ScenarioInput, logName string) error {
	process, err := startStack(input.IngressBinary, input.ProviderConfigPath, filepath.Join(input.LogRoot, logName))
	if err != nil {
		return err
	}
	*input.IngressProcess = process
	*input.IngressStopped = false
	return waitForListenersWithin(
		ctx, process, browserListenerReadinessTimeout, input.ProviderAddress, input.IngressAddress,
	)
}

func downstreamV2Sensitive(input downstreamFencingV2ScenarioInput, values ...string) {
	if input.Sensitive == nil {
		return
	}
	*input.Sensitive = append(*input.Sensitive, values...)
}

func validateDownstreamFencingV2ScenarioInput(ctx context.Context, input downstreamFencingV2ScenarioInput) error {
	if ctx == nil || input.Runner == nil || len(input.Scenarios) != 18 || input.RedisClient == nil ||
		input.OrchestratorRedisClient == nil || input.CapacityNamespace == "" || input.WitnessPath == "" ||
		input.ObservationPath == "" || len(input.Callers) != 2 || input.Callers[0] == nil || input.Callers[1] == nil ||
		len(input.Identities) != 2 || input.TargetID == "" || input.ExpectedMarker == "" || input.LeaseTTL <= 0 ||
		input.IngressProcess == nil || *input.IngressProcess == nil || input.IngressStopped == nil ||
		input.IngressBinary == "" || input.ProviderConfigPath == "" || input.LogRoot == "" ||
		input.ProviderAddress == "" || input.IngressAddress == "" || input.Sensitive == nil ||
		input.LockedV2.EvidenceProfile != lock.DownstreamFencingV2Profile {
		return errors.New("witnessed-v2 scenario input is invalid")
	}
	return nil
}
