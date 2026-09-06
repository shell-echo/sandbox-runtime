package rediscapacity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	witnessedActionPolicyFormat       = "browser-downstream-action-fence-v2"
	witnessedActionCheckpointFormat   = "browser-downstream-action-checkpoint-v1"
	maxWitnessedActionHistoryEntries  = 4096
	maxWitnessSynchronizationAttempts = 4
)

// WitnessedActionFencer adds deletion and rollback detection to the ADR 0033
// exact-member action decision. It is an explicitly selected successor and
// does not rewrite or silently adopt an existing v1 action namespace.
type WitnessedActionFencer struct {
	capacity    *Capacity
	witness     ActionHistoryWitness
	policyKey   string
	stateKey    string
	policyArgs  []any
	tokenSource func() (string, error)
}

type WitnessedActionFencingDescriptor struct {
	PolicyFormat              string `json:"policy_format"`
	PolicyFingerprint         string `json:"policy_fingerprint"`
	CapacityPolicyFingerprint string `json:"capacity_policy_fingerprint"`
	ProvisionScript           string `json:"provision_script_sha1"`
	AuthorizeScript           string `json:"authorize_script_sha1"`
	CheckpointFormat          string `json:"checkpoint_format"`
	MaxClaimLifetimeMS        int64  `json:"max_claim_lifetime_ms"`
	MaxActionWindowMS         int64  `json:"max_action_window_ms"`
	MaxHistoryEntries         int    `json:"max_history_entries"`
}

func NewWitnessedActionFencer(capacity *Capacity, witness ActionHistoryWitness) (*WitnessedActionFencer, error) {
	if capacity == nil || capacity.client == nil || len(capacity.keys) != 3 || len(capacity.policyArgs) != 9 ||
		capacity.keyTag == "" || capacity.maxPerSession != 1 || nilInterface(witness) {
		return nil, gateway.ErrDownstreamUnavailable
	}
	capacityFingerprint := fmt.Sprint(capacity.policyArgs[1])
	policyInput := strings.Join([]string{
		witnessedActionPolicyFormat,
		capacityFingerprint,
		witnessedActionProvisionScript.Hash(),
		witnessedActionAuthorizeScript.Hash(),
		witnessedActionCheckpointFormat,
		strconv.FormatInt(gateway.MaxDownstreamClaimLifetime.Milliseconds(), 10),
		strconv.FormatInt(gateway.MaxDownstreamActionWindow.Milliseconds(), 10),
		strconv.Itoa(maxWitnessedActionHistoryEntries),
	}, "|")
	policyDigest := sha256.Sum256([]byte(policyInput))
	prefix := "sandbox-runtime:{" + capacity.keyTag + "}:capacity:action-fence:"
	return &WitnessedActionFencer{
		capacity:  capacity,
		witness:   witness,
		policyKey: prefix + "policy",
		stateKey:  prefix + "state",
		policyArgs: []any{
			witnessedActionPolicyFormat,
			hex.EncodeToString(policyDigest[:]),
			capacityFingerprint,
			witnessedActionAuthorizeScript.Hash(),
			witnessedActionProvisionScript.Hash(),
			gateway.MaxDownstreamClaimLifetime.Milliseconds(),
			gateway.MaxDownstreamActionWindow.Milliseconds(),
			maxWitnessedActionHistoryEntries,
		},
		tokenSource: randomActionHistoryToken,
	}, nil
}

func (f *WitnessedActionFencer) Descriptor() WitnessedActionFencingDescriptor {
	if f == nil || len(f.policyArgs) != 8 {
		return WitnessedActionFencingDescriptor{}
	}
	return WitnessedActionFencingDescriptor{
		PolicyFormat: witnessedActionPolicyFormat, PolicyFingerprint: fmt.Sprint(f.policyArgs[1]),
		CapacityPolicyFingerprint: fmt.Sprint(f.policyArgs[2]),
		ProvisionScript:           witnessedActionProvisionScript.Hash(), AuthorizeScript: witnessedActionAuthorizeScript.Hash(),
		CheckpointFormat:   witnessedActionCheckpointFormat,
		MaxClaimLifetimeMS: gateway.MaxDownstreamClaimLifetime.Milliseconds(),
		MaxActionWindowMS:  gateway.MaxDownstreamActionWindow.Milliseconds(),
		MaxHistoryEntries:  maxWitnessedActionHistoryEntries,
	}
}

// Provision preflights a virgin Redis namespace, creates the independent
// witness, then installs matching v2 state. It never upgrades v1 in place.
func (f *WitnessedActionFencer) Provision(ctx context.Context) error {
	if !f.valid() {
		return gateway.ErrDownstreamUnavailable
	}
	if err := f.capacity.Verify(ctx); err != nil {
		return actionHistoryDownstreamError(ctx, err)
	}
	checkpoint, err := f.witness.Load(ctx, f.policyFingerprint())
	if err != nil {
		if !errors.Is(err, ErrActionHistoryNotProvisioned) || downstreamContextError(ctx) != nil {
			return actionHistoryDownstreamError(ctx, err)
		}
		token, tokenErr := f.tokenSource()
		if tokenErr != nil {
			return gateway.ErrDownstreamUnavailable
		}
		checkpoint, tokenErr = NewActionHistoryCheckpoint(0, token)
		if tokenErr != nil {
			return gateway.ErrDownstreamUnavailable
		}
		if _, preflightErr := f.synchronize(ctx, "preflight", checkpoint); preflightErr != nil {
			return actionHistoryDownstreamError(ctx, preflightErr)
		}
		if provisionErr := f.witness.Provision(ctx, f.policyFingerprint(), checkpoint); provisionErr != nil {
			return actionHistoryDownstreamError(ctx, provisionErr)
		}
	}
	if _, err := f.synchronize(ctx, "provision", checkpoint); err != nil {
		return actionHistoryDownstreamError(ctx, err)
	}
	return nil
}

// Verify is runtime-only. It requires both retained Redis state and the
// independently durable witness, and may finish one acknowledged Redis
// checkpoint that was not yet committed to the witness after an interruption.
func (f *WitnessedActionFencer) Verify(ctx context.Context) error {
	if !f.valid() {
		return gateway.ErrDownstreamUnavailable
	}
	checkpoint, err := f.witness.Load(ctx, f.policyFingerprint())
	if err != nil {
		return actionHistoryDownstreamError(ctx, err)
	}
	if _, err := f.synchronize(ctx, "verify", checkpoint); err != nil {
		return actionHistoryDownstreamError(ctx, err)
	}
	return nil
}

func (f *WitnessedActionFencer) AuthorizeAction(
	ctx context.Context,
	subject gateway.DownstreamFenceSubject,
	claim gateway.DownstreamFence,
	requiredWindow time.Duration,
) (gateway.DownstreamFenceDecision, error) {
	if !f.valid() {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	if err := downstreamContextError(ctx); err != nil {
		return gateway.DownstreamFenceDecision{}, err
	}
	if subject.Validate() != nil || claim.Validate() != nil ||
		requiredWindow < gateway.MinDownstreamActionWindow || requiredWindow > gateway.MaxDownstreamActionWindow ||
		requiredWindow%time.Millisecond != 0 {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	member, parsed, err := decodeActionClaim(claim)
	if err != nil {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	capacitySubject := gateway.CapacitySubject{
		TenantID: subject.TenantID, SandboxID: subject.SandboxID,
		BrowserSessionID: subject.BrowserSessionID, CapabilityProfileID: subject.CapabilityProfileID,
		ExpiresAt: subject.ExpiresAt.UTC(),
	}
	if capacitySubject.Validate() != nil || capacitySubject.ExpiresAt.UnixMilli() > maxLuaExactInteger {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	tenant, session := subjectFingerprints(capacitySubject)
	boundExpiry := strconv.FormatInt(capacitySubject.ExpiresAt.UnixMilli(), 10)
	if parsed.tenant != tenant || parsed.session != session || parsed.boundExpiry != boundExpiry {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
	}

	for attempt := 0; attempt < maxWitnessSynchronizationAttempts; attempt++ {
		checkpoint, loadErr := f.witness.Load(ctx, f.policyFingerprint())
		if loadErr != nil {
			return gateway.DownstreamFenceDecision{}, actionHistoryDownstreamError(ctx, loadErr)
		}
		checkpoint, loadErr = f.synchronize(ctx, "verify", checkpoint)
		if loadErr != nil {
			return gateway.DownstreamFenceDecision{}, actionHistoryDownstreamError(ctx, loadErr)
		}
		nextToken, tokenErr := f.tokenSource()
		if tokenErr != nil || !actionHistoryTokenPattern.MatchString(nextToken) || nextToken == checkpoint.token {
			return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
		}
		args := appendCopy(f.capacity.policyArgs, f.policyArgs...)
		args = append(args,
			witnessedActionCheckpointFormat, checkpoint.sequence, checkpoint.token, nextToken,
			member, tenant, session, boundExpiry, actionSubjectFingerprint(subject), requiredWindow.Milliseconds(),
		)
		keys := []string{
			f.capacity.keys[0], f.capacity.keys[1], f.capacity.keys[2], f.policyKey,
			f.stateKey,
		}
		result, runErr := f.run(ctx, witnessedActionAuthorizeScript, keys, args...)
		if runErr != nil {
			return gateway.DownstreamFenceDecision{}, runErr
		}
		values, resultErr := resultStrings(result)
		if resultErr != nil || len(values) == 0 {
			return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
		}
		switch values[0] {
		case "conflict":
			if len(values) != 1 {
				return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
			}
			continue
		case "current":
			if len(values) != 1 {
				return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
			}
			return gateway.DownstreamFenceDecision{}, nil
		case "lost":
			if len(values) != 1 {
				return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
			}
			return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
		case "activated":
			if len(values) != 3 || values[2] != nextToken {
				return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
			}
			sequence, parseErr := strconv.ParseInt(values[1], 10, 64)
			replacement, checkpointErr := NewActionHistoryCheckpoint(sequence, values[2])
			if parseErr != nil || checkpointErr != nil || replacement.sequence != checkpoint.sequence+1 {
				return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
			}
			if advanceErr := f.advanceWitness(ctx, checkpoint, replacement); advanceErr != nil {
				return gateway.DownstreamFenceDecision{}, advanceErr
			}
			return gateway.DownstreamFenceDecision{Activated: true}, nil
		default:
			return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
		}
	}
	return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
}

func (f *WitnessedActionFencer) synchronize(
	ctx context.Context,
	mode string,
	checkpoint ActionHistoryCheckpoint,
) (ActionHistoryCheckpoint, error) {
	for attempt := 0; attempt < maxWitnessSynchronizationAttempts; attempt++ {
		args := appendCopy(f.capacity.policyArgs, f.policyArgs...)
		args = append(args, witnessedActionCheckpointFormat, checkpoint.sequence, checkpoint.token, mode)
		result, err := f.run(ctx, witnessedActionProvisionScript,
			[]string{f.capacity.keys[1], f.capacity.keys[2], f.policyKey, f.stateKey}, args...)
		if err != nil {
			return ActionHistoryCheckpoint{}, err
		}
		values, err := resultStrings(result)
		if err != nil || len(values) == 0 {
			return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
		}
		switch values[0] {
		case "virgin":
			if mode != "preflight" || len(values) != 1 {
				return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
			}
			return checkpoint, nil
		case "ready":
			if mode == "preflight" || len(values) != 1 {
				return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
			}
			return checkpoint, nil
		case "provisioned":
			if mode != "provision" || len(values) != 1 {
				return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
			}
			return checkpoint, nil
		case "ahead":
			if mode == "preflight" || len(values) != 3 {
				return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
			}
			sequence, parseErr := strconv.ParseInt(values[1], 10, 64)
			replacement, checkpointErr := NewActionHistoryCheckpoint(sequence, values[2])
			if parseErr != nil || checkpointErr != nil || replacement.sequence != checkpoint.sequence+1 {
				return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
			}
			if err := f.advanceWitness(ctx, checkpoint, replacement); err != nil {
				return ActionHistoryCheckpoint{}, err
			}
			checkpoint = replacement
			mode = "verify"
		default:
			return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
		}
	}
	return ActionHistoryCheckpoint{}, gateway.ErrDownstreamUnavailable
}

func (f *WitnessedActionFencer) advanceWitness(
	ctx context.Context,
	previous ActionHistoryCheckpoint,
	replacement ActionHistoryCheckpoint,
) error {
	err := f.witness.CompareAndSwap(ctx, f.policyFingerprint(), previous, replacement)
	if err != nil && !errors.Is(err, ErrActionHistoryConflict) {
		return actionHistoryDownstreamError(ctx, err)
	}
	current, loadErr := f.witness.Load(ctx, f.policyFingerprint())
	if loadErr != nil || !current.Equal(replacement) {
		return actionHistoryDownstreamError(ctx, loadErr)
	}
	return nil
}

func (f *WitnessedActionFencer) run(ctx context.Context, script *goredis.Script, keys []string, args ...any) (any, error) {
	if err := downstreamContextError(ctx); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, f.capacity.operationTimeout)
	result, err := script.Run(opCtx, f.capacity.client, keys, args...).Result()
	cancel()
	if err != nil {
		if contextErr := downstreamContextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, gateway.ErrDownstreamUnavailable
	}
	return result, nil
}

func (f *WitnessedActionFencer) valid() bool {
	return f != nil && f.capacity != nil && f.capacity.client != nil && len(f.policyArgs) == 8 &&
		f.policyKey != "" && f.stateKey != "" &&
		!nilInterface(f.witness) && f.tokenSource != nil
}

func (f *WitnessedActionFencer) policyFingerprint() string {
	if f == nil || len(f.policyArgs) < 2 {
		return ""
	}
	return fmt.Sprint(f.policyArgs[1])
}

func actionHistoryDownstreamError(ctx context.Context, err error) error {
	if contextErr := downstreamContextError(ctx); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, context.Canceled) {
		return errors.Join(gateway.ErrDownstreamUnavailable, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(gateway.ErrDownstreamUnavailable, context.DeadlineExceeded)
	}
	return gateway.ErrDownstreamUnavailable
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ gateway.DownstreamFenceAuthority = (*WitnessedActionFencer)(nil)
