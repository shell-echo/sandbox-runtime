package rediscapacity

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	actionPolicyFormat = "browser-downstream-action-fence-v1"
	actionClaimPrefix  = "v1."
)

var capacityMemberPattern = regexp.MustCompile(
	`^([0-9a-f]{32}):([0-9]{20}):([0-9a-f]{64}):([0-9a-f]{64}):([0-9]{1,15})$`,
)

// ActionFencer verifies one opaque capacity claim at the downstream Browser
// ingress. It shares the capacity hash tag but owns a separate immutable policy
// and retained per-session high-water records.
type ActionFencer struct {
	capacity        *Capacity
	policyKey       string
	highWaterPrefix string
	policyArgs      []any
}

// ActionFencingDescriptor contains only stable policy and program identities.
// It deliberately excludes the namespace, Redis keys, claims, subjects,
// owners, and fencing values.
type ActionFencingDescriptor struct {
	PolicyFormat              string `json:"policy_format"`
	PolicyFingerprint         string `json:"policy_fingerprint"`
	CapacityPolicyFingerprint string `json:"capacity_policy_fingerprint"`
	ProvisionScript           string `json:"provision_script_sha1"`
	AuthorizeScript           string `json:"authorize_script_sha1"`
	MaxClaimLifetimeMS        int64  `json:"max_claim_lifetime_ms"`
	MaxActionWindowMS         int64  `json:"max_action_window_ms"`
}

// NewActionFencer binds downstream action fencing to an existing capacity
// adapter without changing its immutable policy or fingerprint.
func NewActionFencer(capacity *Capacity) (*ActionFencer, error) {
	if capacity == nil || capacity.client == nil || len(capacity.keys) != 3 ||
		len(capacity.policyArgs) != 9 || capacity.keyTag == "" || capacity.maxPerSession != 1 {
		return nil, gateway.ErrDownstreamUnavailable
	}
	capacityFingerprint := fmt.Sprint(capacity.policyArgs[1])
	policyInput := strings.Join([]string{
		actionPolicyFormat,
		capacityFingerprint,
		actionProvisionScript.Hash(),
		actionAuthorizeScript.Hash(),
		strconv.FormatInt(gateway.MaxDownstreamClaimLifetime.Milliseconds(), 10),
		strconv.FormatInt(gateway.MaxDownstreamActionWindow.Milliseconds(), 10),
	}, "|")
	policyDigest := sha256.Sum256([]byte(policyInput))
	prefix := "sandbox-runtime:{" + capacity.keyTag + "}:capacity:action-fence:"
	return &ActionFencer{
		capacity:        capacity,
		policyKey:       prefix + "policy",
		highWaterPrefix: prefix + "high-water:",
		policyArgs: []any{
			actionPolicyFormat,
			hex.EncodeToString(policyDigest[:]),
			capacityFingerprint,
			actionAuthorizeScript.Hash(),
			gateway.MaxDownstreamClaimLifetime.Milliseconds(),
			gateway.MaxDownstreamActionWindow.Milliseconds(),
		},
	}, nil
}

func (f *ActionFencer) Descriptor() ActionFencingDescriptor {
	if f == nil || len(f.policyArgs) != 6 {
		return ActionFencingDescriptor{}
	}
	return ActionFencingDescriptor{
		PolicyFormat:              actionPolicyFormat,
		PolicyFingerprint:         fmt.Sprint(f.policyArgs[1]),
		CapacityPolicyFingerprint: fmt.Sprint(f.policyArgs[2]),
		ProvisionScript:           actionProvisionScript.Hash(),
		AuthorizeScript:           actionAuthorizeScript.Hash(),
		MaxClaimLifetimeMS:        gateway.MaxDownstreamClaimLifetime.Milliseconds(),
		MaxActionWindowMS:         gateway.MaxDownstreamActionWindow.Milliseconds(),
	}
}

// Provision installs the independent action policy. The capacity policy and
// fencing counter must already exist and match exactly.
func (f *ActionFencer) Provision(ctx context.Context) error {
	return f.checkPolicy(ctx, "provision")
}

// Verify is startup-only and never creates missing action policy.
func (f *ActionFencer) Verify(ctx context.Context) error {
	return f.checkPolicy(ctx, "verify")
}

func (f *ActionFencer) checkPolicy(ctx context.Context, mode string) error {
	if f == nil || f.capacity == nil || f.capacity.client == nil || len(f.policyArgs) != 6 {
		return gateway.ErrDownstreamUnavailable
	}
	args := appendCopy(f.capacity.policyArgs, f.policyArgs...)
	args = append(args, mode)
	result, err := f.run(ctx, actionProvisionScript,
		[]string{f.capacity.keys[1], f.capacity.keys[2], f.policyKey}, args...)
	if err != nil {
		return err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) != 1 || (values[0] != "provisioned" && values[0] != "ready") {
		return gateway.ErrDownstreamUnavailable
	}
	return nil
}

// AuthorizeAction atomically validates the exact active capacity member and
// compare-and-advances the retained per-session high-water record.
func (f *ActionFencer) AuthorizeAction(
	ctx context.Context,
	subject gateway.DownstreamFenceSubject,
	claim gateway.DownstreamFence,
	requiredWindow time.Duration,
) (gateway.DownstreamFenceDecision, error) {
	if f == nil || f.capacity == nil || f.capacity.client == nil || len(f.policyArgs) != 6 {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	if err := downstreamContextError(ctx); err != nil {
		return gateway.DownstreamFenceDecision{}, err
	}
	if err := subject.Validate(); err != nil || claim.Validate() != nil {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	if requiredWindow < gateway.MinDownstreamActionWindow || requiredWindow > gateway.MaxDownstreamActionWindow ||
		requiredWindow%time.Millisecond != 0 {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	member, parsed, err := decodeActionClaim(claim)
	if err != nil {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	capacitySubject := gateway.CapacitySubject{
		TenantID: subject.TenantID, SandboxID: subject.SandboxID,
		BrowserSessionID:    subject.BrowserSessionID,
		CapabilityProfileID: subject.CapabilityProfileID, ExpiresAt: subject.ExpiresAt.UTC(),
	}
	if err := capacitySubject.Validate(); err != nil || capacitySubject.ExpiresAt.UnixMilli() > maxLuaExactInteger {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	tenant, session := subjectFingerprints(capacitySubject)
	boundExpiry := strconv.FormatInt(capacitySubject.ExpiresAt.UnixMilli(), 10)
	if parsed.tenant != tenant || parsed.session != session || parsed.boundExpiry != boundExpiry {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
	}

	actionSubject := actionSubjectFingerprint(subject)
	args := appendCopy(f.capacity.policyArgs, f.policyArgs...)
	args = append(args, member, tenant, session, boundExpiry, actionSubject, requiredWindow.Milliseconds())
	keys := []string{
		f.capacity.keys[0], f.capacity.keys[1], f.capacity.keys[2], f.policyKey,
		f.highWaterPrefix + session,
	}
	result, err := f.run(ctx, actionAuthorizeScript, keys, args...)
	if err != nil {
		return gateway.DownstreamFenceDecision{}, err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) != 1 {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	switch values[0] {
	case "current":
		return gateway.DownstreamFenceDecision{}, nil
	case "activated":
		return gateway.DownstreamFenceDecision{Activated: true}, nil
	case "lost":
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamFenceLost
	default:
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
}

func actionSubjectFingerprint(subject gateway.DownstreamFenceSubject) string {
	return digestParts(
		"browser-downstream-action-subject-v1", subject.TenantID, subject.SandboxID,
		subject.BrowserSessionID, subject.CapabilityProfileID,
		strconv.FormatInt(subject.ConnectionGeneration, 10),
		strconv.FormatInt(subject.ExpiresAt.UTC().UnixMilli(), 10),
	)
}

func (f *ActionFencer) run(ctx context.Context, script *goredis.Script, keys []string, args ...any) (any, error) {
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

type parsedCapacityMember struct {
	owner       string
	fence       int64
	tenant      string
	session     string
	boundExpiry string
}

func parseCapacityMember(member string) (parsedCapacityMember, error) {
	matches := capacityMemberPattern.FindStringSubmatch(member)
	if len(matches) != 6 {
		return parsedCapacityMember{}, gateway.ErrDownstreamUnavailable
	}
	fence, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil || fence < 1 || fence > maxLuaExactInteger {
		return parsedCapacityMember{}, gateway.ErrDownstreamUnavailable
	}
	expiry, err := strconv.ParseInt(matches[5], 10, 64)
	if err != nil || expiry < 1 || expiry > maxLuaExactInteger {
		return parsedCapacityMember{}, gateway.ErrDownstreamUnavailable
	}
	return parsedCapacityMember{
		owner: matches[1], fence: fence, tenant: matches[3], session: matches[4], boundExpiry: matches[5],
	}, nil
}

func decodeActionClaim(claim gateway.DownstreamFence) (string, parsedCapacityMember, error) {
	if err := claim.Validate(); err != nil {
		return "", parsedCapacityMember{}, gateway.ErrDownstreamUnavailable
	}
	opaque := claim.Opaque()
	if !strings.HasPrefix(opaque, actionClaimPrefix) {
		return "", parsedCapacityMember{}, gateway.ErrDownstreamUnavailable
	}
	encoded := strings.TrimPrefix(opaque, actionClaimPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return "", parsedCapacityMember{}, gateway.ErrDownstreamUnavailable
	}
	member := string(decoded)
	parsed, err := parseCapacityMember(member)
	if err != nil {
		return "", parsedCapacityMember{}, gateway.ErrDownstreamUnavailable
	}
	return member, parsed, nil
}

func (l *connectionLease) DownstreamFence() (gateway.DownstreamFence, error) {
	if l == nil || l.capacity == nil {
		return gateway.DownstreamFence{}, gateway.ErrDownstreamUnavailable
	}
	l.stateMu.Lock()
	switch {
	case l.releasing || l.released || l.terminationKind == "lost":
		l.stateMu.Unlock()
		return gateway.DownstreamFence{}, gateway.ErrDownstreamFenceLost
	case l.terminationKind != "":
		l.stateMu.Unlock()
		return gateway.DownstreamFence{}, gateway.ErrDownstreamUnavailable
	}
	member := l.member
	l.stateMu.Unlock()
	if _, err := parseCapacityMember(member); err != nil {
		return gateway.DownstreamFence{}, gateway.ErrDownstreamUnavailable
	}
	claim, err := gateway.NewDownstreamFence(actionClaimPrefix + base64.RawURLEncoding.EncodeToString([]byte(member)))
	if err != nil {
		return gateway.DownstreamFence{}, gateway.ErrDownstreamUnavailable
	}
	return claim, nil
}

func downstreamContextError(ctx context.Context) error {
	if ctx == nil {
		return errors.Join(gateway.ErrDownstreamUnavailable, context.Canceled)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(gateway.ErrDownstreamUnavailable, err)
	}
	return nil
}

var (
	_ gateway.FencedConnectionLease    = (*connectionLease)(nil)
	_ gateway.DownstreamFenceAuthority = (*ActionFencer)(nil)
)
