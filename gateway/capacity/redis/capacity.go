// Package rediscapacity implements the caller-owned authenticated connection
// capacity port with one shared Redis-compatible authority.
package rediscapacity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime/gateway"
)

const (
	MinLeaseTTL          = time.Second
	MaxLeaseTTL          = 5 * time.Minute
	MinRenewInterval     = 100 * time.Millisecond
	MinOperationTimeout  = 50 * time.Millisecond
	MaxOperationTimeout  = 30 * time.Second
	minSafetyMargin      = 100 * time.Millisecond
	maxNamespaceLength   = 128
	capacityPolicyFormat = "browser-authenticated-capacity-zset-v1"
	maxLuaExactInteger   = int64(999999999999999)
)

var (
	namespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	ownerPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

type Options struct {
	Client *goredis.Client

	Namespace     string
	MaxTotal      int
	MaxPerTenant  int
	MaxPerSession int

	LeaseTTL            time.Duration
	RenewInterval       time.Duration
	RenewalSafetyMargin time.Duration
	OperationTimeout    time.Duration
}

type Capacity struct {
	client *goredis.Client
	keys   []string
	keyTag string

	policyArgs       []any
	maxTotal         int
	maxPerTenant     int
	maxPerSession    int
	leaseTTL         time.Duration
	renewInterval    time.Duration
	safetyMargin     time.Duration
	operationTimeout time.Duration
	ownerSource      func() (string, error)
}

// Descriptor contains only stable, non-sensitive inputs needed to identify an
// adapter policy and its server-side programs in reproducible evidence.
type Descriptor struct {
	PolicyFormat      string `json:"policy_format"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	ProvisionScript   string `json:"provision_script_sha1"`
	AcquireScript     string `json:"acquire_script_sha1"`
	RenewScript       string `json:"renew_script_sha1"`
	ReleaseScript     string `json:"release_script_sha1"`
}

func New(options Options) (*Capacity, error) {
	if options.Client == nil {
		return nil, fmt.Errorf("%w: Redis client", gateway.ErrInvalidRequest)
	}
	if len(options.Namespace) > maxNamespaceLength || !namespacePattern.MatchString(options.Namespace) {
		return nil, fmt.Errorf("%w: capacity namespace", gateway.ErrInvalidRequest)
	}
	if options.MaxTotal < 1 || options.MaxTotal > gateway.MaxConnectionCapacity ||
		options.MaxPerTenant < 1 || options.MaxPerTenant > options.MaxTotal ||
		options.MaxPerSession < 1 || options.MaxPerSession > options.MaxPerTenant {
		return nil, fmt.Errorf("%w: shared capacity limits", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(options.LeaseTTL) || options.LeaseTTL < MinLeaseTTL || options.LeaseTTL > MaxLeaseTTL {
		return nil, fmt.Errorf("%w: capacity lease TTL", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(options.RenewInterval) || options.RenewInterval < MinRenewInterval ||
		options.RenewInterval > options.LeaseTTL/2 {
		return nil, fmt.Errorf("%w: capacity renew interval", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(options.OperationTimeout) || options.OperationTimeout < MinOperationTimeout ||
		options.OperationTimeout > MaxOperationTimeout {
		return nil, fmt.Errorf("%w: capacity operation timeout", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(options.RenewalSafetyMargin) || options.RenewalSafetyMargin < minSafetyMargin ||
		options.RenewalSafetyMargin < options.OperationTimeout ||
		options.RenewInterval+options.OperationTimeout+options.RenewalSafetyMargin >= options.LeaseTTL {
		return nil, fmt.Errorf("%w: capacity renewal safety margin", gateway.ErrInvalidRequest)
	}
	clientOptions := options.Client.Options()
	if clientOptions.MaxRetries != 0 || !clientOptions.ContextTimeoutEnabled || clientOptions.Protocol != 2 ||
		!clientOptions.DisableIdentity || !boundedClientTimeout(clientOptions.DialTimeout, options.OperationTimeout) ||
		!boundedClientTimeout(clientOptions.ReadTimeout, options.OperationTimeout) ||
		!boundedClientTimeout(clientOptions.WriteTimeout, options.OperationTimeout) ||
		!boundedClientTimeout(clientOptions.PoolTimeout, options.OperationTimeout) {
		return nil, fmt.Errorf("%w: unsafe Redis client options", gateway.ErrInvalidRequest)
	}

	policyInput := fmt.Sprintf("%s|%d|%d|%d|%d|%d|%d|%d|%s|%s|%s|%s", capacityPolicyFormat,
		options.MaxTotal, options.MaxPerTenant, options.MaxPerSession, options.LeaseTTL.Milliseconds(),
		options.RenewInterval.Milliseconds(), options.RenewalSafetyMargin.Milliseconds(), options.OperationTimeout.Milliseconds(),
		provisionScript.Hash(), acquireScript.Hash(), renewScript.Hash(), releaseScript.Hash())
	policyDigest := sha256.Sum256([]byte(policyInput))
	namespaceDigest := sha256.Sum256([]byte(options.Namespace))
	tag := hex.EncodeToString(namespaceDigest[:])
	policyArgs := []any{
		capacityPolicyFormat, hex.EncodeToString(policyDigest[:]), options.MaxTotal, options.MaxPerTenant,
		options.MaxPerSession, options.LeaseTTL.Milliseconds(), options.RenewInterval.Milliseconds(),
		options.RenewalSafetyMargin.Milliseconds(), options.OperationTimeout.Milliseconds(),
	}
	return &Capacity{
		client: options.Client,
		keys: []string{
			"sandbox-runtime:{" + tag + "}:capacity:leases",
			"sandbox-runtime:{" + tag + "}:capacity:policy",
			"sandbox-runtime:{" + tag + "}:capacity:fence",
		},
		keyTag:     tag,
		policyArgs: policyArgs,
		maxTotal:   options.MaxTotal, maxPerTenant: options.MaxPerTenant, maxPerSession: options.MaxPerSession,
		leaseTTL: options.LeaseTTL, renewInterval: options.RenewInterval,
		safetyMargin: options.RenewalSafetyMargin, operationTimeout: options.OperationTimeout,
		ownerSource: randomOwner,
	}, nil
}

// Descriptor returns policy and script fingerprints without exposing the raw
// namespace, Redis keys, subjects, owners, fences, or connection material.
func (c *Capacity) Descriptor() Descriptor {
	if c == nil || len(c.policyArgs) < 2 {
		return Descriptor{}
	}
	return Descriptor{
		PolicyFormat: capacityPolicyFormat, PolicyFingerprint: fmt.Sprint(c.policyArgs[1]),
		ProvisionScript: provisionScript.Hash(), AcquireScript: acquireScript.Hash(),
		RenewScript: renewScript.Hash(), ReleaseScript: releaseScript.Hash(),
	}
}

// Provision installs an immutable policy in a namespace that an administrator
// has independently confirmed is virgin or fully drained. Runtime startup must
// call Verify so shared-state loss cannot silently recreate capacity authority.
func (c *Capacity) Provision(ctx context.Context) error {
	return c.checkPolicy(ctx, "provision")
}

// Verify requires the exact immutable policy and fencing history to exist. It
// never creates missing shared state.
func (c *Capacity) Verify(ctx context.Context) error {
	return c.checkPolicy(ctx, "verify")
}

func (c *Capacity) checkPolicy(ctx context.Context, mode string) error {
	if c == nil || c.client == nil {
		return gateway.ErrCapacityUnavailable
	}
	result, err := c.run(ctx, provisionScript, c.keys, appendCopy(c.policyArgs, mode)...)
	if err != nil {
		return err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) == 0 || (values[0] != "provisioned" && values[0] != "ready") {
		return errors.Join(gateway.ErrCapacityUnavailable, errors.Join(err,
			fmt.Errorf("shared capacity policy rejected: %s", strings.Join(values, ":"))))
	}
	return nil
}

func (c *Capacity) Acquire(ctx context.Context, subject gateway.CapacitySubject) (gateway.ConnectionLease, error) {
	if c == nil || c.client == nil || c.ownerSource == nil {
		return nil, gateway.ErrCapacityUnavailable
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := subject.Validate(); err != nil {
		return nil, errors.Join(gateway.ErrCapacityUnavailable, err)
	}
	grantExpiresAt := subject.ExpiresAt.UTC()
	if grantExpiresAt.UnixMilli() > maxLuaExactInteger {
		return nil, errors.Join(gateway.ErrCapacityUnavailable, errors.New("capacity grant expiry exceeds the exact shared-store range"))
	}
	owner, err := c.ownerSource()
	if err != nil || !ownerPattern.MatchString(owner) {
		return nil, errors.Join(gateway.ErrCapacityUnavailable, errors.Join(err, errors.New("capacity owner generation failed")))
	}
	tenant, session := subjectFingerprints(subject)
	args := appendCopy(c.policyArgs, grantExpiresAt.UnixMilli(), tenant, session, owner)
	started := time.Now()
	result, err := c.run(ctx, acquireScript, c.keys, args...)
	if err != nil {
		return nil, err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) == 0 {
		return nil, errors.Join(gateway.ErrCapacityUnavailable, errors.Join(err, errors.New("shared capacity acquire result is malformed")))
	}
	switch values[0] {
	case "exhausted":
		return nil, gateway.ErrCapacityExhausted
	case "ok":
		if len(values) != 4 {
			return nil, errors.Join(gateway.ErrCapacityUnavailable, errors.New("shared capacity acquire result is malformed"))
		}
		deadline, err := confirmedDeadline(started, values[2], values[3])
		if err != nil {
			return nil, errors.Join(gateway.ErrCapacityUnavailable, err)
		}
		if time.Until(deadline) <= c.safetyMargin+c.operationTimeout {
			_, _ = c.run(context.Background(), releaseScript, c.keys[:1], values[1])
			return nil, errors.Join(gateway.ErrCapacityUnavailable, errors.New("shared capacity lease has no safe renewal window"))
		}
		lease := &connectionLease{
			capacity: c, member: values[1], grantExpiresAt: grantExpiresAt, confirmedUntil: deadline,
			grantBound: expiryMatchesGrant(values[3], grantExpiresAt),
			events:     make(chan gateway.CapacityEvent, 1), stop: make(chan struct{}), done: make(chan struct{}),
			releaseGate: make(chan struct{}, 1),
		}
		go lease.renew()
		return lease, nil
	default:
		return nil, errors.Join(gateway.ErrCapacityUnavailable,
			fmt.Errorf("shared capacity acquire rejected: %s", strings.Join(values, ":")))
	}
}

type connectionLease struct {
	capacity        *Capacity
	member          string
	grantExpiresAt  time.Time
	confirmedUntil  time.Time
	grantBound      bool
	events          chan gateway.CapacityEvent
	stop            chan struct{}
	done            chan struct{}
	stopOnce        sync.Once
	signalOnce      sync.Once
	stateMu         sync.Mutex
	releaseGate     chan struct{}
	releasing       bool
	released        bool
	terminationKind string
}

func (l *connectionLease) Events() <-chan gateway.CapacityEvent {
	if l == nil {
		return nil
	}
	return l.events
}

func (l *connectionLease) renew() {
	defer close(l.done)
	retrying := false
	var lastRenewalError error
	for {
		remaining := time.Until(l.confirmedUntil.Add(-l.capacity.safetyMargin))
		if remaining <= 0 {
			l.signalBoundary(lastRenewalError)
			return
		}
		latestStart := remaining - l.capacity.operationTimeout
		if latestStart <= 0 {
			timer := time.NewTimer(remaining)
			select {
			case <-l.stop:
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
				l.signalBoundary(lastRenewalError)
				return
			}
		}
		delay := l.capacity.renewInterval
		if retrying {
			delay /= 4
			if delay < 25*time.Millisecond {
				delay = 25 * time.Millisecond
			}
		}
		if delay > latestStart {
			delay = latestStart
		}
		timer := time.NewTimer(delay)
		select {
		case <-l.stop:
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}

		boundary := l.confirmedUntil.Add(-l.capacity.safetyMargin)
		if !time.Now().Before(boundary) {
			l.signalBoundary(lastRenewalError)
			return
		}
		renewContext, cancel := context.WithDeadline(context.Background(), boundary)
		kind, deadline, grantBound, err := l.renewOnce(renewContext)
		cancel()
		if kind == "" {
			l.confirmedUntil = deadline
			l.grantBound = grantBound
			retrying = false
			lastRenewalError = nil
			continue
		}
		if kind == "lost" || kind == "unavailable" {
			l.signal(kind, err)
			return
		}
		lastRenewalError = err
		if !time.Now().Before(boundary) {
			l.signal("unavailable", err)
			return
		}
		retrying = true
	}
}

func (l *connectionLease) boundaryKind() string {
	if l.grantBound {
		return "lost"
	}
	return "unavailable"
}

func (l *connectionLease) signalBoundary(lastRenewalError error) {
	if lastRenewalError != nil {
		l.signal("unavailable", lastRenewalError)
		return
	}
	l.signal(l.boundaryKind(), errors.New("shared capacity renewal safety boundary reached"))
}

func (l *connectionLease) renewOnce(ctx context.Context) (string, time.Time, bool, error) {
	args := appendCopy(l.capacity.policyArgs, l.member, l.grantExpiresAt.UnixMilli())
	started := time.Now()
	result, err := l.capacity.run(ctx, renewScript, l.capacity.keys, args...)
	if err != nil {
		return "retry", time.Time{}, false, err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) == 0 {
		return "unavailable", time.Time{}, false, errors.Join(err, errors.New("shared capacity renew result is malformed"))
	}
	switch values[0] {
	case "ok":
		if len(values) != 3 {
			return "unavailable", time.Time{}, false, errors.New("shared capacity renew result is malformed")
		}
		deadline, err := confirmedDeadline(started, values[1], values[2])
		if err != nil {
			return "unavailable", time.Time{}, false, err
		}
		return "", deadline, expiryMatchesGrant(values[2], l.grantExpiresAt), nil
	case "lost":
		return "lost", time.Time{}, false, errors.New("shared capacity ownership was lost")
	default:
		return "unavailable", time.Time{}, false, fmt.Errorf("shared capacity renew rejected: %s", strings.Join(values, ":"))
	}
}

func (l *connectionLease) signal(kind string, err error) {
	l.stateMu.Lock()
	defer l.stateMu.Unlock()
	if l.releasing {
		return
	}
	l.signalOnce.Do(func() {
		l.terminationKind = kind
		l.events <- gateway.CapacityEvent{Kind: capacityEventKind(kind), Err: err}
	})
}

func (l *connectionLease) Release(ctx context.Context) error {
	if l == nil || l.capacity == nil {
		return gateway.ErrCapacityUnavailable
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	l.stateMu.Lock()
	if l.released {
		l.stateMu.Unlock()
		return nil
	}
	l.releasing = true
	l.stopOnce.Do(func() { close(l.stop) })
	l.stateMu.Unlock()
	select {
	case <-l.done:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case l.releaseGate <- struct{}{}:
		defer func() { <-l.releaseGate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	l.stateMu.Lock()
	if l.released {
		l.stateMu.Unlock()
		return nil
	}
	l.stateMu.Unlock()
	result, err := l.capacity.run(ctx, releaseScript, l.capacity.keys[:1], l.member)
	if err != nil {
		return err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) != 1 || (values[0] != "released" && values[0] != "absent") {
		return errors.Join(gateway.ErrCapacityUnavailable, errors.Join(err, errors.New("shared capacity release result is malformed")))
	}
	l.stateMu.Lock()
	l.released = true
	l.stateMu.Unlock()
	return nil
}

func (c *Capacity) run(ctx context.Context, script *goredis.Script, keys []string, args ...any) (any, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, c.operationTimeout)
	result, err := script.Run(opCtx, c.client, keys, args...).Result()
	cancel()
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, errors.Join(gateway.ErrCapacityUnavailable, err)
	}
	return result, nil
}

func capacityEventKind(value string) gateway.CapacityEventKind {
	if value == "lost" {
		return gateway.CapacityEventLost
	}
	return gateway.CapacityEventUnavailable
}

func subjectFingerprints(subject gateway.CapacitySubject) (string, string) {
	tenant := digestParts(subject.TenantID)
	sessionKind, sessionID := "runtime", subject.RuntimeSessionID
	if subject.BrowserSessionID != "" {
		sessionKind, sessionID = "browser", subject.BrowserSessionID
	}
	session := digestParts(subject.TenantID, subject.SandboxID, sessionKind, sessionID)
	return tenant, session
}

func digestParts(parts ...string) string {
	hash := sha256.New()
	var length [4]byte
	for _, part := range parts {
		binary.BigEndian.PutUint32(length[:], uint32(len(part)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func randomOwner() (string, error) {
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(owner[:]), nil
}

func confirmedDeadline(started time.Time, serverNow, expiry string) (time.Time, error) {
	nowMilliseconds, err := strconv.ParseInt(serverNow, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("shared capacity server time is malformed")
	}
	expiryMilliseconds, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || expiryMilliseconds <= nowMilliseconds {
		return time.Time{}, errors.New("shared capacity expiry is malformed")
	}
	return started.Add(time.Duration(expiryMilliseconds-nowMilliseconds) * time.Millisecond), nil
}

func expiryMatchesGrant(expiry string, grantExpiry time.Time) bool {
	expiryMilliseconds, err := strconv.ParseInt(expiry, 10, 64)
	return err == nil && expiryMilliseconds == grantExpiry.UnixMilli()
}

func resultStrings(result any) ([]string, error) {
	values, ok := result.([]any)
	if !ok {
		return nil, errors.New("shared capacity script result is not an array")
	}
	converted := make([]string, len(values))
	for index, value := range values {
		switch typed := value.(type) {
		case string:
			converted[index] = typed
		case []byte:
			converted[index] = string(typed)
		case int64:
			converted[index] = strconv.FormatInt(typed, 10)
		default:
			return nil, fmt.Errorf("shared capacity script value %d has type %T", index, value)
		}
	}
	return converted, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func boundedClientTimeout(value, operationTimeout time.Duration) bool {
	return value > 0 && value <= operationTimeout
}

func wholeMilliseconds(value time.Duration) bool {
	return value%time.Millisecond == 0
}

func appendCopy(source []any, values ...any) []any {
	result := make([]any, 0, len(source)+len(values))
	result = append(result, source...)
	return append(result, values...)
}

var _ gateway.ConnectionCapacity = (*Capacity)(nil)
var _ gateway.ConnectionLease = (*connectionLease)(nil)
