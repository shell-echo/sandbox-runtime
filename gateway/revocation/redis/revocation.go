// Package redisrevocation implements the caller-owned durable revocation ports
// with one Redis-compatible authority.
package redisrevocation

import (
	"context"
	"crypto/sha256"
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
	MinGrantLifetime    = time.Second
	MaxGrantLifetime    = 24 * time.Hour
	MinPollInterval     = 50 * time.Millisecond
	MaxPollInterval     = 30 * time.Second
	MinOperationTimeout = 50 * time.Millisecond
	MaxOperationTimeout = 30 * time.Second

	maxNamespaceLength     = 128
	revocationPolicyFormat = "gateway-revocation-tombstone-v1"
	maxLuaExactInteger     = int64(999999999999999)
)

var namespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Options configures one immutable revocation namespace. Namespace must be
// operator-owned and distinct from every capacity namespace. Client ownership
// remains with the caller; closing Revocations does not close the client.
type Options struct {
	Client *goredis.Client

	Namespace        string
	MaxGrantLifetime time.Duration
	PollInterval     time.Duration
	OperationTimeout time.Duration
}

// Revocations is a shared, durable source and writer for exact grant
// revocations. It stores only hashed namespace and grant identities.
type Revocations struct {
	client           *goredis.Client
	policyKey        string
	grantKeyPrefix   string
	policyArgs       []any
	pollInterval     time.Duration
	operationTimeout time.Duration
}

// Descriptor contains only stable, non-sensitive values needed to identify an
// adapter policy and its server-side programs in reproducible evidence.
type Descriptor struct {
	PolicyFormat      string `json:"policy_format"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	ProvisionScript   string `json:"provision_script_sha1"`
	CheckScript       string `json:"check_script_sha1"`
	RevokeScript      string `json:"revoke_script_sha1"`
}

// New validates all local safety bounds without contacting the store.
func New(options Options) (*Revocations, error) {
	if options.Client == nil {
		return nil, fmt.Errorf("%w: Redis client", gateway.ErrInvalidRequest)
	}
	if len(options.Namespace) > maxNamespaceLength || !namespacePattern.MatchString(options.Namespace) {
		return nil, fmt.Errorf("%w: revocation namespace", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(options.MaxGrantLifetime) || options.MaxGrantLifetime < MinGrantLifetime ||
		options.MaxGrantLifetime > MaxGrantLifetime {
		return nil, fmt.Errorf("%w: maximum revocation grant lifetime", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(options.PollInterval) || options.PollInterval < MinPollInterval ||
		options.PollInterval > MaxPollInterval {
		return nil, fmt.Errorf("%w: revocation poll interval", gateway.ErrInvalidRequest)
	}
	if !wholeMilliseconds(options.OperationTimeout) || options.OperationTimeout < MinOperationTimeout ||
		options.OperationTimeout > MaxOperationTimeout || options.OperationTimeout > options.PollInterval {
		return nil, fmt.Errorf("%w: revocation operation timeout", gateway.ErrInvalidRequest)
	}
	clientOptions := options.Client.Options()
	if clientOptions.MaxRetries != 0 || !clientOptions.ContextTimeoutEnabled || clientOptions.Protocol != 2 ||
		!clientOptions.DisableIdentity || !boundedClientTimeout(clientOptions.DialTimeout, options.OperationTimeout) ||
		!boundedClientTimeout(clientOptions.ReadTimeout, options.OperationTimeout) ||
		!boundedClientTimeout(clientOptions.WriteTimeout, options.OperationTimeout) ||
		!boundedClientTimeout(clientOptions.PoolTimeout, options.OperationTimeout) {
		return nil, fmt.Errorf("%w: unsafe Redis client options", gateway.ErrInvalidRequest)
	}

	policyInput := fmt.Sprintf("%s|%d|%d|%d|%s|%s|%s", revocationPolicyFormat,
		options.MaxGrantLifetime.Milliseconds(), options.PollInterval.Milliseconds(), options.OperationTimeout.Milliseconds(),
		provisionScript.Hash(), checkScript.Hash(), revokeScript.Hash())
	policyDigest := sha256.Sum256([]byte(policyInput))
	namespaceDigest := sha256.Sum256([]byte(options.Namespace))
	tag := hex.EncodeToString(namespaceDigest[:])
	root := "sandbox-runtime:{" + tag + "}:revocation:"
	return &Revocations{
		client:         options.Client,
		policyKey:      root + "policy",
		grantKeyPrefix: root + "grant:",
		policyArgs: []any{revocationPolicyFormat, hex.EncodeToString(policyDigest[:]),
			options.MaxGrantLifetime.Milliseconds(), options.PollInterval.Milliseconds(), options.OperationTimeout.Milliseconds(),
			provisionScript.Hash(), checkScript.Hash(), revokeScript.Hash()},
		pollInterval:     options.PollInterval,
		operationTimeout: options.OperationTimeout,
	}, nil
}

// Descriptor returns policy and script fingerprints without exposing the raw
// namespace, Redis keys, grant identities, or connection material.
func (r *Revocations) Descriptor() Descriptor {
	if r == nil || len(r.policyArgs) < 2 {
		return Descriptor{}
	}
	return Descriptor{
		PolicyFormat: revocationPolicyFormat, PolicyFingerprint: fmt.Sprint(r.policyArgs[1]),
		ProvisionScript: provisionScript.Hash(), CheckScript: checkScript.Hash(), RevokeScript: revokeScript.Hash(),
	}
}

// Provision installs the immutable policy after an administrator has
// independently confirmed that the namespace is virgin or fully drained.
func (r *Revocations) Provision(ctx context.Context) error {
	return r.checkPolicy(ctx, "provision")
}

// Verify requires the exact immutable policy to exist. It never recreates
// missing shared state.
func (r *Revocations) Verify(ctx context.Context) error {
	return r.checkPolicy(ctx, "verify")
}

func (r *Revocations) checkPolicy(ctx context.Context, mode string) error {
	if r == nil || r.client == nil {
		return gateway.ErrRevocationUnavailable
	}
	result, err := r.run(ctx, provisionScript, []string{r.policyKey}, appendCopy(r.policyArgs, mode)...)
	if err != nil {
		return err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) == 0 || (values[0] != "provisioned" && values[0] != "ready") {
		return errors.Join(gateway.ErrRevocationUnavailable, errors.Join(err,
			fmt.Errorf("shared revocation policy rejected: %s", strings.Join(values, ":"))))
	}
	return nil
}

// Revoke durably records the exact grant through its declared expiry. Repeated
// or out-of-order writes retain the greatest observed expiry.
func (r *Revocations) Revoke(ctx context.Context, subject gateway.RevocationSubject) error {
	if r == nil || r.client == nil {
		return gateway.ErrRevocationUnavailable
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := validateSubject(subject); err != nil {
		return errors.Join(gateway.ErrRevocationUnavailable, err)
	}
	result, err := r.run(ctx, revokeScript, r.subjectKeys(subject), appendCopy(r.policyArgs, subject.ExpiresAt.UTC().UnixMilli())...)
	if err != nil {
		return err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) != 1 || values[0] != "revoked" {
		return errors.Join(gateway.ErrRevocationUnavailable, errors.Join(err,
			fmt.Errorf("shared revocation write rejected: %s", strings.Join(values, ":"))))
	}
	return nil
}

// Watch synchronously establishes a level-triggered initial observation and
// then polls the same durable tombstone until revocation, authority failure, or
// context cancellation. Store failures are reported through a terminal watch
// so Err remains stable after Done closes.
func (r *Revocations) Watch(ctx context.Context, subject gateway.RevocationSubject) (gateway.RevocationWatch, error) {
	if r == nil || r.client == nil {
		return nil, gateway.ErrRevocationUnavailable
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateSubject(subject); err != nil {
		return nil, errors.Join(gateway.ErrRevocationUnavailable, err)
	}

	watch := &revocationWatch{done: make(chan struct{})}
	revoked, err := r.check(ctx, subject)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		watch.finish(gateway.ErrRevocationUnavailable)
		return watch, nil
	}
	if revoked {
		watch.finish(gateway.ErrRevoked)
		return watch, nil
	}
	go r.poll(ctx, subject, watch)
	return watch, nil
}

func (r *Revocations) poll(ctx context.Context, subject gateway.RevocationSubject, watch *revocationWatch) {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			watch.finish(ctx.Err())
			return
		case <-watch.done:
			return
		case <-ticker.C:
		}
		revoked, err := r.check(ctx, subject)
		if err != nil {
			if contextErr := contextError(ctx); contextErr != nil {
				watch.finish(contextErr)
			} else {
				watch.finish(gateway.ErrRevocationUnavailable)
			}
			return
		}
		if revoked {
			watch.finish(gateway.ErrRevoked)
			return
		}
	}
}

func (r *Revocations) check(ctx context.Context, subject gateway.RevocationSubject) (bool, error) {
	result, err := r.run(ctx, checkScript, r.subjectKeys(subject), r.policyArgs...)
	if err != nil {
		return false, err
	}
	values, err := resultStrings(result)
	if err != nil || len(values) != 1 {
		return false, errors.Join(gateway.ErrRevocationUnavailable, errors.Join(err, errors.New("shared revocation check result is malformed")))
	}
	switch values[0] {
	case "clear":
		return false, nil
	case "revoked":
		return true, nil
	default:
		return false, errors.Join(gateway.ErrRevocationUnavailable,
			fmt.Errorf("shared revocation check rejected: %s", strings.Join(values, ":")))
	}
}

func (r *Revocations) subjectKeys(subject gateway.RevocationSubject) []string {
	digest := sha256.Sum256([]byte(subject.GrantID))
	return []string{r.policyKey, r.grantKeyPrefix + hex.EncodeToString(digest[:])}
}

func (r *Revocations) run(ctx context.Context, script *goredis.Script, keys []string, args ...any) (any, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	opCtx, cancel := context.WithTimeout(ctx, r.operationTimeout)
	result, err := script.Run(opCtx, r.client, keys, args...).Result()
	cancel()
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, errors.Join(gateway.ErrRevocationUnavailable, err)
	}
	return result, nil
}

type revocationWatch struct {
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func (w *revocationWatch) Done() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.done
}

func (w *revocationWatch) Err() error {
	if w == nil {
		return gateway.ErrRevocationUnavailable
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *revocationWatch) finish(err error) {
	w.once.Do(func() {
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		close(w.done)
	})
}

func validateSubject(subject gateway.RevocationSubject) error {
	if err := subject.Validate(); err != nil {
		return err
	}
	expiry := subject.ExpiresAt.UTC().UnixMilli()
	if expiry < 1 || expiry > maxLuaExactInteger {
		return fmt.Errorf("%w: revocation expiry exceeds the exact shared-store range", gateway.ErrInvalidGrant)
	}
	return nil
}

func resultStrings(result any) ([]string, error) {
	values, ok := result.([]any)
	if !ok {
		return nil, fmt.Errorf("shared revocation script returned %T", result)
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
			return nil, fmt.Errorf("shared revocation script value %d has type %T", index, value)
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

var _ gateway.RevocationSource = (*Revocations)(nil)
var _ gateway.RevocationWriter = (*Revocations)(nil)
var _ gateway.RevocationWatch = (*revocationWatch)(nil)
