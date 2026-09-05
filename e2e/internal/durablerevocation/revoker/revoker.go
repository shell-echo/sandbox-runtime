package revoker

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/durablerevocation/wire"
	"github.com/shell-echo/sandbox-runtime/gateway"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
)

const (
	minimumTimeout = 50 * time.Millisecond
	maximumTimeout = 60 * time.Second
)

// Revoker executes exact-grant writes through an independently configured
// caller-owned durable authority.
type Revoker struct {
	mu         sync.Mutex
	writer     gateway.RevocationWriter
	closer     io.Closer
	controlLog *controlLog
	bindings   map[string]resolvedGrantBinding
	lastSeq    uint64
	terminated bool
	clock      func() time.Time
}

// New creates a verify-only Redis-compatible revoker. Policy provisioning is
// an administrative orchestrator responsibility and never occurs here.
func New(ctx context.Context, config wire.RevokerConfig) (*Revoker, error) {
	if ctx == nil {
		return nil, errors.New("revoker initialization failed")
	}
	bindings, err := prepareConfig(config)
	if err != nil {
		return nil, err
	}
	log, err := openControlLog(config.ControlLogFile)
	if err != nil {
		return nil, err
	}
	client, err := newRedisClient(config.RedisURL, time.Duration(config.RevocationPolicy.OperationTimeoutMillis)*time.Millisecond)
	if err != nil {
		_ = log.Close()
		return nil, errors.New("revoker initialization failed")
	}
	authority, err := redisrevocation.New(redisrevocation.Options{
		Client: client, Namespace: config.RevocationNamespace,
		MaxGrantLifetime: time.Duration(config.RevocationPolicy.MaxGrantLifetimeMillis) * time.Millisecond,
		PollInterval:     time.Duration(config.RevocationPolicy.PollIntervalMillis) * time.Millisecond,
		OperationTimeout: time.Duration(config.RevocationPolicy.OperationTimeoutMillis) * time.Millisecond,
	})
	if err != nil {
		_ = client.Close()
		_ = log.Close()
		return nil, errors.New("revoker initialization failed")
	}
	if err := authority.Verify(ctx); err != nil {
		_ = client.Close()
		_ = log.Close()
		return nil, errors.New("revoker initialization failed")
	}
	return newRevoker(authority, client, log, bindings), nil
}

func newRedisClient(endpoint string, operationTimeout time.Duration) (*goredis.Client, error) {
	options, err := goredis.ParseURL(endpoint)
	if err != nil {
		return nil, errors.New("invalid Redis configuration")
	}
	options.Protocol = 2
	options.MaxRetries = -1
	options.ContextTimeoutEnabled = true
	options.DisableIdentity = true
	options.DialTimeout = operationTimeout
	options.ReadTimeout = operationTimeout
	options.WriteTimeout = operationTimeout
	options.PoolTimeout = operationTimeout
	return goredis.NewClient(options), nil
}

func newRevoker(writer gateway.RevocationWriter, closer io.Closer, log *controlLog, bindings map[string]resolvedGrantBinding) *Revoker {
	return &Revoker{writer: writer, closer: closer, controlLog: log, bindings: bindings, clock: time.Now}
}

// Execute applies one control command without exposing grant or backend data.
func (r *Revoker) Execute(ctx context.Context, command wire.Command) wire.Response {
	if r == nil || ctx == nil {
		return wire.Response{Version: wire.ProtocolVersion, Sequence: command.Sequence, ErrorCode: wire.ErrorInternal}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	response := wire.Response{Version: wire.ProtocolVersion, Sequence: command.Sequence}
	if r.terminated || command.Version != wire.ProtocolVersion || command.Sequence == 0 || command.Sequence <= r.lastSeq {
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
	r.lastSeq = command.Sequence

	switch command.Action {
	case wire.ActionRevoke:
		return r.revoke(ctx, command, response)
	case wire.ActionShutdown:
		if !validShutdown(command) {
			response.ErrorCode = wire.ErrorInvalidCommand
			return response
		}
		r.terminated = true
		response.OK = true
		response.Outcome = wire.OutcomeTerminated
		return response
	default:
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
}

func (r *Revoker) revoke(ctx context.Context, command wire.Command, response wire.Response) wire.Response {
	if !validRevoke(command) {
		response.ErrorCode = wire.ErrorInvalidCommand
		return response
	}
	binding, exists := r.bindings[command.GrantBindingID]
	if !exists {
		response.ErrorCode = wire.ErrorUnknownGrantBinding
		return response
	}
	startedAt := r.clock().UTC()
	operationCtx, cancel := context.WithTimeout(ctx, time.Duration(command.TimeoutMillis)*time.Millisecond)
	err := r.writer.Revoke(operationCtx, gateway.RevocationSubject{GrantID: binding.grantID, ExpiresAt: binding.expiresAt})
	cancel()
	finishedAt := r.clock().UTC()
	if err != nil {
		response.ErrorCode = wire.ErrorRevocationUnavailable
		return response
	}
	if err := r.controlLog.appendCommitted(finishedAt, finishedAt.Sub(startedAt)); err != nil {
		response.ErrorCode = wire.ErrorControlLogUnavailable
		return response
	}
	response.OK = true
	response.Outcome = wire.OutcomeRevoked
	return response
}

func validRevoke(command wire.Command) bool {
	return command.ConnectionID == "" && command.GatewayID == "" && logicalIDPattern.MatchString(command.GrantBindingID) &&
		command.TimeoutMillis >= minimumTimeout.Milliseconds() && command.TimeoutMillis <= maximumTimeout.Milliseconds()
}

func validShutdown(command wire.Command) bool {
	return command.ConnectionID == "" && command.GatewayID == "" && command.GrantBindingID == "" && command.TimeoutMillis == 0
}

// Close releases the independent Redis client and evidence sink.
func (r *Revoker) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var closeErr error
	if r.controlLog != nil {
		closeErr = errors.Join(closeErr, r.controlLog.Close())
		r.controlLog = nil
	}
	if r.closer != nil {
		closeErr = errors.Join(closeErr, r.closer.Close())
		r.closer = nil
	}
	return closeErr
}
