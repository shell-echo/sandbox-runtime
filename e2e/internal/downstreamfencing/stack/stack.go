package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
	basestack "github.com/shell-echo/sandbox-runtime-e2e/internal/stack"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	"github.com/shell-echo/sandbox-runtime/gateway/cdpfence"
)

// The process budget exceeds the locked five-second downstream close budget
// so shutdown can close a hijacked stream and still confirm handler exit.
const componentShutdownTimeout = 10 * time.Second

type lifecycleComponent interface {
	Startup(context.Context) error
	Shutdown(context.Context) error
}

// Stack is one independently started Provider/private-ingress process. It
// owns no public Gateway, caller policy, or capacity acquisition path.
type Stack struct {
	provider lifecycleComponent
	ingress  lifecycleComponent

	closeProvider func() error
	closeRedis    func() error
	stopTimeout   time.Duration

	mu        sync.Mutex
	started   bool
	running   bool
	closed    bool
	runCancel context.CancelFunc
	runDone   chan struct{}

	shutdownOnce sync.Once
	shutdownErr  error
	closeOnce    sync.Once
	closeErr     error
}

func Open(ctx context.Context, input Config) (_ *Stack, resultErr error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ValidateConfig(input); err != nil {
		return nil, err
	}
	config := cloneConfig(input)
	stack := &Stack{}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, stack.Close())
		}
	}()

	// Freeze local private material before touching Redis, Docker, or any
	// runtime-owned resource.
	if _, err := readTLSFile(config.Provider.ProviderPrivateKeyFile, maxPrivateKeyBytes, true); err != nil {
		return nil, errors.New("validate Provider private key")
	}
	ingressTLS, err := loadPrivateServerTLSConfig(config.Ingress)
	if err != nil {
		return nil, err
	}

	operationTimeout := durationMillis(config.Authority.CapacityPolicy.OperationTimeoutMillis)
	redisClient, err := newRedisClient(config.Authority.RedisURL, operationTimeout)
	if err != nil {
		return nil, errors.New("construct retained action-fence client")
	}
	stack.closeRedis = redisClient.Close
	policy := config.Authority.CapacityPolicy
	capacity, err := rediscapacity.New(rediscapacity.Options{
		Client: redisClient, Namespace: config.Authority.CapacityNamespace,
		MaxTotal: policy.MaxTotal, MaxPerTenant: policy.MaxPerTenant, MaxPerSession: policy.MaxPerSession,
		LeaseTTL: durationMillis(policy.LeaseTTLMillis), RenewInterval: durationMillis(policy.RenewIntervalMillis),
		RenewalSafetyMargin: durationMillis(policy.RenewalSafetyMarginMillis), OperationTimeout: operationTimeout,
	})
	if err != nil {
		return nil, errors.New("construct retained capacity authority")
	}
	// Runtime startup is verify-only. Policy provisioning is an explicit,
	// independently controlled harness operation.
	if err := capacity.Verify(ctx); err != nil {
		return nil, errors.New("verify retained capacity authority")
	}
	actionFencer, err := rediscapacity.NewActionFencer(capacity)
	if err != nil {
		return nil, errors.New("construct retained action-fence authority")
	}
	if err := actionFencer.Verify(ctx); err != nil {
		return nil, errors.New("verify retained action-fence authority")
	}

	provider, err := basestack.OpenBrowserProvider(ctx, config.Provider)
	if err != nil {
		return nil, fmt.Errorf("construct Browser Provider: %w", err)
	}
	stack.provider = provider
	stack.closeProvider = provider.Close
	ingressPolicy := config.Ingress
	ingress, err := cdpfence.New(cdpfence.Options{
		Authority: actionFencer, ActionTimeout: durationMillis(ingressPolicy.ActionTimeoutMillis),
		CloseTimeout: durationMillis(ingressPolicy.CloseTimeoutMillis), MaxSessions: ingressPolicy.MaxSessions,
		MaxActionBytes: ingressPolicy.MaxActionBytes,
	})
	if err != nil {
		return nil, errors.New("construct unique downstream-fencing ingress")
	}
	handler, err := transport.NewHandler(transport.HandlerOptions{
		Ingress: ingress, Resolver: provider, GatewayRoles: ingressPolicy.AllowedGatewayURIs,
		ResolveTimeout:    durationMillis(ingressPolicy.ResolveTimeoutMillis),
		ActivationTimeout: durationMillis(ingressPolicy.ActivationTimeoutMillis),
		MaxMessageBytes:   ingressPolicy.MaxActionBytes,
	})
	if err != nil {
		return nil, errors.New("construct private downstream-fencing transport")
	}
	privateIngress, err := newPrivateServerWithTLS(ingressPolicy, policy, handler, ingressTLS)
	if err != nil {
		return nil, err
	}
	stack.ingress = privateIngress
	return stack, nil
}

// Run starts the Provider API and private ingress concurrently and stops both
// if either listener fails or the caller cancels the process context.
func (s *Stack) Run(ctx context.Context) (resultErr error) {
	if s == nil || ctx == nil || s.provider == nil || s.ingress == nil {
		return errors.New("Provider/private-ingress stack is unavailable")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		cancel()
		return errors.New("Provider/private-ingress stack cannot be started")
	}
	s.started, s.running = true, true
	s.runCancel = cancel
	s.runDone = make(chan struct{})
	done := s.runDone
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.running = false
		s.runCancel = nil
		close(done)
		s.mu.Unlock()
	}()

	type componentResult struct {
		name string
		err  error
	}
	results := make(chan componentResult, 2)
	go func() { results <- componentResult{name: "Provider", err: s.provider.Startup(runCtx)} }()
	go func() { results <- componentResult{name: "private ingress", err: s.ingress.Startup(runCtx)} }()

	first := <-results
	firstWasExpected := runCtx.Err() != nil
	if first.err == nil && !firstWasExpected {
		first.err = errors.New("component stopped unexpectedly")
	}
	cancel()
	shutdownErr := s.shutdownComponents()
	var second componentResult
	timer := time.NewTimer(s.componentStopTimeout())
	defer timer.Stop()
	select {
	case second = <-results:
	case <-timer.C:
		return errors.Join(
			boundedComponentError(first.name, first.err, firstWasExpected),
			shutdownErr,
			errors.New("remaining Provider/private-ingress component did not stop"),
		)
	}
	return errors.Join(
		boundedComponentError(first.name, first.err, firstWasExpected),
		boundedComponentError(second.name, second.err, true),
		shutdownErr,
	)
}

func (s *Stack) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		cancel := s.runCancel
		done := s.runDone
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		s.closeErr = errors.Join(s.closeErr, s.shutdownComponents())
		if done != nil {
			select {
			case <-done:
			case <-time.After(2 * s.componentStopTimeout()):
				s.closeErr = errors.Join(s.closeErr, errors.New("Provider/private-ingress process did not stop"))
			}
		}
		if s.closeProvider != nil {
			s.closeErr = errors.Join(s.closeErr, s.closeProvider())
		}
		if s.closeRedis != nil {
			s.closeErr = errors.Join(s.closeErr, s.closeRedis())
		}
	})
	return s.closeErr
}

func (s *Stack) shutdownComponents() error {
	if s == nil {
		return nil
	}
	s.shutdownOnce.Do(func() {
		if s.ingress != nil {
			s.shutdownErr = errors.Join(s.shutdownErr, shutdownComponent(s.ingress, s.componentStopTimeout()))
		}
		if s.provider != nil {
			s.shutdownErr = errors.Join(s.shutdownErr, shutdownComponent(s.provider, s.componentStopTimeout()))
		}
	})
	return s.shutdownErr
}

func (s *Stack) componentStopTimeout() time.Duration {
	if s != nil && s.stopTimeout > 0 {
		return s.stopTimeout
	}
	return componentShutdownTimeout
}

func shutdownComponent(component lifecycleComponent, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- component.Shutdown(ctx) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newRedisClient(endpoint string, operationTimeout time.Duration) (*goredis.Client, error) {
	options, err := goredis.ParseURL(endpoint)
	if err != nil {
		return nil, err
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

func boundedComponentError(name string, err error, expectedCancellation bool) error {
	if err == nil {
		return nil
	}
	if expectedCancellation &&
		(errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, net.ErrClosed) || errors.Is(err, http.ErrServerClosed)) {
		return nil
	}
	return fmt.Errorf("%s stopped: %w", name, err)
}
