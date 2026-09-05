package gatewaystack

import (
	"context"
	"errors"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/shell-echo/sandbox-runtime-e2e/internal/downstreamfencing/transport"
	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/gateway/adapter"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	gatewaycomposition "github.com/shell-echo/sandbox-runtime/gateway/composition"
	gatewayedge "github.com/shell-echo/sandbox-runtime/gateway/edge"
	redisrevocation "github.com/shell-echo/sandbox-runtime/gateway/revocation/redis"
)

type Stack struct {
	server           *publicServer
	capacityClient   *goredis.Client
	revocationClient *goredis.Client
	privateResolver  *transport.Resolver
	audit            *evidenceWriter
	controller       *controller
	cancel           context.CancelFunc
	closeOnce        sync.Once
	closeErr         error
}

func Open(ctx context.Context, input Config) (_ *Stack, resultErr error) {
	if ctx == nil {
		return nil, context.Canceled
	}
	if err := ValidateConfig(input); err != nil {
		return nil, err
	}
	config := cloneConfig(input)
	publicTLS, err := loadPublicServerTLSConfig(config)
	if err != nil {
		return nil, err
	}
	privateTLS, err := loadPrivateClientTLSConfig(config.PrivateIngress)
	if err != nil {
		return nil, err
	}
	processCtx, cancel := context.WithCancel(ctx)
	stack := &Stack{cancel: cancel}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, stack.Close())
		}
	}()

	capacityClient, err := newRedisClient(config.Authority.RedisURL, durationMillis(config.Authority.CapacityPolicy.OperationTimeoutMillis))
	if err != nil {
		return nil, errors.New("construct retained capacity client")
	}
	stack.capacityClient = capacityClient
	policy := config.Authority.CapacityPolicy
	capacity, err := rediscapacity.New(rediscapacity.Options{
		Client: capacityClient, Namespace: config.Authority.CapacityNamespace,
		MaxTotal: policy.MaxTotal, MaxPerTenant: policy.MaxPerTenant, MaxPerSession: policy.MaxPerSession,
		LeaseTTL: durationMillis(policy.LeaseTTLMillis), RenewInterval: durationMillis(policy.RenewIntervalMillis),
		RenewalSafetyMargin: durationMillis(policy.RenewalSafetyMarginMillis),
		OperationTimeout:    durationMillis(policy.OperationTimeoutMillis),
	})
	if err != nil {
		return nil, errors.New("construct retained capacity authority")
	}
	if err := capacity.Verify(ctx); err != nil {
		return nil, errors.New("verify retained capacity authority")
	}

	revocationClient, err := newRedisClient(config.Authority.RedisURL, durationMillis(config.Authority.RevocationPolicy.OperationTimeoutMillis))
	if err != nil {
		return nil, errors.New("construct retained revocation client")
	}
	stack.revocationClient = revocationClient
	revocationPolicy := config.Authority.RevocationPolicy
	revocations, err := redisrevocation.New(redisrevocation.Options{
		Client: revocationClient, Namespace: config.Authority.RevocationNamespace,
		MaxGrantLifetime: durationMillis(revocationPolicy.MaxGrantLifetimeMillis),
		PollInterval:     durationMillis(revocationPolicy.PollIntervalMillis),
		OperationTimeout: durationMillis(revocationPolicy.OperationTimeoutMillis),
	})
	if err != nil {
		return nil, errors.New("construct retained revocation authority")
	}
	if err := revocations.Verify(ctx); err != nil {
		return nil, errors.New("verify retained revocation authority")
	}

	audit, err := newEvidenceWriter(config.AuditFile)
	if err != nil {
		return nil, errors.New("open Gateway audit")
	}
	stack.audit = audit
	controller, err := newController(config.Principals, config.Endpoints, config.GrantBindings)
	if err != nil {
		return nil, err
	}
	stack.controller = controller
	privateResolver, err := transport.NewResolver(transport.ResolverOptions{
		Address: config.PrivateIngress.Address, TLSConfig: privateTLS,
		ResolveTimeout:  durationMillis(config.PrivateIngress.ResolveTimeoutMillis),
		ConnectTimeout:  durationMillis(config.PrivateIngress.ConnectAndIOTimeoutMillis),
		MaxMessageBytes: config.PrivateIngress.MaxMessageBytes,
	})
	if err != nil {
		return nil, errors.New("construct private downstream-fencing resolver")
	}
	stack.privateResolver = privateResolver
	edgeGate, err := gatewayedge.NewLocalLimiter(gatewayedge.LocalOptions{
		MaxConcurrent:        gatewayedge.MaxConcurrentConnections,
		MaxRequestsPerWindow: gatewayedge.MaxRequestsPerWindow,
		Window:               gatewayedge.MaxWindow,
	})
	if err != nil {
		return nil, errors.New("construct local public-edge limiter")
	}
	service, err := gatewaycomposition.NewFencedBrowser(gatewaycomposition.BrowserOptions{
		Authorizer: controller, Revocations: revocations, Recorder: &auditRecorder{writer: audit},
		FencedResolver: privateResolver,
		WebSocket: adapter.WebSocketOptions{
			Admission: controller.admit, OriginPatterns: []string{"https://reference-caller.invalid"},
			MaxFrameBytes: lockedMaxMessageBytes,
		},
		Edge: edgeGate, Capacity: capacity,
		MaxReconnects: lockedReconnects, ReconnectBackoff: durationMillis(lockedReconnectBackoffMillis),
		CapacityReleaseTimeout: 2 * durationMillis(lockedCapacityOperationTimeoutMillis),
		MaxConnections:         gateway.MaxConnectionCapacity, MaxConnectionsPerSession: gateway.MaxConnectionCapacity,
	})
	if err != nil {
		return nil, errors.New("construct downstream-fenced Browser Gateway")
	}
	controller.service = service
	server, err := newPublicServer(config.Address, controller.handler(processCtx), publicTLS)
	if err != nil {
		return nil, errors.New("construct Browser public-edge server")
	}
	stack.server = server
	return stack, nil
}

func (s *Stack) Run(ctx context.Context) error {
	if s == nil || s.server == nil || ctx == nil {
		return errors.New("downstream-fencing Gateway is unavailable")
	}
	return s.server.Startup(ctx)
}

func (s *Stack) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.closeErr = errors.Join(s.closeErr, s.server.Shutdown(ctx))
			cancel()
		}
		if s.controller != nil {
			s.closeErr = errors.Join(s.closeErr, s.controller.wait())
		}
		if s.privateResolver != nil {
			s.privateResolver.CloseIdleConnections()
		}
		if s.audit != nil {
			s.closeErr = errors.Join(s.closeErr, s.audit.Close())
		}
		if s.revocationClient != nil {
			s.closeErr = errors.Join(s.closeErr, s.revocationClient.Close())
		}
		if s.capacityClient != nil {
			s.closeErr = errors.Join(s.closeErr, s.capacityClient.Close())
		}
	})
	return s.closeErr
}

func newRedisClient(endpoint string, operationTimeout time.Duration) (*goredis.Client, error) {
	options, err := goredis.ParseURL(endpoint)
	if err != nil {
		return nil, errors.New("parse Redis configuration")
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
