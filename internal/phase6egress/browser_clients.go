package phase6egress

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	goredis "github.com/redis/go-redis/v9"
	rediscapacity "github.com/shell-echo/sandbox-runtime/gateway/capacity/redis"
	"github.com/shell-echo/sandbox-runtime/internal/egressbroker"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
)

// BrowserExternalOptions contains no endpoint or alternate dial target. The
// closed security profile owns both fixed aliases and the broker address.
type BrowserExternalOptions struct {
	Profile                phase6security.Profile
	Broker                 *egressbroker.Client
	BrokerGuard            *phase6tls.PeerCRLGuard
	Certificate            func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	Resolver               CredentialResolver
	CapacityBindingID      string
	ExpectedCapacityUser   string
	WitnessBindingID       string
	WitnessDatabase        string
	WitnessUser            string
	CapacityNamespace      string
	MaxTotal               int
	MaxPerTenant           int
	LeaseTTL               time.Duration
	RenewInterval          time.Duration
	RenewalSafetyMargin    time.Duration
	OperationTimeout       time.Duration
	CredentialPollInterval time.Duration
}

// BrowserExternalClients owns both external pools, their matching capacity
// and independent witness, and the fail-closed material lifetime guard.
// The containing ingress process must start CredentialGuard polling and
// close this object when its drain callback fires.
type BrowserExternalClients struct {
	Capacity *rediscapacity.Capacity
	Fencer   *rediscapacity.WitnessedActionFencer
	Guard    *CredentialGuard
	Role     *WitnessRoleGuard
	Redis    *goredis.Client
	Witness  *pgxpool.Pool
	once     sync.Once
}

func NewBrowserExternalClients(ctx context.Context, options BrowserExternalOptions) (*BrowserExternalClients, error) {
	if ctx == nil || ctx.Err() != nil || options.Profile.Validate() != nil ||
		options.Broker == nil || options.BrokerGuard == nil || !options.BrokerGuard.Ready() ||
		options.Certificate == nil || options.Resolver == nil ||
		options.OperationTimeout < time.Second || options.OperationTimeout > 5*time.Second {
		return nil, ErrUnavailable
	}
	principal := "browser-action-ingress-runtime"
	capacityTarget, _, capacityLease, capacityErr := selectTarget(options.Profile, principal, "capacity")
	witnessTarget, _, witnessLease, witnessErr := selectTarget(options.Profile, principal, "action-history")
	if capacityErr != nil || witnessErr != nil || options.OperationTimeout >= capacityLease ||
		options.OperationTimeout >= witnessLease {
		return nil, ErrUnavailable
	}
	guard, credentials, witnessConfig, err := NewCredentialGuard(ctx, options.Resolver,
		options.CapacityBindingID, options.WitnessBindingID,
		WitnessTarget{Host: witnessTarget.Host, Port: witnessTarget.Port,
			Database: options.WitnessDatabase, User: options.WitnessUser},
		options.CredentialPollInterval, time.Now)
	if err != nil || credentials.Username != options.ExpectedCapacityUser ||
		!externalUserPattern.MatchString(options.ExpectedCapacityUser) {
		return nil, ErrUnavailable
	}
	capacityAlias, err := NewFixedAlias(options.Profile, principal, "capacity", options.Broker,
		options.BrokerGuard, options.Certificate, capacityLease)
	if err != nil {
		return nil, ErrUnavailable
	}
	witnessAlias, err := NewFixedAlias(options.Profile, principal, "action-history", options.Broker,
		options.BrokerGuard, options.Certificate, witnessLease)
	if err != nil {
		return nil, ErrUnavailable
	}
	redisOptions := &goredis.Options{Network: "tcp", Addr: capacityAlias.address, DB: 0,
		TLSConfig: capacityAlias.ExternalTLSConfig()}
	if err := capacityAlias.BindRedis(redisOptions, credentials, options.OperationTimeout); err != nil {
		return nil, ErrUnavailable
	}
	// The password's original Go string cannot be erased; keep no additional
	// copies in the composition and never serialize the options or pool.
	credentials = CapacityValkeyCredentials{}
	redisClient := goredis.NewClient(redisOptions)
	closeRedis := func() { _ = redisClient.Close() }
	witnessConfig.MaxConns = 4
	witnessConfig.MinConns = 0
	witnessConfig.MaxConnLifetime = witnessLease
	witnessConfig.MaxConnIdleTime = witnessLease
	if err := witnessAlias.BindPostgres(witnessConfig); err != nil {
		closeRedis()
		return nil, ErrUnavailable
	}
	witnessConfig.AfterConnect = func(connectCtx context.Context, connection *pgx.Conn) error {
		checkCtx, cancel := context.WithTimeout(connectCtx, options.OperationTimeout)
		defer cancel()
		return rediscapacity.VerifyPostgresActionHistoryRuntimeConnection(checkCtx, connection,
			options.WitnessDatabase, options.WitnessUser)
	}
	witnessPool, err := pgxpool.NewWithConfig(ctx, witnessConfig)
	if err != nil {
		closeRedis()
		return nil, ErrUnavailable
	}
	clients := &BrowserExternalClients{Guard: guard, Redis: redisClient, Witness: witnessPool}
	fail := func() (*BrowserExternalClients, error) { clients.Close(); return nil, ErrUnavailable }
	var drainBudget time.Duration
	for _, candidate := range options.Profile.Principals {
		if candidate.Name == principal && candidate.TLS != nil {
			drainBudget = time.Duration(candidate.TLS.ConnectionDrainSeconds) * time.Second
		}
	}
	roleGuard, err := NewWitnessRoleGuard(witnessPool, options.WitnessDatabase, options.WitnessUser,
		options.CredentialPollInterval, options.OperationTimeout, options.OperationTimeout, drainBudget)
	if err != nil {
		return fail()
	}
	clients.Role = roleGuard
	if roleGuard.Refresh(ctx) != nil {
		return fail()
	}
	capacity, err := rediscapacity.New(rediscapacity.Options{Client: redisClient,
		Namespace: options.CapacityNamespace, MaxTotal: options.MaxTotal,
		MaxPerTenant: options.MaxPerTenant, MaxPerSession: 1,
		LeaseTTL: options.LeaseTTL, RenewInterval: options.RenewInterval,
		RenewalSafetyMargin: options.RenewalSafetyMargin, OperationTimeout: options.OperationTimeout})
	if err != nil {
		return fail()
	}
	witness, err := rediscapacity.NewPostgresActionHistoryWitness(rediscapacity.PostgresActionHistoryWitnessOptions{
		Capacity: capacity, Pool: witnessPool, OperationTimeout: options.OperationTimeout})
	if err != nil {
		return fail()
	}
	fencer, err := rediscapacity.NewWitnessedActionFencer(capacity, witness)
	if err != nil {
		return fail()
	}
	clients.Capacity, clients.Fencer = capacity, fencer
	verifyCtx, cancel := context.WithTimeout(ctx, 5*options.OperationTimeout)
	defer cancel()
	if guard.Check(verifyCtx) != nil || capacity.Verify(verifyCtx) != nil || fencer.Verify(verifyCtx) != nil ||
		guard.Check(verifyCtx) != nil {
		return fail()
	}
	// The host/port used by Redis must remain the exact profile target even
	// after its options have been populated by go-redis.
	if redisClient.Options().Addr != capacityAlias.address ||
		capacityTarget.Host != capacityAlias.remote.ServerName {
		return fail()
	}
	return clients, nil
}

func (c *BrowserExternalClients) Close() error {
	if c == nil {
		return nil
	}
	var result error
	c.once.Do(func() {
		if c.Role != nil {
			c.Role.Close()
		}
		if c.Redis != nil {
			result = errors.Join(result, c.Redis.Close())
		}
		if c.Witness != nil {
			c.Witness.Close()
		}
	})
	return result
}
