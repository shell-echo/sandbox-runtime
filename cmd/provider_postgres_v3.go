package cmd

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
)

type providerV3DatabaseAuthority struct {
	profile  phase6security.Profile
	owner    string
	template string
	capacity int
}

func providerV3DatabaseBinding(cfg *config.ProviderProcessConfig, profile phase6security.Profile) (providerV3DatabaseAuthority, error) {
	if cfg == nil || cfg.SchemaVersion != config.ProviderProductionSchemaV3 || profile.Validate() != nil {
		return providerV3DatabaseAuthority{}, errors.New("Provider v3 database authority is unavailable")
	}
	var owner, template, namespace, controller string
	var capacity int
	switch cfg.Profile {
	case config.ProviderProcessBrowserProfile:
		owner, template = "provider-browser-runtime", "browser-sandbox-runtime"
		namespace, controller = cfg.Browser.Docker.Namespace, cfg.Browser.Docker.ControllerID
		capacity = cfg.Browser.Docker.MaxSessionsPerController
	case config.ProviderProcessDesktopProfile:
		owner, template = "provider-desktop-runtime", "desktop-sandbox-runtime"
		namespace, controller = cfg.Desktop.Docker.Namespace, cfg.Desktop.Docker.ControllerID
		capacity = cfg.Desktop.Docker.MaxSessionsPerController
	default:
		return providerV3DatabaseAuthority{}, errors.New("Provider v3 database owner is unavailable")
	}
	if profile.AssertProviderDatabaseRuntime(owner, namespace, controller,
		cfg.Postgres.RuntimeRole, cfg.Postgres.RuntimeDSNBindingID) != nil {
		return providerV3DatabaseAuthority{}, errors.New("Provider v3 database binding does not match profile")
	}
	clientBinding, _, clientAgent, _, _, err := profile.PostgresClientAgentForOwner(owner)
	if err != nil || clientBinding.SocketPath != cfg.Postgres.ClientAgentSocket ||
		clientAgent.UID != cfg.Postgres.ClientAgentUID || clientAgent.GID != cfg.Postgres.ClientAgentGID ||
		clientBinding.SocketPath == cfg.Transport.AgentSocket {
		return providerV3DatabaseAuthority{}, errors.New("Provider v3 PostgreSQL client signer does not match profile")
	}
	if _, err := profile.ProjectSandboxIdentityPlan(template, owner, capacity); err != nil {
		return providerV3DatabaseAuthority{}, errors.New("Provider v3 identity capacity does not match profile")
	}
	return providerV3DatabaseAuthority{profile: profile, owner: owner, template: template, capacity: capacity}, nil
}

// openProviderV3Postgres requires the complete owner profile, its own fixed
// broker, own workload TLS agent and purpose-bound DSN before constructing a
// pgx pool. No failed check falls back to the legacy direct-URL opener.
func openProviderV3Postgres(ctx context.Context, lifetime context.Context, cfg *config.ProviderProcessConfig,
	registry *secretref.Registry) (*pgxpool.Pool, func(), providerV3DatabaseAuthority, error) {
	if ctx == nil || lifetime == nil || registry == nil || ctx.Err() != nil || lifetime.Err() != nil {
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database startup is unavailable")
	}
	profile, err := loadProviderSecurityProfile(cfg)
	if err != nil {
		return nil, nil, providerV3DatabaseAuthority{}, err
	}
	authority, err := providerV3DatabaseBinding(cfg, profile)
	if err != nil {
		return nil, nil, providerV3DatabaseAuthority{}, err
	}
	binding, service, edge, _, err := profile.ProviderDatabaseAuthority(authority.owner)
	if err != nil || len(service.DNSNames) != 1 {
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database target is unavailable")
	}
	role, err := phase6security.VerifyPeerCRLRoleFile(cfg.Transport.PeerCRLRoleFile, profile,
		cfg.Transport.PeerCRLSourceMappingDigest, cfg.Transport.PeerCRLRoleDigest)
	if err != nil {
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 peer revocation authority is unavailable")
	}
	operationTimeout := time.Duration(cfg.Transport.OperationTimeoutMillis) * time.Millisecond
	broker, guard, err := phase6egress.NewBrokerClient(profile, phase6egress.BrokerClientAuthority{
		PolicyID: binding.EgressPolicyID, PeerCRLRole: role,
		AgentSocket: cfg.Transport.AgentSocket, AgentUID: cfg.Transport.AgentUID,
		AgentGID: cfg.Transport.AgentGID, OperationTimeout: operationTimeout})
	if err != nil {
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database broker is unavailable")
	}
	cleanupGuard := func() { guard.Close() }
	if err := guard.Bootstrap(ctx); err != nil {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database broker revocation evidence is unavailable")
	}
	agentBinding, agent, principal, err := profile.TLSAgentForSubject(authority.owner)
	if err != nil || agentBinding.SocketPath != cfg.Transport.AgentSocket || agent.UID != cfg.Transport.AgentUID ||
		agent.GID != cfg.Transport.AgentGID {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database signer binding is unavailable")
	}
	clientBinding, _, clientAgent, clientPrincipal, _, err := profile.PostgresClientAgentForOwner(authority.owner)
	if err != nil || clientBinding.SocketPath != cfg.Postgres.ClientAgentSocket ||
		clientAgent.UID != cfg.Postgres.ClientAgentUID || clientAgent.GID != cfg.Postgres.ClientAgentGID ||
		clientPrincipal.PrincipalDigest != principal.PrincipalDigest {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 PostgreSQL client signer binding is unavailable")
	}
	signer, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: cfg.Postgres.ClientAgentSocket, ExpectedUID: cfg.Postgres.ClientAgentUID,
		ExpectedGID: cfg.Postgres.ClientAgentGID, RoleGID: clientPrincipal.GID,
		OperationTimeout: operationTimeout, Now: time.Now})
	if err != nil {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database signer is unavailable")
	}
	alias, err := phase6egress.NewProviderPostgresAlias(ctx, profile, authority.owner, broker, guard,
		signer.CertificateForHandshake)
	if err != nil {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database TLS identity is unavailable")
	}
	material, err := registry.Resolve(ctx, binding.RuntimeDSNBindingID,
		secretref.PurposePostgresRuntimeDSN, secretref.SystemTenant)
	if err != nil {
		material.Destroy()
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database material is unavailable")
	}
	poolConfig, parseErr := phase6egress.ParseBoundPostgresDSN(material.Bytes, phase6egress.BoundPostgresTarget{
		Host: service.DNSNames[0], Port: edge.Port, Database: binding.DatabaseName, User: binding.RuntimeRole})
	material.Destroy()
	if parseErr != nil {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database material does not match profile")
	}
	poolConfig.MaxConns, poolConfig.MinConns = cfg.Postgres.MaxConnections, cfg.Postgres.MinConnections
	poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime, poolConfig.HealthCheckPeriod =
		30*time.Minute, 5*time.Minute, 30*time.Second
	if err := alias.BindProviderPostgres(poolConfig); err != nil {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database tunnel is unavailable")
	}
	poolConfig.AfterConnect = func(connectContext context.Context, connection *pgx.Conn) error {
		return providerpostgres.VerifyBoundRuntimeConnection(connectContext, connection,
			binding.DatabaseName, binding.RuntimeRole)
	}
	// A pooled connection cannot outlive the broker revocation guard's
	// readiness simply because its PostgreSQL handshake happened earlier.
	poolConfig.BeforeAcquire = func(acquireContext context.Context, _ *pgx.Conn) bool {
		return acquireContext != nil && acquireContext.Err() == nil && guard.Ready()
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database pool is unavailable")
	}
	stopPolling, err := guard.StartPolling(lifetime)
	if err != nil {
		pool.Close()
		cleanupGuard()
		return nil, nil, providerV3DatabaseAuthority{}, errors.New("Provider v3 database revocation monitor is unavailable")
	}
	close := func() { stopPolling(); pool.Close(); guard.Close() }
	return pool, close, authority, nil
}

func verifyProviderV3IdentityState(ctx context.Context, state *providerpostgres.Store,
	authority providerV3DatabaseAuthority) error {
	plan, err := authority.profile.ProjectSandboxIdentityPlan(authority.template, authority.owner, authority.capacity)
	if err != nil {
		return errors.New("Provider v3 identity authority is unavailable")
	}
	repository, err := providerpostgres.NewSandboxIdentityRepository(ctx, state, plan)
	if err != nil {
		return errors.New("Provider v3 identity database binding is unavailable")
	}
	if _, err := repository.Reservations(ctx); err != nil {
		return errors.New("Provider v3 identity ledger is unavailable or uninitialized")
	}
	return nil
}
