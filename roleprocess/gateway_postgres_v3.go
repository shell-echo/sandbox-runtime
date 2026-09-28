package roleprocess

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
)

func preflightGatewayV3Postgres(cfg *config.DataPlaneProcessConfig,
	credential GatewayCredentialAuthority) (phase6security.Profile, error) {
	if cfg == nil || cfg.SchemaVersion != config.DataPlaneProductionSchemaV3 ||
		cfg.Role != config.DataPlaneGateway || cfg.Validate() != nil {
		return phase6security.Profile{}, errors.New("Gateway v3 PostgreSQL configuration is unavailable")
	}
	profile, err := phase6security.VerifyFile(cfg.TLS.SecurityProfilePath)
	if err != nil || profile.ProfileDigest != cfg.TLS.SecurityProfileDigest {
		return phase6security.Profile{}, errors.New("Gateway v3 security profile mismatch")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("gateway-runtime")
	if err != nil || authority.BrokerOnly || authority.Dialer != "gateway-runtime" ||
		authority.SQLRole != credential.PostgresRuntimeRole ||
		authority.Signer.SocketPath != credential.PostgresClientAgentSocket ||
		authority.Signer.AgentUID != credential.PostgresClientAgentUID ||
		authority.Signer.AgentGID != credential.PostgresClientAgentGID {
		return phase6security.Profile{}, errors.New("Gateway v3 PostgreSQL target does not match profile")
	}
	if _, err := phase6security.VerifyPeerCRLRoleFile(cfg.TLS.PeerCRLRoleFile, profile,
		cfg.TLS.PeerCRLSourceMappingDigest, cfg.TLS.PeerCRLRoleDigest); err != nil {
		return phase6security.Profile{}, errors.New("Gateway v3 peer CRL role does not match profile")
	}
	role, err := phase6security.VerifyPeerCRLRoleFile(credential.PostgresPeerCRLRoleFile, profile,
		credential.PostgresPeerCRLSourceMappingDigest, credential.PostgresPeerCRLRoleDigest)
	if err != nil || len(role.Edges) != 1 || role.Edges[0].EdgeID != authority.PeerEdgeID ||
		role.Edges[0].Direction != "outbound" || role.Edges[0].PeerAnchorID != authority.ServerAnchor.ID {
		return phase6security.Profile{}, errors.New("Gateway v3 PostgreSQL peer CRL role does not match profile")
	}
	if _, _, _, _, _, err := profile.GatewayProviderInstanceBoundary("provider-runtime", credential.ProviderOrigin); err != nil {
		return phase6security.Profile{}, errors.New("Gateway v3 Provider dependency does not match profile")
	}
	return profile, nil
}

func openGatewayV3Postgres(ctx context.Context, cfg *config.DataPlaneProcessConfig,
	credential GatewayCredentialAuthority, profile phase6security.Profile,
	registry *secretref.Registry) (*pgxpool.Pool, func(), error) {
	if ctx == nil || ctx.Err() != nil || registry == nil {
		return nil, nil, errors.New("Gateway v3 PostgreSQL startup is unavailable")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("gateway-runtime")
	if err != nil || authority.BrokerOnly || authority.SQLRole != credential.PostgresRuntimeRole {
		return nil, nil, errors.New("Gateway v3 PostgreSQL authority is unavailable")
	}
	_, _, _, subject, _, err := profile.PostgresClientSignerForOwner(authority.Owner)
	if err != nil {
		return nil, nil, errors.New("Gateway v3 PostgreSQL signer is unavailable")
	}
	operationTimeout := time.Duration(cfg.TLS.OperationTimeoutMillis) * time.Millisecond
	signer, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: credential.PostgresClientAgentSocket, ExpectedUID: credential.PostgresClientAgentUID,
		ExpectedGID: credential.PostgresClientAgentGID, RoleGID: subject.GID,
		OperationTimeout: operationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, errors.New("Gateway v3 PostgreSQL signer is unavailable")
	}
	role, err := phase6security.VerifyPeerCRLRoleFile(credential.PostgresPeerCRLRoleFile, profile,
		credential.PostgresPeerCRLSourceMappingDigest, credential.PostgresPeerCRLRoleDigest)
	if err != nil {
		return nil, nil, errors.New("Gateway v3 PostgreSQL peer role is unavailable")
	}
	guard, err := phase6tls.PostgresPeerGuard(profile, phase6tls.PostgresPeerAuthority{
		Owner: authority.Owner, PeerCRLRole: role, AgentSocket: credential.PostgresClientAgentSocket,
		AgentUID: credential.PostgresClientAgentUID, AgentGID: credential.PostgresClientAgentGID,
		OperationTimeout: operationTimeout})
	if err != nil || guard.Bootstrap(ctx) != nil {
		if guard != nil {
			guard.Close()
		}
		return nil, nil, errors.New("Gateway v3 PostgreSQL peer revocation evidence is unavailable")
	}
	direct, err := phase6egress.NewDirectPostgres(ctx, profile, authority.Owner, signer.CertificateForHandshake)
	if err != nil {
		guard.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL TLS identity is unavailable")
	}
	material, err := registry.Resolve(ctx, credential.ProductRuntimeDSNBindingID,
		secretref.PurposePostgresRuntimeDSN, secretref.SystemTenant)
	if err != nil {
		material.Destroy()
		guard.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL material is unavailable")
	}
	poolConfig, parseErr := phase6egress.ParseBoundPostgresDSN(material.Bytes, phase6egress.BoundPostgresTarget{
		Host: authority.ServerHost, Port: authority.ServerPort, Database: authority.Database, User: authority.SQLRole})
	material.Destroy()
	if parseErr != nil {
		guard.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL material does not match profile")
	}
	poolConfig.MaxConns, poolConfig.MinConns = credential.PostgresMaxConnections, 0
	poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime, poolConfig.HealthCheckPeriod =
		30*time.Minute, 5*time.Minute, 30*time.Second
	if err := direct.Bind(poolConfig, guard); err != nil {
		guard.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL direct connection is unavailable")
	}
	ownGuard, err := phase6egress.NewPostgresOwnGuard(profile, authority.Owner, signer, operationTimeout, time.Now)
	if err != nil || ownGuard.Refresh(ctx) != nil ||
		phase6egress.BindPostgresOwnGuard(poolConfig, ownGuard) != nil {
		if ownGuard != nil {
			ownGuard.Close()
		}
		guard.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL client revocation guard is unavailable")
	}
	poolConfig.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		return productpostgres.VerifyBoundGatewayConnection(ctx, connection, authority.Database, authority.SQLRole)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		ownGuard.Close()
		guard.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL pool is unavailable")
	}
	stopPolling, err := guard.StartPolling(ctx)
	if err != nil {
		ownGuard.Close()
		guard.Close()
		pool.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL revocation monitor is unavailable")
	}
	stopOwnPolling, err := ownGuard.StartPolling(ctx)
	if err != nil {
		stopPolling()
		ownGuard.Close()
		guard.Close()
		pool.Close()
		return nil, nil, errors.New("Gateway v3 PostgreSQL client revocation monitor is unavailable")
	}
	return pool, func() { stopOwnPolling(); stopPolling(); ownGuard.Close(); guard.Close(); pool.Close() }, nil
}
