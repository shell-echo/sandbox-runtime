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
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/workloadtlsagent"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
)

// preflightProductV3Postgres runs before the material registry or any DB
// connection. A former direct-DSN v3 snapshot cannot silently enter the
// final nine-role shared-service profile.
func preflightProductV3Postgres(cfg *config.ProductProcessConfig) (phase6security.Profile, error) {
	if cfg == nil || cfg.SchemaVersion != config.ProductProductionSchemaV3 || cfg.Validate() != nil {
		return phase6security.Profile{}, errors.New("Product v3 PostgreSQL configuration is unavailable")
	}
	profile, err := phase6security.VerifySlice6ProfileForDeployment(cfg.TLS.SecurityProfilePath, "product-runtime")
	if err != nil || profile.ProfileDigest != cfg.TLS.SecurityProfileDigest {
		return phase6security.Profile{}, errors.New("Product v3 security profile mismatch")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("product-runtime")
	if err != nil || authority.BrokerOnly || authority.Dialer != "product-runtime" ||
		authority.SQLRole != cfg.Postgres.RuntimeRole || authority.Signer.SocketPath != cfg.Postgres.ClientAgentSocket ||
		authority.Signer.AgentUID != cfg.Postgres.ClientAgentUID ||
		authority.Signer.AgentGID != cfg.Postgres.ClientAgentGID {
		return phase6security.Profile{}, errors.New("Product v3 PostgreSQL target does not match profile")
	}
	role, err := phase6security.VerifySlice6PeerCRLRoleForDeployment(cfg.Postgres.PeerCRLRoleFile,
		"product-runtime", phase6security.Slice6PostgresPeerCRLRoleFile, profile,
		cfg.Postgres.PeerCRLSourceMappingDigest, cfg.Postgres.PeerCRLRoleDigest)
	if err != nil || len(role.Edges) != 1 || role.Edges[0].EdgeID != authority.PeerEdgeID ||
		role.Edges[0].Direction != "outbound" || role.Edges[0].PeerAnchorID != authority.ServerAnchor.ID {
		return phase6security.Profile{}, errors.New("Product v3 PostgreSQL peer CRL role does not match profile")
	}
	if _, err := phase6security.VerifySlice6PeerCRLRoleForDeployment(cfg.TLS.PeerCRLRoleFile,
		"product-runtime", phase6security.Slice6PeerCRLRoleFile, profile,
		cfg.TLS.PeerCRLSourceMappingDigest, cfg.TLS.PeerCRLRoleDigest); err != nil {
		return phase6security.Profile{}, errors.New("Product v3 private peer CRL role does not match profile")
	}
	return profile, nil
}

func openProductV3Postgres(ctx, lifetime context.Context, cfg *config.ProductProcessConfig,
	profile phase6security.Profile, registry *secretref.Registry) (*pgxpool.Pool, func(), error) {
	return openDirectV3Postgres(ctx, lifetime, profile, registry, directV3PostgresSettings{
		Owner: "product-runtime", RuntimeRole: cfg.Postgres.RuntimeRole,
		DSNBindingID:      cfg.Postgres.RuntimeDSNBindingID,
		Purpose:           secretref.PurposePostgresRuntimeDSN,
		ClientAgentSocket: cfg.Postgres.ClientAgentSocket,
		ClientAgentUID:    cfg.Postgres.ClientAgentUID, ClientAgentGID: cfg.Postgres.ClientAgentGID,
		PeerCRLRoleFile:            cfg.Postgres.PeerCRLRoleFile,
		PeerCRLRoleDigest:          cfg.Postgres.PeerCRLRoleDigest,
		PeerCRLSourceMappingDigest: cfg.Postgres.PeerCRLSourceMappingDigest,
		OperationTimeout:           time.Duration(cfg.TLS.OperationTimeoutMillis) * time.Millisecond,
		MaxConnections:             cfg.Postgres.MaxConnections, MinConnections: cfg.Postgres.MinConnections,
		AfterConnect: func(ctx context.Context, connection *pgx.Conn) error {
			return productpostgres.VerifyBoundRuntimeConnection(ctx, connection, "product", cfg.Postgres.RuntimeRole)
		},
	})
}

type directV3PostgresSettings struct {
	Owner, RuntimeRole, DSNBindingID, ClientAgentSocket            string
	Purpose                                                        secretref.Purpose
	ClientAgentUID, ClientAgentGID                                 uint32
	PeerCRLRoleFile, PeerCRLRoleDigest, PeerCRLSourceMappingDigest string
	OperationTimeout                                               time.Duration
	MaxConnections, MinConnections                                 int32
	AfterConnect                                                   func(context.Context, *pgx.Conn) error
	MigrationDiagnostic                                            bool
}

// directPostgresStage is a closed, local-only startup diagnostic. It never
// contains a cause, endpoint, credential, path or SQL statement. Error() keeps
// the existing generic error for Product and Provider runtime callers.
type directPostgresStage string

const (
	postgresStageAuthority             directPostgresStage = "authority"
	postgresStageSignerClient          directPostgresStage = "signer-client"
	postgresStagePeerRole              directPostgresStage = "peer-role"
	postgresStagePeerGuardConstruction directPostgresStage = "peer-guard-construction"
	postgresStagePeerBootstrap         directPostgresStage = "peer-bootstrap"
	postgresStageTLSClient             directPostgresStage = "TLS-client"
	postgresStageMaterialResolve       directPostgresStage = "material-resolve"
	postgresStageDSNBinding            directPostgresStage = "DSN-binding"
	postgresStagePoolBinding           directPostgresStage = "pool-binding"
	postgresStageOwnGuardConstruction  directPostgresStage = "own-guard-construction"
	postgresStageOwnRefresh            directPostgresStage = "own-refresh"
	postgresStagePoolCreate            directPostgresStage = "pool-create"
	postgresStageMonitorStart          directPostgresStage = "monitor-start"
)

type directPostgresStartupError struct {
	stage     directPostgresStage
	message   string
	peerClass phase6tls.PeerCRLFailureClass
}

func (e *directPostgresStartupError) Error() string { return e.message }

func postgresStartupError(stage directPostgresStage, message string) error {
	return &directPostgresStartupError{stage: stage, message: message}
}

func postgresPeerStartupError(message string, err error) error {
	return &directPostgresStartupError{stage: postgresStagePeerBootstrap, message: message,
		peerClass: phase6tls.PeerCRLFailureOf(err)}
}

func closedMigrationPeerClass(class phase6tls.PeerCRLFailureClass) string {
	switch class {
	case phase6tls.PeerCRLLocalGuardFailure, phase6tls.PeerCRLParentCanceledFailure,
		phase6tls.PeerCRLParentDeadlineFailure, phase6tls.PeerCRLInternalDeadlineFailure,
		phase6tls.PeerCRLRequestBuildFailure, phase6tls.PeerCRLSocketPeerFailure,
		phase6tls.PeerCRLTransportFailure, phase6tls.PeerCRLAgentResponseFailure,
		phase6tls.PeerCRLBindingFailure, phase6tls.PeerCRLSemanticFailure:
		return string(class)
	default:
		return string(phase6tls.PeerCRLUnknownFailure)
	}
}

func migrationPostgresConnectError(err error) error {
	const generic = "migration v2 PostgreSQL connection is unavailable"
	var startup *directPostgresStartupError
	if !errors.As(err, &startup) {
		return errors.New(generic)
	}
	line := generic + ": stage=" + string(startup.stage)
	switch startup.stage {
	case postgresStagePeerBootstrap:
		return errors.New(line + ": class=" + closedMigrationPeerClass(startup.peerClass))
	case postgresStageAuthority, postgresStageSignerClient, postgresStagePeerRole,
		postgresStagePeerGuardConstruction,
		postgresStageTLSClient, postgresStageMaterialResolve, postgresStageDSNBinding,
		postgresStagePoolBinding, postgresStageOwnGuardConstruction, postgresStageOwnRefresh,
		postgresStagePoolCreate, postgresStageMonitorStart:
		return errors.New(line)
	default:
		return errors.New(generic)
	}
}

type postgresPeerStartupGuard interface {
	Bootstrap(context.Context) error
	Close()
}

func bootstrapPostgresPeer(ctx context.Context, guard postgresPeerStartupGuard, constructionErr error) error {
	if constructionErr != nil || guard == nil {
		if guard != nil {
			guard.Close()
		}
		return postgresStartupError(postgresStagePeerGuardConstruction, "direct v3 PostgreSQL peer revocation evidence is unavailable")
	}
	if err := guard.Bootstrap(ctx); err != nil {
		guard.Close()
		return postgresPeerStartupError("direct v3 PostgreSQL peer revocation evidence is unavailable", err)
	}
	return nil
}

type postgresOwnStartupGuard interface {
	Refresh(context.Context) error
	Close()
}

func refreshPostgresOwn(ctx context.Context, guard postgresOwnStartupGuard, constructionErr error) error {
	if constructionErr != nil || guard == nil {
		if guard != nil {
			guard.Close()
		}
		return postgresStartupError(postgresStageOwnGuardConstruction, "direct v3 PostgreSQL client revocation evidence is unavailable")
	}
	if guard.Refresh(ctx) != nil {
		guard.Close()
		return postgresStartupError(postgresStageOwnRefresh, "direct v3 PostgreSQL client revocation evidence is unavailable")
	}
	return nil
}

// openDirectV3Postgres is shared by Product and the coding Provider; neither
// may select the Browser/Desktop broker-only database path.
func openDirectV3Postgres(ctx, lifetime context.Context, profile phase6security.Profile,
	registry *secretref.Registry, settings directV3PostgresSettings) (*pgxpool.Pool, func(), error) {
	if ctx == nil || lifetime == nil || ctx.Err() != nil || lifetime.Err() != nil || registry == nil {
		return nil, nil, postgresStartupError(postgresStageAuthority, "direct v3 PostgreSQL startup is unavailable")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority(settings.Owner)
	if err != nil || authority.BrokerOnly || authority.Dialer != settings.Owner ||
		authority.SQLRole != settings.RuntimeRole || authority.Signer.SocketPath != settings.ClientAgentSocket ||
		authority.Signer.AgentUID != settings.ClientAgentUID || authority.Signer.AgentGID != settings.ClientAgentGID {
		return nil, nil, postgresStartupError(postgresStageAuthority, "direct v3 PostgreSQL authority is unavailable")
	}
	_, _, _, subject, _, err := profile.PostgresClientSignerForOwner(authority.Owner)
	if err != nil {
		return nil, nil, postgresStartupError(postgresStageSignerClient, "direct v3 PostgreSQL signer is unavailable")
	}
	operationTimeout := settings.OperationTimeout
	signer, err := workloadtlsagent.NewProductionClient(workloadtlsagent.ClientConfig{
		SocketPath: settings.ClientAgentSocket, ExpectedUID: settings.ClientAgentUID,
		ExpectedGID: settings.ClientAgentGID, RoleGID: subject.GID,
		OperationTimeout: operationTimeout, Now: time.Now})
	if err != nil {
		return nil, nil, postgresStartupError(postgresStageSignerClient, "direct v3 PostgreSQL signer is unavailable")
	}
	role, err := phase6security.VerifyPeerCRLRoleFile(settings.PeerCRLRoleFile, profile,
		settings.PeerCRLSourceMappingDigest, settings.PeerCRLRoleDigest)
	if err != nil {
		return nil, nil, postgresStartupError(postgresStagePeerRole, "direct v3 PostgreSQL peer role is unavailable")
	}
	guard, err := phase6tls.PostgresPeerGuard(profile, phase6tls.PostgresPeerAuthority{
		Owner: authority.Owner, PeerCRLRole: role, AgentSocket: settings.ClientAgentSocket,
		AgentUID: settings.ClientAgentUID, AgentGID: settings.ClientAgentGID,
		OperationTimeout: operationTimeout})
	var peerStartup postgresPeerStartupGuard
	if guard != nil {
		peerStartup = guard
	}
	if startupErr := bootstrapPostgresPeer(ctx, peerStartup, err); startupErr != nil {
		return nil, nil, startupErr
	}
	direct, err := phase6egress.NewDirectPostgres(ctx, profile, authority.Owner, signer.CertificateForHandshake)
	if err != nil || direct == nil {
		guard.Close()
		return nil, nil, postgresStartupError(postgresStageTLSClient, "direct v3 PostgreSQL TLS identity is unavailable")
	}
	if settings.Purpose != secretref.PurposePostgresRuntimeDSN &&
		settings.Purpose != secretref.PurposePostgresMigrationDSN {
		guard.Close()
		return nil, nil, postgresStartupError(postgresStageMaterialResolve, "direct v3 PostgreSQL material purpose is unavailable")
	}
	material, err := registry.Resolve(ctx, settings.DSNBindingID,
		settings.Purpose, secretref.SystemTenant)
	if err != nil {
		material.Destroy()
		guard.Close()
		return nil, nil, postgresStartupError(postgresStageMaterialResolve, "direct v3 PostgreSQL material is unavailable")
	}
	poolConfig, parseErr := phase6egress.ParseBoundPostgresDSN(material.Bytes, phase6egress.BoundPostgresTarget{
		Host: authority.ServerHost, Port: authority.ServerPort, Database: authority.Database, User: authority.SQLRole})
	material.Destroy()
	if parseErr != nil {
		guard.Close()
		return nil, nil, postgresStartupError(postgresStageDSNBinding, "direct v3 PostgreSQL material does not match profile")
	}
	poolConfig.MaxConns, poolConfig.MinConns = settings.MaxConnections, settings.MinConnections
	poolConfig.MaxConnLifetime, poolConfig.MaxConnIdleTime, poolConfig.HealthCheckPeriod =
		30*time.Minute, 5*time.Minute, 30*time.Second
	if err := direct.Bind(poolConfig, guard); err != nil {
		guard.Close()
		return nil, nil, postgresStartupError(postgresStagePoolBinding, "direct v3 PostgreSQL connection is unavailable")
	}
	ownGuard, err := phase6egress.NewPostgresOwnGuard(profile, settings.Owner, signer,
		operationTimeout, time.Now)
	var ownStartup postgresOwnStartupGuard
	if ownGuard != nil {
		ownStartup = ownGuard
	}
	if startupErr := refreshPostgresOwn(ctx, ownStartup, err); startupErr != nil {
		guard.Close()
		return nil, nil, startupErr
	}
	if err := phase6egress.BindPostgresOwnGuard(poolConfig, ownGuard); err != nil {
		ownGuard.Close()
		guard.Close()
		return nil, nil, postgresStartupError(postgresStagePoolBinding, "direct v3 PostgreSQL client connection guard is unavailable")
	}
	if settings.AfterConnect == nil {
		ownGuard.Close()
		guard.Close()
		return nil, nil, postgresStartupError(postgresStagePoolBinding, "direct v3 PostgreSQL connection verification is unavailable")
	}
	poolConfig.AfterConnect = settings.AfterConnect
	if settings.MigrationDiagnostic && bindMigrationConnectionDiagnostic(ctx, poolConfig) != nil {
		ownGuard.Close()
		guard.Close()
		return nil, nil, postgresStartupError(postgresStagePoolBinding, "direct v3 PostgreSQL connection diagnostic is unavailable")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		ownGuard.Close()
		guard.Close()
		return nil, nil, postgresStartupError(postgresStagePoolCreate, "direct v3 PostgreSQL pool is unavailable")
	}
	stopPolling, err := guard.StartPolling(lifetime)
	if err != nil {
		ownGuard.Close()
		guard.Close()
		pool.Close()
		return nil, nil, postgresStartupError(postgresStageMonitorStart, "direct v3 PostgreSQL revocation monitor is unavailable")
	}
	stopOwnPolling, err := ownGuard.StartPolling(lifetime)
	if err != nil {
		stopPolling()
		ownGuard.Close()
		guard.Close()
		pool.Close()
		return nil, nil, postgresStartupError(postgresStageMonitorStart, "direct v3 PostgreSQL client revocation monitor is unavailable")
	}
	return pool, func() { stopOwnPolling(); stopPolling(); ownGuard.Close(); guard.Close(); pool.Close() }, nil
}
