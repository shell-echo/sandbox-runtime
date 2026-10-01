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
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
)

type migrationV2Authority struct {
	Owner, Role, ProfilePath, ProfileDigest, DSNBindingID          string
	ClientAgentSocket                                              string
	ClientAgentUID, ClientAgentGID                                 uint32
	PeerCRLRoleFile, PeerCRLRoleDigest, PeerCRLSourceMappingDigest string
	MaxConnections                                                 int32
}

func preflightMigrationV2(value migrationV2Authority) (phase6security.Profile, phase6security.Slice6PostgresAuthority, error) {
	profile, err := phase6security.VerifySlice6ProfileForDeployment(value.ProfilePath, value.Owner)
	if err != nil || profile.ProfileDigest != value.ProfileDigest {
		return phase6security.Profile{}, phase6security.Slice6PostgresAuthority{}, errors.New("migration v2 security profile mismatch")
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority(value.Owner)
	if err != nil || !authority.Migration || authority.BrokerOnly || authority.Dialer != value.Owner ||
		authority.SQLRole != value.Role || authority.Signer.SocketPath != value.ClientAgentSocket ||
		authority.Signer.AgentUID != value.ClientAgentUID || authority.Signer.AgentGID != value.ClientAgentGID {
		return phase6security.Profile{}, phase6security.Slice6PostgresAuthority{}, errors.New("migration v2 PostgreSQL target does not match profile")
	}
	role, err := phase6security.VerifySlice6PeerCRLRoleForDeployment(value.PeerCRLRoleFile,
		value.Owner, phase6security.Slice6PostgresPeerCRLRoleFile, profile,
		value.PeerCRLSourceMappingDigest, value.PeerCRLRoleDigest)
	if err != nil || len(role.Edges) != 1 || role.Edges[0].EdgeID != authority.PeerEdgeID ||
		role.Edges[0].Direction != "outbound" || role.Edges[0].PeerAnchorID != authority.ServerAnchor.ID {
		return phase6security.Profile{}, phase6security.Slice6PostgresAuthority{}, errors.New("migration v2 PostgreSQL peer CRL role does not match profile")
	}
	return profile, authority, nil
}

func runProductMigrationV2(cmdContext context.Context, cfg *config.ProductMigrationConfig) error {
	value := migrationV2Authority{Owner: "product-migration-job", Role: cfg.Postgres.Role,
		ProfilePath: cfg.Postgres.SecurityProfilePath, ProfileDigest: cfg.Postgres.SecurityProfileDigest,
		DSNBindingID: cfg.Postgres.DSNBindingID, ClientAgentSocket: cfg.Postgres.ClientAgentSocket,
		ClientAgentUID: cfg.Postgres.ClientAgentUID, ClientAgentGID: cfg.Postgres.ClientAgentGID,
		PeerCRLRoleFile: cfg.Postgres.PeerCRLRoleFile, PeerCRLRoleDigest: cfg.Postgres.PeerCRLRoleDigest,
		PeerCRLSourceMappingDigest: cfg.Postgres.PeerCRLSourceMappingDigest,
		MaxConnections:             cfg.Postgres.MaxConnections}
	return runMigrationV2(cmdContext, time.Duration(cfg.Postgres.StartupTimeoutSeconds)*time.Second,
		value, func() (*secretref.Registry, error) { return newProductMigrationMaterialRegistry(cfg.Materials) },
		productpostgres.ApplyMigrationsPrecreatedSchema, productpostgres.VerifyMigrationRole)
}

func runProviderMigrationV2(cmdContext context.Context, cfg *config.ProviderMigrationConfig) error {
	value := migrationV2Authority{Owner: cfg.Postgres.Job, Role: cfg.Postgres.Role,
		ProfilePath: cfg.Postgres.SecurityProfilePath, ProfileDigest: cfg.Postgres.SecurityProfileDigest,
		DSNBindingID: cfg.Postgres.DSNBindingID, ClientAgentSocket: cfg.Postgres.ClientAgentSocket,
		ClientAgentUID: cfg.Postgres.ClientAgentUID, ClientAgentGID: cfg.Postgres.ClientAgentGID,
		PeerCRLRoleFile: cfg.Postgres.PeerCRLRoleFile, PeerCRLRoleDigest: cfg.Postgres.PeerCRLRoleDigest,
		PeerCRLSourceMappingDigest: cfg.Postgres.PeerCRLSourceMappingDigest,
		MaxConnections:             cfg.Postgres.MaxConnections}
	return runMigrationV2(cmdContext, time.Duration(cfg.Postgres.StartupTimeoutSeconds)*time.Second,
		value, func() (*secretref.Registry, error) { return newProviderMigrationMaterialRegistry(cfg.Materials) },
		providerpostgres.ApplyMigrationsPrecreatedSchema, providerpostgres.VerifyMigrationRole)
}

func runMigrationV2(parent context.Context, timeout time.Duration, value migrationV2Authority,
	newRegistry func() (*secretref.Registry, error), apply func(context.Context, *pgxpool.Pool) error,
	verify func(context.Context, *pgxpool.Pool, string) error) error {
	if parent == nil || parent.Err() != nil || timeout < time.Second || timeout > time.Minute ||
		newRegistry == nil || apply == nil || verify == nil {
		return errors.New("migration v2 authority is unavailable")
	}
	profile, authority, err := preflightMigrationV2(value)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	registry, err := newRegistry()
	if err != nil {
		return errors.New("migration v2 material registry is unavailable")
	}
	defer registry.Close()
	pool, closePool, err := openDirectV3Postgres(ctx, parent, profile, registry, directV3PostgresSettings{
		Owner: value.Owner, RuntimeRole: value.Role, DSNBindingID: value.DSNBindingID,
		Purpose:           secretref.PurposePostgresMigrationDSN,
		ClientAgentSocket: value.ClientAgentSocket, ClientAgentUID: value.ClientAgentUID,
		ClientAgentGID: value.ClientAgentGID, PeerCRLRoleFile: value.PeerCRLRoleFile,
		PeerCRLRoleDigest: value.PeerCRLRoleDigest, PeerCRLSourceMappingDigest: value.PeerCRLSourceMappingDigest,
		OperationTimeout: min(timeout, 30*time.Second), MaxConnections: value.MaxConnections,
		AfterConnect: func(connectionCtx context.Context, connection *pgx.Conn) error {
			return phase6egress.VerifyBoundMigrationDDLConnection(connectionCtx, connection,
				authority.Database, authority.SQLRole)
		},
	})
	if err != nil {
		return errors.New("migration v2 PostgreSQL connection is unavailable")
	}
	defer closePool()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("migration v2 PostgreSQL readiness is unavailable")
	}
	// AfterConnect has already verified target, login and bounded DDL privilege
	// on the connection before ApplyMigrations can issue its first statement.
	if err := apply(ctx, pool); err != nil {
		return err // unknown transaction outcome is never automatically replayed
	}
	return verify(ctx, pool, value.Role)
}
