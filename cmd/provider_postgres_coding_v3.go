package cmd

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
)

func openProviderCodingV3Postgres(ctx, lifetime context.Context, cfg *config.ProviderProcessConfig,
	profile phase6security.ProfileV2, registry *secretref.Registry) (*pgxpool.Pool, func(), error) {
	return openDirectV3Postgres(ctx, lifetime, profile, registry, directV3PostgresSettings{
		Owner: "provider-runtime", RuntimeRole: cfg.Postgres.RuntimeRole,
		DSNBindingID:      cfg.Postgres.RuntimeDSNBindingID,
		Purpose:           secretref.PurposePostgresRuntimeDSN,
		ClientAgentSocket: cfg.Postgres.ClientAgentSocket,
		ClientAgentUID:    cfg.Postgres.ClientAgentUID, ClientAgentGID: cfg.Postgres.ClientAgentGID,
		PeerCRLRoleFile:            cfg.Postgres.PeerCRLRoleFile,
		PeerCRLRoleDigest:          cfg.Postgres.PeerCRLRoleDigest,
		PeerCRLSourceMappingDigest: cfg.Postgres.PeerCRLSourceMappingDigest,
		OperationTimeout:           time.Duration(cfg.Transport.OperationTimeoutMillis) * time.Millisecond,
		MaxConnections:             cfg.Postgres.MaxConnections, MinConnections: cfg.Postgres.MinConnections,
		AfterConnect: func(ctx context.Context, connection *pgx.Conn) error {
			return providerpostgres.VerifyBoundRuntimeConnection(ctx, connection, "provider", cfg.Postgres.RuntimeRole)
		},
	})
}
