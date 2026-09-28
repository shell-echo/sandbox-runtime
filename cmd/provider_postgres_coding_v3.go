package cmd

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	providerpostgres "github.com/shell-echo/sandbox-runtime/provider/adapter/postgres"
)

func preflightProviderCodingV3Postgres(cfg *config.ProviderProcessConfig) (phase6security.Profile, error) {
	if cfg == nil || cfg.SchemaVersion != config.ProviderProductionSchemaV3 ||
		cfg.Profile != config.ProviderProcessCodingShellProfile || cfg.Validate() != nil {
		return phase6security.Profile{}, errors.New("coding Provider v3 PostgreSQL configuration is unavailable")
	}
	profile, err := loadProviderSecurityProfile(cfg)
	if err != nil {
		return phase6security.Profile{}, err
	}
	authority, err := profile.ResolveSlice6FinalPostgresAuthority("provider-runtime")
	if err != nil || authority.BrokerOnly || authority.Dialer != "provider-runtime" ||
		authority.SQLRole != cfg.Postgres.RuntimeRole || authority.Signer.SocketPath != cfg.Postgres.ClientAgentSocket ||
		authority.Signer.AgentUID != cfg.Postgres.ClientAgentUID ||
		authority.Signer.AgentGID != cfg.Postgres.ClientAgentGID {
		return phase6security.Profile{}, errors.New("coding Provider v3 PostgreSQL target does not match profile")
	}
	if _, err := phase6security.VerifyPeerCRLRoleFile(cfg.Transport.PeerCRLRoleFile, profile,
		cfg.Transport.PeerCRLSourceMappingDigest, cfg.Transport.PeerCRLRoleDigest); err != nil {
		return phase6security.Profile{}, errors.New("coding Provider v3 peer CRL role does not match profile")
	}
	role, err := phase6security.VerifyPeerCRLRoleFile(cfg.Postgres.PeerCRLRoleFile, profile,
		cfg.Postgres.PeerCRLSourceMappingDigest, cfg.Postgres.PeerCRLRoleDigest)
	if err != nil || len(role.Edges) != 1 || role.Edges[0].EdgeID != authority.PeerEdgeID ||
		role.Edges[0].Direction != "outbound" || role.Edges[0].PeerAnchorID != authority.ServerAnchor.ID {
		return phase6security.Profile{}, errors.New("coding Provider v3 PostgreSQL peer CRL role does not match profile")
	}
	edge, _, _, _, _, err := profile.ProductProviderInstanceBoundary("provider-runtime")
	if err != nil || edge.TargetAddress != cfg.Transport.Address.Addr() {
		return phase6security.Profile{}, errors.New("coding Provider v3 Contract edge does not match profile")
	}
	return profile, nil
}

func openProviderCodingV3Postgres(ctx, lifetime context.Context, cfg *config.ProviderProcessConfig,
	profile phase6security.Profile, registry *secretref.Registry) (*pgxpool.Pool, func(), error) {
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
