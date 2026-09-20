package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/product"
	productpostgres "github.com/shell-echo/sandbox-runtime/product/adapter/postgres"
	"github.com/shell-echo/sandbox-runtime/productapi"
	"github.com/shell-echo/sandbox-runtime/productapi/identityfile"
	productprocess "github.com/shell-echo/sandbox-runtime/productapi/process"
	"github.com/shell-echo/sandbox-runtime/productapi/tokenidentity"
	productapiv1 "github.com/shell-echo/sandbox-runtime/productapi/v1"
	"github.com/shell-echo/sandbox-runtime/server"
	"github.com/spf13/cobra"
)

const maxProductPostgresDSNBytes int64 = 8 << 10

var productCmd = &cobra.Command{
	Use:   "product",
	Short: "Operate the independent Product process",
}

var productServeCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Start the independent Product API process",
	SilenceUsage: true,
	RunE:         runProductServe,
}

func runProductServe(cmd *cobra.Command, _ []string) error {
	productConfig := config.ProductProcess
	if productConfig == nil || !productConfig.Enabled {
		return errors.New("product_process.enabled must be true for product serve")
	}
	if config.ProviderProcess != nil && config.ProviderProcess.Enabled {
		return errors.New("Product and Provider process authorities cannot share one command")
	}
	if config.Application == nil {
		return errors.New("application configuration is required")
	}
	if err := productConfig.Validate(); err != nil {
		return err
	}
	switch productConfig.DeploymentLevel {
	case config.ProductDevelopmentLevel:
		if config.Application.Mode != config.ApplicationDevelopmentMode {
			return errors.New("development Product composition requires application.mode=development")
		}
		return runDevelopmentProduct(cmd.Context(), productConfig)
	case config.ProductProductionLevel:
		if config.Application.Mode != config.ApplicationProductionMode {
			return errors.New("production Product composition requires application.mode=production")
		}
		return runProductionProduct(cmd.Context(), productConfig)
	default:
		return errors.New("unsupported Product deployment level")
	}
}

func runDevelopmentProduct(ctx context.Context, productConfig *config.ProductProcessConfig) error {
	startupContext, cancelStartup := context.WithTimeout(ctx, time.Duration(productConfig.Postgres.StartupTimeoutSeconds)*time.Second)
	defer cancelStartup()
	pool, err := openProductPostgres(startupContext, productConfig.Postgres)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := productpostgres.ApplyMigrations(startupContext, pool); err != nil {
		return fmt.Errorf("apply Product database migrations: %w", err)
	}
	if err := pool.Ping(startupContext); err != nil {
		return errors.New("Product database is unavailable at startup")
	}

	authenticator, err := identityfile.Load(productConfig.Identity.BindingsFile)
	if err != nil {
		return err
	}
	store, err := productpostgres.New(pool, time.Duration(productConfig.Postgres.OperationTimeoutSeconds)*time.Second)
	if err != nil {
		return fmt.Errorf("construct Product store: %w", err)
	}
	ids := product.CryptoIDGenerator{}
	application, err := product.NewApplication(store, unavailablePrimarySlotPolicy{}, ids)
	if err != nil {
		return fmt.Errorf("construct Product application: %w", err)
	}
	apiHandler, err := productapiv1.NewHandler(application, authenticator, ids)
	if err != nil {
		return fmt.Errorf("construct Product API: %w", err)
	}
	readinessTimeout := time.Duration(productConfig.Postgres.OperationTimeoutSeconds) * time.Second
	productServer, err := productprocess.NewServer(productConfig.API, apiHandler, productprocess.ReadinessFunc(func(ctx context.Context) error {
		readinessContext, cancel := context.WithTimeout(ctx, readinessTimeout)
		defer cancel()
		return pool.Ping(readinessContext)
	}))
	if err != nil {
		return err
	}
	return server.RunE(map[string]server.Server{"product": productServer})
}

func runProductionProduct(ctx context.Context, productConfig *config.ProductProcessConfig) error {
	startupContext, cancelStartup := context.WithTimeout(ctx, time.Duration(productConfig.Postgres.StartupTimeoutSeconds)*time.Second)
	defer cancelStartup()
	migrationPool, err := openProductPostgresFile(startupContext, productConfig.Postgres.MigrationDSNFile, productConfig.Postgres.MigrationMaxConnections, 0)
	if err != nil {
		return fmt.Errorf("open Product migration database: %w", err)
	}
	defer migrationPool.Close()
	if err := productpostgres.ApplyMigrations(startupContext, migrationPool); err != nil {
		return fmt.Errorf("apply Product database migrations: %w", err)
	}
	runtimePool, err := openProductPostgresFile(startupContext, productConfig.Postgres.RuntimeDSNFile, productConfig.Postgres.MaxConnections, productConfig.Postgres.MinConnections)
	if err != nil {
		return fmt.Errorf("open Product runtime database: %w", err)
	}
	defer runtimePool.Close()
	if err := runtimePool.Ping(startupContext); err != nil {
		return errors.New("Product runtime database is unavailable at startup")
	}
	if err := productpostgres.VerifySeparatedRoles(startupContext, migrationPool, runtimePool, productConfig.Postgres.MigrationRole, productConfig.Postgres.RuntimeRole); err != nil {
		return fmt.Errorf("verify Product database authority: %w", err)
	}
	if err := productpostgres.VerifySchemaCompatibility(startupContext, runtimePool); err != nil {
		return fmt.Errorf("verify Product database schema: %w", err)
	}
	// Migration authority is intentionally released before the network listener
	// can accept traffic. No runtime path retains a DDL-capable connection.
	migrationPool.Close()

	authenticator, err := tokenidentity.Load(productConfig.Identity.KeyRingFile, productConfig.Identity.Issuer, productConfig.Identity.Audience,
		time.Duration(productConfig.Identity.ClockSkewSeconds)*time.Second, time.Duration(productConfig.Identity.MaxTokenLifetimeSeconds)*time.Second)
	if err != nil {
		return err
	}
	tlsConfig, err := productprocess.LoadTLSConfig(productConfig.TLS.CertificateFile, productConfig.TLS.PrivateKeyFile)
	if err != nil {
		return err
	}
	store, err := productpostgres.New(runtimePool, time.Duration(productConfig.Postgres.OperationTimeoutSeconds)*time.Second)
	if err != nil {
		return fmt.Errorf("construct Product store: %w", err)
	}
	ids := product.CryptoIDGenerator{}
	application, err := product.NewApplication(store, unavailablePrimarySlotPolicy{}, ids)
	if err != nil {
		return fmt.Errorf("construct Product application: %w", err)
	}
	apiHandler, err := productapiv1.NewHandlerWithCapabilities(application, nil, nil, nil, nil, productionKernelCapabilities{}, authenticator, ids)
	if err != nil {
		return fmt.Errorf("construct Product API: %w", err)
	}
	operationTimeout := time.Duration(productConfig.Postgres.OperationTimeoutSeconds) * time.Second
	monitorTimeout := operationTimeout
	if monitorTimeout > time.Second {
		monitorTimeout = time.Second
	}
	monitor, err := productprocess.NewDependencyMonitor(func(checkContext context.Context) error {
		if err := runtimePool.Ping(checkContext); err != nil {
			return err
		}
		return productpostgres.VerifySchemaCompatibility(checkContext, runtimePool)
	}, time.Second, monitorTimeout)
	if err != nil {
		return err
	}
	productServer, err := productprocess.NewTLSServer(productConfig.API, apiHandler, monitor, tlsConfig)
	if err != nil {
		return err
	}
	return server.RunE(map[string]server.Server{"product": productServer, "product-dependencies": monitor})
}

type productionKernelCapabilities struct{}

func (productionKernelCapabilities) Snapshot(ctx context.Context, _ productapi.Principal) ([]productapiv1.ProductCapability, error) {
	if ctx == nil {
		return nil, product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Provider and Gateway are deliberately not composed before Slices 3-4.
	// Advertising the unavailable Product surface is the complete current
	// dependency result and prevents route presence from becoming readiness.
	return []productapiv1.ProductCapability{{
		CapabilityID: "product.workspace", Version: "1.0.0", Readiness: "unavailable", ProtocolProfiles: []string{},
	}}, nil
}

type unavailablePrimarySlotPolicy struct{}

func (unavailablePrimarySlotPolicy) AuthorizePrimarySlot(ctx context.Context, _ product.SlotSpec) error {
	if ctx == nil {
		return product.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return product.ErrCapabilityUnsupported
}

func openProductPostgres(ctx context.Context, postgres config.ProductPostgresConfig) (*pgxpool.Pool, error) {
	return openProductPostgresFile(ctx, postgres.DSNFile, postgres.MaxConnections, postgres.MinConnections)
}

func openProductPostgresFile(ctx context.Context, path string, maxConnections, minConnections int32) (*pgxpool.Pool, error) {
	raw, err := secretfile.Read(path, maxProductPostgresDSNBytes)
	if err != nil {
		return nil, fmt.Errorf("load Product PostgreSQL connection secret: %w", err)
	}
	defer clear(raw)
	dsn := strings.TrimSuffix(string(raw), "\n")
	if dsn == "" || strings.TrimSpace(dsn) != dsn || strings.ContainsAny(dsn, "\x00\r\n") {
		return nil, errors.New("invalid Product PostgreSQL connection secret")
	}
	parsedURL, err := url.Parse(dsn)
	if err != nil || (parsedURL.Scheme != "postgres" && parsedURL.Scheme != "postgresql") || parsedURL.Host == "" || parsedURL.User == nil {
		return nil, errors.New("invalid Product PostgreSQL connection secret")
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid Product PostgreSQL connection secret")
	}
	poolConfig.MaxConns = maxConnections
	poolConfig.MinConns = minConnections
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	poolConfig.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.New("open Product PostgreSQL pool")
	}
	return pool, nil
}

func init() {
	productCmd.AddCommand(productServeCmd)
	rootCmd.AddCommand(productCmd)
}
