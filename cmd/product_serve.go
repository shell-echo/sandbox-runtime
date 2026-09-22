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
	"github.com/shell-echo/sandbox-runtime/internal/rolematerials"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
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

var productMigrateCmd = &cobra.Command{
	Use:          "migrate",
	Short:        "Run the one-shot Product database migration process",
	SilenceUsage: true,
	RunE:         runProductMigrate,
}

func runProductServe(cmd *cobra.Command, _ []string) error {
	productConfig := config.ProductProcess
	if productConfig == nil || !productConfig.Enabled {
		return errors.New("product_process.enabled must be true for product serve")
	}
	if config.ProviderProcess != nil && config.ProviderProcess.Enabled {
		return errors.New("Product and Provider process authorities cannot share one command")
	}
	if config.ProductMigration != nil && config.ProductMigration.Enabled {
		return errors.New("Product runtime and migration authorities cannot share one command")
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
	materialRegistry, err := newProductRuntimeMaterialRegistry(productConfig.Materials)
	if err != nil {
		return err
	}
	defer materialRegistry.Close()
	runtimePool, err := openProductPostgresRegistry(startupContext, materialRegistry, productConfig.Postgres.RuntimeDSNBindingID,
		secretref.PurposePostgresRuntimeDSN, productConfig.Postgres.MaxConnections, productConfig.Postgres.MinConnections)
	if err != nil {
		return fmt.Errorf("open Product runtime database: %w", err)
	}
	defer runtimePool.Close()
	if err := runtimePool.Ping(startupContext); err != nil {
		return errors.New("Product runtime database is unavailable at startup")
	}
	if err := productpostgres.VerifyRuntimeRole(startupContext, runtimePool, productConfig.Postgres.RuntimeRole); err != nil {
		return fmt.Errorf("verify Product runtime database authority: %w", err)
	}
	if err := productpostgres.VerifySchemaCompatibility(startupContext, runtimePool); err != nil {
		return fmt.Errorf("verify Product database schema: %w", err)
	}
	keyRing, err := materialRegistry.Resolve(startupContext, productConfig.Identity.KeyRingBindingID, secretref.PurposeIdentityKeyRing, secretref.SystemTenant)
	if err != nil {
		keyRing.Destroy()
		return productMaterialError(err, "load Product identity key-ring material")
	}
	authenticator, err := tokenidentity.LoadMaterial(keyRing.Bytes, productConfig.Identity.Issuer, productConfig.Identity.Audience,
		time.Duration(productConfig.Identity.ClockSkewSeconds)*time.Second, time.Duration(productConfig.Identity.MaxTokenLifetimeSeconds)*time.Second)
	keyRing.Destroy()
	if err != nil {
		return err
	}
	tlsConfig, err := productprocess.LoadTLSConfigFromRegistry(startupContext, materialRegistry, productConfig.TLS.CertificateBindingID,
		productConfig.TLS.PrivateKeyBindingID, productConfig.TLS.ExpectedServerName, time.Now)
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
		if err := productpostgres.VerifySchemaCompatibility(checkContext, runtimePool); err != nil {
			return err
		}
		return verifyProductMaterialDependencies(checkContext, materialRegistry, productConfig)
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
	return openProductPostgresMaterial(ctx, raw, maxConnections, minConnections)
}

func openProductPostgresRegistry(ctx context.Context, registry *secretref.Registry, bindingID string, purpose secretref.Purpose, maxConnections, minConnections int32) (*pgxpool.Pool, error) {
	material, err := registry.Resolve(ctx, bindingID, purpose, secretref.SystemTenant)
	if err != nil {
		material.Destroy()
		return nil, productMaterialError(err, "load Product PostgreSQL connection material")
	}
	defer material.Destroy()
	return openProductPostgresMaterial(ctx, material.Bytes, maxConnections, minConnections)
}

func openProductPostgresMaterial(ctx context.Context, raw []byte, maxConnections, minConnections int32) (*pgxpool.Pool, error) {
	if len(raw) < 1 || int64(len(raw)) > maxProductPostgresDSNBytes {
		return nil, errors.New("invalid Product PostgreSQL connection secret")
	}
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

func newProductRuntimeMaterialRegistry(materials config.ProductMaterialsConfig) (*secretref.Registry, error) {
	return newProductAgentRegistry(materials, []secretref.Purpose{
		secretref.PurposeTLSCertificate,
		secretref.PurposeTLSPrivateKey,
		secretref.PurposePostgresRuntimeDSN,
		secretref.PurposeIdentityKeyRing,
	}, true)
}

func newProductMigrationMaterialRegistry(materials config.ProductMaterialsConfig) (*secretref.Registry, error) {
	return newProductAgentRegistry(materials, []secretref.Purpose{secretref.PurposePostgresMigrationDSN}, false)
}

func newProductAgentRegistry(materials config.ProductMaterialsConfig, allowedPurposes []secretref.Purpose, cache bool) (*secretref.Registry, error) {
	registry, err := rolematerials.New(materials, secretref.RoleProduct, allowedPurposes, cache, time.Now)
	if err != nil {
		return nil, errors.New("construct Product material registry")
	}
	return registry, nil
}

func verifyProductMaterialDependencies(ctx context.Context, registry *secretref.Registry, productConfig *config.ProductProcessConfig) error {
	checks := []struct {
		bindingID string
		purpose   secretref.Purpose
	}{
		{productConfig.TLS.CertificateBindingID, secretref.PurposeTLSCertificate},
		{productConfig.TLS.PrivateKeyBindingID, secretref.PurposeTLSPrivateKey},
		{productConfig.Postgres.RuntimeDSNBindingID, secretref.PurposePostgresRuntimeDSN},
		{productConfig.Identity.KeyRingBindingID, secretref.PurposeIdentityKeyRing},
	}
	for _, check := range checks {
		material, err := registry.Resolve(ctx, check.bindingID, check.purpose, secretref.SystemTenant)
		material.Destroy()
		if err != nil {
			return productMaterialError(err, "Product material dependency is unavailable")
		}
	}
	return nil
}

func runProductMigrate(cmd *cobra.Command, _ []string) error {
	migrationConfig := config.ProductMigration
	if migrationConfig == nil || !migrationConfig.Enabled {
		return errors.New("product_migration.enabled must be true for product migrate")
	}
	if config.ProductProcess != nil && config.ProductProcess.Enabled {
		return errors.New("Product migration and runtime authorities cannot share one command")
	}
	if config.ProviderProcess != nil && config.ProviderProcess.Enabled {
		return errors.New("Product migration and Provider authorities cannot share one command")
	}
	if config.Application == nil || config.Application.Mode != config.ApplicationProductionMode {
		return errors.New("Product migration requires application.mode=production")
	}
	if err := migrationConfig.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), time.Duration(migrationConfig.Postgres.StartupTimeoutSeconds)*time.Second)
	defer cancel()
	registry, err := newProductMigrationMaterialRegistry(migrationConfig.Materials)
	if err != nil {
		return err
	}
	defer registry.Close()
	pool, err := openProductPostgresRegistry(ctx, registry, migrationConfig.Postgres.DSNBindingID,
		secretref.PurposePostgresMigrationDSN, migrationConfig.Postgres.MaxConnections, 0)
	if err != nil {
		return fmt.Errorf("open Product migration database: %w", err)
	}
	defer pool.Close()
	if err := productpostgres.ApplyMigrations(ctx, pool); err != nil {
		return fmt.Errorf("apply Product database migrations: %w", err)
	}
	if err := productpostgres.VerifyMigrationRole(ctx, pool, migrationConfig.Postgres.Role); err != nil {
		return fmt.Errorf("verify Product migration database authority: %w", err)
	}
	pool.Close()
	registry.Close()
	return nil
}

func productMaterialError(err error, message string) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New(message)
}

func init() {
	productCmd.AddCommand(productServeCmd, productMigrateCmd)
	rootCmd.AddCommand(productCmd)
}
