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
	"github.com/shell-echo/sandbox-runtime/productapi/identityfile"
	productprocess "github.com/shell-echo/sandbox-runtime/productapi/process"
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
	if config.Application == nil || config.Application.Mode != config.ApplicationDevelopmentMode {
		return errors.New("Phase 6 Slice 1 Product composition requires application.mode=development")
	}
	if err := productConfig.Validate(); err != nil {
		return err
	}

	startupContext, cancelStartup := context.WithTimeout(cmd.Context(), time.Duration(productConfig.Postgres.StartupTimeoutSeconds)*time.Second)
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
	raw, err := secretfile.Read(postgres.DSNFile, maxProductPostgresDSNBytes)
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
	poolConfig.MaxConns = postgres.MaxConnections
	poolConfig.MinConns = postgres.MinConnections
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
