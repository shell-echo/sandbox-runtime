package cmd

import (
	"context"
	"errors"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/roleprocess"
	"github.com/spf13/cobra"
)

var (
	gatewayRoleCmd = &cobra.Command{Use: "gateway", Short: "Operate the independent public Gateway role"}
	guestRoleCmd   = &cobra.Command{Use: "guest", Short: "Operate the independent outbound Guest role"}
	browserRoleCmd = &cobra.Command{Use: "browser", Short: "Operate the independent private Browser role"}
	desktopRoleCmd = &cobra.Command{Use: "desktop", Short: "Operate the independent private Desktop role"}
)

func roleServeCommand(role config.DataPlaneRole, section string, cfg func() *config.DataPlaneProcessConfig) *cobra.Command {
	return &cobra.Command{
		Use: "serve", Short: "Start the independent production role", SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDataPlaneServe(cmd.Context(), role, section, cfg())
		},
	}
}

func runDataPlaneServe(ctx context.Context, role config.DataPlaneRole, section string, cfg *config.DataPlaneProcessConfig) error {
	if cfg == nil || !cfg.Enabled {
		return errors.New(section + ".enabled must be true for this command")
	}
	if config.Application == nil || config.Application.Mode != config.ApplicationProductionMode {
		return errors.New("data-plane role serve requires application.mode=production")
	}
	if cfg.Role != role {
		return errors.New("data-plane role configuration does not match command")
	}
	for name, enabled := range map[string]bool{
		"product_process":  config.ProductProcess != nil && config.ProductProcess.Enabled,
		"provider_process": config.ProviderProcess != nil && config.ProviderProcess.Enabled,
		"gateway_process":  config.GatewayProcess != nil && config.GatewayProcess.Enabled && role != config.DataPlaneGateway,
		"guest_process":    config.GuestProcess != nil && config.GuestProcess.Enabled && role != config.DataPlaneGuest,
		"browser_process":  config.BrowserProcess != nil && config.BrowserProcess.Enabled && role != config.DataPlaneBrowser,
		"desktop_process":  config.DesktopProcess != nil && config.DesktopProcess.Enabled && role != config.DataPlaneDesktop,
	} {
		if enabled {
			return errors.New(name + " cannot share one command with " + string(role) + " authority")
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	var err error
	var graph roleprocess.ApplicationGraph
	switch role {
	case config.DataPlaneGateway:
		graph, err = roleprocess.NewGatewayApplicationGraph(ctx, cfg)
	case config.DataPlaneGuest:
		graph, err = roleprocess.NewGuestApplicationGraph(ctx, cfg)
	case config.DataPlaneBrowser, config.DataPlaneDesktop:
		// Provider remains the sole handoff/runtime authority. These role
		// processes are restricted opaque executor relays and do not own
		// Provider state or Docker control.
		graph, err = roleprocess.NewExecutorApplicationGraph(ctx, cfg)
	default:
		graph, err = roleprocess.ApplicationGraph{}, errors.New("unsupported data-plane role")
	}
	if err != nil {
		return err
	}
	composition, err := roleprocess.NewWithGraph(ctx, cfg, graph)
	if err != nil {
		return err
	}
	return composition.Startup(ctx)
}

func init() {
	gatewayRoleCmd.AddCommand(roleServeCommand(config.DataPlaneGateway, "gateway_process", func() *config.DataPlaneProcessConfig { return config.GatewayProcess }))
	guestRoleCmd.AddCommand(roleServeCommand(config.DataPlaneGuest, "guest_process", func() *config.DataPlaneProcessConfig { return config.GuestProcess }))
	browserRoleCmd.AddCommand(roleServeCommand(config.DataPlaneBrowser, "browser_process", func() *config.DataPlaneProcessConfig { return config.BrowserProcess }))
	desktopRoleCmd.AddCommand(roleServeCommand(config.DataPlaneDesktop, "desktop_process", func() *config.DataPlaneProcessConfig { return config.DesktopProcess }))
	rootCmd.AddCommand(gatewayRoleCmd, guestRoleCmd, browserRoleCmd, desktopRoleCmd)
}
