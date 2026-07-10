package cmd

import (
	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/server"
	"github.com/shell-echo/sandbox-runtime/server/api"
	"github.com/spf13/cobra"
)

// serveCmd starts the long-running servers. Configuration and the logger have
// already been initialised by the root command's PersistentPreRunE.
var serveCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Start the server",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		apiServer, err := api.NewServer(config.Application.IsDevelopment(), config.Server.API)
		if err != nil {
			return err
		}
		return server.RunE(map[string]server.Server{"api": apiServer})
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
