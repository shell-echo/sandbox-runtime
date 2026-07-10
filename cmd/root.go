// Package cmd defines the command-line interface for sandbox-runtime, built on
// cobra. It exposes the root command and the Execute entry point invoked by
// main.
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/logger"
	"github.com/spf13/cobra"
)

// configPath holds the value of the persistent --config/-c flag.
var configPath string

// rootCmd is the base command. It has no RunE, so a bare invocation prints help
// (and, importantly, cobra does that without running PersistentPreRunE).
var rootCmd = &cobra.Command{
	Use:   "sandbox-runtime",
	Short: "A composable Linux sandbox runtime for remote GUI applications",
	Long: `sandbox-runtime is a composable Linux sandbox runtime.

It is used to launch, access, and control remote GUI applications
such as cloud browsers, desktop environments, and GUI apps inside
isolated Linux sandbox instances.`,
	SilenceUsage: true,
	// Execute prints the error and sets the exit code itself, so keep cobra from
	// also printing it (which would duplicate the message).
	SilenceErrors: true,
	// PersistentPreRunE initialises the process-wide dependencies — config, then
	// the logger built from it — for every runnable command. It does not run for
	// `--help` or a bare invocation (the root has no RunE), so those never touch
	// the log file.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := config.Load(configPath); err != nil {
			return err
		}
		return logger.Init(config.Logger.Options)
	},
}

// Execute runs the root command, then flushes the logger, and exits with a
// non-zero status on any error. logger.Sync runs even when the command failed
// and is a no-op if the logger was never initialised (e.g. plain --help).
func Execute() {
	err := errors.Join(rootCmd.Execute(), logger.Sync())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// init wires up persistent flags shared by all subcommands.
func init() {
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "config file path")
}
