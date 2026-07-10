package cmd

import "testing"

// TestServeCmdRegistered confirms the serve subcommand is wired onto the root
// command.
func TestServeCmdRegistered(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "serve" {
			return
		}
	}
	t.Error("serve command not registered on rootCmd")
}
