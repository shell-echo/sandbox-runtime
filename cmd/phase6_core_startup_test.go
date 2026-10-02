package cmd

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/spf13/cobra"
)

func TestPhase6CoreCommandOwnerIsExact(t *testing.T) {
	previousProvider, previousMigration := config.ProviderProcess, config.ProviderMigration
	t.Cleanup(func() {
		config.ProviderProcess, config.ProviderMigration = previousProvider, previousMigration
	})
	for _, candidate := range []struct {
		parent, action, expected string
	}{
		{"product", "serve", "product-runtime"},
		{"product", "migrate", "product-migration-job"},
		{"gateway", "serve", "gateway-runtime"},
		{"guest", "serve", "guest-runtime"},
		{"browser", "serve", "browser-runtime-role"},
		{"desktop", "serve", "desktop-runtime-role"},
		{"product", "other", ""},
		{"other", "serve", ""},
	} {
		parent := &cobra.Command{Use: candidate.parent}
		child := &cobra.Command{Use: candidate.action}
		parent.AddCommand(child)
		if actual := phase6CoreCommandOwner(child); actual != candidate.expected {
			t.Fatalf("%s %s resolved as %q, want %q", candidate.parent, candidate.action, actual, candidate.expected)
		}
	}
	for _, candidate := range []struct {
		profile  config.ProviderProcessProfile
		expected string
	}{
		{config.ProviderProcessCodingShellProfile, "provider-runtime"},
		{config.ProviderProcessBrowserProfile, "provider-browser-runtime"},
		{config.ProviderProcessDesktopProfile, "provider-desktop-runtime"},
		{"unreviewed", ""},
	} {
		config.ProviderProcess = &config.ProviderProcessConfig{Profile: candidate.profile}
		parent := &cobra.Command{Use: "provider"}
		child := &cobra.Command{Use: "serve"}
		parent.AddCommand(child)
		if actual := phase6CoreCommandOwner(child); actual != candidate.expected {
			t.Fatalf("Provider profile %q resolved as %q, want %q", candidate.profile, actual, candidate.expected)
		}
	}
	for _, job := range []string{"provider-migration-job", "provider-browser-migration-job", "provider-desktop-migration-job"} {
		config.ProviderMigration = &config.ProviderMigrationConfig{}
		config.ProviderMigration.Postgres.Job = job
		parent := &cobra.Command{Use: "provider"}
		child := &cobra.Command{Use: "migrate"}
		parent.AddCommand(child)
		if actual := phase6CoreCommandOwner(child); actual != job {
			t.Fatalf("Provider migration %q resolved as %q", job, actual)
		}
	}
}
