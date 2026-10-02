package cmd

import (
	"errors"
	"os"
	"syscall"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/spf13/cobra"
)

const phase6CoreStartupPath = phase6security.Slice6PrivateConfigDirectory + "/" + phase6security.Slice6StartupConfigFile
const phase6CoreProfilePath = phase6security.Slice6PrivateConfigDirectory + "/" + phase6security.Slice6ProfileConfigFile

// The Phase 6 core entrypoint admits only a role-owned, bounded startup file
// from its existing Profile-declared private mount. The role is inferred from
// the validated Profile and actual process UID/GID, not an argv/env claim.
func loadCommandConfig(cmd *cobra.Command, path string) error {
	if path != phase6CoreStartupPath {
		if err := config.Load(path); err != nil {
			return err
		}
		if phase6CoreConfigEnabled() {
			return errors.New("Phase 6 core roles require their exact private startup config")
		}
		return nil
	}
	profile, err := phase6security.VerifyFile(phase6CoreProfilePath)
	if err != nil || phase6security.VerifySlice6DesiredFinalExternalProfile(profile) != nil {
		return errors.New("Phase 6 core startup Profile is unavailable")
	}
	owner := ""
	for _, principal := range profile.Principals {
		target, targetErr := phase6security.Slice6DesiredImageTarget(principal.Name)
		if targetErr == nil && target == "core" && principal.UID == uint32(os.Getuid()) &&
			principal.GID == uint32(os.Getgid()) {
			if owner != "" {
				return errors.New("Phase 6 core process identity is ambiguous")
			}
			owner = principal.Name
		}
	}
	if owner == "" || phase6security.VerifySlice6PrivateConfigPath(profile, owner,
		phase6security.Slice6StartupConfigFile, path) != nil ||
		phase6security.VerifySlice6PrivateConfigPath(profile, owner,
			phase6security.Slice6ProfileConfigFile, phase6CoreProfilePath) != nil {
		return errors.New("Phase 6 core startup file is not owned by this process")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		return errors.New("Phase 6 core startup file is not private and regular")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) {
		return errors.New("Phase 6 core startup file owner mismatch")
	}
	document, err := secretfile.Read(path, 64<<10)
	if err != nil {
		return errors.New("Phase 6 core startup file is unavailable")
	}
	defer clear(document)
	if err := config.LoadPhase6CoreBytes(document, owner); err != nil {
		return err
	}
	if phase6CoreCommandOwner(cmd) != owner {
		return errors.New("Phase 6 core command does not match its process identity")
	}
	return nil
}

func phase6CoreCommandOwner(cmd *cobra.Command) string {
	if cmd == nil || cmd.Parent() == nil {
		return ""
	}
	parent, action := cmd.Parent().Name(), cmd.Name()
	switch {
	case parent == "product" && action == "serve":
		return "product-runtime"
	case parent == "product" && action == "migrate":
		return "product-migration-job"
	case parent == "provider" && action == "serve" && config.ProviderProcess != nil:
		switch config.ProviderProcess.Profile {
		case config.ProviderProcessCodingShellProfile:
			return "provider-runtime"
		case config.ProviderProcessBrowserProfile:
			return "provider-browser-runtime"
		case config.ProviderProcessDesktopProfile:
			return "provider-desktop-runtime"
		}
	case parent == "provider" && action == "migrate" && config.ProviderMigration != nil:
		return config.ProviderMigration.Postgres.Job
	case parent == "gateway" && action == "serve":
		return "gateway-runtime"
	case parent == "guest" && action == "serve":
		return "guest-runtime"
	case parent == "browser" && action == "serve":
		return "browser-runtime-role"
	case parent == "desktop" && action == "serve":
		return "desktop-runtime-role"
	}
	return ""
}

func phase6CoreConfigEnabled() bool {
	return config.ProductProcess != nil && config.ProductProcess.Enabled && config.ProductProcess.SchemaVersion == config.ProductProductionSchemaV3 ||
		config.ProductMigration != nil && config.ProductMigration.Enabled && config.ProductMigration.SchemaVersion == config.ProductMigrationSchemaV2 ||
		config.ProviderProcess != nil && config.ProviderProcess.Enabled && config.ProviderProcess.SchemaVersion == config.ProviderProductionSchemaV3 ||
		config.ProviderMigration != nil && config.ProviderMigration.Enabled && config.ProviderMigration.SchemaVersion == config.ProviderMigrationSchemaV2 ||
		config.GatewayProcess != nil && config.GatewayProcess.Enabled && config.GatewayProcess.SchemaVersion == config.DataPlaneProductionSchemaV3 ||
		config.GuestProcess != nil && config.GuestProcess.Enabled && config.GuestProcess.SchemaVersion == config.DataPlaneProductionSchemaV3 ||
		config.BrowserProcess != nil && config.BrowserProcess.Enabled && config.BrowserProcess.SchemaVersion == config.DataPlaneProductionSchemaV3 ||
		config.DesktopProcess != nil && config.DesktopProcess.Enabled && config.DesktopProcess.SchemaVersion == config.DataPlaneProductionSchemaV3
}
