package cmd

import (
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestProviderContractSelectionDoesNotAliasDesktopToCodingShell(t *testing.T) {
	for _, item := range []struct {
		profile config.ProviderProcessProfile
		name    string
		edge    string
	}{
		{config.ProviderProcessCodingShellProfile, "provider-runtime", phase6security.ProductProviderContractEdgeID},
		{config.ProviderProcessDesktopProfile, "provider-desktop-runtime", phase6security.ProductProviderDesktopContractEdgeID},
		{"browser", "", ""},
	} {
		name, edge := providerContractSelection(item.profile)
		if name != item.name || edge != item.edge {
			t.Fatalf("Provider profile %q selected %q/%q", item.profile, name, edge)
		}
	}
}
