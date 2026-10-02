package config

import (
	"encoding/json"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func TestMaterialProviderV2RequiresExplicitCrossUIDDirectoryGroup(t *testing.T) {
	binding := secretref.Binding{Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://phase6/kv/guest-agent/guest_signing_key", Version: "v1",
		Purpose: secretref.PurposeGuestSigningKey, TenantID: secretref.SystemTenant, Role: secretref.RoleGuest}
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	base := RoleMaterialsConfig{Provider: RoleMaterialProviderConfig{Type: UnixWorkloadMaterialProviderV2,
		Alias: "guest-agent", SocketPath: "/run/phase6/material/guest-agent/agent.sock",
		ExpectedUID: 20010, ExpectedGID: 30010, DirectoryGID: 30011,
		OperationTimeoutSeconds: 3, CacheSeconds: 1},
		Bindings: []RoleMaterialBindingConfig{{ID: "signing-key", Provider: "guest-agent", Document: string(document)}}}
	if decoded, err := base.DecodeBindings(secretref.RoleGuest); err != nil || decoded["signing-key"] != binding {
		t.Fatalf("exact v2 binding rejected: %v", err)
	}
	for name, mutate := range map[string]func(*RoleMaterialsConfig){
		"missing directory group": func(c *RoleMaterialsConfig) { c.Provider.DirectoryGID = 0 },
		"agent group reused":      func(c *RoleMaterialsConfig) { c.Provider.DirectoryGID = c.Provider.ExpectedGID },
		"v1 group smuggling": func(c *RoleMaterialsConfig) {
			c.Provider.Type = UnixWorkloadMaterialProviderV1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if _, err := changed.DecodeBindings(secretref.RoleGuest); err == nil {
				t.Fatal("invalid material transport admitted")
			}
		})
	}
}
