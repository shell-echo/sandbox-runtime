package cmd

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/config"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

func TestCodingV3BindingClosesCanonicalOriginalPlan(t *testing.T) {
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version, ProfileDigest: digest("a"),
		OwnerDeployment: "provider-runtime", OwnerPrincipalDigest: digest("b"), Namespace: "provider-coding", ControllerID: "provider-coding-controller",
		Template: "coding-sandbox-runtime", TemplateDigest: digest("c"), ImageDigest: digest("d"), ImageConfigDigest: digest("e"), NetworkMode: "none",
		Limits: codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64}, Capacity: 2, Slots: []codingidentity.Slot{
			{ID: "coding-0000", WorkloadUID: 57000, WorkloadGID: 58000, InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace", OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57001, WorkloadGID: 58001, InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace", OutputsVolume: "coding-0001-outputs"}}}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding := dockercontrol.CodingReceiptBinding{Plan: plan, SpecBySlot: map[string]string{"coding-0000": digest("1"), "coding-0001": digest("2")},
		ProfileDigest: plan.ProfileDigest, DaemonDigest: digest("3"), DaemonEnvironmentDigest: digest("4"), EndpointScopeDigest: digest("5"), RuntimePlatform: "linux/arm64/v8",
		ControlPolicyDigest: digest("6"), PeerPrincipalDigest: plan.OwnerPrincipalDigest, PlanDigest: planDigest, Capacity: 2}
	document, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeCodingReceiptBinding(string(document))
	if err != nil || got.PlanDigest != planDigest || got.ControlPolicyDigest != binding.ControlPolicyDigest {
		t.Fatalf("exact binding: %v", err)
	}
	for _, bad := range []string{string(document) + "\n", string(document) + "{}", "{\"unexpected\":1," + string(document[1:]), "{\"Capacity\":2," + string(document[1:]), strings.Repeat(" ", (64<<10)+1)} {
		if _, err := decodeCodingReceiptBinding(bad); err == nil {
			t.Fatal("noncanonical/unbounded binding admitted")
		}
	}
	for name, mutate := range map[string]func(*dockercontrol.CodingReceiptBinding){
		"wrong owner":    func(b *dockercontrol.CodingReceiptBinding) { b.PeerPrincipalDigest = digest("7") },
		"wrong profile":  func(b *dockercontrol.CodingReceiptBinding) { b.ProfileDigest = digest("7") },
		"wrong plan":     func(b *dockercontrol.CodingReceiptBinding) { b.PlanDigest = digest("7") },
		"third slot":     func(b *dockercontrol.CodingReceiptBinding) { b.Capacity = 3 },
		"missing policy": func(b *dockercontrol.CodingReceiptBinding) { b.ControlPolicyDigest = "" },
		"crossed spec": func(b *dockercontrol.CodingReceiptBinding) {
			b.SpecBySlot = map[string]string{"other": digest("1"), "coding-0001": digest("2")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := binding
			mutate(&b)
			d, _ := json.Marshal(b)
			if _, err := decodeCodingReceiptBinding(string(d)); err == nil {
				t.Fatal("unbound original authority admitted")
			}
		})
	}
}

func TestCodingV3CreatePortCannotUseLegacyRuntimeCalls(t *testing.T) {
	port := &codingV3CreatePort{}
	if port.Create(t.Context(), lifecycle.Sandbox{}) == nil {
		t.Fatal("legacy Create was admitted")
	}
	if _, err := port.Inspect(t.Context(), "caller-runtime-id"); err == nil {
		t.Fatal("legacy Inspect was admitted")
	}
	if port.DispatchCodingCreateAuthority(t.Context(), dockercontrol.CodingCreateAuthority{}) == nil {
		t.Fatal("missing typed client dispatched")
	}
}

func TestCodingV3SelectedCommandAndAllConstructorsRemainHeld(t *testing.T) {
	cfg := &config.ProviderProcessConfig{SchemaVersion: config.ProviderProductionSchemaV3, Profile: config.ProviderProcessCodingShellProfile}
	if err := runProviderCodingV3(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "Security Profile v2") {
		t.Fatalf("command reached dependencies before hold: %v", err)
	}
	if registry, err := newProviderRuntimeMaterialRegistry(cfg, phase6security.Profile{}); err == nil || registry != nil {
		t.Fatal("v3 reused v1 material registry")
	}
	// This intentionally uninitialized registry would fail if reached. The
	// typed v2 PG path must reject its profile before resolving any material.
	pool, closePool, err := openDirectV3Postgres(t.Context(), t.Context(), phase6security.ProfileV2{}, &secretref.Registry{}, directV3PostgresSettings{Owner: "provider-runtime"})
	if err == nil || pool != nil || closePool != nil || err.Error() != "direct v3 PostgreSQL authority is unavailable" {
		t.Fatalf("v2 PG reached material/pool startup: %v", err)
	}
	if deps, err := newCodingV3Dependencies(t.Context(), t.Context(), nil, codingV3Inputs{}); err == nil || deps != nil {
		t.Fatal("unbound composition was constructed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := runProviderCodingV3(ctx, cfg); err == nil {
		t.Fatal("cancelled startup admitted")
	}
	if _, err := preflightProviderCodingV3(cfg); err == nil {
		t.Fatal("disabled/incomplete configuration admitted")
	}
	var dependencies *codingV3Dependencies
	dependencies.Close()
	closed := 0
	dependencies = &codingV3Dependencies{close: func() { closed++ }}
	dependencies.Close()
	dependencies.Close()
	if closed != 1 {
		t.Fatal("dependency resources closed more than once")
	}
}
