package qualificationharness

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func digestOf(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func configurationFixture() Configuration {
	return Configuration{
		Architecture: "darwin/arm64", TargetDigest: digestOf("1"), RunNamespaceDigest: digestOf("2"),
		ComponentConfigurations: ComponentConfigurationDigests{
			Provider: digestOf("3"), Caller: digestOf("4"), Adapter: digestOf("5"), Gateway: digestOf("6"),
			Observer: digestOf("7"), Inspector: digestOf("8"), Teardown: digestOf("9"),
		},
	}
}

func freezeFixture(t *testing.T) *FrozenConfiguration {
	t.Helper()
	frozen, err := Freeze(context.Background(), "../..", configurationFixture())
	if err != nil {
		t.Fatal(err)
	}
	return frozen
}

func TestFreezeBindsCompleteProfileInventory(t *testing.T) {
	frozen := freezeFixture(t)
	if frozen.Digest() == "" || !frozen.Matches(configurationFixture()) {
		t.Fatal("frozen configuration has no commitment or does not match its input")
	}
	id, version, profileDigest := frozen.ProfileIdentity()
	if id != "sandbox-runtime-external-caller-coding-shell-v1" || version != "1.0.0" ||
		profileDigest != "sha256:4effea27fd3d7668b88eeb95c69e19b51556914b7949b1a39ce522b2aec46c14" {
		t.Fatalf("unexpected profile identity: %q %q %q", id, version, profileDigest)
	}
	target := frozen.TargetIdentity()
	if target.TargetDigest != digestOf("1") || target.TargetDigestProfile != TargetDigestProfile ||
		target.Architecture != "darwin/arm64" || target.RunNamespaceDigest != digestOf("2") ||
		target.RunNamespaceDigestProfile != RunNamespaceDigestProfile {
		t.Fatalf("unexpected target identity: %+v", target)
	}
	topology := frozen.Topology()
	if !topology.DedicatedDisposableTarget || !topology.RunUniqueNamespace || topology.AdmittedControllers != 2 ||
		!topology.DistinctTenants || topology.SameCAUnadmittedIdentityCount != 1 || len(topology.Actors) != 4 ||
		!topology.CallerProcessSeparate || !topology.CallerGatewayOwnedByCaller ||
		topology.ObserverControlDomain != "qualification_operator" || len(topology.ObserverControlDomainDisjoint) != 3 ||
		len(topology.ProcessIsolationGroups) != 10 || topology.TargetIdentity != target {
		t.Fatalf("unexpected topology: %+v", topology)
	}
	if got := frozen.ArtifactRequirements(); len(got) != 11 || got[0].ArtifactID != "provider" ||
		got[4].ArtifactID != "runtime_image" || got[10].ArtifactID != "teardown" {
		t.Fatalf("unexpected artifact inventory: %+v", got)
	}
	configurations := frozen.ConfigurationExpectations()
	wantIDs := []string{
		"architecture", "provider_configuration", "caller_configuration", "adapter_configuration",
		"gateway_configuration", "observer_configuration", "inspector_configuration", "teardown_configuration",
		"topology", "scenario_inventory",
	}
	if len(configurations) != len(wantIDs) {
		t.Fatalf("configuration inventory length = %d", len(configurations))
	}
	for index, wantID := range wantIDs {
		if got := configurations[index]; got.ID != wantID || !strings.HasPrefix(got.Digest, "sha256:") ||
			got.DigestProfile != ConfigurationDigestProfile {
			t.Fatalf("configuration[%d] = %+v", index, got)
		}
	}
	if configurations[1].Digest != digestOf("3") || configurations[7].Digest != digestOf("9") {
		t.Fatalf("component configuration digests changed: %+v", configurations)
	}
	phases := frozen.ScenarioInventory()
	if len(phases) != 2 || phases[0].PhaseID != "initial" || phases[0].DependsOnPhase != nil || len(phases[0].CaseIDs) != 15 ||
		phases[1].PhaseID != "reconstruction" || phases[1].DependsOnPhase == nil || *phases[1].DependsOnPhase != "initial" || len(phases[1].CaseIDs) != 5 ||
		phases[0].CaseIDs[0] != "initial.locked-capability-discovery" || phases[1].CaseIDs[4] != "reconstruction.same-shell-reconnect" {
		t.Fatalf("unexpected scenario inventory: %+v", phases)
	}
	limits := frozen.RuntimeLimits()
	if limits.MaxSandboxes != 1 || limits.MaxExecutionSeconds != 1800 || limits.MaxCleanupSeconds != 300 ||
		limits.MaxTotalWallClockSeconds != 2100 || limits.SandboxCPUMillis != 500 || limits.SandboxPIDs != 64 {
		t.Fatalf("unexpected runtime limits: %+v", limits)
	}
	cleanup := frozen.CleanupRequirements()
	if cleanup.Authority != CleanupAuthority || len(cleanup.InspectorScope) != 5 || cleanup.PreRunRunOwnedResourceCount != 0 ||
		cleanup.PostTeardownStabilitySamples != 3 || cleanup.PostTeardownStabilityIntervalMS != 1000 {
		t.Fatalf("unexpected cleanup requirements: %+v", cleanup)
	}
}

func TestFreezeHasStableKnownDigests(t *testing.T) {
	frozen := freezeFixture(t)
	if got, want := frozen.Digest(), "sha256:92d4f5c8ac88fa338fe2ad8d416e9443273376d71c87f6860f7f5777ae733b88"; got != want {
		t.Fatalf("commitment digest = %q, want %q", got, want)
	}
	configurations := frozen.ConfigurationExpectations()
	for _, test := range []struct {
		index int
		want  string
	}{
		{0, "sha256:a3432d314a98287ab4b7917cb390dea0f5daff4636c7ba01a2faf414d871b3a4"},
		{8, "sha256:a8aaef7361bba05bd999d270a4c939302b292386223fddb6aa253ee23b392dcb"},
		{9, "sha256:23e08e01345f8650c1d71c48d6b9d65abfa52b6ce6aaaf5ae504a46376a4e15f"},
	} {
		if got := configurations[test.index].Digest; got != test.want {
			t.Fatalf("configuration %q digest = %q, want %q", configurations[test.index].ID, got, test.want)
		}
	}
}

func TestFreezeBindsEveryStaticInputField(t *testing.T) {
	base := freezeFixture(t)
	changes := map[string]func(*Configuration){
		"architecture": func(input *Configuration) { input.Architecture = "linux/arm64" },
		"target":       func(input *Configuration) { input.TargetDigest = digestOf("a") },
		"namespace":    func(input *Configuration) { input.RunNamespaceDigest = digestOf("b") },
		"provider":     func(input *Configuration) { input.ComponentConfigurations.Provider = digestOf("a") },
		"caller":       func(input *Configuration) { input.ComponentConfigurations.Caller = digestOf("a") },
		"adapter":      func(input *Configuration) { input.ComponentConfigurations.Adapter = digestOf("a") },
		"gateway":      func(input *Configuration) { input.ComponentConfigurations.Gateway = digestOf("a") },
		"observer":     func(input *Configuration) { input.ComponentConfigurations.Observer = digestOf("a") },
		"inspector":    func(input *Configuration) { input.ComponentConfigurations.Inspector = digestOf("a") },
		"teardown":     func(input *Configuration) { input.ComponentConfigurations.Teardown = digestOf("a") },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			input := configurationFixture()
			change(&input)
			changed, err := Freeze(context.Background(), "../..", input)
			if err != nil {
				t.Fatal(err)
			}
			if base.Matches(input) || changed.Digest() == base.Digest() {
				t.Fatal("changed input did not change the frozen commitment")
			}
		})
	}
}

func TestFreezeRejectsInvalidConfigurationAndContext(t *testing.T) {
	if got, err := Freeze(nil, "../..", configurationFixture()); got != nil || err != ErrConfiguration {
		t.Fatalf("nil context = %v, %v", got, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := Freeze(cancelled, "../..", configurationFixture()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context = %v, %v", got, err)
	}
	for name, change := range map[string]func(*Configuration){
		"empty_architecture":          func(input *Configuration) { input.Architecture = "" },
		"uppercase_architecture":      func(input *Configuration) { input.Architecture = "Darwin/arm64" },
		"colon_architecture":          func(input *Configuration) { input.Architecture = "linux:arm64" },
		"dot_architecture_segment":    func(input *Configuration) { input.Architecture = "linux/./arm64" },
		"parent_architecture_segment": func(input *Configuration) { input.Architecture = "linux/../arm64" },
		"empty_architecture_segment":  func(input *Configuration) { input.Architecture = "linux//arm64" },
		"trailing_architecture_slash": func(input *Configuration) { input.Architecture = "linux/arm64/" },
		"long_architecture":           func(input *Configuration) { input.Architecture = "a" + strings.Repeat("b", 64) },
		"target_uppercase_digest":     func(input *Configuration) { input.TargetDigest = "sha256:" + strings.Repeat("A", 64) },
		"namespace_short_digest":      func(input *Configuration) { input.RunNamespaceDigest = "sha256:12" },
		"empty_provider":              func(input *Configuration) { input.ComponentConfigurations.Provider = "" },
		"empty_caller":                func(input *Configuration) { input.ComponentConfigurations.Caller = "" },
		"empty_adapter":               func(input *Configuration) { input.ComponentConfigurations.Adapter = "" },
		"empty_gateway":               func(input *Configuration) { input.ComponentConfigurations.Gateway = "" },
		"empty_observer":              func(input *Configuration) { input.ComponentConfigurations.Observer = "" },
		"empty_inspector":             func(input *Configuration) { input.ComponentConfigurations.Inspector = "" },
		"empty_teardown":              func(input *Configuration) { input.ComponentConfigurations.Teardown = "" },
	} {
		t.Run(name, func(t *testing.T) {
			input := configurationFixture()
			change(&input)
			if got, err := Freeze(context.Background(), "../..", input); got != nil || err != ErrConfiguration {
				t.Fatalf("invalid input = %v, %v", got, err)
			}
		})
	}
	if got, err := Freeze(context.Background(), t.TempDir(), configurationFixture()); got != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatalf("missing authority = %v, %v", got, err)
	}
	var zero FrozenConfiguration
	if zero.Digest() != "" || zero.Matches(Configuration{}) || (*FrozenConfiguration)(nil).Matches(configurationFixture()) {
		t.Fatal("zero frozen configuration is usable")
	}
}

func TestFrozenConfigurationReturnsDefensiveCopies(t *testing.T) {
	frozen := freezeFixture(t)
	originalDigest := frozen.Digest()
	topology := frozen.Topology()
	*topology.Actors[0].TenantBinding = "changed"
	topology.ObserverControlDomainDisjoint[0] = "changed"
	topology.ProcessIsolationGroups[0][0] = "changed"
	artifacts := frozen.ArtifactRequirements()
	artifacts[0].ArtifactID = "changed"
	configurations := frozen.ConfigurationExpectations()
	configurations[0].ID = "changed"
	phases := frozen.ScenarioInventory()
	*phases[1].DependsOnPhase = "changed"
	phases[0].CaseIDs[0] = "changed"
	cleanup := frozen.CleanupRequirements()
	cleanup.InspectorScope[0] = "changed"
	if got := frozen.Topology(); *got.Actors[0].TenantBinding != "tenant_a" || got.ObserverControlDomainDisjoint[0] != "external_caller" || got.ProcessIsolationGroups[0][0] != "provider" {
		t.Fatal("topology mutation escaped")
	}
	if frozen.ArtifactRequirements()[0].ArtifactID != "provider" || frozen.ConfigurationExpectations()[0].ID != "architecture" ||
		*frozen.ScenarioInventory()[1].DependsOnPhase != "initial" || frozen.ScenarioInventory()[0].CaseIDs[0] != "initial.locked-capability-discovery" ||
		frozen.CleanupRequirements().InspectorScope[0] != "runtime_allocations" ||
		frozen.Digest() != originalDigest {
		t.Fatal("returned mutation changed frozen state")
	}
}

func TestFrozenConfigurationConcurrentReads(t *testing.T) {
	frozen := freezeFixture(t)
	var group sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 100; iteration++ {
				if frozen.Digest() == "" || len(frozen.Topology().Actors) != 4 || len(frozen.ArtifactRequirements()) != 11 ||
					len(frozen.ConfigurationExpectations()) != 10 || len(frozen.CleanupRequirements().InspectorScope) != 5 || len(frozen.ScenarioInventory()) != 2 {
					t.Errorf("incomplete concurrent snapshot")
					return
				}
			}
		}()
	}
	group.Wait()
}

func TestConfigurationShapeRemainsClosedAndComparable(t *testing.T) {
	configurationType := reflect.TypeOf(Configuration{})
	componentType := reflect.TypeOf(ComponentConfigurationDigests{})
	if !configurationType.Comparable() || !componentType.Comparable() {
		t.Fatal("static configuration must remain byte-comparable")
	}
	if got := configurationType.NumField(); got != 4 {
		t.Fatalf("Configuration has %d fields, want exact closed set of 4", got)
	}
	if got := componentType.NumField(); got != 7 {
		t.Fatalf("ComponentConfigurationDigests has %d fields, want exact closed set of 7", got)
	}
}
