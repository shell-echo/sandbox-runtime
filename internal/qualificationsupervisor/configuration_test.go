package qualificationsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"runtime"
	"testing"
)

func locationFixture() LocationConfiguration {
	return LocationConfiguration{
		ProfilePath: "/qualification/profile.json", ProviderOrigin: "https://provider.example",
		GatewayProbeEndpoint: "wss://gateway.example/probe", CallerStateRoot: "/caller/state",
		WorkingDirectory: "/adapter/work", EvidenceRoot: "/observer/evidence",
	}
}

func requireConfigurationPlatform(t *testing.T) {
	t.Helper()
	if !supportedPlatform(runtime.GOOS) {
		if got, err := PrepareConfiguration(nil, LocationConfiguration{}); got != nil || !errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatalf("unsupported platform: %v", err)
		}
		t.Skip("Darwin/Linux lexical preflight only")
	}
}

func TestPrepareConfigurationSnapshot(t *testing.T) {
	requireConfigurationPlatform(t)
	input := locationFixture()
	c, err := PrepareConfiguration(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	// Independent exact preimage: no production serialization helper is reused.
	canonical := `{"caller_state_root":"/caller/state","evidence_root":"/observer/evidence","gateway_probe_endpoint":"wss://gateway.example/probe","profile_path":"/qualification/profile.json","provider_origin":"https://provider.example","working_directory":"/adapter/work"}`
	sum := sha256.Sum256([]byte(canonical))
	if c.Digest() != "sha256:"+hex.EncodeToString(sum[:]) || c.Locations() != input || !c.Matches(input) {
		t.Fatal("snapshot or full-document digest mismatch")
	}
	input.ProviderOrigin = "https://changed.example"
	copy := c.Locations()
	copy.CallerStateRoot = "/changed/state"
	if c.Locations() != locationFixture() || c.Matches(input) || c.Matches(copy) {
		t.Fatal("external mutation changed snapshot or escaped matching")
	}
	var zero PreparedConfiguration
	if zero.Matches(LocationConfiguration{}) || (*PreparedConfiguration)(nil).Matches(locationFixture()) {
		t.Fatal("unprepared configuration accepted")
	}
}

func TestConfigurationBindsEveryField(t *testing.T) {
	requireConfigurationPlatform(t)
	base, err := PrepareConfiguration(context.Background(), locationFixture())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < reflect.TypeFor[LocationConfiguration]().NumField(); i++ {
		t.Run(reflect.TypeFor[LocationConfiguration]().Field(i).Name, func(t *testing.T) {
			input := locationFixture()
			field := reflect.ValueOf(&input).Elem().Field(i)
			if i == 1 {
				field.SetString("https://other.example")
			} else {
				field.SetString(field.String() + "-other")
			}
			changed, err := PrepareConfiguration(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if base.Matches(input) || changed.Digest() == base.Digest() {
				t.Fatal("field not bound")
			}
		})
	}
}

func TestConfigurationRejectsInvalidLocations(t *testing.T) {
	requireConfigurationPlatform(t)
	cases := []struct {
		name   string
		change func(*LocationConfiguration)
	}{
		{"relative_profile", func(c *LocationConfiguration) { c.ProfilePath = "profile.json" }},
		{"unclean_state", func(c *LocationConfiguration) { c.CallerStateRoot = "/caller/../state" }},
		{"root_work", func(c *LocationConfiguration) { c.WorkingDirectory = "/" }},
		{"empty_evidence", func(c *LocationConfiguration) { c.EvidenceRoot = "" }},
		{"unicode_work", func(c *LocationConfiguration) { c.WorkingDirectory = "/工作" }},
		{"provider_query", func(c *LocationConfiguration) { c.ProviderOrigin += "?secret=value" }},
		{"provider_credentials", func(c *LocationConfiguration) { c.ProviderOrigin = "https://secret@provider.example" }},
		{"provider_path", func(c *LocationConfiguration) { c.ProviderOrigin += "/path" }},
		{"provider_plaintext", func(c *LocationConfiguration) { c.ProviderOrigin = "http://provider.example" }},
		{"gateway_fragment", func(c *LocationConfiguration) { c.GatewayProbeEndpoint += "#secret" }},
		{"gateway_no_path", func(c *LocationConfiguration) { c.GatewayProbeEndpoint = "wss://gateway.example" }},
		{"default_port", func(c *LocationConfiguration) { c.ProviderOrigin += ":443" }},
		{"uppercase_host", func(c *LocationConfiguration) { c.ProviderOrigin = "https://Provider.example" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := locationFixture()
			tc.change(&input)
			got, err := PrepareConfiguration(context.Background(), input)
			if got != nil || err != ErrConfiguration {
				t.Fatalf("expected sanitized rejection, got %v", err)
			}
		})
	}
}

func TestConfigurationAllFiveOverlapPairs(t *testing.T) {
	requireConfigurationPlatform(t)
	// Field indexes: profile, provider, gateway, state, work, evidence.
	for _, pair := range [][2]int{{0, 3}, {0, 4}, {0, 5}, {3, 4}, {3, 5}} {
		for _, paths := range [][2]string{{"/same", "/same"}, {"/same", "/same/child"}, {"/same/child", "/same"}} {
			input := locationFixture()
			fields := reflect.ValueOf(&input).Elem()
			fields.Field(pair[0]).SetString(paths[0])
			fields.Field(pair[1]).SetString(paths[1])
			if got, err := PrepareConfiguration(context.Background(), input); got != nil || err != ErrConfiguration {
				t.Fatalf("pair %v did not reject %v", pair, paths)
			}
		}
	}
	input := locationFixture()
	input.ProfilePath = "/same"
	input.CallerStateRoot = "/same-prefix"
	// The locked policy has no working_directory:evidence_root overlap pair.
	input.WorkingDirectory = "/shared"
	input.EvidenceRoot = "/shared"
	if _, err := PrepareConfiguration(context.Background(), input); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationContext(t *testing.T) {
	requireConfigurationPlatform(t)
	if got, err := PrepareConfiguration(nil, locationFixture()); got != nil || err != ErrConfiguration {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := PrepareConfiguration(ctx, locationFixture()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
