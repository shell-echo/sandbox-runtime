package telemetry

import (
	"strings"
	"testing"
)

func TestRegistryKeepsFixedLowCardinalityMetrics(t *testing.T) {
	registry, err := New([]Metric{{Name: "provider_ready", Labels: []string{"role", "reason"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Inc("provider_ready"); err != nil {
		t.Fatal(err)
	}
	if registry.Snapshot()["provider_ready"] != 1 {
		t.Fatal("counter was not incremented")
	}
	if err := registry.Inc("tenant_123"); err == nil {
		t.Fatal("unregistered high-cardinality metric was accepted")
	}
}

func TestRegistryWritesStablePrometheusCounters(t *testing.T) {
	registry, err := New([]Metric{{Name: "zeta_total"}, {Name: "alpha_total", Labels: []string{"role"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Inc("zeta_total"); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	if err := registry.WritePrometheus(&output); err != nil {
		t.Fatal(err)
	}
	want := "# TYPE alpha_total counter\nalpha_total 0\n# TYPE zeta_total counter\nzeta_total 1\n"
	if output.String() != want {
		t.Fatalf("metrics = %q, want %q", output.String(), want)
	}
	if strings.Contains(output.String(), "role=") {
		t.Fatal("metric output accepted dynamic label values")
	}
}
