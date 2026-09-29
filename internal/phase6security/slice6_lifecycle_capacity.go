package phase6security

import (
	"errors"
	"math"
	"sort"
)

var ErrInvalidSlice6CapacityPlan = errors.New("invalid Slice 6 lifecycle capacity plan")

// Slice6ConcurrencyEnvelope is a conservative, source-level simultaneous
// process set for capacity planning. It is neither an observed start/stop
// receipt nor permission to omit a role from the complete lifecycle gate.
type Slice6ConcurrencyEnvelope struct {
	Name             string
	Principals       []string
	ExternalServices []string
}

// Slice6ResourceBudget is arithmetic over supplied finite limits, not
// observed cgroup usage or approval of the supplied limits. The release gate
// must bind those limits to reviewed duty classes and real measurements.
type Slice6ResourceBudget struct {
	Envelope      string
	MemoryBytes   int64
	CPUMillis     int64
	PIDs          int64
	ProcessCount  int
	ExternalCount int
}

var slice6OneShotMigrationBundles = []struct {
	name, job, material, materialTLS, postgresTLS string
}{
	{"product_migration", "product-migration-job", "product-migration-agent", "product-migration-agent-tls-agent", "product-migration-postgres-tls-agent"},
	{"provider_migration", "provider-migration-job", "provider-migration-agent", "provider-migration-agent-tls-agent", "provider-migration-postgres-tls-agent"},
	{"provider_browser_migration", "provider-browser-migration-job", "provider-browser-migration-agent", "provider-browser-migration-agent-tls-agent", "provider-browser-migration-postgres-tls-agent"},
	{"provider_desktop_migration", "provider-desktop-migration-job", "provider-desktop-migration-agent", "provider-desktop-migration-agent-tls-agent", "provider-desktop-migration-postgres-tls-agent"},
}

var slice6DynamicSandboxTemplates = []string{"browser-sandbox-runtime", "desktop-sandbox-runtime"}

// Slice6CandidateConcurrencyEnvelopes keeps every steady role in every
// candidate envelope and adds one real one-shot migration bundle at a time.
// Both dynamic sandbox templates appear together in the media/input envelope
// for conservative peak planning, not as permanently running processes.
func Slice6CandidateConcurrencyEnvelopes() []Slice6ConcurrencyEnvelope {
	oneShot := make(map[string]bool, len(slice6OneShotMigrationBundles)*4)
	for _, bundle := range slice6OneShotMigrationBundles {
		for _, name := range []string{bundle.job, bundle.material, bundle.materialTLS, bundle.postgresTLS} {
			oneShot[name] = true
		}
	}
	dynamic := make(map[string]bool, len(slice6DynamicSandboxTemplates))
	for _, name := range slice6DynamicSandboxTemplates {
		dynamic[name] = true
	}
	steady := make([]string, 0, len(slice6ApprovedDeploymentKinds)-len(oneShot)-len(dynamic))
	for _, name := range Slice6DesiredDeploymentNames() {
		if !oneShot[name] && !dynamic[name] {
			steady = append(steady, name)
		}
	}
	external := make([]string, 0, len(slice6DesiredExternalServices))
	for _, service := range slice6DesiredExternalServices {
		external = append(external, service.name)
	}
	envelopes := make([]Slice6ConcurrencyEnvelope, 0, len(slice6OneShotMigrationBundles)+2)
	envelopes = append(envelopes, Slice6ConcurrencyEnvelope{Name: "steady_without_sandboxes",
		Principals: append([]string(nil), steady...), ExternalServices: append([]string(nil), external...)})
	for _, bundle := range slice6OneShotMigrationBundles {
		members := append([]string(nil), steady...)
		members = append(members, bundle.job, bundle.material, bundle.materialTLS, bundle.postgresTLS)
		sort.Strings(members)
		envelopes = append(envelopes, Slice6ConcurrencyEnvelope{Name: bundle.name,
			Principals: members, ExternalServices: append([]string(nil), external...)})
	}
	media := append(append([]string(nil), steady...), slice6DynamicSandboxTemplates...)
	sort.Strings(media)
	envelopes = append(envelopes, Slice6ConcurrencyEnvelope{Name: "browser_desktop_active",
		Principals: media, ExternalServices: append([]string(nil), external...)})
	return envelopes
}

// CalculateSlice6ResourceBudgets requires an exact limit for every approved
// deployment and external service, including one-shot jobs and sandboxes.
// It rejects missing or surplus entries so a superficially small peak cannot
// be produced by omitting a lifecycle identity. The returned sums do not
// include Docker daemon/kernel overhead or prove host admission.
func CalculateSlice6ResourceBudgets(principals, external map[string]Resources) ([]Slice6ResourceBudget, error) {
	if len(principals) != len(slice6ApprovedDeploymentKinds) || len(external) != len(slice6DesiredExternalServices) {
		return nil, ErrInvalidSlice6CapacityPlan
	}
	for name, limit := range principals {
		if _, approved := slice6ApprovedDeploymentKinds[name]; !approved || !validSlice6CapacityLimit(limit) {
			return nil, ErrInvalidSlice6CapacityPlan
		}
	}
	approvedExternal := make(map[string]bool, len(slice6DesiredExternalServices))
	for _, service := range slice6DesiredExternalServices {
		approvedExternal[service.name] = true
	}
	for name, limit := range external {
		if !approvedExternal[name] || !validSlice6CapacityLimit(limit) {
			return nil, ErrInvalidSlice6CapacityPlan
		}
	}
	result := make([]Slice6ResourceBudget, 0, len(slice6OneShotMigrationBundles)+2)
	for _, envelope := range Slice6CandidateConcurrencyEnvelopes() {
		budget := Slice6ResourceBudget{Envelope: envelope.Name,
			ProcessCount: len(envelope.Principals), ExternalCount: len(envelope.ExternalServices)}
		for _, name := range envelope.Principals {
			if !addSlice6CapacityLimit(&budget, principals[name]) {
				return nil, ErrInvalidSlice6CapacityPlan
			}
		}
		for _, name := range envelope.ExternalServices {
			if !addSlice6CapacityLimit(&budget, external[name]) {
				return nil, ErrInvalidSlice6CapacityPlan
			}
		}
		result = append(result, budget)
	}
	return result, nil
}

func validSlice6CapacityLimit(limit Resources) bool {
	return limit.MemoryBytes >= 16<<20 && limit.MemoryBytes <= 64<<30 &&
		limit.CPUMillis >= 10 && limit.CPUMillis <= 64000 &&
		limit.PIDs >= 4 && limit.PIDs <= 4096
}

func addSlice6CapacityLimit(budget *Slice6ResourceBudget, limit Resources) bool {
	if budget.MemoryBytes > math.MaxInt64-limit.MemoryBytes ||
		budget.CPUMillis > math.MaxInt64-limit.CPUMillis ||
		budget.PIDs > math.MaxInt64-limit.PIDs {
		return false
	}
	budget.MemoryBytes += limit.MemoryBytes
	budget.CPUMillis += limit.CPUMillis
	budget.PIDs += limit.PIDs
	return true
}
