// Package telemetry provides bounded, privacy-safe process metrics. Labels are
// fixed at construction; caller, tenant, grant, host, path, and backend IDs
// cannot become metric cardinality.
package telemetry

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

var ErrInvalidMetric = errors.New("invalid metric definition")

type Metric struct {
	Name   string
	Labels []string
}

type Registry struct {
	mu       sync.RWMutex
	metrics  map[string]Metric
	counters map[string]uint64
}

func New(metrics []Metric) (*Registry, error) {
	if len(metrics) == 0 || len(metrics) > 256 {
		return nil, ErrInvalidMetric
	}
	registry := &Registry{metrics: make(map[string]Metric, len(metrics)), counters: make(map[string]uint64, len(metrics))}
	for _, metric := range metrics {
		if err := validateMetric(metric); err != nil {
			return nil, err
		}
		if _, exists := registry.metrics[metric.Name]; exists {
			return nil, ErrInvalidMetric
		}
		metric.Labels = append([]string(nil), metric.Labels...)
		sort.Strings(metric.Labels)
		registry.metrics[metric.Name] = metric
	}
	return registry, nil
}

func (r *Registry) Inc(name string) error {
	if r == nil {
		return ErrInvalidMetric
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.metrics[name]; !exists {
		return ErrInvalidMetric
	}
	if r.counters[name] == ^uint64(0) {
		return ErrInvalidMetric
	}
	r.counters[name]++
	return nil
}

func (r *Registry) Snapshot() map[string]uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]uint64, len(r.metrics))
	for name := range r.metrics {
		result[name] = r.counters[name]
	}
	return result
}

// WritePrometheus emits a deterministic counter-only exposition. Label names
// are retained in the registry as a schema review aid, but values are never
// accepted from request data; this API therefore cannot create tenant,
// credential, host-path, or backend-ID cardinality.
func (r *Registry) WritePrometheus(writer io.Writer) error {
	if r == nil || writer == nil {
		return ErrInvalidMetric
	}
	snapshot := r.Snapshot()
	names := make([]string, 0, len(snapshot))
	for name := range snapshot {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := fmt.Fprintf(writer, "# TYPE %s counter\n%s %d\n", name, name, snapshot[name]); err != nil {
			return err
		}
	}
	return nil
}

func validateMetric(metric Metric) error {
	if !validName(metric.Name) || len(metric.Labels) > 8 {
		return ErrInvalidMetric
	}
	seen := make(map[string]struct{}, len(metric.Labels))
	for _, label := range metric.Labels {
		if !validName(label) {
			return ErrInvalidMetric
		}
		if _, exists := seen[label]; exists {
			return ErrInvalidMetric
		}
		seen[label] = struct{}{}
	}
	return nil
}

func validName(value string) bool {
	if value == "" || len(value) > 96 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != ':' {
			return false
		}
	}
	return true
}
