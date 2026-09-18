// Package productphase3evidence validates the bounded standalone Product
// Phase 3 evidence envelope. It deliberately does not convert same-repository
// process evidence into deployment, HA, hostile-tenant, or production claims.
package productphase3evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	ProviderRevision = "98995384c60a924f25ca58d3b7e561207bfa5be8"
	ProviderTree     = "0a627baed11c8a6ddbe8a24bbc1869e4f85edc16"
	ProductTree      = "sha256:a5c9cfa4fdfcdb481336732b4b33de39b57ef6e30dc668b95a0cf524b143b4d1"
	PostgresImage    = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	requiredRoles   = []string{"gateway", "guest", "product", "provider"}
	requiredCases   = []string{
		"capability-readiness",
		"guest-file-boundary",
		"process-cleanup",
		"product-authentication",
		"product-restart-recovery",
		"provider-fault-closure",
		"terminal-ticket-replay",
		"terminal-websocket-roundtrip",
		"tenant-nondisclosure",
	}
	requiredNonClaims = []string{"deployment-qualified", "ha-qualified", "hostile-multi-tenant-qualified", "production-ready"}
)

type Manifest struct {
	SchemaVersion  int                `json:"schema_version"`
	RunID          string             `json:"run_id"`
	Result         string             `json:"result"`
	EvidenceTier   string             `json:"evidence_tier"`
	SourceRevision string             `json:"source_revision"`
	StartedAt      string             `json:"started_at"`
	CompletedAt    string             `json:"completed_at"`
	Provider       ProviderIdentity   `json:"provider_contract"`
	Product        ProductIdentity    `json:"product_contract"`
	PostgreSQL     PostgreSQLIdentity `json:"postgresql"`
	Processes      []ProcessEvidence  `json:"processes"`
	Scenarios      []ScenarioEvidence `json:"scenarios"`
	Cleanup        CleanupEvidence    `json:"cleanup"`
	NonClaims      []string           `json:"non_claims"`
}

type ProviderIdentity struct {
	Revision string `json:"revision"`
	Tree     string `json:"tree"`
}

type ProductIdentity struct {
	Tree             string `json:"tree"`
	ResourceCount    int    `json:"resource_count"`
	OperationCount   int    `json:"operation_count"`
	ConformanceCases int    `json:"conformance_cases"`
}

type PostgreSQLIdentity struct {
	Image       string `json:"image"`
	FreshSchema bool   `json:"fresh_schema"`
}

type ProcessEvidence struct {
	Role                 string `json:"role"`
	ExecutableDigest     string `json:"executable_digest"`
	IndependentOSProcess bool   `json:"independent_os_process"`
}

type ScenarioEvidence struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type CleanupEvidence struct {
	ChildProcessesReaped bool `json:"child_processes_reaped"`
	ContainerRemoved     bool `json:"container_removed"`
	ScopedRowsRemoved    bool `json:"scoped_rows_removed"`
}

func VerifyFile(path string) (Manifest, error) {
	document, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read Product Phase 3 evidence: %w", err)
	}
	return Verify(document)
}

func Verify(document []byte) (Manifest, error) {
	if len(document) == 0 || len(document) > 1<<20 {
		return Manifest{}, errors.New("Product Phase 3 evidence size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode Product Phase 3 evidence: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("Product Phase 3 evidence has trailing JSON")
	}
	if err := validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func validate(manifest Manifest) error {
	if manifest.SchemaVersion != 1 || manifest.Result != "passed" || manifest.EvidenceTier != "same-repository-separate-process" {
		return errors.New("unexpected Product Phase 3 evidence identity or result")
	}
	if manifest.RunID == "" || strings.ContainsAny(manifest.RunID, "/\\\x00") || !revisionPattern.MatchString(manifest.SourceRevision) || manifest.StartedAt == "" || manifest.CompletedAt == "" {
		return errors.New("invalid Product Phase 3 run metadata")
	}
	if manifest.Provider.Revision != ProviderRevision || manifest.Provider.Tree != ProviderTree {
		return errors.New("Provider Contract identity does not match the Phase 3 lock")
	}
	if manifest.Product.Tree != ProductTree || manifest.Product.ResourceCount != 9 || manifest.Product.OperationCount != 27 || manifest.Product.ConformanceCases != 3 {
		return errors.New("Product Contract identity does not match the Phase 3 lock")
	}
	if manifest.PostgreSQL.Image != PostgresImage || !manifest.PostgreSQL.FreshSchema {
		return errors.New("PostgreSQL evidence is not the pinned fresh-schema profile")
	}
	if err := exactProcesses(manifest.Processes); err != nil {
		return err
	}
	if err := exactScenarios(manifest.Scenarios); err != nil {
		return err
	}
	if !manifest.Cleanup.ChildProcessesReaped || !manifest.Cleanup.ContainerRemoved || !manifest.Cleanup.ScopedRowsRemoved {
		return errors.New("Product Phase 3 cleanup evidence is incomplete")
	}
	if !sameStrings(manifest.NonClaims, requiredNonClaims) {
		return errors.New("Product Phase 3 non-claim boundary is incomplete")
	}
	encoded, _ := json.Marshal(manifest)
	for _, forbidden := range []string{"Bearer ", "product-ticket.", "postgres://", "internal_endpoint_reference", "connection_ticket", "private_key"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			return fmt.Errorf("Product Phase 3 evidence contains forbidden secret or private field %q", forbidden)
		}
	}
	return nil
}

func exactProcesses(processes []ProcessEvidence) error {
	roles := make([]string, 0, len(processes))
	for _, process := range processes {
		if !process.IndependentOSProcess || !digestPattern.MatchString(process.ExecutableDigest) {
			return fmt.Errorf("invalid process evidence for %q", process.Role)
		}
		roles = append(roles, process.Role)
	}
	if !sameStrings(roles, requiredRoles) {
		return errors.New("Product Phase 3 process set is not exact")
	}
	return nil
}

func exactScenarios(scenarios []ScenarioEvidence) error {
	ids := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		if scenario.Status != "passed" {
			return fmt.Errorf("Product Phase 3 scenario %q did not pass", scenario.ID)
		}
		ids = append(ids, scenario.ID)
	}
	if !sameStrings(ids, requiredCases) {
		return errors.New("Product Phase 3 scenario set is not exact")
	}
	return nil
}

func sameStrings(got, want []string) bool {
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] || index > 0 && got[index] == got[index-1] {
			return false
		}
	}
	return true
}
