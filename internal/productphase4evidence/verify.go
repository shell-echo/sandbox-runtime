// Package productphase4evidence validates the bounded Product Browser release
// evidence envelope. It does not turn same-repository process evidence into a
// deployment, HA, hostile-tenant, independent-caller, or production claim.
package productphase4evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

const (
	ProviderRevision = "98995384c60a924f25ca58d3b7e561207bfa5be8"
	ProviderTree     = "0a627baed11c8a6ddbe8a24bbc1869e4f85edc16"
	ProductTree      = "sha256:9490513228774da2e06cc3d01bc65192d37adea89d12d4ad83efdd6ce0f14560"
	PostgresImage    = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	ValkeyImage      = "ghcr.io/valkey-io/valkey@sha256:ccfa19b0d743e48927e1c8c14e39e0acb97b5cea347fef0bfe340247fea920cd"
	ObjectStore      = "encrypted-local-recording-store-v1"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	requiredRoles   = []string{"browser", "gateway", "product", "provider"}
	requiredCases   = []string{
		"automation-roundtrip", "bounded-backpressure", "browser-live-recording-integrity",
		"browser-slot-session-lifecycle", "contract-identities", "exact-cleanup",
		"gateway-restart-recovery", "product-authentication", "product-restart-recovery",
		"provider-fault-closure", "tenant-nondisclosure", "viewer-controller-fencing",
	}
	requiredNonClaims = []string{"deployment-qualified", "ha-qualified", "hostile-multi-tenant-qualified", "independent-caller-qualified", "production-ready"}
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
	PostgreSQL     ServiceIdentity    `json:"postgresql"`
	Coordination   ServiceIdentity    `json:"coordination"`
	ObjectStorage  ServiceIdentity    `json:"object_storage"`
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

type ServiceIdentity struct {
	Profile string `json:"profile"`
	Fresh   bool   `json:"fresh"`
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
	ContainersRemoved    bool `json:"containers_removed"`
	ScopedRowsRemoved    bool `json:"scoped_rows_removed"`
	ObjectContentRemoved bool `json:"object_content_removed"`
	CoordinationDrained  bool `json:"coordination_drained"`
}

func VerifyFile(path string) (Manifest, error) {
	document, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read Product Phase 4 evidence: %w", err)
	}
	return Verify(document)
}

func Verify(document []byte) (Manifest, error) {
	if len(document) == 0 || len(document) > 1<<20 {
		return Manifest{}, errors.New("Product Phase 4 evidence size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode Product Phase 4 evidence: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("Product Phase 4 evidence has trailing JSON")
	}
	if err := validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func validate(manifest Manifest) error {
	if manifest.SchemaVersion != 1 || manifest.Result != "passed" || manifest.EvidenceTier != "same-repository-separate-process" {
		return errors.New("unexpected Product Phase 4 evidence identity or result")
	}
	if manifest.RunID == "" || strings.ContainsAny(manifest.RunID, "/\\\x00") || !revisionPattern.MatchString(manifest.SourceRevision) || manifest.StartedAt == "" || manifest.CompletedAt == "" {
		return errors.New("invalid Product Phase 4 run metadata")
	}
	if manifest.Provider.Revision != ProviderRevision || manifest.Provider.Tree != ProviderTree {
		return errors.New("Provider Contract identity does not match the Phase 4 lock")
	}
	if manifest.Product.Tree != ProductTree || manifest.Product.ResourceCount != 9 || manifest.Product.OperationCount != 27 || manifest.Product.ConformanceCases != 3 {
		return errors.New("Product Contract identity does not match the Phase 4 lock")
	}
	if manifest.PostgreSQL != (ServiceIdentity{Profile: PostgresImage, Fresh: true}) || manifest.Coordination != (ServiceIdentity{Profile: ValkeyImage, Fresh: true}) || manifest.ObjectStorage != (ServiceIdentity{Profile: ObjectStore, Fresh: true}) {
		return errors.New("Phase 4 service identity or freshness is invalid")
	}
	if err := exactProcesses(manifest.Processes); err != nil {
		return err
	}
	if err := exactScenarios(manifest.Scenarios); err != nil {
		return err
	}
	cleanup := manifest.Cleanup
	if !cleanup.ChildProcessesReaped || !cleanup.ContainersRemoved || !cleanup.ScopedRowsRemoved || !cleanup.ObjectContentRemoved || !cleanup.CoordinationDrained {
		return errors.New("Product Phase 4 cleanup evidence is incomplete")
	}
	if !sameStrings(manifest.NonClaims, requiredNonClaims) {
		return errors.New("Product Phase 4 non-claim boundary is incomplete")
	}
	encoded, _ := json.Marshal(manifest)
	for _, forbidden := range []string{"Bearer ", "Ticket ", "product-ticket.", "postgres://", "redis://", "internal_endpoint_reference", "connection_ticket", "private_key", "object_reference", "consent_reference"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			return fmt.Errorf("Product Phase 4 evidence contains forbidden secret or private field %q", forbidden)
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
		return errors.New("Product Phase 4 process set is not exact")
	}
	return nil
}

func exactScenarios(scenarios []ScenarioEvidence) error {
	ids := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		if scenario.Status != "passed" {
			return fmt.Errorf("Product Phase 4 scenario %q did not pass", scenario.ID)
		}
		ids = append(ids, scenario.ID)
	}
	if !sameStrings(ids, requiredCases) {
		return errors.New("Product Phase 4 scenario set is not exact")
	}
	return nil
}

func sameStrings(got, want []string) bool {
	got, want = append([]string(nil), got...), append([]string(nil), want...)
	slices.Sort(got)
	slices.Sort(want)
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
