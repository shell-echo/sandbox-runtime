// Package productphase5evidence validates the bounded Product Desktop release
// evidence envelope. It does not turn same-repository process evidence into a
// deployment, HA, hostile-tenant, independent-caller, or production claim.
package productphase5evidence

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
	"time"
)

const (
	BaseProviderRevision    = "98995384c60a924f25ca58d3b7e561207bfa5be8"
	BaseProviderTree        = "0a627baed11c8a6ddbe8a24bbc1869e4f85edc16"
	DesktopProviderRevision = "720ad15c343e71f36615dc4499edd5e764178bca"
	DesktopProviderTree     = "343ffde0819207cf99c005096c336735dd33a735"
	ProductTree             = "sha256:9490513228774da2e06cc3d01bc65192d37adea89d12d4ad83efdd6ce0f14560"
	PostgresImage           = "postgres:16-alpine@sha256:866efe7070b471f3a5397edac0e5edd65c23ff056587c6e47c07d008caaedd28"
	ObjectStore             = "encrypted-local-recording-plus-content-addressed-local-v1"
	DesktopProfile          = "sandbox-runtime-desktop-v1"
	DesktopImage            = "ghcr.io/shell-echo/sandbox-runtime-desktop@sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300"
	DesktopImageDigest      = "sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300"
	DesktopSourceRevision   = "e4a940bda6c5172a78d0dbe40963ca1a99911976"
	DevelopmentTemplate     = "coding-shell-base-v1"
	DevelopmentImage        = "ghcr.io/shell-echo/sandbox-runtime-coding-shell@sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1"
	DevelopmentImageDigest  = "sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1"
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	requiredRoles   = []string{"desktop", "gateway", "guest", "product", "provider"}
	requiredCases   = []string{
		"capability-advertisement", "contract-identities", "desktop-recording-integrity",
		"desktop-slot-session-lifecycle", "desktop-ticket-replay-origin-denial", "exact-cleanup",
		"gateway-restart-recovery", "guest-development-materialization", "guest-restart-recovery",
		"product-authentication", "product-restart-recovery", "provider-dependency-fault-closure",
		"real-desktop-display-control", "tenant-nondisclosure",
	}
	requiredNonClaims = []string{"deployment-qualified", "ha-qualified", "hostile-multi-tenant-qualified", "independent-caller-qualified", "production-ready"}
)

type Manifest struct {
	SchemaVersion       int                `json:"schema_version"`
	RunID               string             `json:"run_id"`
	Result              string             `json:"result"`
	EvidenceTier        string             `json:"evidence_tier"`
	SourceRevision      string             `json:"source_revision"`
	StartedAt           string             `json:"started_at"`
	CompletedAt         string             `json:"completed_at"`
	BaseProvider        ProviderIdentity   `json:"base_provider_contract"`
	DesktopProvider     ProviderIdentity   `json:"desktop_provider_contract"`
	Product             ProductIdentity    `json:"product_contract"`
	PostgreSQL          ServiceIdentity    `json:"postgresql"`
	ObjectStorage       ServiceIdentity    `json:"object_storage"`
	DesktopRuntime      RuntimeIdentity    `json:"desktop_runtime"`
	DevelopmentTemplate TemplateIdentity   `json:"development_template"`
	Processes           []ProcessEvidence  `json:"processes"`
	Scenarios           []ScenarioEvidence `json:"scenarios"`
	Cleanup             CleanupEvidence    `json:"cleanup"`
	NonClaims           []string           `json:"non_claims"`
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

type RuntimeIdentity struct {
	Profile        string `json:"profile"`
	Image          string `json:"image"`
	IndexDigest    string `json:"index_digest"`
	Platform       string `json:"platform"`
	PlatformDigest string `json:"platform_digest"`
	SourceRevision string `json:"source_revision"`
	Signed         bool   `json:"signed"`
}

type TemplateIdentity struct {
	TemplateID  string `json:"template_id"`
	Image       string `json:"image"`
	IndexDigest string `json:"index_digest"`
	Selected    bool   `json:"selected"`
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
	GuestStateRemoved    bool `json:"guest_state_removed"`
	RuntimeRemoved       bool `json:"runtime_removed"`
}

func VerifyFile(path string) (Manifest, error) {
	document, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read Product Phase 5 evidence: %w", err)
	}
	return Verify(document)
}

func Verify(document []byte) (Manifest, error) { //nolint:cyclop
	if len(document) == 0 || len(document) > 1<<20 {
		return Manifest{}, errors.New("Product Phase 5 evidence size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode Product Phase 5 evidence: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("Product Phase 5 evidence has trailing JSON")
	}
	if manifest.SchemaVersion != 1 || manifest.Result != "passed" || manifest.EvidenceTier != "same-repository-independent-process" {
		return Manifest{}, errors.New("unexpected Product Phase 5 evidence identity or result")
	}
	started, startErr := time.Parse(time.RFC3339Nano, manifest.StartedAt)
	completed, completeErr := time.Parse(time.RFC3339Nano, manifest.CompletedAt)
	if manifest.RunID == "" || strings.ContainsAny(manifest.RunID, "/\\\x00") || !revisionPattern.MatchString(manifest.SourceRevision) || startErr != nil || completeErr != nil || completed.Before(started) {
		return Manifest{}, errors.New("invalid Product Phase 5 run metadata")
	}
	if manifest.BaseProvider != (ProviderIdentity{Revision: BaseProviderRevision, Tree: BaseProviderTree}) || manifest.DesktopProvider != (ProviderIdentity{Revision: DesktopProviderRevision, Tree: DesktopProviderTree}) {
		return Manifest{}, errors.New("Provider Contract identities do not match the Phase 5 locks")
	}
	if manifest.Product != (ProductIdentity{Tree: ProductTree, ResourceCount: 9, OperationCount: 27, ConformanceCases: 3}) {
		return Manifest{}, errors.New("Product Contract identity does not match the Phase 5 lock")
	}
	if manifest.PostgreSQL != (ServiceIdentity{Profile: PostgresImage, Fresh: true}) || manifest.ObjectStorage != (ServiceIdentity{Profile: ObjectStore, Fresh: true}) {
		return Manifest{}, errors.New("Phase 5 service identity or freshness is invalid")
	}
	if err := exactRuntime(manifest.DesktopRuntime); err != nil {
		return Manifest{}, err
	}
	if manifest.DevelopmentTemplate != (TemplateIdentity{TemplateID: DevelopmentTemplate, Image: DevelopmentImage, IndexDigest: DevelopmentImageDigest, Selected: true}) {
		return Manifest{}, errors.New("Phase 5 development template identity is invalid")
	}
	if err := exactProcesses(manifest.Processes); err != nil {
		return Manifest{}, err
	}
	if err := exactScenarios(manifest.Scenarios); err != nil {
		return Manifest{}, err
	}
	cleanup := manifest.Cleanup
	if !cleanup.ChildProcessesReaped || !cleanup.ContainersRemoved || !cleanup.ScopedRowsRemoved || !cleanup.ObjectContentRemoved || !cleanup.GuestStateRemoved || !cleanup.RuntimeRemoved {
		return Manifest{}, errors.New("Product Phase 5 cleanup evidence is incomplete")
	}
	if !sameStrings(manifest.NonClaims, requiredNonClaims) {
		return Manifest{}, errors.New("Product Phase 5 non-claim boundary is incomplete")
	}
	encoded, _ := json.Marshal(manifest)
	for _, forbidden := range []string{"Bearer ", "Ticket ", "product-ticket.", "postgres://", "redis://", "ref:desktop-session:", "connection_ticket", "private_key", "object_reference", "consent_reference", "guest_id", "handoff_reference", "/Users/", "/home/"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			return Manifest{}, fmt.Errorf("Product Phase 5 evidence contains forbidden secret or private field %q", forbidden)
		}
	}
	return manifest, nil
}

func exactRuntime(runtime RuntimeIdentity) error {
	if runtime.Profile != DesktopProfile || runtime.Image != DesktopImage || runtime.IndexDigest != DesktopImageDigest || runtime.SourceRevision != DesktopSourceRevision || !runtime.Signed {
		return errors.New("Phase 5 Desktop runtime identity is invalid")
	}
	platforms := map[string]string{
		"linux/amd64":    "sha256:ae1b71855f879066caf73f1056039d52b796d936a19f4b34a58a5565dd89609b",
		"linux/arm64/v8": "sha256:e5d01e272f87df8dc693ba81d85bce2a154ae541ac0166177a9290a005928505",
	}
	if platforms[runtime.Platform] != runtime.PlatformDigest || !digestPattern.MatchString(runtime.PlatformDigest) {
		return errors.New("Phase 5 Desktop runtime platform identity is invalid")
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
		return errors.New("Product Phase 5 process set is not exact")
	}
	return nil
}

func exactScenarios(scenarios []ScenarioEvidence) error {
	ids := make([]string, 0, len(scenarios))
	for _, scenario := range scenarios {
		if scenario.Status != "passed" {
			return fmt.Errorf("Product Phase 5 scenario %q did not pass", scenario.ID)
		}
		ids = append(ids, scenario.ID)
	}
	if !sameStrings(ids, requiredCases) {
		return errors.New("Product Phase 5 scenario set is not exact")
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
