// Package productphase6evidence verifies the closed evidence projection for
// Product v1 Phase 6 Slice 4. It validates evidence supplied by an actual
// operator/process gate; it never creates evidence or infers deployment facts.
package productphase6evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
)

const (
	ManifestID      = "product-v1-phase-6-slice-4"
	ManifestVersion = "1"
	maxManifestSize = 1 << 20
)

var (
	hexDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	revisionPattern  = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
	roleSet          = map[string]struct{}{"product": {}, "gateway": {}, "provider": {}, "guest": {}, "browser": {}, "desktop": {}}
	scenarioSet      = map[string]struct{}{
		"normal_attach_media_input": {}, "provider_dependency_loss": {}, "bounded_reconnect": {},
		"drain_cancellation": {}, "authority_expiry": {}, "fence_generation_epoch_drift": {},
		"replay_rejection": {}, "executor_capacity": {}, "provider_restart": {}, "executor_restart": {},
		"broker_restart": {}, "close_cleanup": {},
	}
)

type Manifest struct {
	ID             string     `json:"id"`
	Version        string     `json:"version"`
	ManifestDigest string     `json:"manifest_digest"`
	Identity       Identity   `json:"identity"`
	Roles          []Role     `json:"roles"`
	Scenarios      []Scenario `json:"scenarios"`
	Cleanup        Cleanup    `json:"cleanup"`
	NonClaims      []string   `json:"non_claims"`
}

type Identity struct {
	SourceRevision                 string `json:"source_revision"`
	SourceTreeDigest               string `json:"source_tree_digest"`
	ConfigDigest                   string `json:"config_digest"`
	ObservedAt                     string `json:"observed_at"`
	CandidateClassification        string `json:"candidate_classification"`
	DesktopCandidateManifestDigest string `json:"desktop_candidate_manifest_digest"`
	DesktopCandidateImageDigest    string `json:"desktop_candidate_image_digest"`
	DesktopCandidatePlatform       string `json:"desktop_candidate_platform"`
}

type Role struct {
	Name            string `json:"name"`
	Command         string `json:"command"`
	ImageDigest     string `json:"image_digest"`
	ProcessIdentity string `json:"process_identity"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	ExitCode        int    `json:"exit_code"`
	Ready           bool   `json:"ready"`
	EvidenceDigest  string `json:"evidence_digest"`
}

type Scenario struct {
	Name           string   `json:"name"`
	Outcome        string   `json:"outcome"`
	Roles          []string `json:"roles"`
	EvidenceDigest string   `json:"evidence_digest"`
}

type Cleanup struct {
	ZeroResources  bool       `json:"zero_resources"`
	Teardown       []Resource `json:"teardown"`
	EvidenceDigest string     `json:"evidence_digest"`
}

type Resource struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func VerifyFile(path string) (Manifest, error) {
	if path == "" {
		return Manifest{}, errors.New("Phase 6 evidence path is required")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxManifestSize {
		return Manifest{}, errors.New("Phase 6 evidence must be a private bounded regular file")
	}
	document, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, errors.New("read Phase 6 evidence")
	}
	return Verify(document)
}

// VerifyRepository binds an already verified manifest to an immutable
// implementation revision in the current repository. HEAD may be newer only
// when every intervening change is documentation/evidence-only and the
// working tree is clean.
func VerifyRepository(manifest Manifest, sourceRoot string) error {
	root, err := filepath.Abs(sourceRoot)
	if err != nil || !filepath.IsAbs(sourceRoot) {
		return errors.New("absolute Phase 6 evidence source root is required")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return errors.New("resolve Phase 6 evidence source root")
	}
	if output, commandErr := gitCommand(root, "rev-parse", "--show-toplevel"); commandErr != nil {
		return errors.New("Phase 6 evidence source root is not the repository root")
	} else if canonicalOutput, resolveErr := filepath.EvalSymlinks(output); resolveErr != nil || filepath.Clean(canonicalOutput) != filepath.Clean(canonicalRoot) {
		return errors.New("Phase 6 evidence source root is not the repository root")
	}
	if _, commandErr := gitCommand(root, "merge-base", "--is-ancestor", manifest.Identity.SourceRevision, "HEAD"); commandErr != nil {
		return errors.New("Phase 6 implementation revision is not a current-history ancestor")
	}
	committedDigest, err := desktopcandidate.SourceTreeDigestAtRevision(root, manifest.Identity.SourceRevision)
	if err != nil || committedDigest != manifest.Identity.SourceTreeDigest {
		return errors.New("Phase 6 evidence source tree does not match its implementation revision")
	}
	status, commandErr := gitCommand(root, "status", "--porcelain", "--untracked-files=all")
	if commandErr != nil || status != "" {
		return errors.New("Phase 6 evidence verification requires a clean working tree")
	}
	changed, commandErr := gitCommand(root, "diff", "--name-only", manifest.Identity.SourceRevision+"..HEAD")
	if commandErr != nil {
		return errors.New("inspect Phase 6 post-implementation changes")
	}
	for _, name := range strings.Fields(changed) {
		if name != "README.md" && !strings.HasPrefix(name, "docs/") {
			return fmt.Errorf("Phase 6 post-implementation change is not evidence-only: %s", name)
		}
	}
	return nil
}

func gitCommand(root string, arguments ...string) (string, error) {
	command := exec.Command("git", arguments...)
	command.Dir = root
	document, err := command.Output()
	return strings.TrimSpace(string(document)), err
}

// Seal binds the supplied observations to the closed manifest digest and
// verifies the resulting document. It does not infer or fabricate evidence.
func Seal(manifest Manifest) (Manifest, error) {
	if manifest.ManifestDigest != "" {
		return Manifest{}, errors.New("Phase 6 evidence is already sealed")
	}
	manifest.ID = ManifestID
	manifest.Version = ManifestVersion
	manifest.ManifestDigest = digestWithoutSelf(manifest)
	document, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, errors.New("encode Phase 6 evidence")
	}
	return Verify(document)
}

func Verify(document []byte) (Manifest, error) { //nolint:gocyclo
	if len(document) == 0 || len(document) > maxManifestSize {
		return Manifest{}, errors.New("Phase 6 evidence size is invalid")
	}
	unique := json.NewDecoder(bytes.NewReader(document))
	if err := scanUniqueJSON(unique); err != nil {
		return Manifest{}, errors.New("Phase 6 evidence contains duplicate or invalid JSON members")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode Phase 6 evidence: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("Phase 6 evidence has trailing JSON")
	}
	if manifest.ID != ManifestID || manifest.Version != ManifestVersion {
		return Manifest{}, errors.New("unexpected Phase 6 evidence identity")
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(document, canonical) {
		return Manifest{}, errors.New("Phase 6 evidence must use canonical JSON encoding")
	}
	if manifest.ManifestDigest != digestWithoutSelf(manifest) {
		return Manifest{}, errors.New("Phase 6 evidence manifest digest mismatch")
	}
	if !revisionPattern.MatchString(manifest.Identity.SourceRevision) || !hexDigestPattern.MatchString(manifest.Identity.SourceTreeDigest) || !hexDigestPattern.MatchString(manifest.Identity.ConfigDigest) || !validTime(manifest.Identity.ObservedAt) ||
		manifest.Identity.CandidateClassification != "local-candidate-non-release" || !hexDigestPattern.MatchString(manifest.Identity.DesktopCandidateManifestDigest) ||
		!hexDigestPattern.MatchString(manifest.Identity.DesktopCandidateImageDigest) || (manifest.Identity.DesktopCandidatePlatform != "linux/amd64" && manifest.Identity.DesktopCandidatePlatform != "linux/arm64/v8") {
		return Manifest{}, errors.New("invalid Phase 6 source identity")
	}
	if len(manifest.Roles) != len(roleSet) {
		return Manifest{}, errors.New("Phase 6 evidence must contain exactly six roles")
	}
	seenRoles := make(map[string]struct{}, len(manifest.Roles))
	seenProcesses := make(map[string]struct{}, len(manifest.Roles))
	for _, role := range manifest.Roles {
		if _, ok := roleSet[role.Name]; !ok {
			return Manifest{}, fmt.Errorf("invalid Phase 6 role %q", role.Name)
		}
		started, startOK := parseTime(role.StartedAt)
		finished, finishOK := parseTime(role.FinishedAt)
		_, duplicateProcess := seenProcesses[role.ProcessIdentity]
		if _, ok := seenRoles[role.Name]; ok || strings.TrimSpace(role.Command) == "" || !hexDigestPattern.MatchString(role.ImageDigest) || strings.TrimSpace(role.ProcessIdentity) == "" || duplicateProcess || !startOK || !finishOK || finished.Before(started) || role.ExitCode != 0 || !role.Ready || !hexDigestPattern.MatchString(role.EvidenceDigest) {
			return Manifest{}, errors.New("invalid Phase 6 role evidence")
		}
		seenRoles[role.Name] = struct{}{}
		seenProcesses[role.ProcessIdentity] = struct{}{}
	}
	if len(seenRoles) != len(roleSet) {
		return Manifest{}, errors.New("Phase 6 role set is incomplete")
	}
	if len(manifest.Scenarios) != len(scenarioSet) {
		return Manifest{}, errors.New("Phase 6 scenario set is incomplete")
	}
	seenScenarios := make(map[string]struct{}, len(manifest.Scenarios))
	for _, scenario := range manifest.Scenarios {
		if _, ok := scenarioSet[scenario.Name]; !ok || scenario.Outcome != "passed" || len(scenario.Roles) < 2 || !hexDigestPattern.MatchString(scenario.EvidenceDigest) {
			return Manifest{}, errors.New("invalid Phase 6 scenario evidence")
		}
		if _, ok := seenScenarios[scenario.Name]; ok {
			return Manifest{}, errors.New("duplicate Phase 6 scenario")
		}
		seenScenarios[scenario.Name] = struct{}{}
		scenarioRoles := make(map[string]struct{}, len(scenario.Roles))
		for _, role := range scenario.Roles {
			if _, ok := seenRoles[role]; !ok {
				return Manifest{}, errors.New("scenario references an unknown role")
			}
			if _, duplicate := scenarioRoles[role]; duplicate {
				return Manifest{}, errors.New("scenario contains a duplicate role")
			}
			scenarioRoles[role] = struct{}{}
		}
	}
	if len(seenScenarios) != len(scenarioSet) || !manifest.Cleanup.ZeroResources || len(manifest.Cleanup.Teardown) == 0 || !hexDigestPattern.MatchString(manifest.Cleanup.EvidenceDigest) {
		return Manifest{}, errors.New("Phase 6 cleanup evidence is incomplete")
	}
	seenResources := make(map[string]struct{}, len(manifest.Cleanup.Teardown))
	for _, resource := range manifest.Cleanup.Teardown {
		if strings.TrimSpace(resource.Name) == "" || resource.Count != 0 {
			return Manifest{}, errors.New("Phase 6 cleanup resource is not empty")
		}
		if _, ok := seenResources[resource.Name]; ok {
			return Manifest{}, errors.New("duplicate Phase 6 cleanup resource")
		}
		seenResources[resource.Name] = struct{}{}
	}
	if len(manifest.NonClaims) == 0 {
		return Manifest{}, errors.New("Phase 6 non-claim boundary is required")
	}
	requiredNonClaims := map[string]bool{
		"local-candidate OCI is not a published or signed artifact":             false,
		"local-candidate evidence is not production release qualification":      false,
		"evidence proves role boundaries and internal executor data paths only": false,
		"complete Product-to-Gateway-to-Provider public E2E remains unproven":   false,
		"production readiness remains unproven":                                 false,
	}
	for _, value := range manifest.NonClaims {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
			return Manifest{}, errors.New("invalid Phase 6 non-claim")
		}
		if _, required := requiredNonClaims[value]; required {
			requiredNonClaims[value] = true
		}
	}
	for _, present := range requiredNonClaims {
		if !present {
			return Manifest{}, errors.New("Phase 6 local-candidate non-claim is incomplete")
		}
	}
	return manifest, nil
}

func scanUniqueJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	var scan func(json.Token) error
	scan = func(value json.Token) error {
		delimiter, ok := value.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object member")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate JSON object member")
				}
				seen[key] = struct{}{}
				next, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				if tokenErr = scan(next); tokenErr != nil {
					return tokenErr
				}
			}
			_, tokenErr := decoder.Token()
			return tokenErr
		case '[':
			for decoder.More() {
				next, tokenErr := decoder.Token()
				if tokenErr != nil {
					return tokenErr
				}
				if tokenErr = scan(next); tokenErr != nil {
					return tokenErr
				}
			}
			_, tokenErr := decoder.Token()
			return tokenErr
		default:
			return errors.New("invalid JSON delimiter")
		}
	}
	if err := scan(token); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func digestWithoutSelf(manifest Manifest) string {
	manifest.ManifestDigest = ""
	document, _ := json.Marshal(manifest)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-slice4-manifest/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validTime(value string) bool {
	_, ok := parseTime(value)
	return ok
}

func parseTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil && !parsed.IsZero() && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}

// ScenarioNames returns the locked scenario order for an external gate.
func ScenarioNames() []string {
	values := make([]string, 0, len(scenarioSet))
	for value := range scenarioSet {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}
