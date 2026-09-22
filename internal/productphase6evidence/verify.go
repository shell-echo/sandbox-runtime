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
	ManifestVersion = "2"
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
	evidenceToolFiles = map[string]struct{}{
		"internal/productphase6evidence/verify.go":      {},
		"internal/productphase6evidence/verify_test.go": {},
		"productphase6gate/common_test.go":              {},
		"productphase6gate/evidence_test.go":            {},
		"productphase6gate/environment_test.go":         {},
		"productphase6gate/measurements_test.go":        {},
		"productphase6gate/release_gate_test.go":        {},
	}
)

type Manifest struct {
	ID             string                   `json:"id"`
	Version        string                   `json:"version"`
	ManifestDigest string                   `json:"manifest_digest"`
	Identity       Identity                 `json:"identity"`
	Roles          []Role                   `json:"roles"`
	Scenarios      []Scenario               `json:"scenarios"`
	Stress         StressMeasurements       `json:"stress_measurements"`
	DesktopMedia   DesktopMediaMeasurements `json:"desktop_media_measurements"`
	Cleanup        Cleanup                  `json:"cleanup"`
	NonClaims      []string                 `json:"non_claims"`
}

type Identity struct {
	RuntimeImplementationRevision   string `json:"runtime_implementation_revision"`
	RuntimeImplementationTreeDigest string `json:"runtime_implementation_tree_digest"`
	EvidenceToolRevision            string `json:"evidence_tool_revision"`
	EvidenceToolTreeDigest          string `json:"evidence_tool_tree_digest"`
	ConfigDigest                    string `json:"config_digest"`
	ObservedAt                      string `json:"observed_at"`
	CandidateClassification         string `json:"candidate_classification"`
	DesktopCandidateManifestDigest  string `json:"desktop_candidate_manifest_digest"`
	DesktopCandidateImageDigest     string `json:"desktop_candidate_image_digest"`
	DesktopCandidatePlatform        string `json:"desktop_candidate_platform"`
}

type RepositoryBinding struct {
	RuntimeImplementationRevision   string
	RuntimeImplementationTreeDigest string
	EvidenceToolRevision            string
	EvidenceToolTreeDigest          string
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

type StressMeasurements struct {
	Harness              string   `json:"harness"`
	Runs50               int      `json:"runs_50"`
	Runs100              int      `json:"runs_100"`
	TotalRuns            int      `json:"total_runs"`
	InputsPerRun         int      `json:"inputs_per_run"`
	TotalInputs          int      `json:"total_inputs"`
	FirstFrameFailures   int      `json:"first_frame_failures"`
	InputFailures        int      `json:"input_failures"`
	InputTimeouts        int      `json:"input_timeouts"`
	CleanupFailures      int      `json:"cleanup_failures"`
	SessionExecRemaining int      `json:"session_exec_remaining"`
	FFmpegRemaining      int      `json:"ffmpeg_remaining"`
	TerminalCauses       []string `json:"terminal_causes"`
	CommandDigest        string   `json:"command_digest"`
	EvidenceDigest       string   `json:"evidence_digest"`
}

type DesktopMediaMeasurements struct {
	Harness                          string `json:"harness"`
	Sessions                         int    `json:"sessions"`
	FirstFrameP95Microseconds        int64  `json:"first_frame_p95_microseconds"`
	FirstFrameMaxMicroseconds        int64  `json:"first_frame_max_microseconds"`
	FirstFrameLimitMilliseconds      int64  `json:"first_frame_limit_milliseconds"`
	WindowMilliseconds               int64  `json:"window_milliseconds"`
	RTPPackets                       int64  `json:"rtp_packets"`
	RTPMarkerFrames                  int64  `json:"rtp_marker_frames"`
	RTPBytes                         int64  `json:"rtp_bytes"`
	RTPSequenceGaps                  int64  `json:"rtp_sequence_gaps"`
	AllowedPacketLoss                int64  `json:"allowed_packet_loss"`
	MaxFPSMilli                      int64  `json:"max_fps_milli"`
	FPSLimitMilli                    int64  `json:"fps_limit_milli"`
	MaxBitrateBPS                    int64  `json:"max_bitrate_bps"`
	BitrateLimitBPS                  int64  `json:"bitrate_limit_bps"`
	ConcurrentInputs                 int64  `json:"concurrent_inputs"`
	MaxInputRoundtripMicroseconds    int64  `json:"max_input_roundtrip_microseconds"`
	InputProcessDeadlineMilliseconds int64  `json:"input_process_deadline_milliseconds"`
	BackpressureStage                string `json:"backpressure_stage"`
	BackpressureCause                string `json:"backpressure_cause"`
	Recovery                         bool   `json:"recovery"`
	GoroutinesBaseline               int    `json:"goroutines_baseline"`
	GoroutinesFinal                  int    `json:"goroutines_final"`
	SessionExecRemaining             int    `json:"session_exec_remaining"`
	FFmpegRemaining                  int    `json:"ffmpeg_remaining"`
	DynamicContainersRemaining       int    `json:"dynamic_containers_remaining"`
	CommandDigest                    string `json:"command_digest"`
	EvidenceDigest                   string `json:"evidence_digest"`
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

// BindRuntimeCandidate verifies that the current commit differs from the
// immutable candidate source only by the closed evidence-tool allowlist.
func BindRuntimeCandidate(candidate desktopcandidate.Manifest, sourceRoot string) (RepositoryBinding, error) {
	if candidate.Validate() != nil {
		return RepositoryBinding{}, errors.New("invalid Phase 6 runtime candidate")
	}
	root, err := verifiedRepositoryRoot(sourceRoot)
	if err != nil {
		return RepositoryBinding{}, err
	}
	evidenceRevision, err := gitCommand(root, "rev-parse", "HEAD")
	if err != nil || !revisionPattern.MatchString(evidenceRevision) {
		return RepositoryBinding{}, errors.New("read Phase 6 evidence tool revision")
	}
	if err := verifyEvidenceToolTransition(root, candidate.SourceRevision, evidenceRevision); err != nil {
		return RepositoryBinding{}, err
	}
	runtimeTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, candidate.SourceRevision)
	if err != nil || runtimeTree != candidate.SourceTreeDigest {
		return RepositoryBinding{}, errors.New("Phase 6 candidate source tree does not match its runtime revision")
	}
	evidenceTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, evidenceRevision)
	if err != nil {
		return RepositoryBinding{}, errors.New("read Phase 6 evidence tool tree")
	}
	status, commandErr := gitCommand(root, "status", "--porcelain", "--untracked-files=all")
	if commandErr != nil || status != "" {
		return RepositoryBinding{}, errors.New("Phase 6 gate requires a clean evidence-tool worktree")
	}
	return RepositoryBinding{
		RuntimeImplementationRevision: candidate.SourceRevision, RuntimeImplementationTreeDigest: runtimeTree,
		EvidenceToolRevision: evidenceRevision, EvidenceToolTreeDigest: evidenceTree,
	}, nil
}

// VerifyRepository binds an already verified manifest to immutable runtime
// and evidence-tool revisions. HEAD may be newer only for documentation.
func VerifyRepository(manifest Manifest, sourceRoot string) error {
	root, err := verifiedRepositoryRoot(sourceRoot)
	if err != nil {
		return err
	}
	if err := verifyEvidenceToolTransition(root, manifest.Identity.RuntimeImplementationRevision, manifest.Identity.EvidenceToolRevision); err != nil {
		return err
	}
	runtimeTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, manifest.Identity.RuntimeImplementationRevision)
	if err != nil || runtimeTree != manifest.Identity.RuntimeImplementationTreeDigest {
		return errors.New("Phase 6 evidence runtime tree mismatch")
	}
	evidenceTree, err := desktopcandidate.SourceTreeDigestAtRevision(root, manifest.Identity.EvidenceToolRevision)
	if err != nil || evidenceTree != manifest.Identity.EvidenceToolTreeDigest {
		return errors.New("Phase 6 evidence tool tree mismatch")
	}
	status, commandErr := gitCommand(root, "status", "--porcelain", "--untracked-files=all")
	if commandErr != nil || status != "" {
		return errors.New("Phase 6 evidence verification requires a clean working tree")
	}
	if _, commandErr := gitCommand(root, "merge-base", "--is-ancestor", manifest.Identity.EvidenceToolRevision, "HEAD"); commandErr != nil {
		return errors.New("Phase 6 evidence tool revision is not a current-history ancestor")
	}
	changed, commandErr := gitCommand(root, "diff", "--name-only", manifest.Identity.EvidenceToolRevision+"..HEAD")
	if commandErr != nil {
		return errors.New("inspect Phase 6 post-evidence changes")
	}
	for _, name := range strings.Fields(changed) {
		if name != "README.md" && !strings.HasPrefix(name, "docs/") {
			return fmt.Errorf("Phase 6 post-evidence change is not documentation-only: %s", name)
		}
	}
	return nil
}

func verifiedRepositoryRoot(sourceRoot string) (string, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil || !filepath.IsAbs(sourceRoot) {
		return "", errors.New("absolute Phase 6 evidence source root is required")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("resolve Phase 6 evidence source root")
	}
	output, commandErr := gitCommand(root, "rev-parse", "--show-toplevel")
	if commandErr != nil {
		return "", errors.New("Phase 6 evidence source root is not the repository root")
	}
	canonicalOutput, resolveErr := filepath.EvalSymlinks(output)
	if resolveErr != nil || filepath.Clean(canonicalOutput) != filepath.Clean(canonicalRoot) {
		return "", errors.New("Phase 6 evidence source root is not the repository root")
	}
	return root, nil
}

func verifyEvidenceToolTransition(root, runtimeRevision, evidenceRevision string) error {
	if !revisionPattern.MatchString(runtimeRevision) || !revisionPattern.MatchString(evidenceRevision) || runtimeRevision == evidenceRevision {
		return errors.New("invalid Phase 6 runtime/evidence revision binding")
	}
	if _, err := gitCommand(root, "merge-base", "--is-ancestor", runtimeRevision, evidenceRevision); err != nil {
		return errors.New("Phase 6 runtime revision is not an evidence-tool ancestor")
	}
	changed, err := gitCommand(root, "diff", "--name-only", runtimeRevision+".."+evidenceRevision)
	if err != nil || strings.TrimSpace(changed) == "" {
		return errors.New("inspect Phase 6 evidence-tool transition")
	}
	for _, name := range strings.Fields(changed) {
		if _, ok := evidenceToolFiles[name]; !ok {
			return fmt.Errorf("Phase 6 evidence-tool transition changed runtime file: %s", name)
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
	if !revisionPattern.MatchString(manifest.Identity.RuntimeImplementationRevision) || !hexDigestPattern.MatchString(manifest.Identity.RuntimeImplementationTreeDigest) ||
		!revisionPattern.MatchString(manifest.Identity.EvidenceToolRevision) || !hexDigestPattern.MatchString(manifest.Identity.EvidenceToolTreeDigest) ||
		manifest.Identity.RuntimeImplementationRevision == manifest.Identity.EvidenceToolRevision || !hexDigestPattern.MatchString(manifest.Identity.ConfigDigest) || !validTime(manifest.Identity.ObservedAt) ||
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
	if !validStressMeasurements(manifest.Stress) {
		return Manifest{}, errors.New("invalid Phase 6 stress measurements")
	}
	if !validDesktopMediaMeasurements(manifest.DesktopMedia) {
		return Manifest{}, errors.New("invalid Phase 6 Desktop media measurements")
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
		"local-candidate OCI is not a published or signed artifact":                    false,
		"local-candidate evidence is not production release qualification":             false,
		"evidence proves role boundaries and internal executor data paths only":        false,
		"complete Product-to-Gateway-to-Provider public E2E remains unproven":          false,
		"production readiness remains unproven":                                        false,
		"measured bitrate upper-bound does not prove visual quality":                   false,
		"thirty-second first-frame limit is a test safety bound, not a production SLO": false,
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

func validStressMeasurements(value StressMeasurements) bool {
	return value.Harness == "phase6-desktop-mux-stress-v2" && value.Runs50 == 50 && value.Runs100 == 100 &&
		value.TotalRuns == value.Runs50+value.Runs100 && value.InputsPerRun == 5 && value.TotalInputs == value.TotalRuns*value.InputsPerRun &&
		value.FirstFrameFailures == 0 && value.InputFailures == 0 && value.InputTimeouts == 0 && value.CleanupFailures == 0 &&
		value.SessionExecRemaining == 0 && value.FFmpegRemaining == 0 && value.TerminalCauses != nil && len(value.TerminalCauses) == 0 &&
		value.CommandDigest == StressCommandDigest(value) && value.EvidenceDigest == StressEvidenceDigest(value)
}

func validDesktopMediaMeasurements(value DesktopMediaMeasurements) bool {
	firstFrameLimitMicros := value.FirstFrameLimitMilliseconds * 1000
	inputLimitMicros := value.InputProcessDeadlineMilliseconds * 1000
	return value.Harness == "phase6-desktop-media-v2" && value.Sessions == 20 &&
		value.FirstFrameP95Microseconds > 0 && value.FirstFrameP95Microseconds <= value.FirstFrameMaxMicroseconds &&
		value.FirstFrameLimitMilliseconds == 30_000 && value.FirstFrameMaxMicroseconds <= firstFrameLimitMicros &&
		value.WindowMilliseconds == 2_000 && value.RTPPackets > 0 && value.RTPMarkerFrames > 0 && value.RTPBytes > 0 &&
		value.RTPSequenceGaps >= 0 && value.AllowedPacketLoss == 0 && value.RTPSequenceGaps <= value.AllowedPacketLoss &&
		value.MaxFPSMilli > 0 && value.FPSLimitMilli == 30_000 && value.MaxFPSMilli <= value.FPSLimitMilli &&
		value.MaxBitrateBPS > 0 && value.BitrateLimitBPS == 2_000_000 && value.MaxBitrateBPS <= value.BitrateLimitBPS &&
		value.ConcurrentInputs >= int64(value.Sessions*10+1) && value.MaxInputRoundtripMicroseconds > 0 &&
		value.InputProcessDeadlineMilliseconds == 1_000 && value.MaxInputRoundtripMicroseconds <= inputLimitMicros &&
		value.BackpressureStage == "media_reader" && value.BackpressureCause == "backpressure_limit" && value.Recovery &&
		value.GoroutinesBaseline > 0 && value.GoroutinesBaseline == value.GoroutinesFinal && value.SessionExecRemaining == 0 &&
		value.FFmpegRemaining == 0 && value.DynamicContainersRemaining == 0 &&
		value.CommandDigest == DesktopMediaCommandDigest(value) && value.EvidenceDigest == DesktopMediaEvidenceDigest(value)
}

func StressCommandDigest(value StressMeasurements) string {
	command := struct {
		Harness      string `json:"harness"`
		Runs50       int    `json:"runs_50"`
		Runs100      int    `json:"runs_100"`
		InputsPerRun int    `json:"inputs_per_run"`
	}{value.Harness, value.Runs50, value.Runs100, value.InputsPerRun}
	return measurementDigest("sandbox-runtime/phase6-slice4/stress-command/v2", command)
}

func StressEvidenceDigest(value StressMeasurements) string {
	value.EvidenceDigest = ""
	return measurementDigest("sandbox-runtime/phase6-slice4/stress-evidence/v2", value)
}

func DesktopMediaCommandDigest(value DesktopMediaMeasurements) string {
	command := struct {
		Harness                     string `json:"harness"`
		Sessions                    int    `json:"sessions"`
		WindowMilliseconds          int64  `json:"window_milliseconds"`
		FirstFrameLimitMilliseconds int64  `json:"first_frame_limit_milliseconds"`
		InputDeadlineMilliseconds   int64  `json:"input_process_deadline_milliseconds"`
		FPSLimitMilli               int64  `json:"fps_limit_milli"`
		BitrateLimitBPS             int64  `json:"bitrate_limit_bps"`
	}{value.Harness, value.Sessions, value.WindowMilliseconds, value.FirstFrameLimitMilliseconds, value.InputProcessDeadlineMilliseconds, value.FPSLimitMilli, value.BitrateLimitBPS}
	return measurementDigest("sandbox-runtime/phase6-slice4/media-command/v2", command)
}

func DesktopMediaEvidenceDigest(value DesktopMediaMeasurements) string {
	value.EvidenceDigest = ""
	return measurementDigest("sandbox-runtime/phase6-slice4/media-evidence/v2", value)
}

func measurementDigest(domain string, value any) string {
	document, _ := json.Marshal(value)
	digest := sha256.Sum256(append(append([]byte(nil), []byte(domain)...), append([]byte{0}, document...)...))
	return "sha256:" + hex.EncodeToString(digest[:])
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
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-slice4-manifest/v2\x00"), document...))
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
