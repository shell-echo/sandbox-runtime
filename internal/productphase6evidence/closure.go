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
	"path"
	"path/filepath"
	"strings"
)

const (
	ClosureRecordID      = "product-v1-phase-6-slice-closure"
	ClosureRecordVersion = "1"
	RetainedMode         = "retained"
	RetainedClaimScope   = "historical_retained"
	maxClosureRecordSize = 16 << 10
)

// ClosureRecord binds one completed slice to the immutable revision at which
// its finalization verifier passed. It does not extend that claim to later
// source revisions.
type ClosureRecord struct {
	ID                    string `json:"id"`
	Version               string `json:"version"`
	RecordDigest          string `json:"record_digest"`
	SliceID               string `json:"slice_id"`
	ManifestSchemaVersion string `json:"manifest_schema_version"`
	RuntimeRevision       string `json:"runtime_revision"`
	EvidenceToolRevision  string `json:"evidence_tool_revision"`
	ClosureRevision       string `json:"closure_revision"`
	ManifestRawSHA256     string `json:"manifest_raw_sha256"`
	ManifestSealedDigest  string `json:"manifest_sealed_digest"`
	ArtifactPath          string `json:"artifact_path"`
	ClosureRecordPath     string `json:"closure_record_path"`
}

// RetainedResult is intentionally explicit that later HEAD source is outside
// the historical slice claim.
type RetainedResult struct {
	Mode               string `json:"mode"`
	ClaimScope         string `json:"claim_scope"`
	SliceID            string `json:"slice_id"`
	CoveredRevision    string `json:"covered_revision"`
	EvaluatedHEAD      string `json:"evaluated_head"`
	ManifestDigest     string `json:"manifest_digest"`
	CurrentHEADCovered bool   `json:"current_head_covered"`
	NonClaim           string `json:"nonclaim"`
}

func SealClosureRecord(record ClosureRecord) (ClosureRecord, error) {
	if record.RecordDigest != "" {
		return ClosureRecord{}, errors.New("Phase 6 closure record is already sealed")
	}
	record.ID = ClosureRecordID
	record.Version = ClosureRecordVersion
	record.RecordDigest = closureRecordDigest(record)
	document, err := json.Marshal(record)
	if err != nil {
		return ClosureRecord{}, errors.New("encode Phase 6 closure record")
	}
	return VerifyClosureRecord(document)
}

func VerifyClosureRecordFile(filePath string) (ClosureRecord, error) {
	if filePath == "" {
		return ClosureRecord{}, errors.New("Phase 6 closure record path is required")
	}
	info, err := os.Lstat(filePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > maxClosureRecordSize {
		return ClosureRecord{}, errors.New("Phase 6 closure record must be a bounded non-writable regular file")
	}
	document, err := os.ReadFile(filePath)
	if err != nil {
		return ClosureRecord{}, errors.New("read Phase 6 closure record")
	}
	return VerifyClosureRecord(document)
}

func VerifyClosureRecord(document []byte) (ClosureRecord, error) {
	if len(document) == 0 || len(document) > maxClosureRecordSize {
		return ClosureRecord{}, errors.New("Phase 6 closure record size is invalid")
	}
	unique := json.NewDecoder(bytes.NewReader(document))
	if err := scanUniqueJSON(unique); err != nil {
		return ClosureRecord{}, errors.New("Phase 6 closure record contains duplicate or invalid JSON members")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var record ClosureRecord
	if err := decoder.Decode(&record); err != nil {
		return ClosureRecord{}, errors.New("decode Phase 6 closure record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ClosureRecord{}, errors.New("Phase 6 closure record has trailing JSON")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(document, canonical) {
		return ClosureRecord{}, errors.New("Phase 6 closure record must use canonical JSON encoding")
	}
	if record.ID != ClosureRecordID || record.Version != ClosureRecordVersion || record.RecordDigest != closureRecordDigest(record) {
		return ClosureRecord{}, errors.New("Phase 6 closure record identity or digest is invalid")
	}
	if record.SliceID != ManifestID || record.ManifestSchemaVersion != ManifestVersion ||
		!revisionPattern.MatchString(record.RuntimeRevision) || !revisionPattern.MatchString(record.EvidenceToolRevision) || !revisionPattern.MatchString(record.ClosureRevision) ||
		record.RuntimeRevision == record.EvidenceToolRevision || record.EvidenceToolRevision == record.ClosureRevision ||
		!hexDigestPattern.MatchString(record.ManifestRawSHA256) || !hexDigestPattern.MatchString(record.ManifestSealedDigest) ||
		!validClosurePath(record.ArtifactPath) || !validClosurePath(record.ClosureRecordPath) || record.ArtifactPath == record.ClosureRecordPath {
		return ClosureRecord{}, errors.New("Phase 6 closure record binding is invalid")
	}
	return record, nil
}

// VerifyRetainedRepository preserves the historical Slice 4 claim without
// treating later source revisions as covered by that claim.
func VerifyRetainedRepository(manifest Manifest, record ClosureRecord, expectedSlice, sourceRoot, manifestPath, recordPath string) (RetainedResult, error) { //nolint:gocyclo
	manifestDocument, manifestErr := json.Marshal(manifest)
	if manifestErr != nil {
		return RetainedResult{}, errors.New("encode Phase 6 retained manifest")
	}
	if _, manifestErr = Verify(manifestDocument); manifestErr != nil {
		return RetainedResult{}, errors.New("invalid Phase 6 retained manifest")
	}
	recordDocument, recordErr := json.Marshal(record)
	if recordErr != nil {
		return RetainedResult{}, errors.New("encode Phase 6 retained closure record")
	}
	if _, recordErr = VerifyClosureRecord(recordDocument); recordErr != nil {
		return RetainedResult{}, errors.New("invalid Phase 6 retained closure record")
	}
	if expectedSlice == "" || expectedSlice != ManifestID || record.SliceID != expectedSlice || manifest.ID != expectedSlice {
		return RetainedResult{}, errors.New("explicit Phase 6 retained slice is invalid")
	}
	root, err := verifiedRepositoryRoot(sourceRoot)
	if err != nil {
		return RetainedResult{}, err
	}
	if record.RuntimeRevision != manifest.Identity.RuntimeImplementationRevision || record.EvidenceToolRevision != manifest.Identity.EvidenceToolRevision ||
		record.ManifestSchemaVersion != manifest.Version || record.ManifestSealedDigest != manifest.ManifestDigest {
		return RetainedResult{}, errors.New("Phase 6 closure record does not bind the manifest")
	}
	if err := verifyBoundPath(root, manifestPath, record.ArtifactPath); err != nil {
		return RetainedResult{}, errors.New("Phase 6 retained manifest path mismatch")
	}
	if err := verifyBoundPath(root, recordPath, record.ClosureRecordPath); err != nil {
		return RetainedResult{}, errors.New("Phase 6 retained closure record path mismatch")
	}
	status, commandErr := gitCommand(root, "status", "--porcelain", "--untracked-files=all")
	if commandErr != nil || status != "" {
		return RetainedResult{}, errors.New("Phase 6 retained verification requires a clean working tree")
	}
	for _, revision := range []string{record.RuntimeRevision, record.EvidenceToolRevision, record.ClosureRevision} {
		if _, commandErr := gitCommand(root, "cat-file", "-e", revision+"^{commit}"); commandErr != nil {
			return RetainedResult{}, errors.New("Phase 6 closure record references a missing commit")
		}
	}
	if err := verifyEvidenceToolTransition(root, record.RuntimeRevision, record.EvidenceToolRevision); err != nil {
		return RetainedResult{}, err
	}
	if err := verifyAncestor(root, record.EvidenceToolRevision, record.ClosureRevision, "evidence tool", "closure"); err != nil {
		return RetainedResult{}, err
	}
	if err := verifyDocumentationTransition(root, record.EvidenceToolRevision, record.ClosureRevision); err != nil {
		return RetainedResult{}, err
	}
	head, commandErr := gitCommand(root, "rev-parse", "HEAD")
	if commandErr != nil || !revisionPattern.MatchString(head) {
		return RetainedResult{}, errors.New("read Phase 6 retained verification HEAD")
	}
	if err := verifyAncestor(root, record.ClosureRevision, head, "closure", "current HEAD"); err != nil {
		return RetainedResult{}, err
	}
	closureManifest, commandErr := gitBytes(root, "show", record.ClosureRevision+":"+record.ArtifactPath)
	if commandErr != nil {
		return RetainedResult{}, errors.New("read Phase 6 manifest at closure revision")
	}
	if rawSHA256(closureManifest) != record.ManifestRawSHA256 {
		return RetainedResult{}, errors.New("Phase 6 closure manifest raw digest mismatch")
	}
	closedManifest, verifyErr := Verify(closureManifest)
	if verifyErr != nil || closedManifest.ManifestDigest != record.ManifestSealedDigest {
		return RetainedResult{}, errors.New("Phase 6 closure manifest is invalid")
	}
	currentManifest, readErr := os.ReadFile(manifestPath)
	if readErr != nil || !bytes.Equal(currentManifest, closureManifest) {
		return RetainedResult{}, errors.New("Phase 6 retained manifest differs from its closure revision")
	}
	if history, commandErr := gitCommand(root, "log", "--format=%H", record.ClosureRevision+"..HEAD", "--", record.ArtifactPath); commandErr != nil || history != "" {
		return RetainedResult{}, errors.New("Phase 6 retained manifest changed after closure")
	}
	if err := verifyImmutableClosureRecord(root, record); err != nil {
		return RetainedResult{}, err
	}
	return RetainedResult{
		Mode: RetainedMode, ClaimScope: RetainedClaimScope, SliceID: expectedSlice,
		CoveredRevision: record.ClosureRevision, EvaluatedHEAD: head, ManifestDigest: manifest.ManifestDigest,
		CurrentHEADCovered: false,
		NonClaim:           "retained evidence does not verify current HEAD or any successor slice",
	}, nil
}

func verifyImmutableClosureRecord(root string, record ClosureRecord) error {
	history, err := gitCommand(root, "log", "--format=%H", "--", record.ClosureRecordPath)
	if err != nil {
		return errors.New("inspect Phase 6 closure record history")
	}
	commits := strings.Fields(history)
	if len(commits) != 1 {
		return errors.New("Phase 6 closure record must be added exactly once")
	}
	introduction := commits[0]
	if err := verifyAncestor(root, record.ClosureRevision, introduction, "closure", "closure record introduction"); err != nil {
		return err
	}
	recorded, err := gitBytes(root, "show", introduction+":"+record.ClosureRecordPath)
	if err != nil {
		return errors.New("read immutable Phase 6 closure record")
	}
	current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(record.ClosureRecordPath)))
	if err != nil || !bytes.Equal(current, recorded) {
		return errors.New("Phase 6 closure record differs from its introduction revision")
	}
	return nil
}

func verifyDocumentationTransition(root, fromRevision, toRevision string) error {
	changed, err := gitCommand(root, "diff", "--name-only", fromRevision+".."+toRevision)
	if err != nil || strings.TrimSpace(changed) == "" {
		return errors.New("inspect Phase 6 finalization transition")
	}
	for _, name := range strings.Fields(changed) {
		if !isPhase6DocumentationPath(name) {
			return fmt.Errorf("Phase 6 finalization transition changed non-documentation file: %s", name)
		}
	}
	return nil
}

func verifyAncestor(root, ancestor, descendant, ancestorName, descendantName string) error {
	if _, err := gitCommand(root, "merge-base", "--is-ancestor", ancestor, descendant); err != nil {
		return fmt.Errorf("Phase 6 %s revision is not a %s ancestor", ancestorName, descendantName)
	}
	return nil
}

func verifyBoundPath(root, absolutePath, relativePath string) error {
	if !filepath.IsAbs(absolutePath) || !validClosurePath(relativePath) {
		return errors.New("invalid bound path")
	}
	resolved, err := filepath.EvalSymlinks(absolutePath)
	if err != nil {
		return err
	}
	expected, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(relativePath)))
	if err != nil || filepath.Clean(resolved) != filepath.Clean(expected) {
		return errors.New("bound path mismatch")
	}
	return nil
}

func validClosurePath(value string) bool {
	return value != "" && !path.IsAbs(value) && path.Clean(value) == value && !strings.Contains(value, "\\") &&
		strings.HasPrefix(value, "docs/audits/") && strings.HasSuffix(value, ".json")
}

func rawSHA256(document []byte) string {
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func closureRecordDigest(record ClosureRecord) string {
	record.RecordDigest = ""
	document, _ := json.Marshal(record)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-slice-closure/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func gitBytes(root string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", arguments...)
	command.Dir = root
	return command.Output()
}
