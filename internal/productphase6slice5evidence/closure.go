package productphase6slice5evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/productphase6evidence"
)

const (
	ClosureRecordID      = "product-v1-phase-6-slice-5-closure"
	ClosureRecordVersion = "1"
	RetainedMode         = "retained"
	RetainedClaimScope   = "historical_retained"
	maxClosureRecordSize = 16 << 10
)

// ClosureRecord binds the Slice 5 manifest to the documentation-only revision
// that archived it. It never extends the Slice 5 claim to successor source.
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

func NewClosureRecord(manifestDocument []byte, manifest Manifest, closureRevision, artifactPath, recordPath string) (ClosureRecord, error) {
	verified, err := Verify(manifestDocument)
	if err != nil || verified.ManifestDigest != manifest.ManifestDigest {
		return ClosureRecord{}, errors.New("Slice 5 closure requires the verified manifest document")
	}
	return SealClosureRecord(ClosureRecord{
		SliceID: ManifestID, ManifestSchemaVersion: ManifestVersion,
		RuntimeRevision:      manifest.RuntimeGate.Identity.RuntimeImplementationRevision,
		EvidenceToolRevision: manifest.RuntimeGate.Identity.EvidenceToolRevision,
		ClosureRevision:      closureRevision, ManifestRawSHA256: RawSHA256(manifestDocument),
		ManifestSealedDigest: manifest.ManifestDigest, ArtifactPath: artifactPath, ClosureRecordPath: recordPath,
	})
}

func SealClosureRecord(record ClosureRecord) (ClosureRecord, error) {
	if record.RecordDigest != "" {
		return ClosureRecord{}, errors.New("Slice 5 closure record is already sealed")
	}
	record.ID = ClosureRecordID
	record.Version = ClosureRecordVersion
	record.RecordDigest = closureRecordDigest(record)
	document, err := json.Marshal(record)
	if err != nil {
		return ClosureRecord{}, errors.New("encode Slice 5 closure record")
	}
	return VerifyClosureRecord(document)
}

func VerifyClosureRecordFile(filePath string) (ClosureRecord, error) {
	if filePath == "" {
		return ClosureRecord{}, errors.New("Slice 5 closure record path is required")
	}
	info, err := os.Lstat(filePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() < 1 || info.Size() > maxClosureRecordSize {
		return ClosureRecord{}, errors.New("Slice 5 closure record must be a bounded non-group-writable regular file")
	}
	document, err := os.ReadFile(filePath)
	if err != nil {
		return ClosureRecord{}, errors.New("read Slice 5 closure record")
	}
	return VerifyClosureRecord(document)
}

func VerifyClosureRecord(document []byte) (ClosureRecord, error) {
	if len(document) < 1 || len(document) > maxClosureRecordSize {
		return ClosureRecord{}, errors.New("Slice 5 closure record size is invalid")
	}
	var record ClosureRecord
	if err := decodeCanonical(document, &record); err != nil {
		return ClosureRecord{}, errors.New("Slice 5 closure record must be closed canonical JSON")
	}
	if record.ID != ClosureRecordID || record.Version != ClosureRecordVersion || record.RecordDigest != closureRecordDigest(record) {
		return ClosureRecord{}, errors.New("Slice 5 closure record identity or digest is invalid")
	}
	if record.SliceID != ManifestID || record.ManifestSchemaVersion != ManifestVersion ||
		!revisionPattern.MatchString(record.RuntimeRevision) || !revisionPattern.MatchString(record.EvidenceToolRevision) || !revisionPattern.MatchString(record.ClosureRevision) ||
		record.RuntimeRevision == record.EvidenceToolRevision || record.EvidenceToolRevision == record.ClosureRevision || record.RuntimeRevision == record.ClosureRevision ||
		!digestPattern.MatchString(record.ManifestRawSHA256) || !digestPattern.MatchString(record.ManifestSealedDigest) ||
		!validClosurePath(record.ArtifactPath) || !validClosurePath(record.ClosureRecordPath) || record.ArtifactPath == record.ClosureRecordPath {
		return ClosureRecord{}, errors.New("Slice 5 closure record binding is invalid")
	}
	return record, nil
}

func VerifyRetainedRepository(manifest Manifest, record ClosureRecord, expectedSlice, sourceRoot, manifestPath, recordPath string) (RetainedResult, error) { //nolint:gocyclo
	manifestDocument, err := json.Marshal(manifest)
	if err != nil {
		return RetainedResult{}, errors.New("encode retained Slice 5 manifest")
	}
	if _, err := Verify(manifestDocument); err != nil {
		return RetainedResult{}, errors.New("invalid retained Slice 5 manifest")
	}
	recordDocument, err := json.Marshal(record)
	if err != nil {
		return RetainedResult{}, errors.New("encode retained Slice 5 closure record")
	}
	if _, err := VerifyClosureRecord(recordDocument); err != nil {
		return RetainedResult{}, errors.New("invalid retained Slice 5 closure record")
	}
	if expectedSlice != ManifestID || record.SliceID != expectedSlice || manifest.ID != expectedSlice {
		return RetainedResult{}, errors.New("explicit retained Slice 5 identity is invalid")
	}
	root, err := verifiedRepositoryRoot(sourceRoot)
	if err != nil {
		return RetainedResult{}, err
	}
	identity := manifest.RuntimeGate.Identity
	if record.RuntimeRevision != identity.RuntimeImplementationRevision || record.EvidenceToolRevision != identity.EvidenceToolRevision ||
		record.ManifestSchemaVersion != manifest.Version || record.ManifestSealedDigest != manifest.ManifestDigest {
		return RetainedResult{}, errors.New("Slice 5 closure record does not bind the manifest")
	}
	if err := verifyBoundPath(root, manifestPath, record.ArtifactPath); err != nil {
		return RetainedResult{}, errors.New("retained Slice 5 manifest path mismatch")
	}
	if err := verifyBoundPath(root, recordPath, record.ClosureRecordPath); err != nil {
		return RetainedResult{}, errors.New("retained Slice 5 closure record path mismatch")
	}
	if status, commandErr := gitText(root, "status", "--porcelain", "--untracked-files=all"); commandErr != nil || status != "" {
		return RetainedResult{}, errors.New("retained Slice 5 verification requires a clean working tree")
	}
	for _, revision := range []string{record.RuntimeRevision, record.EvidenceToolRevision, record.ClosureRevision} {
		if _, commandErr := gitText(root, "cat-file", "-e", revision+"^{commit}"); commandErr != nil {
			return RetainedResult{}, errors.New("Slice 5 closure record references a missing commit")
		}
	}
	if err := productphase6evidence.VerifyImmutableRepositoryBinding(manifest.RuntimeGate, root); err != nil {
		return RetainedResult{}, err
	}
	if err := verifyAncestor(root, record.EvidenceToolRevision, record.ClosureRevision, "evidence tool", "closure"); err != nil {
		return RetainedResult{}, err
	}
	if err := verifyDocumentationTransition(root, record.EvidenceToolRevision, record.ClosureRevision); err != nil {
		return RetainedResult{}, err
	}
	head, commandErr := gitText(root, "rev-parse", "HEAD")
	if commandErr != nil || !revisionPattern.MatchString(head) {
		return RetainedResult{}, errors.New("read retained Slice 5 verification HEAD")
	}
	if err := verifyAncestor(root, record.ClosureRevision, head, "closure", "current HEAD"); err != nil {
		return RetainedResult{}, err
	}
	closureManifest, commandErr := gitBytes(root, "show", record.ClosureRevision+":"+record.ArtifactPath)
	if commandErr != nil || RawSHA256(closureManifest) != record.ManifestRawSHA256 {
		return RetainedResult{}, errors.New("Slice 5 closure manifest raw digest mismatch")
	}
	closedManifest, verifyErr := Verify(closureManifest)
	if verifyErr != nil || closedManifest.ManifestDigest != record.ManifestSealedDigest {
		return RetainedResult{}, errors.New("Slice 5 closure manifest is invalid")
	}
	currentManifest, readErr := os.ReadFile(manifestPath)
	if readErr != nil || !bytes.Equal(currentManifest, closureManifest) {
		return RetainedResult{}, errors.New("retained Slice 5 manifest differs from its closure revision")
	}
	if history, commandErr := gitText(root, "log", "--format=%H", record.ClosureRevision+"..HEAD", "--", record.ArtifactPath); commandErr != nil || history != "" {
		return RetainedResult{}, errors.New("retained Slice 5 manifest changed after closure")
	}
	if err := verifyImmutableClosureRecord(root, record); err != nil {
		return RetainedResult{}, err
	}
	return RetainedResult{
		Mode: RetainedMode, ClaimScope: RetainedClaimScope, SliceID: ManifestID,
		CoveredRevision: record.ClosureRevision, EvaluatedHEAD: head, ManifestDigest: manifest.ManifestDigest,
		CurrentHEADCovered: false,
		NonClaim:           "retained evidence does not verify current HEAD or any successor slice",
	}, nil
}

func verifyImmutableClosureRecord(root string, record ClosureRecord) error {
	history, err := gitText(root, "log", "--format=%H", "--", record.ClosureRecordPath)
	if err != nil {
		return errors.New("inspect Slice 5 closure record history")
	}
	commits := strings.Fields(history)
	if len(commits) != 1 {
		return errors.New("Slice 5 closure record must be added exactly once")
	}
	introduction := commits[0]
	if err := verifyAncestor(root, record.ClosureRevision, introduction, "closure", "closure record introduction"); err != nil {
		return err
	}
	recorded, err := gitBytes(root, "show", introduction+":"+record.ClosureRecordPath)
	if err != nil {
		return errors.New("read immutable Slice 5 closure record")
	}
	current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(record.ClosureRecordPath)))
	if err != nil || !bytes.Equal(current, recorded) {
		return errors.New("Slice 5 closure record differs from its introduction revision")
	}
	return nil
}

func verifyDocumentationTransition(root, fromRevision, toRevision string) error {
	changed, err := gitText(root, "diff", "--name-only", fromRevision+".."+toRevision)
	if err != nil || changed == "" {
		return errors.New("inspect Slice 5 finalization transition")
	}
	for _, name := range strings.Fields(changed) {
		if name != "README.md" && name != "README.zh-CN.md" && !strings.HasPrefix(name, "docs/") {
			return fmt.Errorf("Slice 5 finalization transition changed non-documentation file: %s", name)
		}
	}
	return nil
}

func verifyAncestor(root, ancestor, descendant, ancestorName, descendantName string) error {
	if _, err := gitText(root, "merge-base", "--is-ancestor", ancestor, descendant); err != nil {
		return fmt.Errorf("Slice 5 %s revision is not a %s ancestor", ancestorName, descendantName)
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

func verifiedRepositoryRoot(sourceRoot string) (string, error) {
	if !filepath.IsAbs(sourceRoot) {
		return "", errors.New("absolute Slice 5 source root is required")
	}
	root, err := filepath.EvalSymlinks(filepath.Clean(sourceRoot))
	if err != nil {
		return "", errors.New("resolve Slice 5 source root")
	}
	top, commandErr := gitText(root, "rev-parse", "--show-toplevel")
	if commandErr != nil {
		return "", errors.New("Slice 5 source root is not a repository")
	}
	canonicalTop, resolveErr := filepath.EvalSymlinks(top)
	if resolveErr != nil || filepath.Clean(canonicalTop) != filepath.Clean(root) {
		return "", errors.New("Slice 5 source root is not the repository root")
	}
	return root, nil
}

func RawSHA256(document []byte) string {
	digest := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func closureRecordDigest(record ClosureRecord) string {
	record.RecordDigest = ""
	document, _ := json.Marshal(record)
	digest := sha256.Sum256(append([]byte("sandbox-runtime/phase6-slice5/closure/v1\x00"), document...))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func gitText(root string, arguments ...string) (string, error) {
	document, err := gitBytes(root, arguments...)
	return strings.TrimSpace(string(document)), err
}

func gitBytes(root string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", arguments...)
	command.Dir = root
	return command.Output()
}
