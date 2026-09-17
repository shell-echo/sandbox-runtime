package qualificationarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

var (
	digestPattern           = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	providerRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	externalRevisionPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	idPattern               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type TrustedInputSubject struct {
	InputID       string         `json:"input_id"`
	Source        string         `json:"source"`
	SubjectDigest string         `json:"subject_digest"`
	Statement     map[string]any `json:"statement"`
}

type EnvelopeInput struct {
	ProfileID        string
	ProfileVersion   string
	ProfileDigest    string
	ProviderRevision string
	ExternalRevision string
	CheckpointPath   string
	CheckpointDigest string
	Archive          Result
	Evidence         qualificationreport.Result
	TrustedInputs    []TrustedInputSubject
	CompletedAt      time.Time
}

type Envelope struct {
	FormatVersion int    `json:"format_version"`
	EnvelopeType  string `json:"envelope_type"`
	Profile       struct {
		ID      string `json:"profile_id"`
		Version string `json:"profile_version"`
		Digest  string `json:"profile_digest"`
	} `json:"profile"`
	ProviderSourceRevision string `json:"provider_source_revision"`
	ExternalSourceRevision string `json:"external_source_revision"`
	Checkpoint             struct {
		File   string `json:"file"`
		Digest string `json:"digest"`
	} `json:"execution_checkpoint"`
	EvidenceArchive struct {
		File   string `json:"file"`
		Digest string `json:"digest"`
		Bytes  int64  `json:"bytes"`
		Files  int    `json:"files"`
	} `json:"evidence_archive"`
	Validation struct {
		ReportID               string `json:"report_id"`
		ReportDigest           string `json:"report_digest"`
		PayloadInventoryDigest string `json:"payload_inventory_digest"`
		ReceiptFile            string `json:"receipt_file"`
		RunOutcome             string `json:"run_outcome"`
		ValidationOutcome      string `json:"validation_outcome"`
		FileCount              int    `json:"file_count"`
		TotalBytes             int64  `json:"total_bytes"`
	} `json:"validation"`
	TrustedInputs []TrustedInputSubject `json:"trusted_input_subjects"`
	Disposition   struct {
		Outcome   string   `json:"outcome"`
		Scope     string   `json:"scope"`
		NonClaims []string `json:"non_claims"`
	} `json:"final_disposition"`
	CompletedAt string `json:"completed_at"`
}

type BundleResult struct {
	EnvelopeDigest string
	ArchiveDigest  string
	Evidence       qualificationreport.Result
}

var nonClaims = []string{
	"aggregate-conformance",
	"deployment-readiness",
	"high-availability",
	"hostile-multi-tenant-isolation",
	"multi-controller-reliability",
	"production-readiness",
}

func WriteEnvelope(destination string, input EnvelopeInput) (string, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination ||
		input.ProfileID == "" || input.ProfileVersion == "" || !digestPattern.MatchString(input.ProfileDigest) ||
		!providerRevisionPattern.MatchString(input.ProviderRevision) || !externalRevisionPattern.MatchString(input.ExternalRevision) ||
		!digestPattern.MatchString(input.CheckpointDigest) || !digestPattern.MatchString(input.Archive.Digest) ||
		input.Archive.Files != len(evidenceFiles) || input.Archive.Bytes <= 0 || input.Evidence.RunOutcome != "passed" ||
		filepath.Base(input.CheckpointPath) != "execution-checkpoint.json" || filepath.Base(input.Archive.Path) != "qualification-evidence.tar" ||
		!idPattern.MatchString(input.Evidence.ReportID) || !digestPattern.MatchString(input.Evidence.ReportDigest) ||
		!digestPattern.MatchString(input.Evidence.PayloadInventory) || input.Evidence.ReceiptFile != "receipt.json" ||
		input.Evidence.ValidationOutcome != "accepted" || input.Evidence.FileCount != len(evidenceFiles) || input.Evidence.TotalBytes <= 0 || input.CompletedAt.IsZero() {
		return "", ErrArchive
	}
	envelope := Envelope{
		FormatVersion: 1, EnvelopeType: "sandbox-runtime-external-caller-qualification-result-v1",
		ProviderSourceRevision: input.ProviderRevision, ExternalSourceRevision: input.ExternalRevision,
		TrustedInputs: cloneSubjects(input.TrustedInputs), CompletedAt: input.CompletedAt.UTC().Format(time.RFC3339Nano),
	}
	envelope.Profile.ID, envelope.Profile.Version, envelope.Profile.Digest = input.ProfileID, input.ProfileVersion, input.ProfileDigest
	envelope.Checkpoint.File, envelope.Checkpoint.Digest = filepath.Base(input.CheckpointPath), input.CheckpointDigest
	envelope.EvidenceArchive.File, envelope.EvidenceArchive.Digest = filepath.Base(input.Archive.Path), input.Archive.Digest
	envelope.EvidenceArchive.Bytes, envelope.EvidenceArchive.Files = input.Archive.Bytes, input.Archive.Files
	envelope.Validation.ReportID, envelope.Validation.ReportDigest = input.Evidence.ReportID, input.Evidence.ReportDigest
	envelope.Validation.PayloadInventoryDigest, envelope.Validation.ReceiptFile = input.Evidence.PayloadInventory, input.Evidence.ReceiptFile
	envelope.Validation.RunOutcome, envelope.Validation.ValidationOutcome = input.Evidence.RunOutcome, input.Evidence.ValidationOutcome
	envelope.Validation.FileCount, envelope.Validation.TotalBytes = input.Evidence.FileCount, input.Evidence.TotalBytes
	envelope.Disposition.Outcome = "qualified"
	envelope.Disposition.Scope = "sandbox-runtime-external-caller-coding-shell-v1"
	envelope.Disposition.NonClaims = append([]string(nil), nonClaims...)
	if !validTrustedInputs(envelope.TrustedInputs) || !trustedInputsBindEnvelope(envelope) {
		return "", ErrArchive
	}
	document, err := json.Marshal(envelope)
	if err != nil {
		return "", ErrArchive
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		return "", ErrArchive
	}
	canonical = append(canonical, '\n')
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", ErrArchive
	}
	written, writeErr := file.Write(canonical)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(canonical) {
		_ = os.Remove(destination)
		return "", ErrArchive
	}
	return rawDigest(canonical), nil
}

func VerifyBundle(ctx context.Context, sourceRoot, checkpointPath, archivePath, envelopePath string) (BundleResult, error) {
	if ctx == nil {
		return BundleResult{}, ErrArchive
	}
	for _, path := range []string{sourceRoot, checkpointPath, archivePath, envelopePath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return BundleResult{}, ErrArchive
		}
	}
	document, err := readBoundedFile(envelopePath, 2<<20)
	if err != nil || len(document) < 2 || document[len(document)-1] != '\n' {
		return BundleResult{}, ErrArchive
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return BundleResult{}, ErrArchive
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return BundleResult{}, ErrArchive
	}
	normalized, err := json.Marshal(envelope)
	if err != nil {
		return BundleResult{}, ErrArchive
	}
	canonical, err := jcs.Transform(normalized)
	if err != nil || !bytes.Equal(append(canonical, '\n'), document) || !validEnvelope(envelope) {
		return BundleResult{}, ErrArchive
	}
	checkpoint, err := readBoundedFile(checkpointPath, 2<<20)
	if err != nil || filepath.Base(checkpointPath) != envelope.Checkpoint.File || rawDigest(checkpoint) != envelope.Checkpoint.Digest {
		return BundleResult{}, ErrArchive
	}
	archive, err := readBoundedFile(archivePath, MaxArchiveBytes)
	if err != nil || filepath.Base(archivePath) != envelope.EvidenceArchive.File || int64(len(archive)) != envelope.EvidenceArchive.Bytes || rawDigest(archive) != envelope.EvidenceArchive.Digest {
		return BundleResult{}, ErrArchive
	}
	extracted, err := os.MkdirTemp("", "sandbox-runtime-qualification-archive-")
	if err != nil {
		return BundleResult{}, ErrArchive
	}
	if err := os.Remove(extracted); err != nil {
		return BundleResult{}, ErrArchive
	}
	defer os.RemoveAll(extracted)
	archiveResult, err := Extract(ctx, archivePath, extracted)
	if err != nil || archiveResult.Digest != envelope.EvidenceArchive.Digest {
		return BundleResult{}, ErrArchive
	}
	canonicalRoot, err := os.MkdirTemp("", "sandbox-runtime-qualification-canonical-")
	if err != nil {
		return BundleResult{}, ErrArchive
	}
	defer os.RemoveAll(canonicalRoot)
	canonicalArchive, err := Create(ctx, extracted, filepath.Join(canonicalRoot, "qualification-evidence.tar"))
	if err != nil || canonicalArchive.Digest != archiveResult.Digest || canonicalArchive.Bytes != archiveResult.Bytes {
		return BundleResult{}, ErrArchive
	}
	evidence, err := qualificationreport.VerifyRetained(ctx, extracted, sourceRoot)
	if err != nil || !matchesEvidence(envelope, evidence) {
		return BundleResult{}, ErrArchive
	}
	profile, err := qualificationprofile.VerifyCodingShellV1(ctx, sourceRoot)
	if err != nil || envelope.Profile.ID != profile.ProfileID || envelope.Profile.Version != profile.ProfileVersion || envelope.Profile.Digest != profile.ProfileDigest || !trustedInputsBindEnvelope(envelope) {
		return BundleResult{}, ErrArchive
	}
	return BundleResult{EnvelopeDigest: rawDigest(document), ArchiveDigest: archiveResult.Digest, Evidence: evidence}, nil
}

func validEnvelope(value Envelope) bool {
	if value.FormatVersion != 1 || value.EnvelopeType != "sandbox-runtime-external-caller-qualification-result-v1" ||
		value.Profile.ID == "" || value.Profile.Version == "" || !digestPattern.MatchString(value.Profile.Digest) ||
		!providerRevisionPattern.MatchString(value.ProviderSourceRevision) || !externalRevisionPattern.MatchString(value.ExternalSourceRevision) ||
		value.Checkpoint.File != "execution-checkpoint.json" || !digestPattern.MatchString(value.Checkpoint.Digest) ||
		value.EvidenceArchive.File != "qualification-evidence.tar" || !digestPattern.MatchString(value.EvidenceArchive.Digest) ||
		value.EvidenceArchive.Bytes <= 0 || value.EvidenceArchive.Files != len(evidenceFiles) ||
		value.Validation.RunOutcome != "passed" || value.Validation.ValidationOutcome != "accepted" ||
		!idPattern.MatchString(value.Validation.ReportID) || !digestPattern.MatchString(value.Validation.ReportDigest) ||
		!digestPattern.MatchString(value.Validation.PayloadInventoryDigest) || value.Validation.ReceiptFile != "receipt.json" ||
		value.Validation.FileCount != len(evidenceFiles) || value.Validation.TotalBytes <= 0 ||
		value.Disposition.Outcome != "qualified" || value.Disposition.Scope != "sandbox-runtime-external-caller-coding-shell-v1" ||
		!equalStrings(value.Disposition.NonClaims, nonClaims) || !validTrustedInputs(value.TrustedInputs) {
		return false
	}
	completedAt, err := time.Parse(time.RFC3339Nano, value.CompletedAt)
	return err == nil && completedAt.Location() == time.UTC && value.CompletedAt[len(value.CompletedAt)-1] == 'Z'
}

func trustedInputsBindEnvelope(value Envelope) bool {
	if len(value.TrustedInputs) != 5 {
		return false
	}
	externalOwnership := value.TrustedInputs[0].Statement
	sourceHosting := value.TrustedInputs[1].Statement
	operatingSystem := value.TrustedInputs[3].Statement
	return externalOwnership["source_revision"] == value.ExternalSourceRevision &&
		sourceHosting["source_revision"] == value.ExternalSourceRevision &&
		operatingSystem["provider_source_revision"] == value.ProviderSourceRevision
}

func validTrustedInputs(values []TrustedInputSubject) bool {
	wantIDs := []string{"external-caller-ownership", "source-hosting", "build-system", "operating-system", "network-path"}
	wantSources := []string{"external_caller_owner", "external_caller_owner", "external_caller_owner", "qualification_operator", "qualification_operator"}
	if len(values) != len(wantIDs) {
		return false
	}
	for index, value := range values {
		if value.InputID != wantIDs[index] || value.Source != wantSources[index] || len(value.Statement) == 0 {
			return false
		}
		document, err := json.Marshal(value.Statement)
		if err != nil {
			return false
		}
		canonical, err := jcs.Transform(document)
		if err != nil || rawDigest(canonical) != value.SubjectDigest {
			return false
		}
	}
	return true
}

func matchesEvidence(envelope Envelope, evidence qualificationreport.Result) bool {
	return envelope.Validation.ReportID == evidence.ReportID && envelope.Validation.ReportDigest == evidence.ReportDigest &&
		envelope.Validation.PayloadInventoryDigest == evidence.PayloadInventory && envelope.Validation.ReceiptFile == evidence.ReceiptFile &&
		envelope.Validation.RunOutcome == evidence.RunOutcome && envelope.Validation.ValidationOutcome == evidence.ValidationOutcome &&
		envelope.Validation.FileCount == evidence.FileCount && envelope.Validation.TotalBytes == evidence.TotalBytes
}

func cloneSubjects(values []TrustedInputSubject) []TrustedInputSubject {
	document, _ := json.Marshal(values)
	var result []TrustedInputSubject
	_ = json.Unmarshal(document, &result)
	return result
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return nil, ErrArchive
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrArchive
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrArchive
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, ErrArchive
	}
	return contents, nil
}

func rawDigest(document []byte) string {
	sum := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(sum[:])
}
