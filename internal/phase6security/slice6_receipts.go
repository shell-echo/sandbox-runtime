package phase6security

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	slice6ReceiptIndexProtocol = "sandbox-runtime.phase6-slice6-receipt-index.v1"
	slice6ReceiptProtocol      = "sandbox-runtime.phase6-slice6-run-receipt.v1"
	maxSlice6ReceiptIndexSize  = 2 << 20
	maxSlice6ReceiptSize       = 2 << 20
)

type Slice6ReceiptIndex struct {
	Protocol         string                    `json:"protocol"`
	Version          int                       `json:"version"`
	RunID            string                    `json:"run_id"`
	ProfileDigest    string                    `json:"profile_digest"`
	SourceRevision   string                    `json:"source_revision"`
	SourceTreeDigest string                    `json:"source_tree_digest"`
	Entries          []Slice6ReceiptIndexEntry `json:"entries"`
}

type Slice6ReceiptIndexEntry struct {
	Key            string `json:"key"`
	RawPath        string `json:"raw_path"`
	RawDigest      string `json:"raw_digest"`
	EnvelopePath   string `json:"envelope_path"`
	EnvelopeDigest string `json:"envelope_digest"`
}

// A receipt envelope binds separately retained raw bytes to one logical
// manifest reference. It never contains the final manifest digest, avoiding
// a self-reference cycle. The harness, not this structure, establishes origin.
type Slice6RunReceipt struct {
	Protocol         string `json:"protocol"`
	Version          int    `json:"version"`
	RunID            string `json:"run_id"`
	Key              string `json:"key"`
	Kind             string `json:"kind"`
	Subject          string `json:"subject"`
	ProfileDigest    string `json:"profile_digest"`
	ConfigDigest     string `json:"config_digest"`
	SourceRevision   string `json:"source_revision"`
	SourceTreeDigest string `json:"source_tree_digest"`
	ObservedAt       string `json:"observed_at"`
	Outcome          string `json:"outcome"`
	RawDigest        string `json:"raw_digest"`
	OwnershipRunID   string `json:"ownership_run_id"`
}

// NewSlice6RunID creates one unpredictable identity for a complete live gate.
// It must be called once per run; neither the manifest nor a receipt may
// silently substitute a constant or derive an ID from an old artifact.
func NewSlice6RunID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(random[:]), nil
}

// VerifySlice6EvidenceBundle validates internal run consistency and every
// manifest-referenced runtime receipt. The separate manifest verifier checks
// only structure; neither function proves that a trusted command actually ran
// or that an actor with write access did not rewrite the entire private bundle.
func VerifySlice6EvidenceBundle(manifestPath, receiptRoot string) (Slice6Evidence, error) {
	if !absoluteSlice6ReceiptRoot(receiptRoot) || manifestPath != filepath.Join(receiptRoot, "manifest.json") {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	evidence, err := VerifySlice6EvidenceFile(manifestPath)
	if err != nil {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	indexDocument, err := readPrivateSlice6ReceiptFile(receiptRoot, "receipt-index.json", maxSlice6ReceiptIndexSize)
	if err != nil || digestSlice6Receipt(indexDocument) != evidence.ReceiptIndexDigest {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	var index Slice6ReceiptIndex
	if decodeCanonicalSlice6Receipt(indexDocument, &index) != nil ||
		index.Protocol != slice6ReceiptIndexProtocol || index.Version != 1 ||
		index.RunID != evidence.RunID || index.ProfileDigest != evidence.Profile.ProfileDigest ||
		index.SourceRevision != evidence.RuntimeRevision || index.SourceTreeDigest != evidence.RuntimeTreeDigest {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	expected := expectedSlice6RunReceipts(evidence)
	if len(index.Entries) != len(expected) || len(index.Entries) == 0 {
		return Slice6Evidence{}, ErrInvalidSlice6Evidence
	}
	previous := ""
	manifestObservedAt, _ := time.Parse(time.RFC3339Nano, evidence.ObservedAt)
	paths := make(map[string]bool, len(index.Entries)*2)
	for _, entry := range index.Entries {
		want, ok := expected[entry.Key]
		if !ok || entry.Key <= previous || entry.RawDigest != want ||
			!digestPattern.MatchString(entry.EnvelopeDigest) ||
			!validSlice6ReceiptPath(entry.RawPath) || !validSlice6ReceiptPath(entry.EnvelopePath) ||
			entry.RawPath == entry.EnvelopePath || paths[entry.RawPath] || paths[entry.EnvelopePath] {
			return Slice6Evidence{}, ErrInvalidSlice6Evidence
		}
		previous = entry.Key
		paths[entry.RawPath], paths[entry.EnvelopePath] = true, true
		raw, err := readPrivateSlice6ReceiptFile(receiptRoot, entry.RawPath, maxSlice6ReceiptSize)
		if err != nil || digestSlice6Receipt(raw) != entry.RawDigest {
			return Slice6Evidence{}, ErrInvalidSlice6Evidence
		}
		envelopeDocument, err := readPrivateSlice6ReceiptFile(receiptRoot, entry.EnvelopePath, maxSlice6ReceiptSize)
		if err != nil || digestSlice6Receipt(envelopeDocument) != entry.EnvelopeDigest {
			return Slice6Evidence{}, ErrInvalidSlice6Evidence
		}
		var envelope Slice6RunReceipt
		kind, subject, _ := strings.Cut(entry.Key, "/")
		subject, _, _ = strings.Cut(subject, "/")
		if decodeCanonicalSlice6Receipt(envelopeDocument, &envelope) != nil ||
			envelope.Protocol != slice6ReceiptProtocol || envelope.Version != 1 ||
			envelope.RunID != evidence.RunID || envelope.Key != entry.Key ||
			envelope.Kind != kind || envelope.Subject != subject ||
			envelope.ProfileDigest != evidence.Profile.ProfileDigest ||
			envelope.ConfigDigest != slice6ReceiptConfigDigest(evidence, kind, subject) ||
			envelope.SourceRevision != evidence.RuntimeRevision || envelope.SourceTreeDigest != evidence.RuntimeTreeDigest ||
			!validSlice6Time(envelope.ObservedAt) || envelope.Outcome != slice6ReceiptOutcome(kind) ||
			envelope.RawDigest != entry.RawDigest ||
			(kind == "cleanup" && envelope.OwnershipRunID != evidence.RunID) ||
			(kind != "cleanup" && envelope.OwnershipRunID != "") {
			return Slice6Evidence{}, ErrInvalidSlice6Evidence
		}
		receiptObservedAt, _ := time.Parse(time.RFC3339Nano, envelope.ObservedAt)
		if receiptObservedAt.After(manifestObservedAt) {
			return Slice6Evidence{}, ErrInvalidSlice6Evidence
		}
		if kind == "cleanup" && !validSlice6CleanupReceipt(raw, evidence.RunID, subject) {
			return Slice6Evidence{}, ErrInvalidSlice6Evidence
		}
		if kind == "scenario" && !validSlice6ScenarioReceipt(raw, evidence, subject) {
			return Slice6Evidence{}, ErrInvalidSlice6Evidence
		}
	}
	return evidence, nil
}

// ReadSlice6RunReceipts reopens selected raw files from an already-verified
// bundle. The caller must first call VerifySlice6EvidenceBundle; this reader
// rechecks the index and content hashes against the immutable projection.
func ReadSlice6RunReceipts(receiptRoot string, evidence Slice6Evidence, keys []string) (map[string][]byte, error) {
	if evidence.Validate() != nil || !absoluteSlice6ReceiptRoot(receiptRoot) {
		return nil, ErrInvalidSlice6Evidence
	}
	indexDocument, err := readPrivateSlice6ReceiptFile(receiptRoot, "receipt-index.json", maxSlice6ReceiptIndexSize)
	if err != nil || digestSlice6Receipt(indexDocument) != evidence.ReceiptIndexDigest {
		return nil, ErrInvalidSlice6Evidence
	}
	var index Slice6ReceiptIndex
	if decodeCanonicalSlice6Receipt(indexDocument, &index) != nil ||
		index.Protocol != slice6ReceiptIndexProtocol || index.Version != 1 ||
		index.RunID != evidence.RunID || index.ProfileDigest != evidence.Profile.ProfileDigest ||
		index.SourceRevision != evidence.RuntimeRevision || index.SourceTreeDigest != evidence.RuntimeTreeDigest {
		return nil, ErrInvalidSlice6Evidence
	}
	all := expectedSlice6RunReceipts(evidence)
	if len(keys) == 0 || len(keys) > len(all) {
		return nil, ErrInvalidSlice6Evidence
	}
	wanted := make(map[string]string, len(keys))
	for _, key := range keys {
		digest, ok := all[key]
		if !ok || wanted[key] != "" {
			return nil, ErrInvalidSlice6Evidence
		}
		wanted[key] = digest
	}
	result := make(map[string][]byte, len(wanted))
	for _, entry := range index.Entries {
		want, ok := wanted[entry.Key]
		if !ok {
			continue
		}
		if _, duplicate := result[entry.Key]; duplicate || entry.RawDigest != want {
			return nil, ErrInvalidSlice6Evidence
		}
		raw, err := readPrivateSlice6ReceiptFile(receiptRoot, entry.RawPath, maxSlice6ReceiptSize)
		if err != nil || digestSlice6Receipt(raw) != want {
			return nil, ErrInvalidSlice6Evidence
		}
		result[entry.Key] = raw
	}
	if len(result) != len(wanted) {
		return nil, ErrInvalidSlice6Evidence
	}
	return result, nil
}

// This is the complete set of *run-generated* digests in the current closed
// manifest. Profile, source and candidate-build digests are pre-existing
// immutable inputs, not reissued under each run ID.
func expectedSlice6RunReceipts(e Slice6Evidence) map[string]string {
	result := make(map[string]string)
	add := func(key, digest string) {
		if digest != "" {
			result[key] = digest
		}
	}
	for _, value := range e.Observations.Containers {
		prefix := "container/" + value.DeploymentName + "/"
		add(prefix+"inspect", value.ContainerInspectDigest)
		add(prefix+"image_inspect", value.ImageInspectDigest)
	}
	for _, value := range e.DescriptorReceipts {
		add(value.Kind+"/"+value.Subject+"/descriptor", value.ReceiptDigest)
	}
	for _, value := range e.Observations.Networks {
		add("network/"+value.Name+"/inspect", value.InspectDigest)
	}
	for _, value := range e.Processes {
		add("process/"+value.DeploymentName+"/command", value.CommandDigest)
	}
	for _, value := range e.Components {
		prefix := "component/" + value.Name + "/"
		add(prefix+"process", value.ProcessInspectDigest)
		add(prefix+"socket", value.SocketInspectDigest)
		add(prefix+"session", value.SessionAssociationDigest)
	}
	for _, value := range e.External {
		prefix := "external/" + value.Name + "/"
		add(prefix+"inspect", value.ContainerInspectDigest)
		add(prefix+"image_inspect", value.ImageInspectDigest)
		add(prefix+"tls", value.TLSProbeDigest)
		add(prefix+"reachability", value.ReachabilityProbeDigest)
		if value.PostgresServerAuth != nil {
			proof := value.PostgresServerAuth
			add(prefix+"postgres_mount", proof.ReadOnlyMountInspectDigest)
			add(prefix+"postgres_settings", proof.ServerSettingsProbeDigest)
			add(prefix+"postgres_rules", proof.OrderedParsedRulesDigest)
			add(prefix+"postgres_reload", proof.StartupOrReloadResultDigest)
			add(prefix+"postgres_connections", proof.NewConnectionResultsDigest)
			add(prefix+"postgres_restart", proof.RestartReconcileResultDigest)
		}
	}
	for _, value := range e.Scenarios {
		add("scenario/"+value.Name+"/observation", value.EvidenceDigest)
	}
	for _, value := range e.Cleanup {
		add("cleanup/"+value.Name+"/inventory", value.InspectorDigest)
	}
	return result
}

func slice6ReceiptConfigDigest(e Slice6Evidence, kind, subject string) string {
	deployment := subject
	if kind == "component" {
		for _, component := range e.Profile.Components {
			if component.Name == subject {
				deployment = component.ParentDeployment
				break
			}
		}
	}
	if kind == "container" || kind == "process" || kind == "component" {
		for _, process := range e.Processes {
			if process.DeploymentName == deployment {
				return process.ConfigDigest
			}
		}
	}
	return e.Profile.ProfileDigest
}

func slice6ReceiptOutcome(kind string) string {
	switch kind {
	case "scenario":
		return "passed"
	case "cleanup":
		return "zero_remaining"
	default:
		return "observed"
	}
}

func validSlice6CleanupReceipt(document []byte, runID, name string) bool {
	var value struct {
		RunID         string   `json:"run_id"`
		ResourceClass string   `json:"resource_class"`
		Remaining     int      `json:"remaining"`
		ResourceIDs   []string `json:"resource_ids"`
	}
	return decodeCanonicalSlice6Receipt(document, &value) == nil &&
		value.RunID == runID && value.ResourceClass == name && value.Remaining == 0 &&
		value.ResourceIDs != nil && len(value.ResourceIDs) == 0
}

func validSlice6ScenarioReceipt(document []byte, evidence Slice6Evidence, name string) bool {
	var value struct {
		RunID        string   `json:"run_id"`
		Name         string   `json:"name"`
		Outcome      string   `json:"outcome"`
		Participants []string `json:"participants"`
		Assertions   []string `json:"assertions"`
	}
	if decodeCanonicalSlice6Receipt(document, &value) != nil || value.RunID != evidence.RunID ||
		value.Name != name || value.Outcome != "passed" || len(value.Assertions) == 0 ||
		!sort.StringsAreSorted(value.Assertions) {
		return false
	}
	previous := ""
	for _, assertion := range value.Assertions {
		if assertion <= previous {
			return false
		}
		previous = assertion
	}
	for _, scenario := range evidence.Scenarios {
		if scenario.Name == name {
			return exactStrings(value.Participants, scenario.Participants) &&
				exactStrings(value.Assertions, slice6RequiredAssertions[name])
		}
	}
	return false
}

func digestSlice6Receipt(document []byte) string {
	hash := sha256.Sum256(document)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func decodeCanonicalSlice6Receipt(document []byte, target any) error {
	if len(document) == 0 || rejectDuplicateMembers(document) != nil {
		return ErrInvalidSlice6Evidence
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidSlice6Evidence
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return ErrInvalidSlice6Evidence
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return ErrInvalidSlice6Evidence
	}
	return nil
}

func absoluteSlice6ReceiptRoot(root string) bool {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return false
	}
	info, err := os.Lstat(root)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0o077 == 0
}

func validSlice6ReceiptPath(path string) bool {
	return filepath.IsLocal(path) && filepath.Clean(path) == path && strings.HasPrefix(path, "receipts/") &&
		!strings.Contains(path, "\\") && len(path) <= 240
}

func readPrivateSlice6ReceiptFile(root, path string, maximum int64) ([]byte, error) {
	if !absoluteSlice6ReceiptRoot(root) || (path != "receipt-index.json" && !validSlice6ReceiptPath(path)) {
		return nil, ErrInvalidSlice6Evidence
	}
	fullPath := filepath.Join(root, path)
	directory := filepath.Dir(fullPath)
	for directory != root {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, ErrInvalidSlice6Evidence
		}
		directory = filepath.Dir(directory)
	}
	info, err := os.Lstat(fullPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maximum {
		return nil, ErrInvalidSlice6Evidence
	}
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, ErrInvalidSlice6Evidence
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, ErrInvalidSlice6Evidence
	}
	document, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(document)) != info.Size() || len(document) == 0 || int64(len(document)) > maximum {
		return nil, ErrInvalidSlice6Evidence
	}
	return document, nil
}

func sortedSlice6RunReceiptKeys(e Slice6Evidence) []string {
	expected := expectedSlice6RunReceipts(e)
	keys := make([]string, 0, len(expected))
	for key := range expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
