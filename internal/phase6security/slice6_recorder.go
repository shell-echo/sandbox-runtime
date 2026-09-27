package phase6security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Slice6ReceiptRecorder durably collects the bounded, non-secret observations
// made by one trusted gate run. It does not execute probes or turn fabricated
// input into execution provenance. The caller must keep bootstrap secrets out
// of retained raw observations and supply the actual captured bytes.
type Slice6ReceiptRecorder struct {
	mu               sync.Mutex
	root             string
	runID            string
	profileDigest    string
	sourceRevision   string
	sourceTreeDigest string
	entries          map[string]Slice6ReceiptIndexEntry
	finalized        bool
}

func NewSlice6ReceiptRecorder(root string, e Slice6Evidence) (*Slice6ReceiptRecorder, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" ||
		!slice6RunIDPattern.MatchString(e.RunID) || e.ID != Slice6EvidenceID || e.Version != Slice6EvidenceVersion ||
		e.Profile.Validate() != nil || !slice6RevisionPattern.MatchString(e.RuntimeRevision) ||
		!digestPattern.MatchString(e.RuntimeTreeDigest) {
		return nil, ErrInvalidSlice6Evidence
	}
	for _, path := range []string{root, filepath.Join(root, "receipts"),
		filepath.Join(root, "receipts", "raw"), filepath.Join(root, "receipts", "envelopes")} {
		if err := os.Mkdir(path, 0o700); err != nil {
			return nil, ErrInvalidSlice6Evidence
		}
	}
	return &Slice6ReceiptRecorder{root: root, runID: e.RunID,
		profileDigest: e.Profile.ProfileDigest, sourceRevision: e.RuntimeRevision,
		sourceTreeDigest: e.RuntimeTreeDigest, entries: make(map[string]Slice6ReceiptIndexEntry)}, nil
}

func (r *Slice6ReceiptRecorder) bound(e Slice6Evidence) bool {
	return r != nil && e.ID == Slice6EvidenceID && e.Version == Slice6EvidenceVersion &&
		e.RunID == r.runID && e.Profile.ProfileDigest == r.profileDigest &&
		e.RuntimeRevision == r.sourceRevision && e.RuntimeTreeDigest == r.sourceTreeDigest
}

// Record requires the caller to put the digest of its freshly captured raw
// bytes into the corresponding manifest projection first. It writes a unique
// raw file and companion envelope using the collector's one run identity.
func (r *Slice6ReceiptRecorder) Record(e Slice6Evidence, key string, raw []byte, observedAt time.Time) (string, error) {
	if r == nil || len(raw) == 0 || len(raw) > maxSlice6ReceiptSize ||
		observedAt.IsZero() || observedAt.Location() != time.UTC {
		return "", ErrInvalidSlice6Evidence
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalized || !r.bound(e) || r.entries[key].Key != "" {
		return "", ErrInvalidSlice6Evidence
	}
	rawDigest := digestSlice6Receipt(raw)
	if expectedSlice6RunReceipts(e)[key] != rawDigest {
		return "", ErrInvalidSlice6Evidence
	}
	kind, subject, hasSubject := strings.Cut(key, "/")
	if !hasSubject {
		return "", ErrInvalidSlice6Evidence
	}
	subject, _, hasField := strings.Cut(subject, "/")
	if !hasField || subject == "" ||
		(kind == "scenario" && !validSlice6ScenarioReceipt(raw, e, subject)) ||
		(kind == "cleanup" && !validSlice6CleanupReceipt(raw, e.RunID, subject)) {
		return "", ErrInvalidSlice6Evidence
	}
	token := sha256.Sum256([]byte(key))
	name := hex.EncodeToString(token[:]) + ".json"
	rawPath := "receipts/raw/" + name
	envelopePath := "receipts/envelopes/" + name
	envelope := Slice6RunReceipt{Protocol: slice6ReceiptProtocol, Version: 1, RunID: r.runID,
		Key: key, Kind: kind, Subject: subject, ProfileDigest: r.profileDigest,
		ConfigDigest: slice6ReceiptConfigDigest(e, kind, subject), SourceRevision: r.sourceRevision,
		SourceTreeDigest: r.sourceTreeDigest, ObservedAt: observedAt.Format(time.RFC3339Nano),
		Outcome: slice6ReceiptOutcome(kind), RawDigest: rawDigest}
	if kind == "cleanup" {
		envelope.OwnershipRunID = r.runID
	}
	envelopeDocument, err := json.Marshal(envelope)
	if err != nil || !validSlice6ReceiptPath(rawPath) || !validSlice6ReceiptPath(envelopePath) ||
		writeNewSlice6ReceiptFile(filepath.Join(r.root, rawPath), raw) != nil ||
		writeNewSlice6ReceiptFile(filepath.Join(r.root, envelopePath), envelopeDocument) != nil {
		return "", ErrInvalidSlice6Evidence
	}
	r.entries[key] = Slice6ReceiptIndexEntry{Key: key, RawPath: rawPath, RawDigest: rawDigest,
		EnvelopePath: envelopePath, EnvelopeDigest: digestSlice6Receipt(envelopeDocument)}
	return rawDigest, nil
}

// Finalize refuses incomplete or duplicate receipt sets before writing the
// index and manifest, then independently reopens the complete private bundle.
// A passing return is internal consistency only, not trusted execution proof.
func (r *Slice6ReceiptRecorder) Finalize(e *Slice6Evidence) error {
	if r == nil || e == nil {
		return ErrInvalidSlice6Evidence
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.finalized || !r.bound(*e) {
		return ErrInvalidSlice6Evidence
	}
	expected := expectedSlice6RunReceipts(*e)
	if len(expected) == 0 || len(expected) != len(r.entries) {
		return ErrInvalidSlice6Evidence
	}
	keys := make([]string, 0, len(r.entries))
	for key, entry := range r.entries {
		if expected[key] != entry.RawDigest {
			return ErrInvalidSlice6Evidence
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	index := Slice6ReceiptIndex{Protocol: slice6ReceiptIndexProtocol, Version: 1,
		RunID: r.runID, ProfileDigest: r.profileDigest, SourceRevision: r.sourceRevision,
		SourceTreeDigest: r.sourceTreeDigest}
	for _, key := range keys {
		index.Entries = append(index.Entries, r.entries[key])
	}
	indexDocument, err := json.Marshal(index)
	if err != nil || len(indexDocument) > maxSlice6ReceiptIndexSize {
		return ErrInvalidSlice6Evidence
	}
	candidate := *e
	candidate.ReceiptIndexDigest = digestSlice6Receipt(indexDocument)
	candidate.ManifestDigest = slice6EvidenceDigest(candidate)
	if candidate.Validate() != nil {
		return ErrInvalidSlice6Evidence
	}
	manifestDocument, err := json.Marshal(candidate)
	if err != nil || len(manifestDocument) > maxSlice6EvidenceSize {
		return ErrInvalidSlice6Evidence
	}
	if writeNewSlice6ReceiptFile(filepath.Join(r.root, "receipt-index.json"), indexDocument) != nil ||
		writeNewSlice6ReceiptFile(filepath.Join(r.root, "manifest.json"), manifestDocument) != nil {
		return ErrInvalidSlice6Evidence
	}
	if _, err := VerifySlice6EvidenceBundle(filepath.Join(r.root, "manifest.json"), r.root); err != nil {
		return ErrInvalidSlice6Evidence
	}
	r.finalized = true
	*e = candidate
	return nil
}

func writeNewSlice6ReceiptFile(path string, document []byte) error {
	if len(document) == 0 || len(document) > maxSlice6EvidenceSize {
		return ErrInvalidSlice6Evidence
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalidSlice6Evidence
	}
	written, writeErr := file.Write(document)
	if written != len(document) && writeErr == nil {
		writeErr = ErrInvalidSlice6Evidence
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if errors.Join(writeErr, syncErr, closeErr) != nil {
		return ErrInvalidSlice6Evidence
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrInvalidSlice6Evidence
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrInvalidSlice6Evidence
	}
	return nil
}
