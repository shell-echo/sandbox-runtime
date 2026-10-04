//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/desktopcandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6guestreceipt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6profilebuilder"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6terminalcleanup"
	"golang.org/x/sys/unix"
)

const slice6GuestReceiptEvidenceRootEnv = "SANDBOX_RUNTIME_PHASE6_SLICE6_RUN_EVIDENCE_ROOT"

var errSlice6ReceiptEvidence = errors.New("private Guest receipt evidence unavailable")
var errSlice6ReceiptPublishUncertain = errors.New("private Guest receipt binding publication rollback unconfirmed")

type slice6ReceiptFailureStage string

const (
	slice6ReceiptInputStage           slice6ReceiptFailureStage = "input"
	slice6ReceiptSourceReopenStage    slice6ReceiptFailureStage = "source_reopen"
	slice6ReceiptArtifactMapStage     slice6ReceiptFailureStage = "artifact_map"
	slice6ReceiptRawBindingStage      slice6ReceiptFailureStage = "raw_binding"
	slice6ReceiptMutationStage        slice6ReceiptFailureStage = "mutation"
	slice6ReceiptPublishStage         slice6ReceiptFailureStage = "publish"
	slice6ReceiptIndependentReadStage slice6ReceiptFailureStage = "independent_read"
)

// Only fixed, non-sensitive stages may leave the private evidence closer.
func slice6ReceiptStageError(stage slice6ReceiptFailureStage) error {
	switch stage {
	case slice6ReceiptInputStage, slice6ReceiptSourceReopenStage, slice6ReceiptArtifactMapStage,
		slice6ReceiptRawBindingStage, slice6ReceiptMutationStage, slice6ReceiptPublishStage,
		slice6ReceiptIndependentReadStage:
		return fmt.Errorf("%w: stage=%s", errSlice6ReceiptEvidence, stage)
	default:
		return errSlice6ReceiptEvidence
	}
}

// These are partial, E-owned component observations. They are deliberately
// separate from the closed formal Slice 6 one-run evidence recorder.
type slice6ReceiptEvidenceRoot struct {
	path string
	fd   int
	stat unix.Stat_t
}

type slice6ReceiptRawBinding struct {
	Role             string `json:"role"`
	File             string `json:"file"`
	SHA256           string `json:"sha256"`
	Bytes            int    `json:"bytes"`
	ProfileDigest    string `json:"profile_digest"`
	ConfigDigest     string `json:"config_digest"`
	SelectedImage    string `json:"selected_image"`
	ActualImage      string `json:"actual_image"`
	ContainerID      string `json:"container_id"`
	DockerExitCode   int    `json:"docker_exit_code"`
	CaptureStartUTC  string `json:"capture_start_utc"`
	CaptureFinishUTC string `json:"capture_finish_utc"`
}

type slice6ReceiptEvidenceBinding struct {
	Protocol              string                  `json:"protocol"`
	Disposition           string                  `json:"disposition"`
	RunID                 string                  `json:"run_id"`
	ERevision             string                  `json:"e_revision"`
	ETree                 string                  `json:"e_tree"`
	RRevision             string                  `json:"r_revision"`
	RTree                 string                  `json:"r_tree"`
	FRevision             string                  `json:"f_revision"`
	FTree                 string                  `json:"f_tree"`
	ProfileDigest         string                  `json:"profile_digest"`
	MutationReceiptSHA256 string                  `json:"mutation_receipt_sha256"`
	MutationVerifiedUTC   string                  `json:"mutation_verified_utc"`
	MutationGeneration    int64                   `json:"mutation_generation"`
	ProductArtifact       slice6ReceiptArtifact   `json:"product_artifact"`
	GuestArtifact         slice6ReceiptArtifact   `json:"guest_artifact"`
	Product               slice6ReceiptRawBinding `json:"product"`
	Guest                 slice6ReceiptRawBinding `json:"guest"`
}

type slice6ReceiptArtifact struct {
	ManifestDigest         string `json:"manifest_digest"`
	ArchiveDigest          string `json:"archive_digest"`
	SelectedManifestDigest string `json:"selected_manifest_digest"`
	ConfigDigest           string `json:"config_digest"`
	ImageID                string `json:"image_id"`
}

type slice6ReceiptEvidenceRun struct {
	mu         sync.Mutex
	root       *slice6ReceiptEvidenceRoot
	fd         int
	stat       unix.Stat_t
	id         string
	files      map[string]unix.Stat_t
	bindings   map[string]slice6ReceiptRawBinding
	syncFile   func(*os.File) error
	syncDir    func(int) error
	linkFile   func(int, string, int, string, int) error
	unlinkFile func(int, string, int) error
	afterWrite func(string) error
	complete   bool
	closed     bool
}

func slice6SameInode(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func slice6PrivateDir(s unix.Stat_t) bool {
	return s.Mode&unix.S_IFMT == unix.S_IFDIR && s.Mode&0o7777 == 0o700 && s.Uid == uint32(os.Getuid())
}

func slice6OpenReceiptEvidenceRoot(path string) (*slice6ReceiptEvidenceRoot, error) {
	if !absoluteCleanSlice6Path(path) {
		return nil, errSlice6ReceiptEvidence
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, errSlice6ReceiptEvidence
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errSlice6ReceiptEvidence
	}
	var observed unix.Stat_t
	if unix.Fstat(fd, &observed) != nil || !slice6PrivateDir(observed) {
		unix.Close(fd)
		return nil, errSlice6ReceiptEvidence
	}
	return &slice6ReceiptEvidenceRoot{path: path, fd: fd, stat: observed}, nil
}

func (root *slice6ReceiptEvidenceRoot) check() error {
	if root == nil || root.fd < 0 {
		return errSlice6ReceiptEvidence
	}
	var held, named unix.Stat_t
	if unix.Fstat(root.fd, &held) != nil || unix.Lstat(root.path, &named) != nil ||
		!slice6PrivateDir(held) || !slice6PrivateDir(named) ||
		!slice6SameInode(held, root.stat) || !slice6SameInode(named, root.stat) {
		return errSlice6ReceiptEvidence
	}
	return nil
}

func (root *slice6ReceiptEvidenceRoot) close() error {
	if root == nil || root.fd < 0 {
		return errSlice6ReceiptEvidence
	}
	err := unix.Close(root.fd)
	root.fd = -1
	return err
}

func (root *slice6ReceiptEvidenceRoot) newRun(id string) (*slice6ReceiptEvidenceRun, error) {
	if len(id) != 32 || !lowerHexSlice6(id) || root.check() != nil ||
		unix.Mkdirat(root.fd, id, 0o700) != nil {
		return nil, errSlice6ReceiptEvidence
	}
	fd, err := unix.Openat(root.fd, id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errSlice6ReceiptEvidence
	}
	var observed unix.Stat_t
	if unix.Fstat(fd, &observed) != nil || !slice6PrivateDir(observed) || unix.Fsync(root.fd) != nil {
		unix.Close(fd)
		return nil, errSlice6ReceiptEvidence
	}
	return &slice6ReceiptEvidenceRun{root: root, fd: fd, stat: observed, id: id,
		files: make(map[string]unix.Stat_t), bindings: make(map[string]slice6ReceiptRawBinding),
		syncFile: (*os.File).Sync, syncDir: unix.Fsync, linkFile: unix.Linkat,
		unlinkFile: unix.Unlinkat}, nil
}

func (root *slice6ReceiptEvidenceRoot) openRun(id string) (*slice6ReceiptEvidenceRun, error) {
	if len(id) != 32 || !lowerHexSlice6(id) || root.check() != nil {
		return nil, errSlice6ReceiptEvidence
	}
	fd, err := unix.Openat(root.fd, id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errSlice6ReceiptEvidence
	}
	var observed unix.Stat_t
	if unix.Fstat(fd, &observed) != nil || !slice6PrivateDir(observed) {
		unix.Close(fd)
		return nil, errSlice6ReceiptEvidence
	}
	run := &slice6ReceiptEvidenceRun{root: root, fd: fd, stat: observed, id: id,
		files: make(map[string]unix.Stat_t), bindings: make(map[string]slice6ReceiptRawBinding),
		syncFile: (*os.File).Sync, syncDir: unix.Fsync, linkFile: unix.Linkat,
		unlinkFile: unix.Unlinkat}
	if run.check() != nil {
		unix.Close(fd)
		return nil, errSlice6ReceiptEvidence
	}
	return run, nil
}

func (run *slice6ReceiptEvidenceRun) check() error {
	if run == nil || run.closed || run.fd < 0 || run.root.check() != nil {
		return errSlice6ReceiptEvidence
	}
	var held, named unix.Stat_t
	if unix.Fstat(run.fd, &held) != nil ||
		unix.Fstatat(run.root.fd, run.id, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!slice6PrivateDir(held) || !slice6PrivateDir(named) ||
		!slice6SameInode(held, run.stat) || !slice6SameInode(named, run.stat) {
		return errSlice6ReceiptEvidence
	}
	return nil
}

func slice6ReceiptRawName(role string) string {
	switch role {
	case "product":
		return "product-pid1.stdout"
	case "guest":
		return "guest-pid1.stdout"
	default:
		return ""
	}
}

func (run *slice6ReceiptEvidenceRun) createFile(name string) (*os.File, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.check() != nil || (name != "product-pid1.stdout" && name != "guest-pid1.stdout" &&
		name != "binding.pending" && name != "incomplete.json" && name != "mutation-receipt.json") {
		return nil, errSlice6ReceiptEvidence
	}
	return run.createPrivateFileLocked(name)
}

// The v2 four-process collector has a separate, closed filename set. The
// historical v1 createFile and independent verifier keep their exact names.
func (run *slice6ReceiptEvidenceRun) createV2RawFile(name string) (*os.File, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.check() != nil || (name != "product-a-pid1.stdout" && name != "guest-a-pid1.stdout" &&
		name != "product-b-pid1.stdout" && name != "guest-b-pid1.stdout") {
		return nil, errSlice6ReceiptEvidence
	}
	return run.createPrivateFileLocked(name)
}

func (run *slice6ReceiptEvidenceRun) createPrivateFileLocked(name string) (*os.File, error) {
	fd, err := unix.Openat(run.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, errSlice6ReceiptEvidence
	}
	var observed unix.Stat_t
	if unix.Fstat(fd, &observed) != nil || observed.Mode&unix.S_IFMT != unix.S_IFREG ||
		observed.Mode&0o7777 != 0o600 || observed.Uid != uint32(os.Getuid()) {
		unix.Close(fd)
		return nil, errSlice6ReceiptEvidence
	}
	run.files[name] = observed
	return os.NewFile(uintptr(fd), name), nil
}

func (run *slice6ReceiptEvidenceRun) readFile(name string, limit int) ([]byte, error) {
	run.mu.Lock()
	defer run.mu.Unlock()
	maximum := 128 << 10
	if name == slice6TerminalV3EvidenceFile {
		maximum = phase6terminalcleanup.MaxEvidenceV3Bytes
	}
	if run.check() != nil || limit < 1 || limit > maximum {
		return nil, errSlice6ReceiptEvidence
	}
	wanted, ok := run.files[name]
	if !ok {
		return nil, errSlice6ReceiptEvidence
	}
	var named unix.Stat_t
	if unix.Fstatat(run.fd, name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!slice6SameInode(named, wanted) || named.Mode&unix.S_IFMT != unix.S_IFREG || named.Mode&0o7777 != 0o600 {
		return nil, errSlice6ReceiptEvidence
	}
	fd, err := unix.Openat(run.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errSlice6ReceiptEvidence
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > int64(limit) {
		_ = file.Close()
		return nil, errSlice6ReceiptEvidence
	}
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || !slice6SameInode(opened, wanted) ||
		opened.Mode&unix.S_IFMT != unix.S_IFREG || opened.Mode&0o7777 != 0o600 ||
		opened.Uid != uint32(os.Getuid()) {
		_ = file.Close()
		return nil, errSlice6ReceiptEvidence
	}
	data := make([]byte, info.Size())
	n, readErr := file.ReadAt(data, 0)
	closeErr := file.Close()
	if n != len(data) || (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil {
		return nil, errSlice6ReceiptEvidence
	}
	return data, nil
}

func (run *slice6ReceiptEvidenceRun) writeDocument(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 8192 {
		return errSlice6ReceiptEvidence
	}
	data = append(data, '\n')
	file, err := run.createFile(name)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(data)
	syncErr := run.syncFile(file)
	closeErr := file.Close()
	if writeErr != nil || n != len(data) || syncErr != nil || closeErr != nil || run.check() != nil ||
		run.syncDir(run.fd) != nil {
		return errSlice6ReceiptEvidence
	}
	if run.afterWrite != nil && run.afterWrite(name) != nil {
		return errSlice6ReceiptEvidence
	}
	read, err := run.readFile(name, 8192)
	if err != nil || string(read) != string(data) {
		return errSlice6ReceiptEvidence
	}
	return nil
}

func (run *slice6ReceiptEvidenceRun) recordRaw(binding slice6ReceiptRawBinding) error {
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.check() != nil || slice6ReceiptRawName(binding.Role) != binding.File ||
		binding.ContainerID == "" || len(binding.SHA256) != 71 ||
		!guestRevokeFixtureDigestGate(binding.SHA256) || run.bindings[binding.Role].Role != "" {
		return errSlice6ReceiptEvidence
	}
	run.bindings[binding.Role] = binding
	return nil
}

// A failed publish removes only files this run created and whose inode still
// matches the pinned pending inode. A replacement or failed unlink/sync is an
// uncertain failure, never a reason to remove another file or accept a run.
func (run *slice6ReceiptEvidenceRun) rollbackBinding() error {
	if run.check() != nil {
		return errSlice6ReceiptPublishUncertain
	}
	uncertain := false
	for _, name := range []string{"binding.json", "binding.pending"} {
		wanted, ok := run.files[name]
		if !ok {
			continue
		}
		var observed unix.Stat_t
		err := unix.Fstatat(run.fd, name, &observed, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			delete(run.files, name)
			continue
		}
		if err != nil || !slice6SameInode(wanted, observed) ||
			observed.Mode&unix.S_IFMT != unix.S_IFREG || observed.Uid != uint32(os.Getuid()) ||
			run.unlinkFile(run.fd, name, 0) != nil {
			uncertain = true
			continue
		}
		delete(run.files, name)
	}
	if unix.Fsync(run.fd) != nil {
		uncertain = true
	}
	if uncertain {
		return errSlice6ReceiptPublishUncertain
	}
	return nil
}

func (run *slice6ReceiptEvidenceRun) publishBinding(expected slice6ReceiptExpectedIdentity) error {
	if run.check() != nil {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	pending, ok := run.files["binding.pending"]
	if !ok {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	var named unix.Stat_t
	if unix.Fstatat(run.fd, "binding.pending", &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!slice6SameInode(named, pending) {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	if err := unix.Fstatat(run.fd, "binding.json", &named, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	// Linkat is atomic and refuses an existing name on Darwin/Linux. The
	// pending file remains until the new directory entry is synced.
	run.files["binding.json"] = pending
	if run.linkFile(run.fd, "binding.pending", run.fd, "binding.json", 0) != nil ||
		run.syncDir(run.fd) != nil {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	if run.unlinkFile(run.fd, "binding.pending", 0) != nil {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	delete(run.files, "binding.pending")
	if run.syncDir(run.fd) != nil {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	if slice6VerifyPersistentGuestEvidence(run.root.path, run.id, expected) != nil {
		return slice6ReceiptStageError(slice6ReceiptIndependentReadStage)
	}
	return nil
}

func (run *slice6ReceiptEvidenceRun) finish(binding slice6ReceiptEvidenceBinding,
	mutation slice6GuestRevokeFixtureReceipt, expected slice6ReceiptExpectedIdentity) (resultErr error) {
	run.mu.Lock()
	if run.check() != nil || run.complete || len(run.bindings) != 2 ||
		binding.RunID != run.id || binding.Product != run.bindings["product"] ||
		binding.Guest != run.bindings["guest"] || binding.Disposition != "component_verified" ||
		binding.Protocol != "sandbox-runtime.phase6-guest-receipt-evidence.v1" ||
		len(binding.ERevision) != 40 || !lowerHexSlice6(binding.ERevision) ||
		len(binding.RRevision) != 40 || !lowerHexSlice6(binding.RRevision) ||
		len(binding.FRevision) != 40 || !lowerHexSlice6(binding.FRevision) ||
		!guestRevokeFixtureDigestGate(binding.ETree) || !guestRevokeFixtureDigestGate(binding.RTree) ||
		!guestRevokeFixtureDigestGate(binding.FTree) ||
		!guestRevokeFixtureDigestGate(binding.ProfileDigest) ||
		!guestRevokeFixtureDigestGate(binding.MutationReceiptSHA256) ||
		binding.MutationVerifiedUTC == "" || binding.MutationGeneration != mutation.BindingGeneration ||
		binding.ERevision != expected.ERevision || binding.ETree != expected.ETree ||
		binding.RRevision != expected.RRevision || binding.RTree != expected.RTree ||
		binding.FRevision != expected.FRevision || binding.FTree != expected.FTree ||
		binding.ProfileDigest != expected.ProfileDigest ||
		binding.Product.ConfigDigest != expected.ProductConfigDigest ||
		binding.Guest.ConfigDigest != expected.GuestConfigDigest ||
		binding.ProductArtifact != expected.ProductArtifact ||
		binding.GuestArtifact != expected.GuestArtifact ||
		binding.Product.ContainerID != expected.ProductContainerID ||
		binding.Guest.ContainerID != expected.GuestContainerID ||
		binding.Product.ActualImage != expected.ProductImageID ||
		binding.Guest.ActualImage != expected.GuestImageID ||
		!slice6ValidReceiptArtifact(binding.ProductArtifact, binding.Product.ActualImage) ||
		!slice6ValidReceiptArtifact(binding.GuestArtifact, binding.Guest.ActualImage) {
		run.mu.Unlock()
		return slice6ReceiptStageError(slice6ReceiptInputStage)
	}
	run.mu.Unlock()
	for _, raw := range []slice6ReceiptRawBinding{binding.Product, binding.Guest} {
		document, err := run.readFile(raw.File, phase6guestreceipt.MaxTotalBytes)
		if err != nil || len(document) != raw.Bytes || slice6ReceiptSHA256(document) != raw.SHA256 {
			return slice6ReceiptStageError(slice6ReceiptRawBindingStage)
		}
		if _, err := phase6guestreceipt.Verify(document, raw.Role, raw.ProfileDigest, raw.ConfigDigest); err != nil {
			return slice6ReceiptStageError(slice6ReceiptRawBindingStage)
		}
	}
	if mutation.RunID != run.id || mutation.ProfileDigest != binding.ProfileDigest ||
		mutation.ProductContainerID != binding.Product.ContainerID ||
		mutation.MutationOutcome != "confirmed" || !mutation.BeforeConnected ||
		!mutation.AfterRevoked || !mutation.NonceCleared {
		return slice6ReceiptStageError(slice6ReceiptMutationStage)
	}
	if err := run.writeDocument("mutation-receipt.json", mutation); err != nil {
		return slice6ReceiptStageError(slice6ReceiptMutationStage)
	}
	mutationDocument, err := run.readFile("mutation-receipt.json", 4096)
	if err != nil || len(mutationDocument) < 2 || mutationDocument[len(mutationDocument)-1] != '\n' ||
		slice6ReceiptSHA256(mutationDocument) != binding.MutationReceiptSHA256 {
		return slice6ReceiptStageError(slice6ReceiptMutationStage)
	}
	defer func() {
		if resultErr != nil {
			if rollbackErr := run.rollbackBinding(); rollbackErr != nil {
				resultErr = errors.Join(resultErr, rollbackErr)
			}
		}
	}()
	if err := run.writeDocument("binding.pending", binding); err != nil {
		return slice6ReceiptStageError(slice6ReceiptPublishStage)
	}
	if err := run.publishBinding(expected); err != nil {
		return err
	}
	run.mu.Lock()
	run.complete = true
	run.mu.Unlock()
	return nil
}

func slice6ValidReceiptArtifact(value slice6ReceiptArtifact, image string) bool {
	return guestRevokeFixtureDigestGate(value.ManifestDigest) &&
		guestRevokeFixtureDigestGate(value.ArchiveDigest) &&
		guestRevokeFixtureDigestGate(value.SelectedManifestDigest) &&
		guestRevokeFixtureDigestGate(value.ConfigDigest) && value.ImageID == image
}

func (run *slice6ReceiptEvidenceRun) close() error {
	if run == nil {
		return errSlice6ReceiptEvidence
	}
	run.mu.Lock()
	if run.closed {
		run.mu.Unlock()
		return nil
	}
	complete := run.complete
	run.mu.Unlock()
	var incompleteErr error
	if !complete {
		incompleteErr = run.writeDocument("incomplete.json", struct {
			Protocol    string `json:"protocol"`
			Disposition string `json:"disposition"`
			RunID       string `json:"run_id"`
			RecordedUTC string `json:"recorded_utc"`
		}{"sandbox-runtime.phase6-guest-receipt-evidence.v1", "incomplete", run.id, time.Now().UTC().Format(time.RFC3339Nano)})
	}
	run.mu.Lock()
	run.closed = true
	run.mu.Unlock()
	closeErr := unix.Close(run.fd)
	run.fd = -1
	if incompleteErr != nil || closeErr != nil {
		return errSlice6ReceiptEvidence
	}
	return nil
}

func slice6ReceiptSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type slice6ReceiptExpectedIdentity struct {
	ERevision, ETree, RRevision, RTree, FRevision, FTree, ProfileDigest string
	ProductConfigDigest, GuestConfigDigest                              string
	ProductArtifact, GuestArtifact                                      slice6ReceiptArtifact
	ProductContainerID, GuestContainerID, ProductImageID, GuestImageID  string
}

// Read-only, independent reread of the retained partial component evidence.
// A successful result never upgrades this into the formal Slice 6 manifest.
func slice6VerifyPersistentGuestEvidence(rootPath, id string, expected slice6ReceiptExpectedIdentity) error {
	root, err := slice6OpenReceiptEvidenceRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.close()
	run, err := root.openRun(id)
	if err != nil {
		return err
	}
	defer unix.Close(run.fd)
	var names = []string{"binding.json", "guest-pid1.stdout", "mutation-receipt.json", "product-pid1.stdout"}
	dup, err := unix.Dup(run.fd)
	if err != nil {
		return errSlice6ReceiptEvidence
	}
	dir := os.NewFile(uintptr(dup), "evidence-run")
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(entries) != len(names) {
		return errSlice6ReceiptEvidence
	}
	actualNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		actualNames = append(actualNames, entry.Name())
	}
	slices.Sort(actualNames)
	if !slices.Equal(actualNames, names) {
		return errSlice6ReceiptEvidence
	}
	for _, name := range names {
		var observed unix.Stat_t
		if unix.Fstatat(run.fd, name, &observed, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			observed.Mode&unix.S_IFMT != unix.S_IFREG || observed.Mode&0o7777 != 0o600 ||
			observed.Uid != uint32(os.Getuid()) {
			return errSlice6ReceiptEvidence
		}
		run.files[name] = observed
	}
	encoded, err := run.readFile("binding.json", 8192)
	if err != nil || len(encoded) < 2 || encoded[len(encoded)-1] != '\n' {
		return errSlice6ReceiptEvidence
	}
	var binding slice6ReceiptEvidenceBinding
	if json.Unmarshal(encoded[:len(encoded)-1], &binding) != nil {
		return errSlice6ReceiptEvidence
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(canonical, encoded[:len(encoded)-1]) ||
		binding.Protocol != "sandbox-runtime.phase6-guest-receipt-evidence.v1" ||
		binding.Disposition != "component_verified" || binding.RunID != id ||
		binding.ERevision != expected.ERevision || binding.ETree != expected.ETree ||
		binding.RRevision != expected.RRevision || binding.RTree != expected.RTree ||
		binding.FRevision != expected.FRevision || binding.FTree != expected.FTree ||
		binding.ProfileDigest != expected.ProfileDigest ||
		binding.Product.ConfigDigest != expected.ProductConfigDigest ||
		binding.Guest.ConfigDigest != expected.GuestConfigDigest ||
		binding.ProductArtifact != expected.ProductArtifact ||
		binding.GuestArtifact != expected.GuestArtifact ||
		binding.Product.ContainerID != expected.ProductContainerID ||
		binding.Guest.ContainerID != expected.GuestContainerID ||
		binding.Product.ActualImage != expected.ProductImageID ||
		binding.Guest.ActualImage != expected.GuestImageID ||
		!slice6ValidReceiptArtifact(binding.ProductArtifact, binding.Product.ActualImage) ||
		!slice6ValidReceiptArtifact(binding.GuestArtifact, binding.Guest.ActualImage) {
		return errSlice6ReceiptEvidence
	}
	mutationAt, err := time.Parse(time.RFC3339Nano, binding.MutationVerifiedUTC)
	if err != nil || binding.Product.DockerExitCode != 0 || binding.Guest.DockerExitCode != 1 ||
		binding.Product.ContainerID == binding.Guest.ContainerID || binding.MutationGeneration < 1 {
		return errSlice6ReceiptEvidence
	}
	var pair slice6GuestReceiptPair
	for _, raw := range []slice6ReceiptRawBinding{binding.Product, binding.Guest} {
		started, startErr := time.Parse(time.RFC3339Nano, raw.CaptureStartUTC)
		finished, finishErr := time.Parse(time.RFC3339Nano, raw.CaptureFinishUTC)
		if raw.File != slice6ReceiptRawName(raw.Role) || raw.ProfileDigest != expected.ProfileDigest ||
			raw.Bytes < 1 || raw.Bytes > phase6guestreceipt.MaxTotalBytes ||
			!guestRevokeFixtureDigestGate(raw.SHA256) || raw.ActualImage != raw.SelectedImage ||
			len(raw.ContainerID) != 64 || !lowerHexSlice6(raw.ContainerID) ||
			startErr != nil || finishErr != nil || started.After(mutationAt) || finished.Before(mutationAt) {
			return errSlice6ReceiptEvidence
		}
		document, err := run.readFile(raw.File, phase6guestreceipt.MaxTotalBytes)
		if err != nil || len(document) != raw.Bytes || slice6ReceiptSHA256(document) != raw.SHA256 {
			return errSlice6ReceiptEvidence
		}
		records, err := phase6guestreceipt.Verify(document, raw.Role, raw.ProfileDigest, raw.ConfigDigest)
		if err != nil {
			return errSlice6ReceiptEvidence
		}
		switch raw.Role {
		case "product":
			pair.Product = records
		case "guest":
			pair.Guest = records
		}
	}
	if pair.verifyRevoke(binding.MutationGeneration) != nil {
		return errSlice6ReceiptEvidence
	}
	mutationDocument, err := run.readFile("mutation-receipt.json", 4096)
	if err != nil || len(mutationDocument) < 2 || mutationDocument[len(mutationDocument)-1] != '\n' ||
		slice6ReceiptSHA256(mutationDocument) != binding.MutationReceiptSHA256 {
		return errSlice6ReceiptEvidence
	}
	var mutation slice6GuestRevokeFixtureReceipt
	if json.Unmarshal(mutationDocument[:len(mutationDocument)-1], &mutation) != nil {
		return errSlice6ReceiptEvidence
	}
	canonical, err = json.Marshal(mutation)
	if err != nil || !bytes.Equal(canonical, mutationDocument[:len(mutationDocument)-1]) ||
		mutation.RunID != id || mutation.ProfileDigest != expected.ProfileDigest ||
		mutation.ProductContainerID != binding.Product.ContainerID ||
		mutation.BindingGeneration != binding.MutationGeneration ||
		mutation.MutationOutcome != "confirmed" || !mutation.BeforeConnected ||
		!mutation.AfterRevoked || !mutation.NonceCleared || run.check() != nil {
		return errSlice6ReceiptEvidence
	}
	return nil
}

func slice6ReceiptRoleArtifact(images phase6profilebuilder.ImageSupply, image string) (slice6ReceiptArtifact, error) {
	selected, ok := images.LocalRoleTargets["core"]
	if !ok || selected.Digest != image || selected.Reference != image || selected.Location != "local" ||
		selected.Platform != images.Platform || !guestRevokeFixtureDigestGate(selected.ConfigDigest) {
		return slice6ReceiptArtifact{}, errSlice6ReceiptEvidence
	}
	selectedManifest := image
	switch selected.Kind {
	case phase6security.ImageIdentityOCIManifest:
		if selected.SelectedManifestDigest != "" {
			return slice6ReceiptArtifact{}, errSlice6ReceiptEvidence
		}
	case phase6security.ImageIdentityOCIIndex:
		if !guestRevokeFixtureDigestGate(selected.SelectedManifestDigest) ||
			selected.SelectedManifestDigest == image {
			return slice6ReceiptArtifact{}, errSlice6ReceiptEvidence
		}
		selectedManifest = selected.SelectedManifestDigest
	default:
		return slice6ReceiptArtifact{}, errSlice6ReceiptEvidence
	}
	for _, item := range images.RoleArtifacts {
		if item.Manifest.Source.BuildTarget != "core" {
			continue
		}
		m := item.Manifest
		if m.ImageIdentityKind != selected.Kind || m.RuntimeStoreImageID != image ||
			m.RuntimeStoreDescriptor.Digest != image ||
			m.Source.Platform != images.Platform ||
			m.Source.SourceRevision != images.RuntimeRevision || m.Source.SourceTreeDigest != images.RuntimeTreeDigest ||
			m.SelectedManifestDescriptor.Digest != selectedManifest ||
			m.OCIConfigDigest != selected.ConfigDigest ||
			!guestRevokeFixtureDigestGate(m.ManifestDigest) ||
			!guestRevokeFixtureDigestGate(m.ArchiveDigest) {
			return slice6ReceiptArtifact{}, errSlice6ReceiptEvidence
		}
		return slice6ReceiptArtifact{ManifestDigest: m.ManifestDigest, ArchiveDigest: m.ArchiveDigest,
			SelectedManifestDigest: m.SelectedManifestDescriptor.Digest, ConfigDigest: m.OCIConfigDigest,
			ImageID: m.RuntimeStoreImageID}, nil
	}
	return slice6ReceiptArtifact{}, errSlice6ReceiptEvidence
}

func slice6FinishGuestReceiptEvidence(ctx context.Context, run *slice6ReceiptEvidenceRun,
	static slice6VaultStaticInputs, images phase6profilebuilder.ImageSupply,
	fixture slice6GuestBindingFixtureArtifact, profileDigest string,
	mutation slice6GuestRevokeFixtureReceipt, verifiedAt time.Time,
	productContainerID, guestContainerID string) error {
	if ctx == nil || ctx.Err() != nil || run == nil || run.check() != nil ||
		verifiedAt.IsZero() || !guestRevokeFixtureDigestGate(profileDigest) ||
		mutation.RunID != run.id || mutation.ProfileDigest != profileDigest ||
		mutation.MutationOutcome != "confirmed" || !mutation.BeforeConnected ||
		!mutation.AfterRevoked || !mutation.NonceCleared || mutation.BindingGeneration < 1 ||
		len(static.sourceRevision) != 40 || images.RuntimeRevision != static.sourceRevision ||
		!guestRevokeFixtureDigestGate(images.RuntimeTreeDigest) || fixture.SourceRevision == "" {
		return slice6ReceiptStageError(slice6ReceiptInputStage)
	}
	if images.VerifySources(ctx) != nil {
		return slice6ReceiptStageError(slice6ReceiptSourceReopenStage)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		return slice6ReceiptStageError(slice6ReceiptSourceReopenStage)
	}
	eRevision := os.Getenv(slice6ProductObserverRevisionEnv)
	if verifyCleanSlice6Source(ctx, root, eRevision) != nil ||
		verifyCleanSlice6Source(ctx, static.sourceRoot, static.sourceRevision) != nil ||
		verifyCleanSlice6Source(ctx, os.Getenv(slice6GuestFixtureSourceRootEnv), fixture.SourceRevision) != nil {
		return slice6ReceiptStageError(slice6ReceiptSourceReopenStage)
	}
	eTree, eErr := desktopcandidate.SourceTreeDigestAtRevision(root, eRevision)
	fTree, fErr := desktopcandidate.SourceTreeDigestAtRevision(
		os.Getenv(slice6GuestFixtureSourceRootEnv), fixture.SourceRevision)
	if eErr != nil || fErr != nil {
		return slice6ReceiptStageError(slice6ReceiptSourceReopenStage)
	}
	canonicalMutation, err := json.Marshal(mutation)
	if err != nil || len(canonicalMutation) > 2048 {
		return slice6ReceiptStageError(slice6ReceiptMutationStage)
	}
	run.mu.Lock()
	product, productOK := run.bindings["product"]
	guest, guestOK := run.bindings["guest"]
	run.mu.Unlock()
	if !productOK || !guestOK || product.ProfileDigest != profileDigest ||
		guest.ProfileDigest != profileDigest || product.ContainerID != mutation.ProductContainerID ||
		product.ContainerID != productContainerID || guest.ContainerID != guestContainerID ||
		product.ContainerID == guest.ContainerID {
		return slice6ReceiptStageError(slice6ReceiptRawBindingStage)
	}
	productArtifact, err := slice6ReceiptRoleArtifact(images, product.ActualImage)
	if err != nil {
		return slice6ReceiptStageError(slice6ReceiptArtifactMapStage)
	}
	guestArtifact, err := slice6ReceiptRoleArtifact(images, guest.ActualImage)
	if err != nil {
		return slice6ReceiptStageError(slice6ReceiptArtifactMapStage)
	}
	expected := slice6ReceiptExpectedIdentity{
		ERevision: eRevision, ETree: eTree, RRevision: images.RuntimeRevision,
		RTree: images.RuntimeTreeDigest, FRevision: fixture.SourceRevision, FTree: fTree,
		ProfileDigest: profileDigest, ProductConfigDigest: product.ConfigDigest,
		GuestConfigDigest: guest.ConfigDigest, ProductArtifact: productArtifact,
		GuestArtifact: guestArtifact, ProductContainerID: productContainerID,
		GuestContainerID: guestContainerID, ProductImageID: productArtifact.ImageID,
		GuestImageID: guestArtifact.ImageID,
	}
	binding := slice6ReceiptEvidenceBinding{
		Protocol:    "sandbox-runtime.phase6-guest-receipt-evidence.v1",
		Disposition: "component_verified", RunID: run.id,
		ERevision: eRevision, ETree: eTree, RRevision: images.RuntimeRevision,
		RTree: images.RuntimeTreeDigest, FRevision: fixture.SourceRevision, FTree: fTree,
		ProfileDigest: profileDigest, MutationReceiptSHA256: slice6ReceiptSHA256(append(canonicalMutation, '\n')),
		MutationVerifiedUTC: verifiedAt.Format(time.RFC3339Nano), MutationGeneration: mutation.BindingGeneration,
		ProductArtifact: productArtifact,
		GuestArtifact:   guestArtifact, Product: product, Guest: guest,
	}
	return run.finish(binding, mutation, expected)
}
