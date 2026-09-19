// Package development implements bounded development-environment health and
// workspace materialization inside an already-authorized Guest. Host paths,
// credentials, and runtime coordinates never appear in protocol responses.
package development

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/shell-echo/sandbox-runtime/guestagent"
)

const (
	CapabilityHealth   = "development.health"
	CapabilityPrepare  = "workspace.materialize.prepare"
	CapabilityWrite    = "workspace.materialize.write"
	CapabilityCommit   = "workspace.materialize.commit"
	CapabilityFinalize = "workspace.materialize.finalize"
	CapabilityRollback = "workspace.materialize.rollback"
	MaxEntries         = 10000
	MaxChunkBytes      = 48 << 10
	MaxWorkspaceBytes  = int64(1 << 30)
	stageName          = ".sandbox-runtime-stage"
	backupName         = ".sandbox-runtime-backup"
	markerName         = "materialization.json"
	transactionName    = "materialization-transaction.json"
)

var (
	ErrUnsafeMaterialization = errors.New("unsafe workspace materialization")
	ErrIntegrity             = errors.New("workspace materialization integrity failure")
)

type Mount struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

type Toolchain struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
	Executable string `json:"executable"`
}

type Entry struct {
	Path      string `json:"path"`
	Type      string `json:"type"`
	Mode      uint32 `json:"mode"`
	SizeBytes int64  `json:"size_bytes"`
	Digest    string `json:"digest,omitempty"`
}

type PrepareRequest struct {
	StartupID         string  `json:"startup_id"`
	TemplateRevision  string  `json:"template_revision"`
	WorkspaceRevision string  `json:"workspace_revision"`
	ManifestDigest    string  `json:"manifest_digest"`
	Entries           []Entry `json:"entries"`
}

type WriteRequest struct {
	StartupID string `json:"startup_id"`
	Path      string `json:"path"`
	Offset    int64  `json:"offset"`
	Data      []byte `json:"data"`
}

type StartupRequest struct {
	StartupID string `json:"startup_id"`
}

type HealthResponse struct {
	Live              bool        `json:"live"`
	Ready             bool        `json:"ready"`
	TemplateRevision  string      `json:"template_revision,omitempty"`
	WorkspaceRevision string      `json:"workspace_revision,omitempty"`
	Mounts            []Mount     `json:"mounts"`
	Toolchains        []Toolchain `json:"toolchains"`
}

type Options struct {
	WorkspaceRoot, StateRoot string
	Mounts                   []Mount
	Toolchains               []Toolchain
}

type Service struct {
	mu                       sync.Mutex
	workspaceRoot, stateRoot string
	mounts                   []Mount
	toolchains               []Toolchain
	active                   *materialization
}

type materialization struct {
	startupID, templateRevision, workspaceRevision, manifestDigest string
	entries                                                        map[string]Entry
	previous                                                       *marker
	committed                                                      bool
}

type marker struct {
	StartupID         string `json:"startup_id"`
	TemplateRevision  string `json:"template_revision"`
	WorkspaceRevision string `json:"workspace_revision"`
	ManifestDigest    string `json:"manifest_digest"`
}

type transaction struct {
	StartupID string  `json:"startup_id"`
	Previous  *marker `json:"previous,omitempty"`
}

func New(options Options) (*Service, error) {
	if !filepath.IsAbs(options.WorkspaceRoot) || !filepath.IsAbs(options.StateRoot) || filepath.Clean(options.WorkspaceRoot) == filepath.Clean(options.StateRoot) ||
		!exactMounts(options.Mounts) || !validToolchains(options.Toolchains) {
		return nil, ErrUnsafeMaterialization
	}
	workspace, err := os.Stat(options.WorkspaceRoot)
	if err != nil || !workspace.IsDir() {
		return nil, ErrUnsafeMaterialization
	}
	if err := os.MkdirAll(options.StateRoot, 0o700); err != nil {
		return nil, ErrUnsafeMaterialization
	}
	state, err := os.Stat(options.StateRoot)
	if err != nil || !state.IsDir() || state.Mode().Perm()&0o077 != 0 {
		return nil, ErrUnsafeMaterialization
	}
	for _, toolchain := range options.Toolchains {
		info, err := os.Stat(toolchain.Executable)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return nil, ErrUnsafeMaterialization
		}
	}
	service := &Service{workspaceRoot: filepath.Clean(options.WorkspaceRoot), stateRoot: filepath.Clean(options.StateRoot), mounts: append([]Mount(nil), options.Mounts...), toolchains: append([]Toolchain(nil), options.Toolchains...)}
	if err := service.recover(); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *Service) Handlers() map[string]guestagent.OperationHandler {
	return map[string]guestagent.OperationHandler{
		CapabilityHealth: s.handleHealth, CapabilityPrepare: s.handlePrepare, CapabilityWrite: s.handleWrite,
		CapabilityCommit: s.handleCommit, CapabilityFinalize: s.handleFinalize, CapabilityRollback: s.handleRollback,
	}
}

func (s *Service) handleHealth(ctx context.Context, payload json.RawMessage) (any, error) {
	if len(payload) != 0 && string(payload) != "null" && string(payload) != "{}" {
		var empty struct{}
		if guestagent.DecodeStrict(payload, &empty) != nil {
			return nil, guestagent.ErrInvalid
		}
	}
	return s.Health(ctx)
}

func (s *Service) handlePrepare(ctx context.Context, payload json.RawMessage) (any, error) {
	var request PrepareRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	if err := s.Prepare(ctx, request); err != nil {
		return nil, guestagent.ErrRemote
	}
	return struct {
		Prepared bool `json:"prepared"`
	}{true}, nil
}

func (s *Service) handleWrite(ctx context.Context, payload json.RawMessage) (any, error) {
	var request WriteRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	if err := s.Write(ctx, request); err != nil {
		return nil, guestagent.ErrRemote
	}
	return struct {
		Written int `json:"written"`
	}{len(request.Data)}, nil
}

func (s *Service) handleCommit(ctx context.Context, payload json.RawMessage) (any, error) {
	var request StartupRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	return s.Commit(ctx, request.StartupID)
}

func (s *Service) handleRollback(ctx context.Context, payload json.RawMessage) (any, error) {
	var request StartupRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	if err := s.Rollback(ctx, request.StartupID); err != nil {
		return nil, guestagent.ErrRemote
	}
	return struct {
		RolledBack bool `json:"rolled_back"`
	}{true}, nil
}

func (s *Service) handleFinalize(ctx context.Context, payload json.RawMessage) (any, error) {
	var request StartupRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	if err := s.Finalize(ctx, request.StartupID); err != nil {
		return nil, guestagent.ErrRemote
	}
	return struct {
		Finalized bool `json:"finalized"`
	}{true}, nil
}

func (s *Service) Health(ctx context.Context) (HealthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return HealthResponse{}, err
	}
	response := HealthResponse{Live: true, Mounts: append([]Mount(nil), s.mounts...), Toolchains: append([]Toolchain(nil), s.toolchains...)}
	current, err := readMarker(s.stateRoot)
	if err != nil {
		return response, err
	}
	if current == nil {
		return response, nil
	}
	response.Ready = true
	response.TemplateRevision, response.WorkspaceRevision = current.TemplateRevision, current.WorkspaceRevision
	return response, nil
}

func (s *Service) Prepare(ctx context.Context, request PrepareRequest) error {
	if err := validatePrepare(request); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.active != nil && s.active.startupID == request.StartupID && s.active.templateRevision == request.TemplateRevision && s.active.workspaceRevision == request.WorkspaceRevision && s.active.manifestDigest == request.ManifestDigest {
		return nil
	}
	if s.active != nil {
		return ErrUnsafeMaterialization
	}
	stage := filepath.Join(s.workspaceRoot, stageName)
	backup := filepath.Join(s.workspaceRoot, backupName)
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	if _, err := os.Stat(backup); err == nil {
		return ErrUnsafeMaterialization
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	previous, err := readMarker(s.stateRoot)
	if err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	entries := make(map[string]Entry, len(request.Entries))
	for _, entry := range request.Entries {
		if err := ctx.Err(); err != nil {
			_ = os.RemoveAll(stage)
			return err
		}
		target := filepath.Join(stage, filepath.FromSlash(entry.Path))
		if entry.Type == "directory" {
			if err := os.MkdirAll(target, os.FileMode(entry.Mode)); err != nil {
				_ = os.RemoveAll(stage)
				return err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				_ = os.RemoveAll(stage)
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(entry.Mode))
			if err != nil {
				_ = os.RemoveAll(stage)
				return err
			}
			if err := file.Close(); err != nil {
				_ = os.RemoveAll(stage)
				return err
			}
		}
		entries[entry.Path] = entry
	}
	if err := writeTransaction(s.stateRoot, transaction{StartupID: request.StartupID, Previous: previous}); err != nil {
		_ = os.RemoveAll(stage)
		return err
	}
	s.active = &materialization{startupID: request.StartupID, templateRevision: request.TemplateRevision, workspaceRevision: request.WorkspaceRevision, manifestDigest: request.ManifestDigest, entries: entries, previous: previous}
	return nil
}

func (s *Service) Write(ctx context.Context, request WriteRequest) error {
	if !validID(request.StartupID) || !validPath(request.Path) || request.Offset < 0 || len(request.Data) < 1 || len(request.Data) > MaxChunkBytes {
		return ErrUnsafeMaterialization
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.active == nil || s.active.startupID != request.StartupID {
		return ErrUnsafeMaterialization
	}
	if s.active.committed {
		return ErrUnsafeMaterialization
	}
	entry, ok := s.active.entries[request.Path]
	if !ok || entry.Type != "file" || request.Offset+int64(len(request.Data)) > entry.SizeBytes {
		return ErrUnsafeMaterialization
	}
	target := filepath.Join(s.workspaceRoot, stageName, filepath.FromSlash(request.Path))
	file, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		return ErrUnsafeMaterialization
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != request.Offset {
		return ErrUnsafeMaterialization
	}
	written, err := file.WriteAt(request.Data, request.Offset)
	if err != nil || written != len(request.Data) {
		return ErrIntegrity
	}
	return file.Sync()
}

func (s *Service) Commit(ctx context.Context, startupID string) (HealthResponse, error) {
	if !validID(startupID) {
		return HealthResponse{}, ErrUnsafeMaterialization
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return HealthResponse{}, err
	}
	if s.active == nil || s.active.startupID != startupID {
		return HealthResponse{}, ErrUnsafeMaterialization
	}
	if s.active.committed {
		return s.readyHealth(*s.active), nil
	}
	stage := filepath.Join(s.workspaceRoot, stageName)
	if err := verifyStage(ctx, stage, s.active.entries); err != nil {
		return HealthResponse{}, err
	}
	backup := filepath.Join(s.workspaceRoot, backupName)
	if err := os.Mkdir(backup, 0o700); err != nil {
		return HealthResponse{}, err
	}
	if err := moveVisibleChildren(s.workspaceRoot, backup); err != nil {
		_ = restoreBackup(s.workspaceRoot, backup)
		return HealthResponse{}, err
	}
	if err := moveAllChildren(stage, s.workspaceRoot); err != nil {
		_ = removeVisibleChildren(s.workspaceRoot)
		_ = restoreBackup(s.workspaceRoot, backup)
		return HealthResponse{}, err
	}
	current := marker{StartupID: s.active.startupID, TemplateRevision: s.active.templateRevision, WorkspaceRevision: s.active.workspaceRevision, ManifestDigest: s.active.manifestDigest}
	if err := writeMarker(s.stateRoot, current); err != nil {
		_ = removeVisibleChildren(s.workspaceRoot)
		_ = restoreBackup(s.workspaceRoot, backup)
		return HealthResponse{}, err
	}
	_ = os.RemoveAll(stage)
	s.active.committed = true
	return s.readyHealth(*s.active), nil
}

func (s *Service) Finalize(ctx context.Context, startupID string) error {
	if !validID(startupID) {
		return ErrUnsafeMaterialization
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.active == nil {
		return nil
	}
	if s.active.startupID != startupID || !s.active.committed {
		return ErrUnsafeMaterialization
	}
	if err := os.RemoveAll(filepath.Join(s.workspaceRoot, backupName)); err != nil {
		return err
	}
	if err := removeTransaction(s.stateRoot); err != nil {
		return err
	}
	s.active = nil
	return nil
}

func (s *Service) Rollback(ctx context.Context, startupID string) error {
	if !validID(startupID) {
		return ErrUnsafeMaterialization
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.active != nil && s.active.startupID != startupID {
		return ErrUnsafeMaterialization
	}
	if s.active != nil && s.active.committed {
		if err := removeVisibleChildren(s.workspaceRoot); err != nil {
			return err
		}
		if err := restoreBackup(s.workspaceRoot, filepath.Join(s.workspaceRoot, backupName)); err != nil {
			return err
		}
		if err := restoreMarker(s.stateRoot, s.active.previous); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(filepath.Join(s.workspaceRoot, stageName)); err != nil {
		return err
	}
	backup := filepath.Join(s.workspaceRoot, backupName)
	if s.active == nil {
		if _, err := os.Stat(backup); err == nil {
			if err := removeVisibleChildren(s.workspaceRoot); err != nil {
				return err
			}
			if err := restoreBackup(s.workspaceRoot, backup); err != nil {
				return err
			}
		}
	}
	if err := removeTransaction(s.stateRoot); err != nil {
		return err
	}
	s.active = nil
	return nil
}

func (s *Service) recover() error {
	stage := filepath.Join(s.workspaceRoot, stageName)
	backup := filepath.Join(s.workspaceRoot, backupName)
	pending, err := readTransaction(s.stateRoot)
	if err != nil {
		return err
	}
	_, backupErr := os.Stat(backup)
	if backupErr == nil {
		current, markerErr := readMarker(s.stateRoot)
		if markerErr != nil {
			return markerErr
		}
		if pending != nil && current != nil && current.StartupID == pending.StartupID {
			if err := os.RemoveAll(backup); err != nil {
				return err
			}
		} else {
			if err := removeVisibleChildren(s.workspaceRoot); err != nil {
				return err
			}
			if err := restoreBackup(s.workspaceRoot, backup); err != nil {
				return err
			}
			if pending != nil {
				if err := restoreMarker(s.stateRoot, pending.Previous); err != nil {
					return err
				}
			}
		}
	} else if !errors.Is(backupErr, os.ErrNotExist) {
		return backupErr
	}
	if err := os.RemoveAll(stage); err != nil {
		return err
	}
	return removeTransaction(s.stateRoot)
}

func (s *Service) readyHealth(active materialization) HealthResponse {
	return HealthResponse{
		Live: true, Ready: true, TemplateRevision: active.templateRevision, WorkspaceRevision: active.workspaceRevision,
		Mounts: append([]Mount(nil), s.mounts...), Toolchains: append([]Toolchain(nil), s.toolchains...),
	}
}

func validatePrepare(request PrepareRequest) error {
	if !validID(request.StartupID) || !validDigest(request.TemplateRevision) || !validID(request.WorkspaceRevision) || !validDigest(request.ManifestDigest) || len(request.Entries) > MaxEntries {
		return ErrUnsafeMaterialization
	}
	previous := ""
	var total int64
	for _, entry := range request.Entries {
		if !validPath(entry.Path) || entry.Path <= previous || entry.Mode > 0o777 || entry.SizeBytes < 0 ||
			(entry.Type != "file" && entry.Type != "directory") ||
			(entry.Type == "file" && !validDigest(entry.Digest)) ||
			(entry.Type == "directory" && (entry.Digest != "" || entry.SizeBytes != 0)) {
			return ErrUnsafeMaterialization
		}
		previous = entry.Path
		total += entry.SizeBytes
		if total < 0 || total > MaxWorkspaceBytes {
			return ErrUnsafeMaterialization
		}
	}
	return nil
}

func verifyStage(ctx context.Context, stage string, entries map[string]Entry) error {
	paths := make([]string, 0, len(entries))
	for entryPath := range entries {
		paths = append(paths, entryPath)
	}
	sort.Strings(paths)
	for _, entryPath := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := entries[entryPath]
		info, err := os.Lstat(filepath.Join(stage, filepath.FromSlash(entryPath)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (entry.Type == "file" && (!info.Mode().IsRegular() || info.Size() != entry.SizeBytes)) || (entry.Type == "directory" && !info.IsDir()) {
			return ErrIntegrity
		}
		if entry.Type == "file" {
			file, err := os.Open(filepath.Join(stage, filepath.FromSlash(entryPath)))
			if err != nil {
				return ErrIntegrity
			}
			hash := sha256.New()
			_, copyErr := io.Copy(hash, file)
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != entry.Digest {
				return ErrIntegrity
			}
		}
	}
	return nil
}

func moveVisibleChildren(root, destination string) error {
	children, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.Name() == stageName || child.Name() == backupName {
			continue
		}
		if err := os.Rename(filepath.Join(root, child.Name()), filepath.Join(destination, child.Name())); err != nil {
			return err
		}
	}
	return nil
}

func moveAllChildren(source, destination string) error {
	children, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err := os.Rename(filepath.Join(source, child.Name()), filepath.Join(destination, child.Name())); err != nil {
			return err
		}
	}
	return nil
}

func removeVisibleChildren(root string) error {
	children, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.Name() == stageName || child.Name() == backupName {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, child.Name())); err != nil {
			return err
		}
	}
	return nil
}

func restoreBackup(root, backup string) error {
	if err := moveAllChildren(backup, root); err != nil {
		return err
	}
	return os.RemoveAll(backup)
}

func writeMarker(stateRoot string, value marker) error {
	return writeStateDocument(stateRoot, markerName, value)
}

func restoreMarker(stateRoot string, value *marker) error {
	if value == nil {
		if err := os.Remove(filepath.Join(stateRoot, markerName)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeMarker(stateRoot, *value)
}

func readMarker(stateRoot string) (*marker, error) {
	var value marker
	found, err := readStateDocument(stateRoot, markerName, &value)
	if err != nil || !found {
		return nil, err
	}
	if !validID(value.StartupID) || !validDigest(value.TemplateRevision) || !validID(value.WorkspaceRevision) || !validDigest(value.ManifestDigest) {
		return nil, ErrIntegrity
	}
	return &value, nil
}

func writeTransaction(stateRoot string, value transaction) error {
	return writeStateDocument(stateRoot, transactionName, value)
}

func readTransaction(stateRoot string) (*transaction, error) {
	var value transaction
	found, err := readStateDocument(stateRoot, transactionName, &value)
	if err != nil || !found {
		return nil, err
	}
	if !validID(value.StartupID) || (value.Previous != nil && (!validID(value.Previous.StartupID) || !validDigest(value.Previous.TemplateRevision) || !validID(value.Previous.WorkspaceRevision) || !validDigest(value.Previous.ManifestDigest))) {
		return nil, ErrIntegrity
	}
	return &value, nil
}

func removeTransaction(stateRoot string) error {
	if err := os.Remove(filepath.Join(stateRoot, transactionName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func readStateDocument(stateRoot, name string, value any) (bool, error) {
	document, err := os.ReadFile(filepath.Join(stateRoot, name))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || len(document) == 0 || len(document) > 8192 {
		return false, ErrIntegrity
	}
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return false, ErrIntegrity
	}
	return true, nil
}

func writeStateDocument(stateRoot, targetName string, value any) error {
	document, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(stateRoot, ".materialization-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(document); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filepath.Join(stateRoot, targetName))
}

func exactMounts(values []Mount) bool {
	want := []Mount{{Path: "/inputs", Mode: "ro"}, {Path: "/workspace", Mode: "rw"}, {Path: "/outputs", Mode: "rw"}, {Path: "/tmp", Mode: "rw"}}
	if len(values) != len(want) {
		return false
	}
	for index := range want {
		if values[index] != want[index] {
			return false
		}
	}
	return true
}

func validToolchains(values []Toolchain) bool {
	if len(values) < 1 || len(values) > 16 {
		return false
	}
	previous := ""
	for _, value := range values {
		if !validID(value.ID) || !validID(value.Version) || !validDigest(value.Digest) || !filepath.IsAbs(value.Executable) || value.ID <= previous {
			return false
		}
		previous = value.ID
	}
	return true
}

func validPath(value string) bool {
	if len(value) < 1 || len(value) > 4096 || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00") || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	first := strings.SplitN(value, "/", 2)[0]
	return first != stageName && first != backupName && !strings.HasPrefix(first, ".sandbox-runtime-")
}

func validID(value string) bool {
	if len(value) < 1 || len(value) > 200 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
