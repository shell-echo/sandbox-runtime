// Package files implements confined Guest Agent file observation. All client
// paths are guest-relative; traversal uses openat with O_NOFOLLOW for every
// component and never returns the configured host path.
package files

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime/guestagent"
)

const (
	CapabilityList     = "files.list"
	CapabilityStat     = "files.stat"
	CapabilitySnapshot = "files.snapshot"
	MaxListEntries     = 1000
	MaxSnapshotEntries = 10000
	MaxSnapshotBytes   = int64(256 << 20)
	MaxDigestFileBytes = int64(64 << 20)
)

var (
	ErrUnsafePath = errors.New("unsafe guest-relative path")
	ErrNotFound   = errors.New("guest file not found")
	ErrBounds     = errors.New("guest file operation exceeds bounds")
	ErrSpecial    = errors.New("guest file type is not allowed")
)

type Entry struct {
	Path       string `json:"path"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Mode       uint32 `json:"mode"`
	SizeBytes  int64  `json:"size_bytes"`
	ModifiedAt string `json:"modified_at"`
	Revision   string `json:"revision"`
}

type ListRequest struct {
	Path      string `json:"path"`
	AfterName string `json:"after_name,omitempty"`
	Limit     int    `json:"limit"`
}
type ListResponse struct {
	Items     []Entry `json:"items"`
	NextAfter string  `json:"next_after,omitempty"`
}
type StatRequest struct {
	Path string `json:"path"`
}
type SnapshotRequest struct {
	Path string `json:"path"`
}
type SnapshotResponse struct {
	Entries []Entry `json:"entries"`
}

type Service struct{ rootFD int }

func New(root string) (*Service, error) {
	if root == "" {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	return &Service{rootFD: fd}, nil
}

func (s *Service) Close() error {
	if s == nil || s.rootFD < 0 {
		return nil
	}
	err := unix.Close(s.rootFD)
	s.rootFD = -1
	return err
}

func (s *Service) Handlers() map[string]guestagent.OperationHandler {
	return map[string]guestagent.OperationHandler{
		CapabilityList: s.handleList, CapabilityStat: s.handleStat, CapabilitySnapshot: s.handleSnapshot,
	}
}

func (s *Service) handleList(ctx context.Context, payload json.RawMessage) (any, error) {
	var request ListRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	return s.List(ctx, request)
}
func (s *Service) handleStat(ctx context.Context, payload json.RawMessage) (any, error) {
	var request StatRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	return s.Stat(ctx, request.Path)
}
func (s *Service) handleSnapshot(ctx context.Context, payload json.RawMessage) (any, error) {
	var request SnapshotRequest
	if guestagent.DecodeStrict(payload, &request) != nil {
		return nil, guestagent.ErrInvalid
	}
	entries, err := s.Snapshot(ctx, request.Path)
	return SnapshotResponse{Entries: entries}, err
}

func (s *Service) List(ctx context.Context, request ListRequest) (ListResponse, error) {
	clean, err := normalize(request.Path)
	if err != nil || request.Limit < 1 || request.Limit > MaxListEntries || (request.AfterName != "" && !validName(request.AfterName)) {
		return ListResponse{}, ErrUnsafePath
	}
	fd, info, err := s.open(clean, true)
	if err != nil {
		return ListResponse{}, err
	}
	if !info.IsDir() {
		_ = unix.Close(fd)
		return ListResponse{}, ErrSpecial
	}
	file := os.NewFile(uintptr(fd), "guest-dir")
	defer file.Close()
	items, err := file.ReadDir(-1)
	if err != nil {
		return ListResponse{}, ErrNotFound
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name() < items[j].Name() })
	response := ListResponse{Items: make([]Entry, 0, request.Limit)}
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return ListResponse{}, err
		}
		if item.Name() <= request.AfterName {
			continue
		}
		itemPath := join(clean, item.Name())
		itemFD, itemInfo, err := s.open(itemPath, false)
		if err != nil {
			continue
		}
		_ = unix.Close(itemFD)
		entry := metadataEntry(itemPath, itemInfo)
		response.Items = append(response.Items, entry)
		if len(response.Items) == request.Limit {
			response.NextAfter = item.Name()
			break
		}
	}
	return response, nil
}

func (s *Service) Stat(ctx context.Context, guestPath string) (Entry, error) {
	clean, err := normalize(guestPath)
	if err != nil || clean == "" {
		return Entry{}, ErrUnsafePath
	}
	fd, info, err := s.open(clean, false)
	if err != nil {
		return Entry{}, err
	}
	defer unix.Close(fd)
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return Entry{}, ErrSpecial
	}
	entry := metadataEntry(clean, info)
	if info.Mode().IsRegular() {
		entry.Revision, err = digestFD(ctx, fd, info.Size())
	}
	return entry, err
}

func (s *Service) Snapshot(ctx context.Context, guestPath string) ([]Entry, error) {
	clean, err := normalize(guestPath)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	var totalBytes int64
	var walk func(string) error
	walk = func(current string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		fd, info, err := s.open(current, false)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if current != "" {
			if !info.IsDir() && !info.Mode().IsRegular() {
				return nil
			}
			entry := metadataEntry(current, info)
			if info.Mode().IsRegular() {
				totalBytes += info.Size()
				if totalBytes > MaxSnapshotBytes {
					return ErrBounds
				}
				entry.Revision, err = digestFD(ctx, fd, info.Size())
				if err != nil {
					return err
				}
			}
			entries = append(entries, entry)
			if len(entries) > MaxSnapshotEntries {
				return ErrBounds
			}
		}
		if !info.IsDir() {
			return nil
		}
		directoryFD, duplicateErr := unix.Dup(fd)
		if duplicateErr != nil {
			return ErrNotFound
		}
		file := os.NewFile(uintptr(directoryFD), "guest-dir")
		children, readErr := file.ReadDir(-1)
		_ = file.Close()
		if readErr != nil {
			return ErrNotFound
		}
		sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
		for _, child := range children {
			if child.Type()&os.ModeSymlink != 0 || child.Type()&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice|os.ModeCharDevice) != 0 {
				continue
			}
			if err := walk(join(current, child.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(clean); err != nil {
		return nil, err
	}
	return entries, nil
}

func (s *Service) open(clean string, requireDirectory bool) (int, os.FileInfo, error) {
	if s == nil || s.rootFD < 0 {
		return -1, nil, ErrNotFound
	}
	fd, err := unix.Openat(s.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, nil, ErrNotFound
	}
	if clean != "" {
		components := strings.Split(clean, "/")
		for index, component := range components {
			flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
			if index < len(components)-1 || requireDirectory {
				flags |= unix.O_DIRECTORY
			}
			next, openErr := unix.Openat(fd, component, flags, 0)
			_ = unix.Close(fd)
			if openErr != nil {
				return -1, nil, classifyOpenError(openErr)
			}
			fd = next
		}
	}
	statFD, duplicateErr := unix.Dup(fd)
	if duplicateErr != nil {
		_ = unix.Close(fd)
		return -1, nil, ErrNotFound
	}
	file := os.NewFile(uintptr(statFD), "guest-entry")
	info, err := file.Stat()
	_ = file.Close()
	if err != nil {
		_ = unix.Close(fd)
		return -1, nil, ErrNotFound
	}
	return fd, info, nil
}

func digestFD(ctx context.Context, fd int, size int64) (string, error) {
	if size < 0 || size > MaxDigestFileBytes {
		return "", ErrBounds
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return "", ErrNotFound
	}
	file := os.NewFile(uintptr(dup), "guest-file")
	defer file.Close()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", ErrNotFound
	}
	hash := sha256.New()
	buffer := make([]byte, 32<<10)
	var read int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			read += int64(n)
			if read > MaxDigestFileBytes {
				return "", ErrBounds
			}
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return "", ErrNotFound
		}
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func normalize(value string) (string, error) {
	if len(value) > 4096 || strings.ContainsAny(value, "\x00\\") || strings.HasPrefix(value, "/") {
		return "", ErrUnsafePath
	}
	if value == "" || value == "." {
		return "", nil
	}
	clean := path.Clean(value)
	if clean != value || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", ErrUnsafePath
	}
	for _, component := range strings.Split(clean, "/") {
		if !validName(component) {
			return "", ErrUnsafePath
		}
	}
	return clean, nil
}

func validName(value string) bool {
	return value != "" && value != "." && value != ".." && len(value) <= 255 && !strings.ContainsAny(value, "/\x00\\")
}

func join(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "/" + name
}

func metadataEntry(guestPath string, info os.FileInfo) Entry {
	typeName := "special"
	if info.IsDir() {
		typeName = "directory"
	} else if info.Mode().IsRegular() {
		typeName = "file"
	} else if info.Mode()&os.ModeSymlink != 0 {
		typeName = "symlink"
	}
	revisionSource := strings.Join([]string{guestPath, typeName, info.Mode().String(), time.Unix(0, info.ModTime().UnixNano()).UTC().Format(time.RFC3339Nano)}, "\x00")
	revision := sha256.Sum256([]byte(revisionSource))
	return Entry{Path: guestPath, Name: path.Base(guestPath), Type: typeName, Mode: uint32(info.Mode().Perm()), SizeBytes: info.Size(), ModifiedAt: info.ModTime().UTC().Format(time.RFC3339Nano), Revision: "sha256:" + hex.EncodeToString(revision[:])}
}

func classifyOpenError(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return ErrUnsafePath
	}
	return ErrNotFound
}
