// Package local provides a bounded content-addressed BlobStore for standalone
// Product deployments and tests. Object references are opaque logical names;
// filesystem paths never cross the adapter boundary.
package local

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/shell-echo/sandbox-runtime/product"
)

type Store struct {
	stagingDir string
	objectsDir string
}

func New(root string) (*Store, error) {
	if root == "" {
		return nil, product.ErrInvalid
	}
	info, err := os.Lstat(root)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, product.ErrStoreUnavailable
		}
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, product.ErrStoreUnavailable
		}
		info, err = os.Lstat(root)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, product.ErrInvalid
	}
	store := &Store{stagingDir: filepath.Join(root, "staging"), objectsDir: filepath.Join(root, "objects")}
	for _, directory := range []string{store.stagingDir, store.objectsDir} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, product.ErrStoreUnavailable
		}
	}
	return store, nil
}

func (s *Store) EnsureStaging(ctx context.Context, reference string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	filePath, ok := s.stagingPath(reference)
	if !ok {
		return product.ErrInvalid
	}
	fd, err := unix.Open(filePath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	return unix.Close(fd)
}

func (s *Store) Append(ctx context.Context, reference string, offset int64, chunk []byte) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if offset < 0 || len(chunk) < 1 || len(chunk) > product.MaxChunkBytes {
		return 0, product.ErrInvalid
	}
	filePath, ok := s.stagingPath(reference)
	if !ok {
		return 0, product.ErrInvalid
	}
	fd, err := unix.Open(filePath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, product.ErrStoreUnavailable
	}
	file := os.NewFile(uintptr(fd), "product-staging")
	defer file.Close()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return 0, product.ErrStoreUnavailable
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	info, err := file.Stat()
	if err != nil || info.Size() != offset {
		return 0, product.ErrVersionConflict
	}
	written := 0
	for written < len(chunk) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, err := file.WriteAt(chunk[written:], offset+int64(written))
		written += n
		if err != nil {
			return 0, product.ErrStoreUnavailable
		}
	}
	if err := file.Sync(); err != nil {
		return 0, product.ErrStoreUnavailable
	}
	return offset + int64(written), nil
}

func (s *Store) Inspect(ctx context.Context, reference string) (int64, string, error) {
	filePath, ok := s.referencePath(reference)
	if !ok {
		return 0, "", product.ErrInvalid
	}
	file, err := openNoFollow(filePath)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	return inspectFile(ctx, file)
}

func (s *Store) Commit(ctx context.Context, stagingReference, digest string, size int64) (string, error) {
	if !validDigest(digest) || size < 0 {
		return "", product.ErrInvalid
	}
	actualSize, actualDigest, err := s.Inspect(ctx, stagingReference)
	if err != nil || actualSize != size || actualDigest != digest {
		return "", product.ErrInvalid
	}
	stagingPath, ok := s.stagingPath(stagingReference)
	if !ok {
		return "", product.ErrInvalid
	}
	finalReference := "blob:" + digest
	objectPath, _ := s.objectPath(finalReference)
	if err := os.Link(stagingPath, objectPath); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", product.ErrStoreUnavailable
		}
		existing, openErr := openNoFollow(objectPath)
		if openErr != nil {
			return "", product.ErrStoreUnavailable
		}
		existingSize, existingDigest, inspectErr := inspectFile(ctx, existing)
		_ = existing.Close()
		if inspectErr != nil || existingSize != size || existingDigest != digest {
			return "", product.ErrStoreUnavailable
		}
	}
	if err := os.Remove(stagingPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", product.ErrStoreUnavailable
	}
	return finalReference, nil
}

func (s *Store) Read(ctx context.Context, reference string, offset int64, limit int) ([]byte, bool, error) {
	if offset < 0 || limit < 1 || limit > product.MaxChunkBytes+1 {
		return nil, false, product.ErrInvalid
	}
	filePath, ok := s.objectPath(reference)
	if !ok {
		return nil, false, product.ErrInvalid
	}
	file, err := openNoFollow(filePath)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	buffer := make([]byte, limit)
	n, readErr := file.ReadAt(buffer, offset)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, false, product.ErrStoreUnavailable
	}
	return buffer[:n], errors.Is(readErr, io.EOF), nil
}

// Open resolves only a content digest in the adapter-private object directory.
// Tenant/workspace/revision authorization is completed by the Product store
// before this port is called; no filesystem path crosses the boundary.
func (s *Store) Open(ctx context.Context, tenantID, workspaceID, revisionID, digest string, size int64) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if tenantID == "" || workspaceID == "" || revisionID == "" || !validDigest(digest) || size < 0 || size > product.MaxTransferBytes {
		return nil, product.ErrInvalid
	}
	filePath, ok := s.objectPath("blob:" + digest)
	if !ok {
		return nil, product.ErrInvalid
	}
	file, err := openNoFollow(filePath)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		_ = file.Close()
		return nil, product.ErrStoreUnavailable
	}
	return file, nil
}

func (s *Store) Delete(ctx context.Context, reference string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	filePath, ok := s.stagingPath(reference)
	if !ok {
		return product.ErrInvalid
	}
	if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return product.ErrStoreUnavailable
	}
	return nil
}

func (s *Store) stagingPath(reference string) (string, bool) {
	if !strings.HasPrefix(reference, "staging:xfer_") || len(reference) > 256 || strings.ContainsAny(reference, "/\\\x00") {
		return "", false
	}
	sum := sha256.Sum256([]byte(reference))
	return filepath.Join(s.stagingDir, hex.EncodeToString(sum[:])+".part"), true
}
func (s *Store) objectPath(reference string) (string, bool) {
	if !strings.HasPrefix(reference, "blob:sha256:") || len(reference) != len("blob:sha256:")+64 {
		return "", false
	}
	digest := strings.TrimPrefix(reference, "blob:sha256:")
	if _, err := hex.DecodeString(digest); err != nil {
		return "", false
	}
	return filepath.Join(s.objectsDir, digest+".blob"), true
}
func (s *Store) referencePath(reference string) (string, bool) {
	if value, ok := s.stagingPath(reference); ok {
		return value, true
	}
	return s.objectPath(reference)
}

func openNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, product.ErrStoreUnavailable
	}
	return os.NewFile(uintptr(fd), "product-blob"), nil
}

func inspectFile(ctx context.Context, file *os.File) (int64, string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, "", product.ErrStoreUnavailable
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			size += int64(n)
			_, _ = hash.Write(buffer[:n])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, "", product.ErrStoreUnavailable
		}
	}
	return size, "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

var _ product.BlobStore = (*Store)(nil)
var _ product.WorkspaceContentSource = (*Store)(nil)
