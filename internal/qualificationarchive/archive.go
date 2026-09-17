// Package qualificationarchive creates and extracts the deterministic external
// envelope payload for one completed qualification evidence root.
package qualificationarchive

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const MaxArchiveBytes int64 = 10 << 20

var ErrArchive = errors.New("qualification evidence archive is invalid")

var evidenceFiles = []string{
	"gateway-observer.json",
	"process-supervisor.json",
	"provider-observer.json",
	"receipt.json",
	"report.json",
	"resource-inspector.json",
	"trusted-inputs.json",
}

type Result struct {
	Path   string
	Digest string
	Bytes  int64
	Files  int
}

// Create writes a deterministic uncompressed tar containing exactly the seven
// closed evidence files. The destination must not exist.
func Create(ctx context.Context, evidenceRoot, destination string) (result Result, resultErr error) {
	if ctx == nil || !filepath.IsAbs(evidenceRoot) || !filepath.IsAbs(destination) || filepath.Clean(evidenceRoot) != evidenceRoot || filepath.Clean(destination) != destination {
		return Result{}, ErrArchive
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrArchive, err)
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Result{}, ErrArchive
	}
	committed := false
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if !committed {
			resultErr = errors.Join(resultErr, os.Remove(destination))
		}
	}()
	hash := sha256.New()
	counting := &countWriter{writer: io.MultiWriter(file, hash)}
	writer := tar.NewWriter(counting)
	for _, name := range evidenceFiles {
		if err := ctx.Err(); err != nil {
			_ = writer.Close()
			return Result{}, errors.Join(ErrArchive, err)
		}
		path := filepath.Join(evidenceRoot, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 2<<20 {
			_ = writer.Close()
			return Result{}, ErrArchive
		}
		input, err := os.Open(path)
		if err != nil {
			_ = writer.Close()
			return Result{}, ErrArchive
		}
		opened, statErr := input.Stat()
		if statErr != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
			_ = input.Close()
			_ = writer.Close()
			return Result{}, ErrArchive
		}
		header := &tar.Header{
			Name: name, Mode: 0o600, Size: info.Size(), Typeflag: tar.TypeReg,
			ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
			Uid: 0, Gid: 0,
		}
		if err := writer.WriteHeader(header); err != nil {
			_ = input.Close()
			_ = writer.Close()
			return Result{}, ErrArchive
		}
		copied, copyErr := io.CopyN(writer, input, info.Size())
		closeErr := input.Close()
		if copyErr != nil || closeErr != nil || copied != info.Size() {
			_ = writer.Close()
			return Result{}, ErrArchive
		}
	}
	if err := writer.Close(); err != nil || counting.count <= 0 || counting.count > MaxArchiveBytes {
		return Result{}, ErrArchive
	}
	if err := file.Sync(); err != nil || file.Chmod(0o600) != nil {
		return Result{}, ErrArchive
	}
	committed = true
	return Result{
		Path: destination, Digest: "sha256:" + hex.EncodeToString(hash.Sum(nil)),
		Bytes: counting.count, Files: len(evidenceFiles),
	}, nil
}

// Extract validates the deterministic archive shape and writes its seven files
// into a new private destination directory.
func Extract(ctx context.Context, archivePath, destination string) (result Result, resultErr error) {
	if ctx == nil || !filepath.IsAbs(archivePath) || !filepath.IsAbs(destination) || filepath.Clean(archivePath) != archivePath || filepath.Clean(destination) != destination {
		return Result{}, ErrArchive
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrArchive, err)
	}
	info, err := os.Lstat(archivePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxArchiveBytes {
		return Result{}, ErrArchive
	}
	input, err := os.Open(archivePath)
	if err != nil {
		return Result{}, ErrArchive
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return Result{}, ErrArchive
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return Result{}, ErrArchive
	}
	complete := false
	defer func() {
		if !complete {
			resultErr = errors.Join(resultErr, os.RemoveAll(destination))
		}
	}()
	hash := sha256.New()
	reader := tar.NewReader(io.TeeReader(io.LimitReader(input, MaxArchiveBytes+1), hash))
	seen := make([]string, 0, len(evidenceFiles))
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, errors.Join(ErrArchive, err)
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil || header.Typeflag != tar.TypeReg || header.Mode != 0o600 || header.Size <= 0 || header.Size > 2<<20 || header.Uid != 0 || header.Gid != 0 || !header.ModTime.Equal(time.Unix(0, 0).UTC()) {
			return Result{}, ErrArchive
		}
		index := len(seen)
		if index >= len(evidenceFiles) || header.Name != evidenceFiles[index] {
			return Result{}, ErrArchive
		}
		path := filepath.Join(destination, header.Name)
		output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return Result{}, ErrArchive
		}
		copied, copyErr := io.CopyN(output, reader, header.Size)
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || copied != header.Size {
			return Result{}, ErrArchive
		}
		seen = append(seen, header.Name)
	}
	if !equalStrings(seen, evidenceFiles) {
		return Result{}, ErrArchive
	}
	// Consume and hash any tar end padding while rejecting bytes beyond the
	// bounded source file size already observed.
	if _, err := io.Copy(io.Discard, io.TeeReader(input, hash)); err != nil {
		return Result{}, ErrArchive
	}
	complete = true
	return Result{
		Path: archivePath, Digest: "sha256:" + hex.EncodeToString(hash.Sum(nil)),
		Bytes: info.Size(), Files: len(seen),
	}, nil
}

func EvidenceFiles() []string {
	return append([]string(nil), evidenceFiles...)
}

type countWriter struct {
	writer io.Writer
	count  int64
}

func (w *countWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	w.count += int64(n)
	return n, err
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func init() {
	if !sort.StringsAreSorted(evidenceFiles) {
		panic(fmt.Sprintf("qualification evidence archive paths are not sorted: %v", evidenceFiles))
	}
}
