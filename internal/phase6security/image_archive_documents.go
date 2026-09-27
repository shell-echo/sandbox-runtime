package phase6security

import (
	"archive/tar"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReadOCIArchiveDocuments extracts the exact raw descriptor bytes from a
// private docker-save OCI archive. It does not infer an image identity from
// index.json, which may only be an export wrapper.
func ReadOCIArchiveDocuments(path, kind, storeDigest, selectedDigest, configDigest string) (ImageDescriptorDocuments, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxOCIArchiveBytes ||
		!digestPattern.MatchString(storeDigest) || (configDigest != "" && !digestPattern.MatchString(configDigest)) {
		return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
	}
	if kind != ImageIdentityOCIIndex && kind != ImageIdentityOCIManifest {
		return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
	}
	if kind == ImageIdentityOCIIndex && !digestPattern.MatchString(selectedDigest) {
		return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
	}
	if kind == ImageIdentityOCIManifest && selectedDigest != storeDigest {
		return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
	}
	wanted := map[string]*[]byte{}
	result := ImageDescriptorDocuments{}
	if kind == ImageIdentityOCIIndex {
		wanted[storeDigest] = &result.Index
	}
	wanted[selectedDigest] = &result.Manifest
	if configDigest != "" {
		wanted[configDigest] = &result.Config
	}
	file, err := os.Open(path)
	if err != nil {
		return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
	}
	defer file.Close()
	reader := tar.NewReader(file)
	seen := make(map[string]struct{})
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || header.Name == "" || filepath.IsAbs(header.Name) ||
			strings.HasPrefix(header.Name, "../") || filepath.Clean(header.Name) != strings.TrimSuffix(header.Name, "/") ||
			(header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
		}
		if _, duplicate := seen[header.Name]; duplicate {
			return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
		}
		seen[header.Name] = struct{}{}
		if !strings.HasPrefix(header.Name, "blobs/sha256/") {
			continue
		}
		digest := "sha256:" + strings.TrimPrefix(header.Name, "blobs/sha256/")
		destination, needed := wanted[digest]
		if !needed {
			continue
		}
		if header.Typeflag == tar.TypeDir || header.Size < 1 || header.Size > 4<<20 {
			return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
		}
		value, readErr := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if readErr != nil || int64(len(value)) != header.Size || hashImageBytes(value) != digest {
			return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
		}
		*destination = value
	}
	for _, document := range wanted {
		if len(*document) == 0 {
			return ImageDescriptorDocuments{}, ErrInvalidImageDescriptor
		}
	}
	return result, nil
}
