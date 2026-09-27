package phase6security

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxOCIArchiveBytes = 8 << 30
const maxUncompressedLayerBytes = 2 << 30

// VerifyOCIArchiveLayers checks every selected manifest layer against its
// actual saved blob bytes and the ordered config rootfs diff IDs. It supports
// OCI/Docker gzip or uncompressed tar layers; an unsupported codec fails
// closed. The caller separately verifies top/index/manifest/config descriptors.
func VerifyOCIArchiveLayers(archivePath string, manifestDocument, configDocument []byte) error {
	info, err := os.Lstat(archivePath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxOCIArchiveBytes ||
		rejectDuplicateMembers(manifestDocument) != nil || rejectDuplicateMembers(configDocument) != nil {
		return ErrInvalidImageDescriptor
	}
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if !decodeImageJSON(manifestDocument, &manifest) || !decodeImageJSON(configDocument, &config) ||
		len(manifest.Layers) < 1 || len(manifest.Layers) > 512 || len(manifest.Layers) != len(config.RootFS.DiffIDs) {
		return ErrInvalidImageDescriptor
	}
	layers := make(map[string]int, len(manifest.Layers))
	for index, layer := range manifest.Layers {
		if !digestPattern.MatchString(layer.Digest) || layer.Size < 1 || layer.Size > maxOCIArchiveBytes ||
			!digestPattern.MatchString(config.RootFS.DiffIDs[index]) {
			return ErrInvalidImageDescriptor
		}
		if _, duplicate := layers[layer.Digest]; duplicate {
			return ErrInvalidImageDescriptor
		}
		layers[layer.Digest] = index
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return ErrInvalidImageDescriptor
	}
	defer file.Close()
	reader := tar.NewReader(file)
	seenPaths := map[string]struct{}{}
	verified := 0
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || header.Name == "" || filepath.IsAbs(header.Name) ||
			strings.HasPrefix(header.Name, "../") || filepath.Clean(header.Name) != strings.TrimSuffix(header.Name, "/") ||
			(header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return ErrInvalidImageDescriptor
		}
		if _, duplicate := seenPaths[header.Name]; duplicate {
			return ErrInvalidImageDescriptor
		}
		seenPaths[header.Name] = struct{}{}
		if !strings.HasPrefix(header.Name, "blobs/sha256/") {
			continue
		}
		digest := "sha256:" + strings.TrimPrefix(header.Name, "blobs/sha256/")
		index, needed := layers[digest]
		if !needed {
			continue
		}
		layer := manifest.Layers[index]
		if header.Size != layer.Size || header.Size < 1 || header.Typeflag == tar.TypeDir {
			return ErrInvalidImageDescriptor
		}
		if verifyOCIArchiveLayer(reader, header.Size, layer.MediaType, layer.Digest, config.RootFS.DiffIDs[index]) != nil {
			return ErrInvalidImageDescriptor
		}
		verified++
	}
	if verified != len(layers) {
		return ErrInvalidImageDescriptor
	}
	return nil
}

func verifyOCIArchiveLayer(reader io.Reader, size int64, mediaType, compressedDigest, diffID string) error {
	limited := &io.LimitedReader{R: reader, N: size}
	compressedHash, uncompressedHash := sha256.New(), sha256.New()
	if strings.HasSuffix(mediaType, "+gzip") {
		decompressor, err := gzip.NewReader(io.TeeReader(limited, compressedHash))
		if err != nil {
			return ErrInvalidImageDescriptor
		}
		count, copyErr := io.CopyN(uncompressedHash, decompressor, maxUncompressedLayerBytes+1)
		closeErr := decompressor.Close()
		if count > maxUncompressedLayerBytes || (copyErr != nil && !errors.Is(copyErr, io.EOF)) || closeErr != nil {
			return ErrInvalidImageDescriptor
		}
		if _, err := io.Copy(compressedHash, limited); err != nil {
			return ErrInvalidImageDescriptor
		}
	} else if mediaType == "application/vnd.oci.image.layer.v1.tar" ||
		mediaType == "application/vnd.docker.image.rootfs.diff.tar" {
		if size > maxUncompressedLayerBytes {
			return ErrInvalidImageDescriptor
		}
		if _, err := io.Copy(io.MultiWriter(compressedHash, uncompressedHash), limited); err != nil {
			return ErrInvalidImageDescriptor
		}
	} else {
		return ErrInvalidImageDescriptor
	}
	if limited.N != 0 || "sha256:"+hex.EncodeToString(compressedHash.Sum(nil)) != compressedDigest ||
		"sha256:"+hex.EncodeToString(uncompressedHash.Sum(nil)) != diffID {
		return ErrInvalidImageDescriptor
	}
	return nil
}
