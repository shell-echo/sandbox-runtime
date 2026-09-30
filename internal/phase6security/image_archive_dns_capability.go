package phase6security

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// VerifyOCIArchiveCoreDNSCapability checks the effective /coredns file in
// verified, ordered OCI layers. Docker's runtime capability observation is a
// separate gate; this check only binds the original image bytes to the one
// reviewed file capability required by the stock binary.
func VerifyOCIArchiveCoreDNSCapability(archivePath string, manifestDocument, configDocument []byte) error {
	if len(manifestDocument) == 0 || len(manifestDocument) > 4<<20 ||
		rejectDuplicateMembers(manifestDocument) != nil ||
		VerifyOCIArchiveLayers(archivePath, manifestDocument, configDocument) != nil {
		return ErrInvalidImageDescriptor
	}
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if json.Unmarshal(manifestDocument, &manifest) != nil || len(manifest.Layers) == 0 || len(manifest.Layers) > 512 {
		return ErrInvalidImageDescriptor
	}
	indices := make(map[string]int, len(manifest.Layers))
	for index, layer := range manifest.Layers {
		if !digestPattern.MatchString(layer.Digest) || layer.Size < 1 || layer.Size > maxOCIArchiveBytes {
			return ErrInvalidImageDescriptor
		}
		name := "blobs/sha256/" + strings.TrimPrefix(layer.Digest, "sha256:")
		if _, duplicate := indices[name]; duplicate {
			return ErrInvalidImageDescriptor
		}
		indices[name] = index
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return ErrInvalidImageDescriptor
	}
	defer file.Close()
	pathInfo, pathErr := os.Lstat(archivePath)
	openedInfo, openedErr := file.Stat()
	if pathErr != nil || openedErr != nil || !os.SameFile(pathInfo, openedInfo) ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm() != 0o600 ||
		openedInfo.Size() != pathInfo.Size() {
		return ErrInvalidImageDescriptor
	}
	layers := make([]dnsFileCapability, len(manifest.Layers))
	seen := make(map[int]bool, len(manifest.Layers))
	reader := tar.NewReader(file)
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return ErrInvalidImageDescriptor
		}
		index, wanted := indices[header.Name]
		if !wanted {
			continue
		}
		if seen[index] || header.Size != manifest.Layers[index].Size ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) {
			return ErrInvalidImageDescriptor
		}
		seen[index] = true
		value, err := readCoreDNSCapabilityLayer(reader, header.Size, manifest.Layers[index].MediaType)
		if err != nil {
			return fmt.Errorf("%w: CoreDNS layer %d: %v", ErrInvalidImageDescriptor, index, err)
		}
		layers[index] = value
	}
	if len(seen) != len(manifest.Layers) {
		return ErrInvalidImageDescriptor
	}
	var effective dnsFileCapability
	for _, layer := range layers {
		if layer.deleted {
			effective = dnsFileCapability{}
		}
		if layer.present {
			effective = layer
		}
	}
	if !effective.present || !validCoreDNSFileCapability(effective.value) {
		return fmt.Errorf("%w: CoreDNS capability present=%v value=%x", ErrInvalidImageDescriptor, effective.present, effective.value)
	}
	return nil
}

type dnsFileCapability struct {
	value   []byte
	present bool
	deleted bool
}

func readCoreDNSCapabilityLayer(reader io.Reader, size int64, mediaType string) (dnsFileCapability, error) {
	limited := &io.LimitedReader{R: reader, N: size}
	var stream io.Reader = limited
	var compressed *gzip.Reader
	if mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" ||
		mediaType == "application/vnd.docker.image.rootfs.diff.tar.gzip" {
		var err error
		compressed, err = gzip.NewReader(limited)
		if err != nil {
			return dnsFileCapability{}, ErrInvalidImageDescriptor
		}
		stream = compressed
	} else if mediaType != "application/vnd.oci.image.layer.v1.tar" &&
		mediaType != "application/vnd.docker.image.rootfs.diff.tar" {
		return dnsFileCapability{}, ErrInvalidImageDescriptor
	}
	bounded := &io.LimitedReader{R: stream, N: maxUncompressedLayerBytes + 1}
	tars := tar.NewReader(bounded)
	var result dnsFileCapability
	for {
		header, err := tars.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Name == "" || path.IsAbs(header.Name) {
			return dnsFileCapability{}, fmt.Errorf("%w: inner header %v", ErrInvalidImageDescriptor, err)
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if name == ".." || strings.HasPrefix(name, "../") ||
			slice6ExecutableAncestor(name, "coredns") && header.Typeflag != tar.TypeDir {
			return dnsFileCapability{}, ErrInvalidImageDescriptor
		}
		if slice6ExecutableWhiteout(name, "coredns") {
			if result.present || result.deleted || header.Typeflag != tar.TypeReg {
				return dnsFileCapability{}, ErrInvalidImageDescriptor
			}
			result.deleted = true
			continue
		}
		if name != "coredns" {
			continue
		}
		if result.present || result.deleted ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) ||
			header.Mode&0o777 != 0o755 || header.Size < 1 || header.Size > maxPhase6RoleExecutableBytes {
			return dnsFileCapability{}, fmt.Errorf("%w: CoreDNS header type=%v mode=%o size=%d", ErrInvalidImageDescriptor, header.Typeflag, header.Mode, header.Size)
		}
		capability := header.Xattrs["security.capability"]
		if capability == "" {
			capability = header.PAXRecords["SCHILY.xattr.security.capability"]
		}
		result.value = []byte(capability)
		result.present = true
	}
	if _, err := io.Copy(io.Discard, bounded); err != nil || bounded.N <= 0 {
		return dnsFileCapability{}, fmt.Errorf("%w: bounded drain %v", ErrInvalidImageDescriptor, err)
	}
	if compressed != nil && compressed.Close() != nil || limited.N != 0 {
		return dnsFileCapability{}, fmt.Errorf("%w: compressed drain remaining=%d", ErrInvalidImageDescriptor, limited.N)
	}
	return result, nil
}

func validCoreDNSFileCapability(value []byte) bool {
	if len(value) != 20 && len(value) != 24 {
		return false
	}
	magic := binary.LittleEndian.Uint32(value[:4])
	if magic != 0x02000001 && magic != 0x03000001 ||
		magic == 0x02000001 && len(value) != 20 ||
		magic == 0x03000001 && len(value) != 24 ||
		binary.LittleEndian.Uint32(value[4:8]) != 0x400 {
		return false
	}
	for _, offset := range []int{8, 12, 16} {
		if binary.LittleEndian.Uint32(value[offset:offset+4]) != 0 {
			return false
		}
	}
	return len(value) == 20 || binary.LittleEndian.Uint32(value[20:24]) == 0
}
