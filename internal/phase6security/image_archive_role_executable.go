package phase6security

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

const maxPhase6RoleExecutableBytes = 128 << 20

type roleLayerFile struct {
	data    []byte
	present bool
	deleted bool
}

// ReadVerifiedOCIArchiveRoleExecutable returns the effective executable from
// the selected image's ordered, original-byte-verified layers. It refuses
// whiteouts, links and ambiguous replacements at the exact role path. A
// separately rebuilt source binary must still be compared to these bytes.
func ReadVerifiedOCIArchiveRoleExecutable(archivePath string, manifestDocument, configDocument []byte) ([]byte, error) {
	return readVerifiedOCIArchiveExecutable(archivePath, manifestDocument, configDocument, "usr/local/bin/phase6-role")
}

// ReadVerifiedOCIArchiveFDLoader returns the distinct one-shot startup loader
// bytes from the ordered image layers. Callers compare an independent source
// rebuild before treating a descriptor-bearing role candidate as current.
func ReadVerifiedOCIArchiveFDLoader(archivePath string, manifestDocument, configDocument []byte) ([]byte, error) {
	return readVerifiedOCIArchiveExecutable(archivePath, manifestDocument, configDocument, "usr/local/bin/phase6-fd-loader")
}

// ReadVerifiedOCIArchiveDesktopBroker binds the component digest to the
// effective broker bytes in the selected Desktop image, not a source-tree
// binary or an operator-supplied digest. Runtime process bytes are separately
// observed by the live gate.
func ReadVerifiedOCIArchiveDesktopBroker(archivePath string, manifestDocument, configDocument []byte) ([]byte, error) {
	return readVerifiedOCIArchiveExecutable(archivePath, manifestDocument, configDocument,
		"usr/local/libexec/sandbox-runtime/desktop-broker")
}

func readVerifiedOCIArchiveExecutable(archivePath string, manifestDocument, configDocument []byte, target string) ([]byte, error) {
	if len(manifestDocument) < 1 || len(manifestDocument) > 4<<20 ||
		(target != "usr/local/bin/phase6-role" && target != "usr/local/bin/phase6-fd-loader" &&
			target != "usr/local/libexec/sandbox-runtime/desktop-broker") ||
		rejectDuplicateMembers(manifestDocument) != nil ||
		VerifyOCIArchiveLayers(archivePath, manifestDocument, configDocument) != nil {
		return nil, ErrInvalidImageDescriptor
	}
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if json.Unmarshal(manifestDocument, &manifest) != nil || len(manifest.Layers) < 1 || len(manifest.Layers) > 512 {
		return nil, ErrInvalidImageDescriptor
	}
	indices := make(map[string]int, len(manifest.Layers))
	for index, layer := range manifest.Layers {
		if !digestPattern.MatchString(layer.Digest) || layer.Size < 1 || layer.Size > maxOCIArchiveBytes {
			return nil, ErrInvalidImageDescriptor
		}
		indices["blobs/sha256/"+strings.TrimPrefix(layer.Digest, "sha256:")] = index
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, ErrInvalidImageDescriptor
	}
	defer file.Close()
	pathInfo, pathErr := os.Lstat(archivePath)
	openedInfo, openedErr := file.Stat()
	if pathErr != nil || openedErr != nil || !os.SameFile(pathInfo, openedInfo) ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm() != 0o600 ||
		openedInfo.Size() != pathInfo.Size() {
		return nil, ErrInvalidImageDescriptor
	}
	reader := tar.NewReader(file)
	layerFiles := make([]roleLayerFile, len(manifest.Layers))
	seen := make(map[int]bool, len(manifest.Layers))
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, ErrInvalidImageDescriptor
		}
		index, wanted := indices[header.Name]
		if !wanted {
			continue
		}
		if seen[index] || header.Size != manifest.Layers[index].Size || header.Size < 1 {
			return nil, ErrInvalidImageDescriptor
		}
		seen[index] = true
		value, err := readPhase6ExecutableFromLayer(reader, header.Size, manifest.Layers[index].MediaType, target)
		if err != nil {
			return nil, ErrInvalidImageDescriptor
		}
		layerFiles[index] = value
	}
	if len(seen) != len(manifest.Layers) {
		return nil, ErrInvalidImageDescriptor
	}
	var effective []byte
	for _, value := range layerFiles {
		if value.deleted {
			effective = nil
		}
		if value.present {
			effective = value.data
		}
	}
	if len(effective) == 0 {
		return nil, ErrInvalidImageDescriptor
	}
	return effective, nil
}

func readPhase6ExecutableFromLayer(reader io.Reader, size int64, mediaType, target string) (roleLayerFile, error) {
	limited := &io.LimitedReader{R: reader, N: size}
	var stream io.Reader = limited
	var compressed *gzip.Reader
	if strings.HasSuffix(mediaType, "+gzip") {
		var err error
		compressed, err = gzip.NewReader(limited)
		if err != nil {
			return roleLayerFile{}, ErrInvalidImageDescriptor
		}
		stream = compressed
	} else if mediaType != "application/vnd.oci.image.layer.v1.tar" &&
		mediaType != "application/vnd.docker.image.rootfs.diff.tar" {
		return roleLayerFile{}, ErrInvalidImageDescriptor
	}
	bounded := &io.LimitedReader{R: stream, N: maxUncompressedLayerBytes + 1}
	tarReader := tar.NewReader(bounded)
	var result roleLayerFile
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header.Name == "" || path.IsAbs(header.Name) {
			return roleLayerFile{}, ErrInvalidImageDescriptor
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		if name == ".." || strings.HasPrefix(name, "../") {
			return roleLayerFile{}, ErrInvalidImageDescriptor
		}
		if slice6ExecutableAncestor(name, target) && header.Typeflag != tar.TypeDir {
			return roleLayerFile{}, ErrInvalidImageDescriptor
		}
		if slice6ExecutableWhiteout(name, target) {
			if result.present || result.deleted || header.Typeflag != tar.TypeReg {
				return roleLayerFile{}, ErrInvalidImageDescriptor
			}
			result.deleted = true
			continue
		}
		if name != target {
			continue
		}
		if result.present || result.deleted || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) ||
			header.Size < 1 || header.Size > maxPhase6RoleExecutableBytes || header.Mode&0o777 != 0o555 {
			return roleLayerFile{}, ErrInvalidImageDescriptor
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return roleLayerFile{}, ErrInvalidImageDescriptor
		}
		result.data, result.present = data, true
	}
	if _, err := io.Copy(io.Discard, bounded); err != nil || bounded.N <= 0 {
		return roleLayerFile{}, ErrInvalidImageDescriptor
	}
	if compressed != nil && compressed.Close() != nil {
		return roleLayerFile{}, ErrInvalidImageDescriptor
	}
	if limited.N != 0 {
		return roleLayerFile{}, ErrInvalidImageDescriptor
	}
	return result, nil
}

func slice6ExecutableAncestor(name, target string) bool {
	return name != "" && strings.HasPrefix(target, name+"/")
}

func slice6ExecutableWhiteout(name, target string) bool {
	parts := strings.Split(target, "/")
	for index, part := range parts {
		parent := path.Join(parts[:index]...)
		if name == path.Join(parent, ".wh."+part) || name == path.Join(parent, ".wh..wh..opq") {
			return true
		}
	}
	return false
}
