package desktopcandidate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

const maxNSSFileBytes = 128 << 10
const maxCandidateLayerBytes = 2 << 30

// verifyArchiveAccounts reads the selected, previously digest-verified OCI
// layers, not a Docker label or a second mutable container filesystem. The
// scratch repack has one filesystem layer; BuildKit may append empty layers.
// Any additional layer that changes the filesystem requires a new rule.
func verifyArchiveAccounts(archivePath string, manifestDocument []byte, accounts AccountAllowlist) error {
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if accounts.Validate() != nil || json.Unmarshal(manifestDocument, &manifest) != nil ||
		len(manifest.Layers) < 1 || len(manifest.Layers) > 4 {
		return fmt.Errorf("%w: candidate layer topology", ErrInvalidCandidate)
	}
	layers := make(map[string]int, len(manifest.Layers))
	for index, layer := range manifest.Layers {
		if !digestPattern.MatchString(layer.Digest) || layer.Size < 1 {
			return fmt.Errorf("%w: candidate layer descriptor", ErrInvalidCandidate)
		}
		if _, duplicate := layers[layer.Digest]; duplicate {
			return fmt.Errorf("%w: duplicate candidate layer", ErrInvalidCandidate)
		}
		layers[layer.Digest] = index
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return ErrInvalidCandidate
	}
	defer file.Close()
	outer := tar.NewReader(file)
	seen := make(map[string]struct{}, len(layers))
	contentLayers := 0
	for {
		header, nextErr := outer.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return ErrInvalidCandidate
		}
		blobDigest := "sha256:" + strings.TrimPrefix(header.Name, "blobs/sha256/")
		index, needed := layers[blobDigest]
		if !strings.HasPrefix(header.Name, "blobs/sha256/") || !needed {
			continue
		}
		layer := manifest.Layers[index]
		if _, duplicate := seen[blobDigest]; duplicate || header.Size != layer.Size ||
			header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return ErrInvalidCandidate
		}
		seen[blobDigest] = struct{}{}
		limited := &io.LimitedReader{R: outer, N: layer.Size}
		var source io.Reader = limited
		var zipped *gzip.Reader
		switch layer.MediaType {
		case "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.docker.image.rootfs.diff.tar.gzip":
			zipped, err = gzip.NewReader(limited)
			if err != nil {
				return ErrInvalidCandidate
			}
			source = zipped
		case "application/vnd.oci.image.layer.v1.tar", "application/vnd.docker.image.rootfs.diff.tar":
		default:
			return ErrInvalidCandidate
		}
		bounded := &io.LimitedReader{R: source, N: maxCandidateLayerBytes + 1}
		containsFilesystem, err := inspectNSSLayer(bounded, accounts)
		if err != nil {
			return err
		}
		if containsFilesystem {
			contentLayers++
		}
		if _, err := io.Copy(io.Discard, bounded); err != nil || bounded.N == 0 {
			return fmt.Errorf("%w: uncompressed layer bound", ErrInvalidCandidate)
		}
		if zipped != nil {
			if err := zipped.Close(); err != nil {
				return ErrInvalidCandidate
			}
		}
		if limited.N != 0 {
			return fmt.Errorf("%w: compressed layer trailing bytes", ErrInvalidCandidate)
		}
	}
	if len(seen) != len(layers) || contentLayers != 1 {
		return fmt.Errorf("%w: candidate filesystem layer topology", ErrInvalidCandidate)
	}
	return nil
}

func inspectNSSLayer(source io.Reader, accounts AccountAllowlist) (bool, error) {
	reader := tar.NewReader(source)
	var passwd, group []byte
	entries := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, ErrInvalidCandidate
		}
		entries++
		name := strings.TrimSuffix(path.Clean(strings.TrimPrefix(header.Name, "./")), "/")
		if name == "etc/.wh.passwd" || name == "etc/.wh.group" || name == ".wh.etc" {
			return false, ErrInvalidCandidate
		}
		if name != "etc/passwd" && name != "etc/group" && name != "etc" {
			continue
		}
		canonical := strings.TrimSuffix(strings.TrimPrefix(header.Name, "./"), "/")
		if name != canonical {
			return false, ErrInvalidCandidate
		}
		if name == "etc" {
			if header.Typeflag != tar.TypeDir {
				return false, ErrInvalidCandidate
			}
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA ||
			header.Size < 1 || header.Size > maxNSSFileBytes {
			return false, ErrInvalidCandidate
		}
		content, err := io.ReadAll(io.LimitReader(reader, maxNSSFileBytes+1))
		if err != nil || int64(len(content)) != header.Size {
			return false, ErrInvalidCandidate
		}
		if name == "etc/passwd" {
			if passwd != nil {
				return false, ErrInvalidCandidate
			}
			passwd = content
		} else {
			if group != nil {
				return false, ErrInvalidCandidate
			}
			group = content
		}
	}
	if entries == 0 {
		return false, nil
	}
	if !verifyNSSFile(passwd, accounts, false) {
		return false, fmt.Errorf("%w: passwd capability", ErrInvalidCandidate)
	}
	if !verifyNSSFile(group, accounts, true) {
		return false, fmt.Errorf("%w: group capability", ErrInvalidCandidate)
	}
	return true, nil
}

func verifyNSSFile(document []byte, accounts AccountAllowlist, isGroup bool) bool {
	if len(document) == 0 || len(document) > maxNSSFileBytes || document[len(document)-1] != '\n' || bytes.IndexByte(document, 0) >= 0 {
		return false
	}
	expected := make(map[uint32]string, len(accounts.Accounts))
	for _, account := range accounts.Accounts {
		uidOrGID := account.UID
		if isGroup {
			uidOrGID = account.GID
			expected[uidOrGID] = "desktop-slot-" + strconv.FormatUint(uint64(uidOrGID), 10) + ":x:" +
				strconv.FormatUint(uint64(uidOrGID), 10) + ":"
		} else {
			expected[uidOrGID] = "desktop-slot-" + strconv.FormatUint(uint64(uidOrGID), 10) + ":x:" +
				strconv.FormatUint(uint64(uidOrGID), 10) + ":" + strconv.FormatUint(uint64(account.GID), 10) +
				"::/tmp/desktop-home:/sbin/nologin"
		}
	}
	seenIDs := make(map[uint32]struct{})
	seenNames := make(map[string]struct{})
	for _, line := range strings.Split(strings.TrimSuffix(string(document), "\n"), "\n") {
		fields := strings.Split(line, ":")
		wantFields := 7
		if isGroup {
			wantFields = 4
		}
		if len(fields) != wantFields || fields[0] == "" {
			return false
		}
		id, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return false
		}
		value := uint32(id)
		if !isGroup {
			gid, err := strconv.ParseUint(fields[3], 10, 32)
			if err != nil {
				return false
			}
			if uint32(gid) >= 10000 && uint32(gid) <= 60000 {
				known := false
				for _, account := range accounts.Accounts {
					if account.UID == value && account.GID == uint32(gid) {
						known = true
						break
					}
				}
				if !known {
					return false
				}
			}
		} else if fields[3] != "" {
			for _, member := range strings.Split(fields[3], ",") {
				if strings.HasPrefix(member, "desktop-slot-") {
					return false
				}
			}
		}
		if _, duplicate := seenIDs[value]; duplicate {
			return false
		}
		if _, duplicate := seenNames[fields[0]]; duplicate {
			return false
		}
		seenIDs[value], seenNames[fields[0]] = struct{}{}, struct{}{}
		if want, isExpected := expected[value]; isExpected {
			if line != want {
				return false
			}
			delete(expected, value)
		} else if value >= 10000 && value <= 60000 || strings.HasPrefix(fields[0], "desktop-slot-") {
			return false
		}
	}
	return len(expected) == 0
}
