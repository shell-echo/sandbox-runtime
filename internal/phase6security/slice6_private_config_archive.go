package phase6security

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
)

// Slice6PrivateConfigArchive is an in-memory, exact file set for one fresh
// run-owned volume. Archive may contain private authority bytes: callers must
// keep it out of argv, environment, logs and persistent evidence, and clear it
// after the one-shot preparation container has consumed it.
type Slice6PrivateConfigArchive struct {
	Archive    []byte
	Digests    map[string]string
	TotalBytes int64
}

// BuildSlice6PrivateConfigArchives requires all 76 actual Profile readers in
// one closed handoff. A partial set is never returned; any previously built
// archive bytes are cleared if a later deployment fails validation.
func BuildSlice6PrivateConfigArchives(profile Profile,
	filesByDeployment map[string]map[string][]byte) (map[string]Slice6PrivateConfigArchive, error) {
	if VerifySlice6PrivateConfigMounts(profile) != nil {
		return nil, errSlice6DesiredInventory
	}
	wanted := make([]string, 0, len(profile.Principals))
	for _, principal := range profile.Principals {
		if _, needed := Slice6PrivateConfigMount(principal.Name); needed {
			wanted = append(wanted, principal.Name)
		}
	}
	if len(wanted) != 76 || len(filesByDeployment) != len(wanted) {
		return nil, errSlice6DesiredInventory
	}
	result := make(map[string]Slice6PrivateConfigArchive, len(wanted))
	for _, deployment := range wanted {
		files, present := filesByDeployment[deployment]
		if !present {
			for _, prepared := range result {
				clear(prepared.Archive)
			}
			return nil, errSlice6DesiredInventory
		}
		prepared, err := BuildSlice6PrivateConfigArchive(profile, deployment, files)
		if err != nil {
			for _, previous := range result {
				clear(previous.Archive)
			}
			return nil, err
		}
		result[deployment] = prepared
	}
	return result, nil
}

// BuildSlice6PrivateConfigArchive bounds and orders every input before Docker
// sees it. It does not establish an on-disk quota or prove a read-only mount;
// those are separate observations in the release gate. The caller must first
// verify the complete source-bound final Profile and each authority document;
// this function enforces only the exact file-set and byte handoff boundary.
func BuildSlice6PrivateConfigArchive(profile Profile, deployment string,
	files map[string][]byte) (Slice6PrivateConfigArchive, error) {
	if VerifySlice6PrivateConfigMounts(profile) != nil {
		return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
	}
	want, ok := Slice6PrivateConfigMount(deployment)
	if !ok {
		return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
	}
	names := strings.Split(want.PrivateFiles, ",")
	if len(files) != len(names) {
		return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
	}
	for name := range files {
		if !slices.Contains(names, name) {
			return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
		}
	}
	canonicalProfile, err := json.Marshal(profile)
	if err != nil || !bytes.Equal(files[Slice6ProfileConfigFile], canonicalProfile) {
		return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	result := Slice6PrivateConfigArchive{Digests: make(map[string]string, len(names))}
	for _, name := range names {
		contents, exists := files[name]
		limit, allowed := Slice6PrivateConfigFileLimit(deployment, name)
		if !exists || !allowed || len(contents) == 0 || int64(len(contents)) > limit ||
			result.TotalBytes+int64(len(contents)) > want.MaxBytes {
			clear(buffer.Bytes())
			return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
		}
		result.TotalBytes += int64(len(contents))
		sum := sha256.Sum256(contents)
		result.Digests[name] = "sha256:" + hex.EncodeToString(sum[:])
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(contents)), Typeflag: tar.TypeReg}); err != nil {
			clear(buffer.Bytes())
			return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
		}
		if _, err := writer.Write(contents); err != nil {
			clear(buffer.Bytes())
			return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
		}
	}
	if writer.Close() != nil {
		clear(buffer.Bytes())
		return Slice6PrivateConfigArchive{}, errSlice6DesiredInventory
	}
	result.Archive = buffer.Bytes()
	return result, nil
}
