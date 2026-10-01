package phase6security

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestSlice6PrivateConfigArchiveExactCanonicalFiles(t *testing.T) {
	profile, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	deployment := "browser-executor-backend"
	files := map[string][]byte{Slice6ProfileConfigFile: profileBytes,
		Slice6PeerCRLRoleFile:      []byte(`{"role":"fixture"}`),
		Slice6StartupAuthorityFile: []byte(`{"authority":"fixture"}`)}
	prepared, err := BuildSlice6PrivateConfigArchive(profile, deployment, files)
	if err != nil || prepared.TotalBytes != int64(len(profileBytes)+len(files[Slice6PeerCRLRoleFile])+len(files[Slice6StartupAuthorityFile])) ||
		len(prepared.Digests) != len(files) {
		t.Fatalf("valid exact archive rejected: %v", err)
	}
	defer clear(prepared.Archive)
	reader := tar.NewReader(bytes.NewReader(prepared.Archive))
	wantNames := strings.Split(slice6PrivateConfigMountFiles(t, deployment), ",")
	for _, want := range wantNames {
		header, err := reader.Next()
		if err != nil || header.Name != want || header.Typeflag != tar.TypeReg || header.Mode != 0o600 ||
			header.Size != int64(len(files[want])) {
			t.Fatalf("archive member %q: %+v, %v", want, header, err)
		}
		got, err := io.ReadAll(reader)
		if err != nil || !bytes.Equal(got, files[want]) {
			t.Fatalf("archive member %q bytes differ: %v", want, err)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal("archive contains unexpected member")
	}
	missing := map[string][]byte{Slice6ProfileConfigFile: profileBytes,
		Slice6StartupAuthorityFile: files[Slice6StartupAuthorityFile]}
	if _, err := BuildSlice6PrivateConfigArchive(profile, deployment, missing); err == nil {
		t.Fatal("missing role file accepted")
	}
	extra := map[string][]byte{Slice6ProfileConfigFile: profileBytes,
		Slice6StartupAuthorityFile: files[Slice6StartupAuthorityFile],
		Slice6PeerCRLRoleFile:      files[Slice6PeerCRLRoleFile], "unexpected.json": []byte("x")}
	if _, err := BuildSlice6PrivateConfigArchive(profile, deployment, extra); err == nil {
		t.Fatal("extra file accepted")
	}
	wrongProfile := map[string][]byte{Slice6ProfileConfigFile: []byte("{}"),
		Slice6StartupAuthorityFile: files[Slice6StartupAuthorityFile],
		Slice6PeerCRLRoleFile:      files[Slice6PeerCRLRoleFile]}
	if _, err := BuildSlice6PrivateConfigArchive(profile, deployment, wrongProfile); err == nil {
		t.Fatal("noncanonical or wrong Profile accepted")
	}
	oversized := map[string][]byte{Slice6ProfileConfigFile: profileBytes,
		Slice6StartupAuthorityFile: bytes.Repeat([]byte("x"), (64<<10)+1),
		Slice6PeerCRLRoleFile:      files[Slice6PeerCRLRoleFile]}
	if _, err := BuildSlice6PrivateConfigArchive(profile, deployment, oversized); err == nil {
		t.Fatal("oversized authority accepted")
	}
}

func TestSlice6PrivateConfigArchivesRequireAllReaders(t *testing.T) {
	profile, err := BuildSlice6FinalExternalProfileTarget(reviewedSlice6ImageFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]map[string][]byte)
	for _, principal := range profile.Principals {
		mount, needed := Slice6PrivateConfigMount(principal.Name)
		if !needed {
			continue
		}
		set := make(map[string][]byte)
		for _, name := range strings.Split(mount.PrivateFiles, ",") {
			set[name] = []byte(`{"fixture":true}`)
		}
		set[Slice6ProfileConfigFile] = profileBytes
		files[principal.Name] = set
	}
	archives, err := BuildSlice6PrivateConfigArchives(profile, files)
	if err != nil || len(archives) != 75 {
		t.Fatalf("complete reader set rejected: count=%d err=%v", len(archives), err)
	}
	for _, archive := range archives {
		clear(archive.Archive)
	}
	delete(files, "workload-credential-controller")
	if partial, err := BuildSlice6PrivateConfigArchives(profile, files); err == nil || partial != nil {
		t.Fatal("missing private-config reader accepted")
	}
	files["unreviewed-reader"] = map[string][]byte{Slice6ProfileConfigFile: profileBytes}
	if extra, err := BuildSlice6PrivateConfigArchives(profile, files); err == nil || extra != nil {
		t.Fatal("unknown private-config reader accepted")
	}
}

func slice6PrivateConfigMountFiles(t *testing.T, deployment string) string {
	t.Helper()
	mount, ok := Slice6PrivateConfigMount(deployment)
	if !ok {
		t.Fatal("fixture has no private config mount")
	}
	return mount.PrivateFiles
}
