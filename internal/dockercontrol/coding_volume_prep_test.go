package dockercontrol

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	codingimage "github.com/shell-echo/sandbox-runtime/profiles/coding-shell/image"
)

func testVolumeTemplate(t *testing.T) phase6security.CodingRuntimeTemplateV2 {
	t.Helper()
	_, _, _, plan, _ := testCodingCreate(t)
	template, err := phase6security.NewCodingRuntimeTemplateV2("linux/arm64/v8", codingimage.PublishedARM64ConfigDigest,
		codingimage.PublishedDescriptorSize,
		plan.OwnerPrincipalDigest, testControlDigest("5"), plan.Slots, plan.Limits)
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func TestCodingVolumePrepArchiveIsTwoClosedDirectories(t *testing.T) {
	template := testVolumeTemplate(t)
	document, err := CodingVolumePrepArchive(template, template.Slots[0].ID)
	if err != nil || len(document) != 2048 {
		t.Fatalf("archive size = %d, %v", len(document), err)
	}
	reader := tar.NewReader(bytes.NewReader(document))
	for _, name := range []string{"workspace", "outputs"} {
		header, err := reader.Next()
		if err != nil || header.Name != name || header.Typeflag != tar.TypeDir ||
			header.Size != 0 || header.Mode != 0o770 || header.Uid != int(template.Slots[0].WorkloadUID) ||
			header.Gid != int(template.Slots[0].WorkloadGID) || header.Format != tar.FormatUSTAR ||
			len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 || header.Linkname != "" {
			t.Fatalf("unsafe tar header: %#v, %v", header, err)
		}
	}
	if _, err := reader.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("additional tar entry: %v", err)
	}
	if _, err := CodingVolumePrepArchive(template, "coding-missing"); !errors.Is(err, ErrInvalidVolumePrep) {
		t.Fatalf("unknown slot accepted: %v", err)
	}
	bad := template
	bad.VolumePrepMode = 0o777
	if _, err := CodingVolumePrepArchive(bad, template.Slots[0].ID); !errors.Is(err, ErrInvalidVolumePrep) {
		t.Fatalf("drifted template accepted: %v", err)
	}
}
