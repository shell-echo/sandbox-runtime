package dockercontrol

import (
	"archive/tar"
	"bytes"
	"errors"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidVolumePrep = errors.New("invalid private Coding volume preparation")

// CodingVolumePrepArchive constructs exactly two zero-length directory
// headers. It may only be extracted at "/" of a dedicated, never-started
// preparation carrier with a writable rootfs and exactly the closed Coding
// three-volume mapping. The only entries are the mounted workspace and
// outputs roots; there is no caller-provided path, link or file content.
// The daemon archive API still carries host-equivalent authority. This
// builder alone does not grant the reviewed Control authority or make the
// preparation carrier suitable for running a workload.
func CodingVolumePrepArchive(template phase6security.CodingRuntimeTemplateV2,
	slotID string) ([]byte, error) {
	if template.Validate() != nil {
		return nil, ErrInvalidVolumePrep
	}
	var uid, gid uint32
	for _, slot := range template.Slots {
		if slot.ID == slotID {
			uid, gid = slot.WorkloadUID, slot.WorkloadGID
			break
		}
	}
	if uid == 0 || gid == 0 {
		return nil, ErrInvalidVolumePrep
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, name := range []string{"workspace", "outputs"} {
		header := &tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: int64(template.VolumePrepMode),
			Uid: int(uid), Gid: int(gid), Size: 0, ModTime: time.Unix(0, 0).UTC(), Format: tar.FormatUSTAR}
		if writer.WriteHeader(header) != nil {
			return nil, ErrInvalidVolumePrep
		}
	}
	if writer.Close() != nil || buffer.Len() != 2048 {
		return nil, ErrInvalidVolumePrep
	}
	return buffer.Bytes(), nil
}
