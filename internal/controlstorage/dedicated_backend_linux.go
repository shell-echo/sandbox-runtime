package controlstorage

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// sysfs is read from the actual mounted filesystem device. No block-device
// write permission, ioctl, mount capability, shell command or caller facts.
func readDedicatedLoop(device uint64, b DedicatedBackend) error {
	if b.Validate() != nil || unix.Major(device) != 7 || b.Device != fmt.Sprintf("/dev/loop%d", unix.Minor(device)) {
		return ErrInvalid
	}
	root := fmt.Sprintf("/sys/dev/block/7:%d", unix.Minor(device))
	var fs unix.Statfs_t
	if unix.Statfs(root, &fs) != nil || fs.Type != unix.SYSFS_MAGIC {
		return ErrInvalid
	}
	facts := map[string]string{}
	for _, field := range []string{"size", "ro", "loop/backing_file", "loop/offset", "loop/sizelimit", "loop/autoclear", "loop/partscan", "loop/dio"} {
		f, err := os.Open(root + "/" + field)
		if err != nil {
			return ErrInvalid
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 4098))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(data) > 4097 || !strings.HasSuffix(string(data), "\n") {
			return ErrInvalid
		}
		facts[field] = strings.TrimSuffix(string(data), "\n")
	}
	return verifyDedicatedLoopFacts(b, facts)
}

func verifyDedicatedLoopFacts(b DedicatedBackend, f map[string]string) error {
	if b.Validate() != nil || len(f) != 8 || f["size"] != strconv.FormatInt(b.Bytes/512, 10) || f["ro"] != "0" ||
		f["loop/backing_file"] != b.BackingFile || f["loop/offset"] != "0" || f["loop/sizelimit"] != strconv.FormatInt(b.Bytes, 10) || f["loop/autoclear"] != "0" || f["loop/partscan"] != "0" || f["loop/dio"] != "0" {
		return ErrInvalid
	}
	return nil
}
