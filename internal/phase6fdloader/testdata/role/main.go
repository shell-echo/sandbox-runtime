// This fixed, non-production test target checks Linux exec inheritance of the
// private-FD loader. Inputs are non-secret deterministic fixture bytes.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func main() {
	if os.Getpid() != 1 || verify() != nil {
		_, _ = fmt.Fprintln(os.Stderr, "fd-fixture: invalid")
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "fd-fixture: ok")
}

func verify() error {
	const seals = unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	for _, expected := range []struct {
		fd   int
		data []byte
	}{
		{0, []byte(`{"protocol":"test"}`)},
		{3, bytes.Repeat([]byte{1}, 64)},
		{4, bytes.Repeat([]byte{2}, 64)},
		{5, []byte("private-test-key")},
		{6, bytes.Repeat([]byte{3}, 64)},
	} {
		file := os.NewFile(uintptr(expected.fd), "inherited")
		info, statErr := file.Stat()
		offset, seekErr := file.Seek(0, io.SeekCurrent)
		observedSeals, sealErr := unix.FcntlInt(uintptr(expected.fd), unix.F_GET_SEALS, 0)
		if statErr != nil || seekErr != nil || sealErr != nil || info == nil || !info.Mode().IsRegular() ||
			info.Mode().Perm() != 0o600 || offset != 0 || observedSeals != seals {
			return fmt.Errorf("invalid inherited descriptor")
		}
		contents, err := io.ReadAll(io.LimitReader(file, 2<<20+1))
		if err != nil || !bytes.Equal(contents, expected.data) {
			return fmt.Errorf("invalid inherited contents")
		}
		_ = file.Close()
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		link, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err == nil && strings.Contains(link, "memfd:") &&
			entry.Name() != "0" && entry.Name() != "3" && entry.Name() != "4" &&
			entry.Name() != "5" && entry.Name() != "6" {
			return fmt.Errorf("extra inherited memfd")
		}
	}
	return nil
}
