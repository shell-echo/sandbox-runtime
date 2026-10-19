package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestObservationAnchorRejectsSubstitution(t *testing.T) {
	x := unix.Statx_t{Mask: unix.STATX_BASIC_STATS | unix.STATX_MNT_ID, Dev_major: 254, Dev_minor: 1, Ino: 99, Mnt_id: 42, Mode: unix.S_IFREG | 0o600, Nlink: 1}
	if !sameObservedAnchor(x, x) {
		t.Fatal("identical complete anchor rejected")
	}
	for name, change := range map[string]func(*unix.Statx_t){
		"missing mount ID":             func(v *unix.Statx_t) { v.Mask &^= unix.STATX_MNT_ID },
		"missing inode":                func(v *unix.Statx_t) { v.Mask &^= unix.STATX_INO },
		"missing mode":                 func(v *unix.Statx_t) { v.Mask &^= unix.STATX_MODE },
		"inode":                        func(v *unix.Statx_t) { v.Ino++ },
		"mount replacement same inode": func(v *unix.Statx_t) { v.Mnt_id++ },
		"device":                       func(v *unix.Statx_t) { v.Dev_minor++ },
		"raw device":                   func(v *unix.Statx_t) { v.Rdev_minor++ },
		"owner":                        func(v *unix.Statx_t) { v.Uid++ },
		"group":                        func(v *unix.Statx_t) { v.Gid++ },
		"symlink":                      func(v *unix.Statx_t) { v.Mode = unix.S_IFLNK | 0o600 },
		"permission":                   func(v *unix.Statx_t) { v.Mode |= 0o040 },
		"hardlink":                     func(v *unix.Statx_t) { v.Nlink++ },
	} {
		t.Run(name, func(t *testing.T) {
			y := x
			change(&y)
			if sameObservedAnchor(x, y) || sameObservedAnchor(y, x) {
				t.Fatal("changed or incomplete anchor admitted")
			}
		})
	}
}

func TestObserveFDIsReadOnlyAndMountBound(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "record")
	if err := os.WriteFile(name, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	a, err := observeAnchor(int(f.Fd()), unix.AT_FDCWD, name)
	if err != nil || a.MountID == 0 {
		t.Fatal("real read-only file/statx anchor unavailable")
	}
	w, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := observeAnchor(int(w.Fd()), unix.AT_FDCWD, name); err == nil {
		t.Fatal("writable descriptor accepted")
	}
	if err := os.Rename(name, name+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeAnchor(int(f.Fd()), unix.AT_FDCWD, name); err == nil {
		t.Fatal("same-content replacement accepted")
	}
}

func TestObservedSealStrictOriginalBytes(t *testing.T) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Skip("private root-owned seal test requires the restricted root Docker fixture")
	}
	r := record{"sandbox-runtime.control-backend-provision.v1", strings.Repeat("a", 32), "/dev/loop7", 123, 456, size, "sha256:" + strings.Repeat("b", 64), 0}
	d, _ := json.Marshal(r)
	for name, raw := range map[string][]byte{"canonical": d, "extra newline": append(append([]byte{}, d...), '\n'), "duplicate": []byte(`{"namespace":"a","namespace":"b"}`), "oversize": make([]byte, 4097)} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "record")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			got, _, err := observedRecord(int(f.Fd()))
			if name == "canonical" && (err != nil || got != r) || name != "canonical" && err == nil {
				t.Fatal("seal canonical boundary changed")
			}
		})
	}
	for _, value := range []string{"sha256:", "sha256:" + strings.Repeat("B", 64), "sha256:" + strings.Repeat("g", 64), strings.Repeat("b", 64)} {
		if validInitialDigest(value) {
			t.Fatal("invalid initial digest admitted")
		}
	}
	if !validInitialDigest(r.InitialImageSHA256) {
		t.Fatal("valid original digest refused")
	}
}
