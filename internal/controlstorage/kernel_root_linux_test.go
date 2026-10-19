package controlstorage

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func syntheticKernelFacts() (unix.Stat_t, unix.Statfs_t, string) {
	st := unix.Stat_t{Dev: unix.Mkdev(8, 32), Ino: 2, Mode: unix.S_IFDIR | 0o700, Uid: 57010, Gid: 57011, Nlink: 2}
	fs := unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC, Bsize: 4096, Frsize: 4096, Blocks: (768 << 20) / 4096, Bavail: (700 << 20) / 4096, Files: 32768, Ffree: 32000, Flags: unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC}
	fs.Fsid.Val = [2]int32{123, 456}
	return st, fs, "70 60 8:32 / /receipt rw,nosuid,nodev,noexec - ext4 /dev/vdc rw\n"
}

func TestKernelRootSyntheticFactsAndSessionRebind(t *testing.T) {
	st, fs, m := syntheticKernelFacts()
	a, available, err := kernelRootFromFacts(st, fs, 70, "/receipt", []byte(m))
	if err != nil || available != 700<<20 || a.Identity.DataBytes != 768<<20 || a.Identity.Root != id(&st) {
		t.Fatal("synthetic kernel chain", err)
	}
	b, _, err := kernelRootFromFacts(st, fs, 71, "/receipt", []byte(strings.Replace(m, "70 60", "71 60", 1)))
	if err != nil || a.Identity != b.Identity || a == b {
		t.Fatal("session mount ID confused with persistent identity")
	}
	// Free bytes change as the Store writes; they are not persistent identity.
	fs.Bavail--
	c, _, err := kernelRootFromFacts(st, fs, 70, "/receipt", []byte(m))
	if err != nil || a != c {
		t.Fatal("free space became identity")
	}
}

func TestKernelRootRejectsPathMountReplacementWithSameInode(t *testing.T) {
	fd := unix.Statx_t{Mask: unix.STATX_INO | unix.STATX_MNT_ID, Mnt_id: 70, Ino: 2, Dev_major: 8, Dev_minor: 32}
	if !sameKernelMount(fd, fd) {
		t.Fatal("same mount rejected")
	}
	path := fd
	path.Mnt_id++
	if sameKernelMount(fd, path) {
		t.Fatal("same inode on a different mount accepted")
	}
	path = fd
	path.Mask &^= unix.STATX_MNT_ID
	if sameKernelMount(fd, path) {
		t.Fatal("missing path mount identity accepted")
	}
}

func TestKernelRootRejectsUnsafeFacts(t *testing.T) {
	cases := map[string]func(*unix.Stat_t, *unix.Statfs_t, *string){
		"root user":             func(s *unix.Stat_t, _ *unix.Statfs_t, _ *string) { s.Uid = 0 },
		"shared mode":           func(s *unix.Stat_t, _ *unix.Statfs_t, _ *string) { s.Mode |= 0o070 },
		"tmpfs":                 func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Type = unix.TMPFS_MAGIC },
		"overlay":               func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Type = unix.OVERLAYFS_SUPER_MAGIC },
		"unbounded filesystem":  func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Blocks = (2 << 30) / 4096 },
		"too small":             func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Blocks = (256 << 20) / 4096; f.Bavail = 0 },
		"overflow":              func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Blocks = ^uint64(0) },
		"wrong allocation unit": func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Bsize = 6000; f.Frsize = 6000 },
		"missing noexec":        func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Flags &^= unix.ST_NOEXEC },
		"read only":             func(_ *unix.Stat_t, f *unix.Statfs_t, _ *string) { f.Flags |= unix.ST_RDONLY },
		"child root": func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) {
			*m = strings.Replace(*m, "8:32 / /receipt", "8:32 /old/child /receipt", 1)
		},
		"wrong path":         func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) { *m = strings.Replace(*m, "/receipt", "/another", 1) },
		"wrong device":       func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) { *m = strings.Replace(*m, "8:32", "8:33", 1) },
		"mount missing":      func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) { *m = strings.Replace(*m, "70 60", "71 60", 1) },
		"shared propagation": func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) { *m = strings.Replace(*m, " - ", " shared:1 - ", 1) },
		"alias": func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) {
			*m += "71 60 8:32 / /alias rw,nosuid,nodev,noexec - ext4 /dev/vdc rw\n"
		},
		"duplicate id": func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) { *m += *m },
		"source alias": func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) { *m = strings.Replace(*m, "/dev/vdc", "tmpfs", 1) },
		"mount flags drift": func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) {
			*m = strings.Replace(*m, "rw,nosuid,nodev,noexec", "rw,nosuid,nodev", 1)
		},
		"oversize": func(_ *unix.Stat_t, _ *unix.Statfs_t, m *string) { *m = strings.Repeat("x", maxMountInfoBytes+1) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, f, m := syntheticKernelFacts()
			change(&s, &f, &m)
			if _, _, err := kernelRootFromFacts(s, f, 70, "/receipt", []byte(m)); err == nil {
				t.Fatal("unsafe kernel facts accepted")
			}
		})
	}
}
