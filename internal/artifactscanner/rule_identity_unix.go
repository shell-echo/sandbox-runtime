//go:build darwin || linux

package artifactscanner

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const ruleCustodySupported = true

type ruleDirectory struct {
	file *os.File
	path string
	stat unix.Stat_t
}

type ruleOriginalFile struct {
	file   *os.File
	parent *ruleDirectory
	name   string
	stat   unix.Stat_t
}

// Ignore atime, which our own reads may change. Ctime also detects changes
// when the original bytes, mode and mtime have subsequently been restored.
func sameRuleStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func openRuleDirectory(path string) (*ruleDirectory, error) {
	d := &ruleDirectory{path: path}
	if !absoluteClean(path) || unix.Lstat(path, &d.stat) != nil || d.stat.Mode&unix.S_IFMT != unix.S_IFDIR || d.stat.Mode&0o022 != 0 {
		return nil, ErrRulesUnavailable
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRulesUnavailable
	}
	d.file = os.NewFile(uintptr(fd), "verified-rule-directory")
	if d.check() != nil {
		_ = d.file.Close()
		return nil, ErrRulesUnavailable
	}
	return d, nil
}

func (d *ruleDirectory) check() error {
	var held, linked unix.Stat_t
	if unix.Fstat(int(d.file.Fd()), &held) != nil || unix.Lstat(d.path, &linked) != nil ||
		!sameRuleStat(d.stat, held) || !sameRuleStat(d.stat, linked) {
		return ErrRulesUnavailable
	}
	return nil
}

func (d *ruleDirectory) entries() ([]os.DirEntry, error) {
	// Open dot independently: dup would share an earlier enumeration offset.
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRulesUnavailable
	}
	f := os.NewFile(uintptr(fd), "verified-rule-enumeration")
	var before, after unix.Stat_t
	statErr := unix.Fstat(fd, &before)
	entries, readErr := f.ReadDir(4)
	afterErr := unix.Fstat(fd, &after)
	closeErr := f.Close()
	if statErr != nil || afterErr != nil || closeErr != nil || readErr != nil && readErr != io.EOF ||
		!sameRuleStat(d.stat, before) || !sameRuleStat(d.stat, after) || d.check() != nil {
		return nil, ErrRulesUnavailable
	}
	return entries, nil
}

func (d *ruleDirectory) open(name string) (*ruleOriginalFile, error) {
	switch name {
	case "bytecode.cvd", "bytecode.cld", "daily.cvd", "daily.cld", "main.cvd", "main.cld":
	default:
		return nil, ErrRulesUnavailable
	}
	f := &ruleOriginalFile{parent: d, name: name}
	if d.check() != nil || unix.Fstatat(int(d.file.Fd()), name, &f.stat, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		f.stat.Mode&unix.S_IFMT != unix.S_IFREG || f.stat.Mode&0o022 != 0 || f.stat.Size < 1 || f.stat.Size > ruleFileMaxBytes {
		return nil, ErrRulesUnavailable
	}
	// Native openat refuses a final symlink rather than resolving it. Nonblock
	// also prevents a substituted FIFO from hanging before the fstat refusal.
	fd, err := unix.Openat(int(d.file.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrRulesUnavailable
	}
	f.file = os.NewFile(uintptr(fd), "verified-rule-file")
	if f.check() != nil {
		_ = f.file.Close()
		return nil, ErrRulesUnavailable
	}
	return f, nil
}

func (f *ruleOriginalFile) size() int64 { return f.stat.Size }

func (f *ruleOriginalFile) check() error {
	var held, linked unix.Stat_t
	if unix.Fstat(int(f.file.Fd()), &held) != nil || unix.Fstatat(int(f.parent.file.Fd()), f.name, &linked, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!sameRuleStat(f.stat, held) || !sameRuleStat(f.stat, linked) || f.parent.check() != nil {
		return ErrRulesUnavailable
	}
	return nil
}
