//go:build darwin || linux

package phase6rolecandidate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type candidateDirectory struct {
	path string
	stat unix.Stat_t
}

type candidateFile struct {
	path, name string
	parent     int
	file       *os.File
	stat       unix.Stat_t
	dirs       []candidateDirectory
}

func (s *candidateFile) size() int64 { return s.stat.Size }

func sameCandidateStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func openCandidateFile(path string, maximum int64) (*candidateFile, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum < 1 {
		return nil, ErrInvalidControlCandidate
	}
	s := &candidateFile{path: path, name: filepath.Base(path), parent: -1}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, ErrInvalidControlCandidate
		}
		s.dirs = append(s.dirs, candidateDirectory{p, st})
		if p == string(filepath.Separator) {
			break
		}
	}
	d := s.dirs[0].stat
	if d.Uid != uint32(os.Geteuid()) || d.Mode&0o7777 != 0o700 {
		return nil, ErrInvalidControlCandidate
	}
	fd, err := unix.Open(s.dirs[0].path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalidControlCandidate
	}
	s.parent = fd
	child, err := unix.Openat(fd, s.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = s.Close()
		return nil, ErrInvalidControlCandidate
	}
	s.file = os.NewFile(uintptr(child), "control-candidate-input")
	if unix.Fstat(child, &s.stat) != nil || s.stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		s.stat.Mode&0o7777 != 0o600 || s.stat.Uid != uint32(os.Geteuid()) || s.stat.Nlink != 1 ||
		s.stat.Size < 1 || s.stat.Size > maximum || s.check() != nil {
		_ = s.Close()
		return nil, ErrInvalidControlCandidate
	}
	return s, nil
}

func (s *candidateFile) check() error {
	if s == nil || s.file == nil || s.parent < 0 {
		return ErrInvalidControlCandidate
	}
	var held, linked, parent unix.Stat_t
	if unix.Fstat(int(s.file.Fd()), &held) != nil || unix.Fstatat(s.parent, s.name, &linked, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!sameCandidateStat(s.stat, held) || !sameCandidateStat(s.stat, linked) || unix.Fstat(s.parent, &parent) != nil ||
		!sameCandidateStat(s.dirs[0].stat, parent) {
		return ErrInvalidControlCandidate
	}
	for i, d := range s.dirs {
		var actual unix.Stat_t
		if unix.Lstat(d.path, &actual) != nil || actual.Dev != d.stat.Dev || actual.Ino != d.stat.Ino ||
			actual.Mode != d.stat.Mode || actual.Uid != d.stat.Uid || actual.Gid != d.stat.Gid ||
			(i == 0 && !sameCandidateStat(d.stat, actual)) {
			return ErrInvalidControlCandidate
		}
	}
	return nil
}

// Each pass reads the held original, verifies EOF and all stable attributes,
// and checks cancellation between bounded chunks. The supervised operator run
// supplies the separate hard wall limit for filesystem syscalls.
func (s *candidateFile) copy(ctx context.Context, destination io.Writer) (string, error) {
	if ctx == nil || ctx.Err() != nil || s.check() != nil {
		return "", ErrInvalidControlCandidate
	}
	h := sha256.New()
	w := io.Writer(h)
	if destination != nil {
		w = io.MultiWriter(destination, h)
	}
	r := io.NewSectionReader(s.file, 0, s.stat.Size+1)
	buf := make([]byte, 64<<10)
	var count int64
	for {
		if ctx.Err() != nil {
			return "", ErrInvalidControlCandidate
		}
		n, err := r.Read(buf)
		count += int64(n)
		if count > s.stat.Size {
			return "", ErrInvalidControlCandidate
		}
		if n > 0 {
			written, writeErr := w.Write(buf[:n])
			if writeErr != nil || written != n {
				return "", ErrInvalidControlCandidate
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", ErrInvalidControlCandidate
		}
	}
	if ctx.Err() != nil || count != s.stat.Size || s.check() != nil {
		return "", ErrInvalidControlCandidate
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func (s *candidateFile) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.file != nil {
		err = s.file.Close()
		s.file = nil
	}
	if s.parent >= 0 {
		if e := unix.Close(s.parent); e != nil {
			err = e
		}
		s.parent = -1
	}
	return err
}

// This is a pressure precheck, not a reservation or proof of a filesystem
// quota. Every actual copy/build error and oversized output still fails.
func candidateSpace(path string) error {
	var st unix.Statfs_t
	if unix.Statfs(path, &st) != nil || !candidateSpaceAvailable(uint64(st.Bavail), int64(st.Bsize)) {
		return ErrInvalidControlCandidate
	}
	return nil
}
