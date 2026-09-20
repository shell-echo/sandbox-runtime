// Package secretfile reads bounded private regular files used for process
// startup secrets. It deliberately returns no file content in errors.
package secretfile

import (
	"errors"
	"io"
	"os"
)

// Read returns the exact bytes of a non-empty private regular file. The path
// must not be a symlink, the file must not be accessible by group or others,
// and its identity must remain stable across the read.
func Read(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum < 1 {
		return nil, errors.New("invalid private file request")
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum || before.Mode().Perm() != 0o600 {
		return nil, errors.New("private file must be a non-empty bounded mode-0600 regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open private file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 {
		return nil, errors.New("private file changed while opening")
	}
	document, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(document) < 1 || int64(len(document)) > maximum || int64(len(document)) != opened.Size() {
		return nil, errors.New("read private file")
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) || after.Size() != opened.Size() || after.Mode().Perm() != 0o600 {
		clear(document)
		return nil, errors.New("private file changed while reading")
	}
	return document, nil
}
