//go:build !darwin && !linux

package file

import (
	"errors"
	"os"
)

func acquireFileLock(string) (*os.File, error) {
	return nil, errors.New("file repository locking is supported only on Darwin and Linux")
}

func releaseFileLock(file *os.File) error {
	return file.Close()
}
