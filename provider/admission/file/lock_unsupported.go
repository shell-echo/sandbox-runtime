//go:build !darwin && !linux

package file

import (
	"errors"
	"os"
)

func acquireFileLock(string) (*os.File, error) {
	return nil, errors.New("provider admission guard file locking is unsupported on this platform")
}

func releaseFileLock(file *os.File) error {
	return file.Close()
}
