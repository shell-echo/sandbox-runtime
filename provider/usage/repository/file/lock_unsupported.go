//go:build !darwin && !linux

package file

import (
	"errors"
	"os"
)

func acquireLock(string) (*os.File, error) {
	return nil, errors.New("file usage evidence repository locking is supported only on Darwin and Linux")
}

func releaseLock(*os.File) error { return nil }
