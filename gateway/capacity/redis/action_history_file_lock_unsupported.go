//go:build !darwin && !linux

package rediscapacity

import (
	"errors"
	"os"
)

func acquireActionHistoryFileLock(string) (*os.File, error) {
	return nil, errors.New("action history witness file locking is unsupported on this platform")
}

func releaseActionHistoryFileLock(file *os.File) error {
	return file.Close()
}
