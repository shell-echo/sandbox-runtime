//go:build darwin || linux

package file

import (
	"fmt"
	"os"
	"syscall"
)

func acquireLock(path string) (*os.File, error) {
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("repository is already open: %w", err)
	}
	return lock, nil
}

func releaseLock(lock *os.File) error {
	if lock == nil {
		return nil
	}
	err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	closeErr := lock.Close()
	if err != nil || closeErr != nil {
		return fmt.Errorf("release repository lock: %v; %v", err, closeErr)
	}
	return nil
}
