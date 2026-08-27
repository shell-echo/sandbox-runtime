//go:build !unix

package file

import (
	"errors"
	"os"
)

func acquireLock(string) (*os.File, error) {
	return nil, errors.New("terminal reference registry file locking is unsupported on this platform")
}

func releaseLock(*os.File) error { return nil }
