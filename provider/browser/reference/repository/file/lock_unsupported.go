//go:build !unix

package file

import (
	"errors"
	"os"
)

func acquireLock(path string) (*os.File, error) {
	return nil, errors.New("browser reference locking is unsupported")
}
func releaseLock(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}
