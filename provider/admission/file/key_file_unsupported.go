//go:build !darwin && !linux

package file

import (
	"errors"
	"os"
)

func openRegularTrustedKeyFile(string) (*os.File, error) {
	return nil, errors.New("trusted verification key files are supported only on Darwin and Linux")
}
