//go:build !darwin && !linux

package edge

import (
	"errors"
	"os"
)

func openRegularPublicTLSFile(string) (*os.File, error) {
	return nil, errors.New("public-edge TLS material is supported only on Darwin and Linux")
}
