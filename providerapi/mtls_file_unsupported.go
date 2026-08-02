//go:build !darwin && !linux

package providerapi

import (
	"errors"
	"os"
)

func openRegularTLSFile(string) (*os.File, error) {
	return nil, errors.New("provider TLS material is supported only on Darwin and Linux")
}
