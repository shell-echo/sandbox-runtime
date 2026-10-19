//go:build !linux

package controlbootstrap

import (
	"context"
	"os"
)

func readSealedKey(context.Context, *os.File) ([]byte, error) { return nil, ErrUnavailable }
