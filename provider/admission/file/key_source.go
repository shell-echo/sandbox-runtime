package file

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
)

const maxTrustedPublicKeyFileBytes = 16 << 10

// TrustedKeyFile identifies one operator-managed SPKI PEM public-key file.
// It contains no private key material and is consumed only at startup, before
// a future protected Provider listener can accept traffic.
type TrustedKeyFile struct {
	ID        admission.KeyID
	Algorithm admission.Algorithm
	Path      string
}

// LoadTrustedKeySource reads a bounded, exact set of SPKI PEM public keys and
// freezes them in the application-owned key source. It has no network fallback
// or runtime refresh path. Configuration and listener composition remain
// outside this adapter.
func LoadTrustedKeySource(files []TrustedKeyFile) (admission.TrustedKeySource, error) {
	if len(files) == 0 || len(files) > admission.MaxStaticTrustedKeys {
		return nil, errors.New("trusted verification key file count is outside the allowed range")
	}

	keys := make([]admission.StaticTrustedKey, 0, len(files))
	for index, file := range files {
		if strings.TrimSpace(file.Path) == "" {
			return nil, fmt.Errorf("trusted verification key file %d path is required", index)
		}
		contents, err := readTrustedPublicKeyFile(file.Path)
		if err != nil {
			return nil, fmt.Errorf("read trusted verification key file %d: %w", index, err)
		}
		publicKey, err := parseTrustedPublicKeyPEM(contents)
		if err != nil {
			return nil, fmt.Errorf("parse trusted verification key file %d: %w", index, err)
		}
		keys = append(keys, admission.StaticTrustedKey{
			ID:        file.ID,
			Algorithm: file.Algorithm,
			PublicKey: publicKey,
		})
	}

	source, err := admission.NewStaticTrustedKeySource(keys)
	if err != nil {
		return nil, fmt.Errorf("construct trusted verification key source: %w", err)
	}
	return source, nil
}

func readTrustedPublicKeyFile(path string) ([]byte, error) {
	file, err := openRegularTrustedKeyFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	contents, err := io.ReadAll(io.LimitReader(file, maxTrustedPublicKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxTrustedPublicKeyFileBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxTrustedPublicKeyFileBytes)
	}
	return contents, nil
}

func parseTrustedPublicKeyPEM(contents []byte) (any, error) {
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("file must contain exactly one public-key PEM block")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("public-key PEM is invalid")
	}
	return publicKey, nil
}
