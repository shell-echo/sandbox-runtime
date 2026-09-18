package product

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

type CryptoIDGenerator struct{}

func (CryptoIDGenerator) NewID(prefix string) (string, error) {
	if prefix == "" || !validIdentifier(prefix) {
		return "", ErrInvalid
	}
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate product ID: %w", err)
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}
