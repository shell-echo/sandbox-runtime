package reference

import (
	"crypto/rand"
	"encoding/hex"
)

func SecureGenerator() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "ref:desktop-session:" + hex.EncodeToString(value), nil
}
