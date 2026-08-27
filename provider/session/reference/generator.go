package reference

import (
	"crypto/rand"
	"encoding/hex"
)

// SecureGenerator returns a uniformly random opaque reference. It contains no
// encoded session, tenant, backend, or network information.
func SecureGenerator() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "ref:session:" + hex.EncodeToString(bytes), nil
}
