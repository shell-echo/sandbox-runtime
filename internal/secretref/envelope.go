package secretref

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"strings"
)

const MaxPlaintextBytes = 16 << 20

var (
	ErrInvalidEnvelope = errors.New("invalid encrypted envelope")
	ErrPlaintextLimit  = errors.New("encrypted plaintext exceeds limit")
)

// Envelope is the portable encrypted value stored by Product or a role. The
// key reference never leaves the provider boundary; only its version is
// retained so rotation and revocation can be enforced on decrypt.
type Envelope struct {
	KeyVersion string
	Nonce      []byte
	Ciphertext []byte
}

func Seal(ctx context.Context, provider KeyProvider, reference Reference, version string, plaintext, associatedData []byte) (Envelope, error) {
	if len(plaintext) > MaxPlaintextBytes {
		return Envelope{}, ErrPlaintextLimit
	}
	if provider == nil || ctx == nil || reference.Validate() != nil || strings.TrimSpace(version) == "" {
		return Envelope{}, ErrInvalidEnvelope
	}
	material, err := provider.ResolveKey(ctx, reference, version)
	if err != nil {
		return Envelope{}, err
	}
	if material.Validate() != nil || material.Reference != reference || material.Version != version {
		return Envelope{}, ErrInvalidEnvelope
	}
	defer clear(material.Bytes)
	ciphertext, nonce, err := encrypt(material.Bytes, plaintext, associatedData)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{KeyVersion: material.Version, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func Open(ctx context.Context, provider KeyProvider, reference Reference, envelope Envelope, associatedData []byte) ([]byte, error) {
	if provider == nil || ctx == nil || reference.Validate() != nil || strings.TrimSpace(envelope.KeyVersion) == "" || len(envelope.Nonce) == 0 || len(envelope.Ciphertext) == 0 || len(envelope.Ciphertext) > MaxPlaintextBytes+128 {
		return nil, ErrInvalidEnvelope
	}
	material, err := provider.ResolveKey(ctx, reference, envelope.KeyVersion)
	if err != nil {
		return nil, err
	}
	if material.Validate() != nil || material.Reference != reference || material.Version != envelope.KeyVersion {
		return nil, ErrInvalidEnvelope
	}
	defer clear(material.Bytes)
	return decrypt(material.Bytes, envelope.Nonce, envelope.Ciphertext, associatedData)
}

func encrypt(key, plaintext, associatedData []byte) ([]byte, []byte, error) {
	ciphertext, nonce, err := sealWithKey(key, plaintext, associatedData)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, nonce, nil
}

func sealWithKey(key, plaintext, associatedData []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, ErrInvalidEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, ErrInvalidEnvelope
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, ErrInvalidEnvelope
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nonce, nil
}

func decrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != aead.NonceSize() || len(ciphertext) < aead.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil || len(plaintext) > MaxPlaintextBytes {
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}
