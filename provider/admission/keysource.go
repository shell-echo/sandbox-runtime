package admission

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"math/big"
)

const maxStaticTrustedKeys = 32

// StaticTrustedKey is one immutable, operator-selected public verification
// key. Loading a deployment format belongs to an outer adapter; this value
// object keeps the application port free of files and configuration packages.
type StaticTrustedKey struct {
	ID        KeyID
	Algorithm Algorithm
	PublicKey crypto.PublicKey
}

type staticTrustedKey struct {
	algorithm Algorithm
	publicKey crypto.PublicKey
}

type staticTrustedKeySource struct {
	keys map[KeyID]staticTrustedKey
}

// NewStaticTrustedKeySource freezes a bounded set of exact kid-to-algorithm
// public-key bindings. Duplicate IDs, unsupported algorithms, and a key whose
// type does not match its declared algorithm fail construction rather than
// leaving an ambiguous runtime fallback.
func NewStaticTrustedKeySource(keys []StaticTrustedKey) (TrustedKeySource, error) {
	if len(keys) == 0 || len(keys) > maxStaticTrustedKeys {
		return nil, errors.New("trusted verification key count is outside the allowed range")
	}

	frozen := make(map[KeyID]staticTrustedKey, len(keys))
	for _, entry := range keys {
		if !validBoundedText(string(entry.ID), 1, 128) || !entry.Algorithm.Supported() {
			return nil, errors.New("trusted verification key is invalid")
		}
		if _, exists := frozen[entry.ID]; exists {
			return nil, errors.New("trusted verification key ID is duplicated")
		}
		publicKey, err := clonePublicKeyForAlgorithm(entry.Algorithm, entry.PublicKey)
		if err != nil {
			return nil, errors.New("trusted verification key does not match its algorithm")
		}
		frozen[entry.ID] = staticTrustedKey{algorithm: entry.Algorithm, publicKey: publicKey}
	}

	return &staticTrustedKeySource{keys: frozen}, nil
}

func (s *staticTrustedKeySource) Lookup(ctx context.Context, keyID KeyID, algorithm Algorithm) (crypto.PublicKey, error) {
	if ctx == nil {
		return nil, errors.New("trusted verification key lookup context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("trusted verification key source is unavailable")
	}
	entry, found := s.keys[keyID]
	if !found || entry.algorithm != algorithm {
		return nil, errors.New("trusted verification key is unavailable")
	}
	publicKey, err := clonePublicKeyForAlgorithm(algorithm, entry.publicKey)
	if err != nil {
		return nil, errors.New("trusted verification key is unavailable")
	}
	return publicKey, nil
}

func clonePublicKeyForAlgorithm(algorithm Algorithm, publicKey crypto.PublicKey) (crypto.PublicKey, error) {
	switch algorithm {
	case AlgorithmEdDSA:
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid EdDSA public key")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	case AlgorithmES256:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || key == nil || key.X == nil || key.Y == nil || !elliptic.P256().IsOnCurve(key.X, key.Y) {
			return nil, errors.New("invalid ES256 public key")
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).Set(key.X),
			Y:     new(big.Int).Set(key.Y),
		}, nil
	default:
		return nil, errors.New("unsupported verification algorithm")
	}
}
