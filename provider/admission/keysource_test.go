package admission

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
)

func TestStaticTrustedKeySourceFreezesAndSelectsExactKeys(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	source, err := NewStaticTrustedKeySource([]StaticTrustedKey{
		{ID: "ed-key", Algorithm: AlgorithmEdDSA, PublicKey: edPublic},
		{ID: "es-key", Algorithm: AlgorithmES256, PublicKey: &esPrivate.PublicKey},
	})
	if err != nil {
		t.Fatalf("NewStaticTrustedKeySource() error = %v", err)
	}

	edPublic[0] ^= 0xff
	esPrivate.PublicKey.X.SetInt64(1)

	gotEd, err := source.Lookup(context.Background(), "ed-key", AlgorithmEdDSA)
	if err != nil {
		t.Fatalf("Lookup(ed-key) error = %v", err)
	}
	gotEdKey, ok := gotEd.(ed25519.PublicKey)
	if !ok || gotEdKey[0] == edPublic[0] {
		t.Fatal("Lookup(ed-key) did not return an immutable public-key copy")
	}
	gotEdKey[0] ^= 0xff
	gotEdAgain, err := source.Lookup(context.Background(), "ed-key", AlgorithmEdDSA)
	if err != nil || gotEdAgain.(ed25519.PublicKey)[0] == gotEdKey[0] {
		t.Fatal("Lookup(ed-key) returned mutable source state")
	}

	gotES, err := source.Lookup(context.Background(), "es-key", AlgorithmES256)
	if err != nil {
		t.Fatalf("Lookup(es-key) error = %v", err)
	}
	gotESKey, ok := gotES.(*ecdsa.PublicKey)
	if !ok || gotESKey.X.Cmp(bigOne()) == 0 {
		t.Fatal("Lookup(es-key) did not return an immutable P-256 public key")
	}
}

func TestStaticTrustedKeySourceRejectsUnsafeConstructionAndLookup(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		keys []StaticTrustedKey
	}{
		{name: "empty"},
		{name: "duplicate ID", keys: []StaticTrustedKey{{ID: "key", Algorithm: AlgorithmEdDSA, PublicKey: edPublic}, {ID: "key", Algorithm: AlgorithmEdDSA, PublicKey: edPublic}}},
		{name: "unsupported algorithm", keys: []StaticTrustedKey{{ID: "key", Algorithm: "RS256", PublicKey: edPublic}}},
		{name: "EdDSA key type mismatch", keys: []StaticTrustedKey{{ID: "key", Algorithm: AlgorithmEdDSA, PublicKey: &esPrivate.PublicKey}}},
		{name: "ES256 key type mismatch", keys: []StaticTrustedKey{{ID: "key", Algorithm: AlgorithmES256, PublicKey: edPublic}}},
		{name: "invalid ES256 point", keys: []StaticTrustedKey{{ID: "key", Algorithm: AlgorithmES256, PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256(), X: bigOne(), Y: bigOne()}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewStaticTrustedKeySource(test.keys); err == nil {
				t.Fatal("NewStaticTrustedKeySource() error = nil")
			}
		})
	}

	source, err := NewStaticTrustedKeySource([]StaticTrustedKey{{ID: "key", Algorithm: AlgorithmEdDSA, PublicKey: edPublic}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Lookup(context.Background(), "key", AlgorithmES256); err == nil {
		t.Fatal("Lookup() accepted the wrong algorithm")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Lookup(canceled, "key", AlgorithmEdDSA); !errors.Is(err, context.Canceled) {
		t.Fatalf("Lookup(canceled context) error = %v, want context cancellation", err)
	}
}

func bigOne() *big.Int {
	return big.NewInt(1)
}
