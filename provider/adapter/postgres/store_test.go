package providerpostgres

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestStoredDocumentPreservesNULBearingDomainJSON(t *testing.T) {
	raw := []byte(`{"scope":"sandbox-1\u0000create-key-1"}`)
	stored, err := json.Marshal(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	decoded, exists, err := decodeStoredDocument(stored)
	if err != nil || !exists || string(decoded) != string(raw) {
		t.Fatalf("decoded = %q, %t, %v", decoded, exists, err)
	}
}

func TestStoredDocumentRejectsNonCanonicalShapes(t *testing.T) {
	for _, document := range [][]byte{
		[]byte(`{}`),
		[]byte(`"not-base64"`),
		[]byte(`""`),
	} {
		if _, _, err := decodeStoredDocument(document); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("decode %q error = %v, want ErrCorrupt", document, err)
		}
	}
	if decoded, exists, err := decodeStoredDocument([]byte("null")); err != nil || exists || decoded != nil {
		t.Fatalf("null document = %q, %t, %v", decoded, exists, err)
	}
}
