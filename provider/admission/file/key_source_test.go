package file_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/provider/admission"
	admissionfile "github.com/shell-echo/sandbox-runtime/provider/admission/file"
)

func TestLoadTrustedKeySourceLoadsBoundedSPKIPEMFiles(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	edPath := writePublicKeyFile(t, directory, "ed.pem", edPublic)
	esPath := writePublicKeyFile(t, directory, "es.pem", &esPrivate.PublicKey)

	source, err := admissionfile.LoadTrustedKeySource([]admissionfile.TrustedKeyFile{
		{ID: "ed-key", Algorithm: admission.AlgorithmEdDSA, Path: edPath},
		{ID: "es-key", Algorithm: admission.AlgorithmES256, Path: esPath},
	})
	if err != nil {
		t.Fatalf("LoadTrustedKeySource() error = %v", err)
	}
	if key, err := source.Lookup(context.Background(), "ed-key", admission.AlgorithmEdDSA); err != nil {
		t.Fatalf("Lookup(ed-key) error = %v", err)
	} else if _, ok := key.(ed25519.PublicKey); !ok {
		t.Fatalf("Lookup(ed-key) type = %T", key)
	}
	if key, err := source.Lookup(context.Background(), "es-key", admission.AlgorithmES256); err != nil {
		t.Fatalf("Lookup(es-key) error = %v", err)
	} else if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("Lookup(es-key) type = %T", key)
	}

	link := filepath.Join(directory, "linked-ed.pem")
	if err := os.Symlink(edPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := admissionfile.LoadTrustedKeySource([]admissionfile.TrustedKeyFile{{ID: "linked-ed", Algorithm: admission.AlgorithmEdDSA, Path: link}}); err != nil {
		t.Fatalf("LoadTrustedKeySource(symlink) error = %v", err)
	}
}

func TestLoadTrustedKeySourceRejectsUnsafeFilesBeforeServing(t *testing.T) {
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	validPath := writePublicKeyFile(t, directory, "valid.pem", edPublic)
	invalidTypePath := filepath.Join(directory, "invalid-type.pem")
	if err := os.WriteFile(invalidTypePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-certificate")}), 0o600); err != nil {
		t.Fatal(err)
	}
	trailingPath := filepath.Join(directory, "trailing.pem")
	validContents, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trailingPath, append(validContents, []byte("trailing")...), 0o600); err != nil {
		t.Fatal(err)
	}
	multiBlockPath := filepath.Join(directory, "multiple.pem")
	if err := os.WriteFile(multiBlockPath, append(validContents, validContents...), 0o600); err != nil {
		t.Fatal(err)
	}
	oversizedPath := filepath.Join(directory, "oversized.pem")
	if err := os.WriteFile(oversizedPath, []byte(strings.Repeat("x", 16<<10+1)), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		files []admissionfile.TrustedKeyFile
	}{
		{name: "empty"},
		{name: "missing path", files: []admissionfile.TrustedKeyFile{{ID: "key", Algorithm: admission.AlgorithmEdDSA}}},
		{name: "missing file", files: []admissionfile.TrustedKeyFile{{ID: "key", Algorithm: admission.AlgorithmEdDSA, Path: filepath.Join(directory, "missing.pem")}}},
		{name: "wrong PEM block type", files: []admissionfile.TrustedKeyFile{{ID: "key", Algorithm: admission.AlgorithmEdDSA, Path: invalidTypePath}}},
		{name: "trailing bytes", files: []admissionfile.TrustedKeyFile{{ID: "key", Algorithm: admission.AlgorithmEdDSA, Path: trailingPath}}},
		{name: "multiple PEM blocks", files: []admissionfile.TrustedKeyFile{{ID: "key", Algorithm: admission.AlgorithmEdDSA, Path: multiBlockPath}}},
		{name: "oversized", files: []admissionfile.TrustedKeyFile{{ID: "key", Algorithm: admission.AlgorithmEdDSA, Path: oversizedPath}}},
		{name: "duplicate ID", files: []admissionfile.TrustedKeyFile{{ID: "key", Algorithm: admission.AlgorithmEdDSA, Path: validPath}, {ID: "key", Algorithm: admission.AlgorithmEdDSA, Path: validPath}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := admissionfile.LoadTrustedKeySource(test.files); err == nil {
				t.Fatal("LoadTrustedKeySource() error = nil")
			}
		})
	}
}

func writePublicKeyFile(t *testing.T, directory, name string, publicKey any) string {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
