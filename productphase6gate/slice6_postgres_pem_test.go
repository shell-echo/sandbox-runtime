//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestSlice6CanonicalPostgresCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	withoutFinalLF := bytes.TrimSuffix(canonical, []byte("\n"))
	for _, sample := range []struct {
		name      string
		document  []byte
		canonical bool
	}{
		{"canonical", canonical, true},
		{"vault-no-final-lf", withoutFinalLF, false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			got, certificate, wasCanonical, err := slice6CanonicalPostgresCertificate(sample.document)
			if err != nil || !bytes.Equal(got, canonical) || !bytes.Equal(certificate.Raw, der) ||
				wasCanonical != sample.canonical {
				t.Fatal("one exact certificate DER did not canonicalize")
			}
		})
	}
	for _, sample := range []struct {
		name     string
		document []byte
	}{
		{"prefix", append([]byte("ignored\n"), canonical...)},
		{"trailing-space", append(bytes.Clone(canonical), ' ')},
		{"extra-lf", append(bytes.Clone(canonical), '\n')},
		{"second-block", append(bytes.Clone(canonical), canonical...)},
		{"wrong-type", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})},
		{"header", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X": "Y"}, Bytes: der})},
		{"invalid-der", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if _, _, _, err := slice6CanonicalPostgresCertificate(sample.document); err == nil {
				t.Fatal("invalid Vault certificate representation accepted")
			}
		})
	}
}
