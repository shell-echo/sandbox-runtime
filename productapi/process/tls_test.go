package process

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadTLSConfigRequiresPrivateTLS13ServerIdentity(t *testing.T) {
	directory := t.TempDir()
	certificatePath, keyPath := writeServerIdentity(t, directory, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	config, err := LoadTLSConfig(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("LoadTLSConfig: %v", err)
	}
	if config.MinVersion != 0x0304 || config.MaxVersion != 0x0304 || len(config.Certificates) != 1 {
		t.Fatalf("TLS config = %#v", config)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTLSConfig(certificatePath, keyPath); err == nil {
		t.Fatal("accepted broad private-key permissions")
	}
}

func TestLoadTLSConfigRejectsWrongCertificateUsage(t *testing.T) {
	directory := t.TempDir()
	certificatePath, keyPath := writeServerIdentity(t, directory, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	if _, err := LoadTLSConfig(certificatePath, keyPath); err == nil {
		t.Fatal("accepted client-only certificate")
	}
}

func TestLoadTLSConfigRejectsTrailingPEMMaterial(t *testing.T) {
	directory := t.TempDir()
	certificatePath, keyPath := writeServerIdentity(t, directory, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	file, err := os.OpenFile(certificatePath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("not-pem"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTLSConfig(certificatePath, keyPath); err == nil {
		t.Fatal("accepted trailing certificate material")
	}
}

func writeServerIdentity(t *testing.T, directory string, usages []x509.ExtKeyUsage) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "product.example.test"},
		DNSNames: []string{"product.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePath := filepath.Join(directory, "tls.crt")
	keyPath := filepath.Join(directory, "tls.key")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
