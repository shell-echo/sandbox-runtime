package process

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type productTLSMaterialProvider struct {
	materials map[secretref.Purpose]secretref.SecretMaterial
	returned  [][]byte
}

func (p *productTLSMaterialProvider) ResolveSecret(_ context.Context, binding secretref.Binding) (secretref.SecretMaterial, error) {
	material, ok := p.materials[binding.Purpose]
	if !ok || material.Binding != binding {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	material.Bytes = append([]byte(nil), material.Bytes...)
	p.returned = append(p.returned, material.Bytes)
	return material, nil
}

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

func TestLoadTLSConfigFromRegistryRequiresAtomicScopedBundle(t *testing.T) {
	now := time.Now().UTC()
	directory := t.TempDir()
	certificatePath, keyPath := writeServerIdentity(t, directory, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	registry, provider := productTLSRegistry(t, now, certificatePEM, privateKeyPEM, "bundle-revision-1", "bundle-revision-1")
	config, err := LoadTLSConfigFromRegistry(context.Background(), registry, "product-tls-certificate", "product-tls-private-key", "product.example.test", func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != 0x0304 || config.MaxVersion != 0x0304 || len(config.Certificates) != 1 {
		t.Fatalf("TLS config = %#v", config)
	}
	for _, material := range provider.returned {
		for _, value := range material {
			if value != 0 {
				t.Fatal("resolved TLS material was not cleared")
			}
		}
	}
	if _, err := LoadTLSConfigFromRegistry(context.Background(), registry, "product-tls-private-key", "product-tls-certificate", "product.example.test", func() time.Time { return now }); err == nil {
		t.Fatal("accepted purpose-swapped TLS bindings")
	}
	if _, err := LoadTLSConfigFromRegistry(context.Background(), registry, "product-tls-certificate", "product-tls-private-key", "other.example.test", func() time.Time { return now }); err == nil {
		t.Fatal("accepted SAN substitution")
	}
}

func TestLoadTLSConfigFromRegistryRejectsRevisionDrift(t *testing.T) {
	now := time.Now().UTC()
	certificatePath, keyPath := writeServerIdentity(t, t.TempDir(), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := productTLSRegistry(t, now, certificatePEM, privateKeyPEM, "bundle-revision-1", "bundle-revision-2")
	if _, err := LoadTLSConfigFromRegistry(context.Background(), registry, "product-tls-certificate", "product-tls-private-key", "product.example.test", func() time.Time { return now }); err == nil {
		t.Fatal("accepted mixed TLS revisions")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadTLSConfigFromRegistry(ctx, registry, "product-tls-certificate", "product-tls-private-key", "product.example.test", func() time.Time { return now }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled TLS resolution error = %v", err)
	}
}

func productTLSRegistry(t *testing.T, now time.Time, certificatePEM, privateKeyPEM []byte, certificateRevision, privateKeyRevision string) (*secretref.Registry, *productTLSMaterialProvider) {
	t.Helper()
	certificateBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/product-tls-certificate", Version: "v1",
		Purpose: secretref.PurposeTLSCertificate, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct,
	}
	privateKeyBinding := secretref.Binding{
		Schema: secretref.BindingSchema, Kind: secretref.KindSecret,
		Reference: "secret://vault/product-tls-private-key", Version: "v1",
		Purpose: secretref.PurposeTLSPrivateKey, TenantID: secretref.SystemTenant, Role: secretref.RoleProduct,
	}
	window := secretref.RotationWindow{NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), State: secretref.KeyActive}
	material := func(binding secretref.Binding, value []byte, revision string) secretref.SecretMaterial {
		digest := sha256.Sum256(value)
		return secretref.SecretMaterial{Binding: binding, Bytes: append([]byte(nil), value...), Digest: "sha256:" + hex.EncodeToString(digest[:]), Window: window, Revision: revision}
	}
	provider := &productTLSMaterialProvider{materials: map[secretref.Purpose]secretref.SecretMaterial{
		secretref.PurposeTLSCertificate: material(certificateBinding, certificatePEM, certificateRevision),
		secretref.PurposeTLSPrivateKey:  material(privateKeyBinding, privateKeyPEM, privateKeyRevision),
	}}
	registry, err := secretref.NewRegistry(secretref.RoleProduct,
		[]secretref.Purpose{secretref.PurposeTLSCertificate, secretref.PurposeTLSPrivateKey},
		[]secretref.ProviderRegistration{{Name: "vault-primary", Provider: provider}},
		[]secretref.BindingRegistration{
			{ID: "product-tls-certificate", Provider: "vault-primary", Binding: certificateBinding},
			{ID: "product-tls-private-key", Provider: "vault-primary", Binding: privateKeyBinding},
		}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return registry, provider
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
