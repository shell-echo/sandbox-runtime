package testenv

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
	"time"
)

func TestGeneratePKIProducesUsableDistinctIdentities(t *testing.T) {
	material, err := GeneratePKI(t.TempDir(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if material.ControllerA.URI == material.ControllerB.URI || material.ControllerA.JWSKeyID == material.ControllerB.JWSKeyID {
		t.Fatal("controller identities are not distinct")
	}
	certificate, err := tls.LoadX509KeyPair(material.ControllerA.CertificateFile, material.ControllerA.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != material.ControllerA.URI {
		t.Fatalf("controller URI SAN = %v", leaf.URIs)
	}
	info, err := os.Stat(material.ControllerA.JWSPrivateFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("JWS private-key mode = %o", info.Mode().Perm())
	}
}
