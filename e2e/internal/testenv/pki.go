package testenv

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type Identity struct {
	URI             string
	CertificateFile string
	PrivateKeyFile  string
	JWSPublicFile   string
	JWSPrivateFile  string
	JWSKeyID        string
}

type Material struct {
	CAFile                  string
	ProviderCertificateFile string
	ProviderPrivateKeyFile  string
	GatewayCertificateFile  string
	GatewayPrivateKeyFile   string
	ControllerA             Identity
	ControllerB             Identity
}

func GeneratePKI(root string, now time.Time) (Material, error) {
	if now.IsZero() {
		return Material{}, fmt.Errorf("PKI time is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return Material{}, err
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Material{}, err
	}
	caTemplate := certificateTemplate("sandbox-runtime-e2e CA", now, true)
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return Material{}, err
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return Material{}, err
	}
	caFile := filepath.Join(root, "ca.pem")
	if err := writePEM(caFile, 0o600, "CERTIFICATE", caDER); err != nil {
		return Material{}, err
	}

	providerCertificate, providerKey, err := issueServer(root, "provider", caCertificate, caPrivate, now)
	if err != nil {
		return Material{}, err
	}
	gatewayCertificate, gatewayKey, err := issueServer(root, "gateway", caCertificate, caPrivate, now)
	if err != nil {
		return Material{}, err
	}
	controllerA, err := issueController(root, "controller-a", "spiffe://reference-caller/controller-a", caCertificate, caPrivate, now)
	if err != nil {
		return Material{}, err
	}
	controllerB, err := issueController(root, "controller-b", "spiffe://reference-caller/controller-b", caCertificate, caPrivate, now)
	if err != nil {
		return Material{}, err
	}
	return Material{
		CAFile: caFile, ProviderCertificateFile: providerCertificate, ProviderPrivateKeyFile: providerKey,
		GatewayCertificateFile: gatewayCertificate, GatewayPrivateKeyFile: gatewayKey,
		ControllerA: controllerA, ControllerB: controllerB,
	}, nil
}

func issueServer(root, name string, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time) (string, string, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	template := certificateTemplate(name, now, false)
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.DNSNames = []string{"localhost"}
	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		return "", "", err
	}
	return writeTLSKeyPair(root, name, der, private)
}

func issueController(root, name, identity string, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time) (Identity, error) {
	uri, err := url.Parse(identity)
	if err != nil {
		return Identity{}, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	template := certificateTemplate(name, now, false)
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template.URIs = []*url.URL{uri}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		return Identity{}, err
	}
	certificateFile, privateKeyFile, err := writeTLSKeyPair(root, name, der, private)
	if err != nil {
		return Identity{}, err
	}
	jwsPublic, jwsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(jwsPublic)
	if err != nil {
		return Identity{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(jwsPrivate)
	if err != nil {
		return Identity{}, err
	}
	jwsPublicFile := filepath.Join(root, name+"-jws-public.pem")
	jwsPrivateFile := filepath.Join(root, name+"-jws-private.pem")
	if err := writePEM(jwsPublicFile, 0o600, "PUBLIC KEY", publicDER); err != nil {
		return Identity{}, err
	}
	if err := writePEM(jwsPrivateFile, 0o600, "PRIVATE KEY", privateDER); err != nil {
		return Identity{}, err
	}
	return Identity{
		URI: identity, CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
		JWSPublicFile: jwsPublicFile, JWSPrivateFile: jwsPrivateFile, JWSKeyID: name + "-2026-08",
	}, nil
}

func certificateTemplate(commonName string, now time.Time, isCA bool) *x509.Certificate {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour),
		BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	return template
}

func writeTLSKeyPair(root, name string, certificate []byte, private ed25519.PrivateKey) (string, string, error) {
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", "", err
	}
	certificateFile := filepath.Join(root, name+"-cert.pem")
	privateFile := filepath.Join(root, name+"-key.pem")
	if err := writePEM(certificateFile, 0o600, "CERTIFICATE", certificate); err != nil {
		return "", "", err
	}
	if err := writePEM(privateFile, 0o600, "PRIVATE KEY", privateDER); err != nil {
		return "", "", err
	}
	return certificateFile, privateFile, nil
}

func writePEM(path string, mode os.FileMode, blockType string, bytes []byte) error {
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: bytes})
	if encoded == nil {
		return fmt.Errorf("encode %s", blockType)
	}
	return os.WriteFile(path, encoded, mode)
}
