package qualificationoperator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	ProviderIssuer   = "https://caller.example.test/control"
	ProviderAudience = "urn:shell-echo:sandbox-runtime:provider-instance:qualification"
)

var ErrCredentialPreparation = errors.New("qualification credential preparation failed")

type actorMaterial struct {
	subject        string
	certificate    tls.Certificate
	certificatePEM string
	privateKeyPEM  string
	admissionKey   ed25519.PrivateKey
	admissionID    string
}

type Credentials struct {
	Payloads map[string][]byte

	ProviderCAFile, ProviderServerCertificateFile, ProviderServerPrivateKeyFile string
	ProviderAdmissionPublicKeyFiles                                             map[string]string
	ProviderClients                                                             map[string]tls.Certificate
	ProviderSubjects                                                            map[string]string
	ProviderRoots                                                               *x509.CertPool
	ProviderProxyCertificate                                                    tls.Certificate

	GatewayProxyCertificate                tls.Certificate
	GatewayClients                         map[string]tls.Certificate
	GatewaySubjects                        map[string]string
	GatewayServerRoots, GatewayClientRoots *x509.CertPool
}

func (c *Credentials) Destroy() {
	if c == nil {
		return
	}
	for _, payload := range c.Payloads {
		clear(payload)
	}
	for _, certificate := range c.ProviderClients {
		clearTLSCertificate(&certificate)
	}
	for _, certificate := range c.GatewayClients {
		clearTLSCertificate(&certificate)
	}
	clearTLSCertificate(&c.ProviderProxyCertificate)
	clearTLSCertificate(&c.GatewayProxyCertificate)
	*c = Credentials{}
}

func PrepareCredentials(root, gatewayHost string, now time.Time) (*Credentials, error) {
	if root == "" || filepath.Clean(root) != root || !filepath.IsAbs(root) || net.ParseIP(gatewayHost) != nil || now.IsZero() {
		return nil, ErrCredentialPreparation
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, ErrCredentialPreparation
	}
	providerCA, providerCAKey, providerCAPEM, err := newCA("qualification-provider-ca", now)
	if err != nil {
		return nil, ErrCredentialPreparation
	}
	defer clear(providerCAKey)
	gatewayServerCA, gatewayServerCAKey, gatewayServerCAPEM, err := newCA("qualification-gateway-server-ca", now)
	if err != nil {
		return nil, ErrCredentialPreparation
	}
	defer clear(gatewayServerCAKey)
	gatewayClientCA, gatewayClientCAKey, gatewayClientCAPEM, err := newCA("qualification-gateway-client-ca", now)
	if err != nil {
		return nil, ErrCredentialPreparation
	}
	defer clear(gatewayClientCAKey)

	providerServer, providerServerPEM, providerServerKeyPEM, err := issueServer(providerCA, providerCAKey, "provider", "", net.ParseIP("127.0.0.1"), now)
	if err != nil {
		return nil, ErrCredentialPreparation
	}
	_ = providerServer
	providerProxy, _, _, err := issueServer(providerCA, providerCAKey, "provider-observer", "", net.ParseIP("127.0.0.1"), now)
	if err != nil {
		return nil, ErrCredentialPreparation
	}
	gatewayServer, gatewayServerPEM, gatewayServerKeyPEM, err := issueServer(gatewayServerCA, gatewayServerCAKey, "candidate-gateway", gatewayHost, nil, now)
	if err != nil {
		return nil, ErrCredentialPreparation
	}
	_ = gatewayServer
	gatewayProxy, _, _, err := issueServer(gatewayServerCA, gatewayServerCAKey, "gateway-observer", gatewayHost, nil, now)
	if err != nil {
		return nil, ErrCredentialPreparation
	}

	providerActors := make(map[string]actorMaterial, 3)
	providerClients := make(map[string]tls.Certificate, 3)
	providerSubjects := make(map[string]string, 3)
	publicKeyFiles := make(map[string]string, 2)
	for _, actor := range []string{"controller_a", "controller_b", "same_ca_unadmitted"} {
		subject := "spiffe://provider/" + actor
		client, certPEM, keyPEM, err := issueClient(providerCA, providerCAKey, actor, subject, now)
		if err != nil {
			return nil, ErrCredentialPreparation
		}
		material := actorMaterial{subject: subject, certificate: client, certificatePEM: certPEM, privateKeyPEM: keyPEM}
		if actor != "same_ca_unadmitted" {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, ErrCredentialPreparation
			}
			material.admissionKey = private
			material.admissionID = "qualification-" + actor
			encoded, err := x509.MarshalPKIXPublicKey(public)
			if err != nil {
				return nil, ErrCredentialPreparation
			}
			path := filepath.Join(root, actor+"-admission-public.pem")
			if err := writePrivate(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})); err != nil {
				return nil, ErrCredentialPreparation
			}
			publicKeyFiles[actor] = path
		}
		providerActors[actor] = material
		providerClients[actor] = client
		providerSubjects[actor] = subject
	}

	gatewayActors := make(map[string]actorMaterial, 2)
	gatewayClients := make(map[string]tls.Certificate, 2)
	gatewaySubjects := make(map[string]string, 2)
	for _, actor := range []string{"controller_a", "controller_b"} {
		subject := "spiffe://gateway/" + actor
		client, certPEM, keyPEM, err := issueClient(gatewayClientCA, gatewayClientCAKey, actor, subject, now)
		if err != nil {
			return nil, ErrCredentialPreparation
		}
		gatewayActors[actor] = actorMaterial{subject: subject, certificate: client, certificatePEM: certPEM, privateKeyPEM: keyPEM}
		gatewayClients[actor] = client
		gatewaySubjects[actor] = subject
	}

	payloads := make(map[string][]byte, 8)
	for actor, channel := range map[string]string{
		"controller_a": "provider-controller-a", "controller_b": "provider-controller-b", "same_ca_unadmitted": "provider-same-ca-unadmitted",
	} {
		material := providerActors[actor]
		var admission any
		if actor != "same_ca_unadmitted" {
			admission = map[string]any{
				"issuer": ProviderIssuer, "provider_instance_audience": ProviderAudience,
				"key_id": material.admissionID, "ed25519_private_key_base64url": base64.RawURLEncoding.EncodeToString(material.admissionKey),
			}
		}
		payloads[channel], err = json.Marshal(map[string]any{
			"format_version": 1, "credential_type": "sandbox-provider-client-credentials-v1", "actor": actor,
			"controller_subject": material.subject, "certificate_chain_pem": material.certificatePEM,
			"private_key_pem": material.privateKeyPEM, "admission": admission,
		})
		if err != nil {
			return nil, ErrCredentialPreparation
		}
		clear(material.admissionKey)
	}
	for actor, channel := range map[string]string{"controller_a": "gateway-controller-a", "controller_b": "gateway-controller-b"} {
		material := gatewayActors[actor]
		payloads[channel], err = json.Marshal(map[string]any{
			"format_version": 1, "credential_type": "sandbox-gateway-client-credentials-v1", "actor": actor,
			"controller_subject": material.subject, "certificate_chain_pem": material.certificatePEM, "private_key_pem": material.privateKeyPEM,
		})
		if err != nil {
			return nil, ErrCredentialPreparation
		}
	}
	payloads["provider-trust"] = append([]byte(nil), providerCAPEM...)
	payloads["gateway-trust"] = append([]byte(nil), gatewayServerCAPEM...)
	payloads["gateway-server"], err = json.Marshal(map[string]any{
		"format_version": 1, "credential_type": "sandbox-gateway-server-credentials-v1",
		"certificate_chain_pem": string(gatewayServerPEM), "private_key_pem": string(gatewayServerKeyPEM),
		"client_ca_certificates_pem": string(gatewayClientCAPEM),
		"controller_subjects":        map[string]string{"controller_a": gatewaySubjects["controller_a"], "controller_b": gatewaySubjects["controller_b"]},
	})
	if err != nil {
		return nil, ErrCredentialPreparation
	}

	providerCAFile := filepath.Join(root, "provider-ca.pem")
	providerServerCertificateFile := filepath.Join(root, "provider-server-cert.pem")
	providerServerPrivateKeyFile := filepath.Join(root, "provider-server-key.pem")
	for path, document := range map[string][]byte{
		providerCAFile: providerCAPEM, providerServerCertificateFile: providerServerPEM, providerServerPrivateKeyFile: providerServerKeyPEM,
	} {
		if err := writePrivate(path, document); err != nil {
			return nil, ErrCredentialPreparation
		}
	}
	providerRoots := x509.NewCertPool()
	providerRoots.AddCert(providerCA)
	gatewayServerRoots := x509.NewCertPool()
	gatewayServerRoots.AddCert(gatewayServerCA)
	gatewayClientRoots := x509.NewCertPool()
	gatewayClientRoots.AddCert(gatewayClientCA)
	return &Credentials{
		Payloads:       payloads,
		ProviderCAFile: providerCAFile, ProviderServerCertificateFile: providerServerCertificateFile,
		ProviderServerPrivateKeyFile: providerServerPrivateKeyFile, ProviderAdmissionPublicKeyFiles: publicKeyFiles,
		ProviderClients: providerClients, ProviderSubjects: providerSubjects, ProviderRoots: providerRoots,
		ProviderProxyCertificate: providerProxy,
		GatewayProxyCertificate:  gatewayProxy, GatewayClients: gatewayClients, GatewaySubjects: gatewaySubjects,
		GatewayServerRoots: gatewayServerRoots, GatewayClientRoots: gatewayClientRoots,
	}, nil
}

func newCA(commonName string, now time.Time) (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	template, err := certificateTemplate(commonName, now, true)
	if err != nil {
		return nil, nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return certificate, private, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func issueServer(ca *x509.Certificate, caKey ed25519.PrivateKey, commonName, dnsName string, ip net.IP, now time.Time) (tls.Certificate, []byte, []byte, error) {
	template, err := certificateTemplate(commonName, now, false)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if dnsName != "" {
		template.DNSNames = []string{dnsName}
	}
	if ip != nil {
		template.IPAddresses = []net.IP{ip}
	}
	return issueLeaf(ca, caKey, template)
}

func issueClient(ca *x509.Certificate, caKey ed25519.PrivateKey, commonName, subject string, now time.Time) (tls.Certificate, string, string, error) {
	template, err := certificateTemplate(commonName, now, false)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	u, err := url.Parse(subject)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	template.URIs = []*url.URL{u}
	certificate, certPEM, keyPEM, err := issueLeaf(ca, caKey, template)
	return certificate, string(certPEM), string(keyPEM), err
}

func issueLeaf(ca *x509.Certificate, caKey ed25519.PrivateKey, template *x509.Certificate) (tls.Certificate, []byte, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		clear(private)
		return tls.Certificate{}, nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		clear(private)
		return tls.Certificate{}, nil, nil, err
	}
	defer clear(keyDER)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		clear(private)
		return tls.Certificate{}, nil, nil, err
	}
	certificate.Leaf, err = x509.ParseCertificate(der)
	clear(private)
	return certificate, certPEM, keyPEM, err
}

func certificateTemplate(commonName string, now time.Time, isCA bool) (*x509.Certificate, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	return template, nil
}

func writePrivate(path string, document []byte) error {
	if len(document) == 0 {
		return ErrCredentialPreparation
	}
	return os.WriteFile(path, document, 0o600)
}

func clearTLSCertificate(certificate *tls.Certificate) {
	if certificate == nil {
		return
	}
	if key, ok := certificate.PrivateKey.(ed25519.PrivateKey); ok {
		clear(key)
	}
	certificate.PrivateKey = nil
	certificate.Certificate = nil
	certificate.Leaf = nil
}
