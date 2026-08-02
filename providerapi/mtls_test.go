package providerapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testServerName      = "provider.test"
	testAllowedIdentity = "spiffe://agent-platform/provider-client"
)

type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

type testCertificateOptions struct {
	commonName  string
	dnsNames    []string
	emails      []string
	ipAddresses []net.IP
	uriStrings  []string
	extKeyUsage []x509.ExtKeyUsage
	notBefore   time.Time
	notAfter    time.Time
}

type testMTLSMaterial struct {
	serverConfig *tls.Config
	clientRoots  *x509.CertPool
	client       tls.Certificate
	ca           testCA
	directory    string
	serverCert   string
	serverKey    string
	clientCA     string
}

func TestLoadMTLSConfigAdmitsExactVerifiedURI(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})

	clientErr, serverErr := runTLSHandshake(material.serverConfig, clientTLSConfig(material, &material.client))
	if clientErr != nil || serverErr != nil {
		t.Fatalf("valid mTLS handshake failed: client=%v server=%v", clientErr, serverErr)
	}
}

func TestLoadMTLSConfigRejectsCertificateFailures(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		clientCert func(*testing.T, testMTLSMaterial) *tls.Certificate
	}{
		{
			name:       "no client certificate",
			clientCert: func(*testing.T, testMTLSMaterial) *tls.Certificate { return nil },
		},
		{
			name: "untrusted client CA",
			clientCert: func(t *testing.T, material testMTLSMaterial) *tls.Certificate {
				otherCA := newTestCA(t, "untrusted")
				certificate := issueTestCertificate(t, otherCA, testCertificateOptions{
					uriStrings:  []string{testAllowedIdentity},
					extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				})
				return &certificate
			},
		},
		{
			name: "expired client certificate",
			clientCert: func(t *testing.T, material testMTLSMaterial) *tls.Certificate {
				certificate := issueTestCertificate(t, material.ca, testCertificateOptions{
					uriStrings:  []string{testAllowedIdentity},
					extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					notBefore:   now.Add(-2 * time.Hour),
					notAfter:    now.Add(-time.Hour),
				})
				return &certificate
			},
		},
		{
			name: "not yet valid client certificate",
			clientCert: func(t *testing.T, material testMTLSMaterial) *tls.Certificate {
				certificate := issueTestCertificate(t, material.ca, testCertificateOptions{
					uriStrings:  []string{testAllowedIdentity},
					extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					notBefore:   now.Add(time.Hour),
					notAfter:    now.Add(2 * time.Hour),
				})
				return &certificate
			},
		},
		{
			name: "wrong extended key usage",
			clientCert: func(t *testing.T, material testMTLSMaterial) *tls.Certificate {
				certificate := issueTestCertificate(t, material.ca, testCertificateOptions{
					uriStrings:  []string{testAllowedIdentity},
					extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				})
				return &certificate
			},
		},
		{
			name: "missing client-auth extended key usage",
			clientCert: func(t *testing.T, material testMTLSMaterial) *tls.Certificate {
				certificate := issueTestCertificate(t, material.ca, testCertificateOptions{
					uriStrings: []string{testAllowedIdentity},
				})
				return &certificate
			},
		},
		{
			name: "any extended key usage",
			clientCert: func(t *testing.T, material testMTLSMaterial) *tls.Certificate {
				certificate := issueTestCertificate(t, material.ca, testCertificateOptions{
					uriStrings:  []string{testAllowedIdentity},
					extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
				})
				return &certificate
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
			clientErr, serverErr := runTLSHandshake(material.serverConfig, clientTLSConfig(material, tt.clientCert(t, material)))
			if clientErr == nil && serverErr == nil {
				t.Fatal("handshake unexpectedly succeeded")
			}
		})
	}
}

func TestLoadMTLSConfigRejectsUnallowedIdentitySources(t *testing.T) {
	tests := []struct {
		name      string
		allowlist []string
		options   testCertificateOptions
	}{
		{
			name:      "no URI SAN",
			allowlist: []string{testAllowedIdentity},
			options:   testCertificateOptions{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		},
		{
			name:      "different URI SAN",
			allowlist: []string{testAllowedIdentity},
			options: testCertificateOptions{
				uriStrings:  []string{"spiffe://agent-platform/other-client"},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			name:      "common name",
			allowlist: []string{testAllowedIdentity},
			options: testCertificateOptions{
				commonName:  testAllowedIdentity,
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			name:      "DNS SAN",
			allowlist: []string{"https://client.example"},
			options: testCertificateOptions{
				dnsNames:    []string{"client.example"},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			name:      "email SAN",
			allowlist: []string{"mailto:client@example.test"},
			options: testCertificateOptions{
				emails:      []string{"client@example.test"},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			name:      "IP SAN",
			allowlist: []string{"https://192.0.2.1"},
			options: testCertificateOptions{
				ipAddresses: []net.IP{net.ParseIP("192.0.2.1")},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := newTestMTLSMaterial(t, tt.allowlist)
			certificate := issueTestCertificate(t, material.ca, tt.options)
			clientErr, serverErr := runTLSHandshake(material.serverConfig, clientTLSConfig(material, &certificate))
			if clientErr == nil && serverErr == nil {
				t.Fatal("handshake unexpectedly succeeded")
			}
		})
	}
}

func TestLoadMTLSConfigAdmitsOneExactURIAmongMultiple(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	certificate := issueTestCertificate(t, material.ca, testCertificateOptions{
		uriStrings:  []string{"urn:example:not-allowed", testAllowedIdentity, "https://example.test/also-not-allowed"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	clientErr, serverErr := runTLSHandshake(material.serverConfig, clientTLSConfig(material, &certificate))
	if clientErr != nil || serverErr != nil {
		t.Fatalf("valid mTLS handshake failed: client=%v server=%v", clientErr, serverErr)
	}
}

func TestLoadMTLSConfigDoesNotNormalizeIdentityForAdmission(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{"https://EXAMPLE.test/%7Eclient"})
	certificate := issueTestCertificate(t, material.ca, testCertificateOptions{
		uriStrings:  []string{"https://example.test/~client"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	clientErr, serverErr := runTLSHandshake(material.serverConfig, clientTLSConfig(material, &certificate))
	if clientErr == nil && serverErr == nil {
		t.Fatal("semantically similar but non-identical URI unexpectedly succeeded")
	}
}

func TestLoadMTLSConfigRejectsInvalidAllowlist(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	tests := []struct {
		name       string
		identities []string
	}{
		{name: "nil", identities: nil},
		{name: "empty", identities: []string{}},
		{name: "empty entry", identities: []string{""}},
		{name: "relative URI", identities: []string{"provider/client"}},
		{name: "fragment URI", identities: []string{"urn:provider:client#fragment"}},
		{name: "malformed URI", identities: []string{"https://example.test/%zz"}},
		{name: "noncanonical URI", identities: []string{"https://example.test/a b"}},
		{name: "invalid UTF-8", identities: []string{string([]byte{0xff})}},
		{name: "oversized identity", identities: []string{"urn:" + strings.Repeat("a", 2045)}},
		{name: "oversized list", identities: testAllowedURIIdentities(33)},
		{name: "duplicate", identities: []string{testAllowedIdentity, testAllowedIdentity}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadMTLSConfig(material.serverCert, material.serverKey, material.clientCA, tt.identities); err == nil {
				t.Fatal("LoadMTLSConfig unexpectedly succeeded")
			}
		})
	}
}

func TestLoadMTLSConfigRejectsInvalidFiles(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	otherCA := newTestCA(t, "other-server")
	otherServer := issueTestCertificate(t, otherCA, testCertificateOptions{
		dnsNames:    []string{testServerName},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	otherKeyPath := filepath.Join(material.directory, "other-server.key")
	writeTestFile(t, otherKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshalECPrivateKey(t, otherServer.PrivateKey.(*ecdsa.PrivateKey))}))

	emptyPath := filepath.Join(material.directory, "empty.pem")
	writeTestFile(t, emptyPath, nil)
	malformedPath := filepath.Join(material.directory, "malformed.pem")
	writeTestFile(t, malformedPath, []byte("not PEM"))
	nonCertificatePath := filepath.Join(material.directory, "private-key.pem")
	writeTestFile(t, nonCertificatePath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshalECPrivateKey(t, material.ca.key)}))
	nonCAPath := filepath.Join(material.directory, "not-a-ca.crt")
	writeTestFile(t, nonCAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: material.client.Certificate[0]}))
	missingPath := filepath.Join(material.directory, "missing.pem")
	oversizedCertificatePath := filepath.Join(material.directory, "oversized-certificate.pem")
	writeTestFile(t, oversizedCertificatePath, padPEMToSize(t, readTestFile(t, material.serverCert), maxServerCertificateBytes+1))
	oversizedKeyPath := filepath.Join(material.directory, "oversized-key.pem")
	writeTestFile(t, oversizedKeyPath, padPEMToSize(t, readTestFile(t, material.serverKey), maxServerPrivateKeyBytes+1))
	oversizedCAPath := filepath.Join(material.directory, "oversized-ca.pem")
	writeTestFile(t, oversizedCAPath, padPEMToSize(t, readTestFile(t, material.clientCA), maxClientCABundleBytes+1))
	nonRegularPath := filepath.Join(material.directory, "non-regular")
	if err := os.Mkdir(nonRegularPath, 0o700); err != nil {
		t.Fatalf("create non-regular TLS path: %v", err)
	}

	tests := []struct {
		name     string
		certPath string
		keyPath  string
		caPath   string
		wantText string
	}{
		{name: "empty path", certPath: "", keyPath: material.serverKey, caPath: material.clientCA},
		{name: "missing certificate", certPath: missingPath, keyPath: material.serverKey, caPath: material.clientCA},
		{name: "empty certificate", certPath: emptyPath, keyPath: material.serverKey, caPath: material.clientCA},
		{name: "malformed certificate", certPath: malformedPath, keyPath: material.serverKey, caPath: material.clientCA},
		{name: "oversized certificate", certPath: oversizedCertificatePath, keyPath: material.serverKey, caPath: material.clientCA, wantText: "file exceeds 65536 bytes"},
		{name: "missing key", certPath: material.serverCert, keyPath: missingPath, caPath: material.clientCA},
		{name: "oversized key", certPath: material.serverCert, keyPath: oversizedKeyPath, caPath: material.clientCA, wantText: "file exceeds 65536 bytes"},
		{name: "mismatched key pair", certPath: material.serverCert, keyPath: otherKeyPath, caPath: material.clientCA},
		{name: "missing client CA", certPath: material.serverCert, keyPath: material.serverKey, caPath: missingPath},
		{name: "empty client CA", certPath: material.serverCert, keyPath: material.serverKey, caPath: emptyPath},
		{name: "malformed client CA", certPath: material.serverCert, keyPath: material.serverKey, caPath: malformedPath},
		{name: "non-certificate client CA", certPath: material.serverCert, keyPath: material.serverKey, caPath: nonCertificatePath},
		{name: "non-CA client certificate", certPath: material.serverCert, keyPath: material.serverKey, caPath: nonCAPath},
		{name: "oversized client CA", certPath: material.serverCert, keyPath: material.serverKey, caPath: oversizedCAPath, wantText: "file exceeds 262144 bytes"},
		{name: "non-regular certificate", certPath: nonRegularPath, keyPath: material.serverKey, caPath: material.clientCA, wantText: "file must be a regular file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadMTLSConfig(tt.certPath, tt.keyPath, tt.caPath, []string{testAllowedIdentity})
			if err == nil {
				t.Fatal("LoadMTLSConfig unexpectedly succeeded")
			}
			if tt.wantText != "" && !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("LoadMTLSConfig error = %q, want text %q", err, tt.wantText)
			}
		})
	}
}

func TestLoadMTLSConfigAcceptsTLSMaterialAtSizeLimits(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	certificatePEM := readTestFile(t, material.serverCert)
	privateKeyPEM := readTestFile(t, material.serverKey)
	clientCAPEM := readTestFile(t, material.clientCA)

	certificatePath := filepath.Join(material.directory, "maximum-certificate.pem")
	writeTestFile(t, certificatePath, padPEMToSize(t, certificatePEM, maxServerCertificateBytes))
	privateKeyPath := filepath.Join(material.directory, "maximum-key.pem")
	writeTestFile(t, privateKeyPath, padPEMToSize(t, privateKeyPEM, maxServerPrivateKeyBytes))
	clientCAPath := filepath.Join(material.directory, "maximum-ca.pem")
	writeTestFile(t, clientCAPath, padPEMToSize(t, clientCAPEM, maxClientCABundleBytes))

	if _, err := loadMTLSConfig(certificatePath, privateKeyPath, clientCAPath, []string{testAllowedIdentity}); err != nil {
		t.Fatalf("loadMTLSConfig rejected TLS material at documented size limits: %v", err)
	}
}

func TestLoadCertPoolCertificateCountBoundary(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	clientCAPEM := readTestFile(t, material.clientCA)
	maximumPath := filepath.Join(material.directory, "maximum-ca-count.pem")
	writeTestFile(t, maximumPath, bytes.Repeat(clientCAPEM, maxClientCACertificates))
	if _, err := loadCertPool(maximumPath); err != nil {
		t.Fatalf("loadCertPool rejected maximum certificate count: %v", err)
	}

	overflowPath := filepath.Join(material.directory, "overflow-ca-count.pem")
	writeTestFile(t, overflowPath, bytes.Repeat(clientCAPEM, maxClientCACertificates+1))
	if _, err := loadCertPool(overflowPath); err == nil {
		t.Fatal("loadCertPool accepted too many certificates")
	}

	malformedPath := filepath.Join(material.directory, "maximum-ca-count-malformed-tail.pem")
	writeTestFile(t, malformedPath, append(bytes.Repeat(clientCAPEM, maxClientCACertificates), []byte("not PEM")...))
	if _, err := loadCertPool(malformedPath); err == nil || !strings.Contains(err.Error(), "malformed PEM data") {
		t.Fatalf("loadCertPool malformed tail error = %v", err)
	}

	nonCertificatePath := filepath.Join(material.directory, "maximum-ca-count-key-tail.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshalECPrivateKey(t, material.ca.key)})
	writeTestFile(t, nonCertificatePath, append(bytes.Repeat(clientCAPEM, maxClientCACertificates), keyPEM...))
	if _, err := loadCertPool(nonCertificatePath); err == nil || !strings.Contains(err.Error(), "non-certificate PEM block") {
		t.Fatalf("loadCertPool non-certificate tail error = %v", err)
	}
}

func TestLoadMTLSConfigRejectsSemanticallyInvalidMaterial(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	now := time.Now()
	serverCases := []struct {
		name    string
		options testCertificateOptions
	}{
		{
			name: "expired server",
			options: testCertificateOptions{dnsNames: []string{testServerName},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)},
		},
		{
			name: "future server",
			options: testCertificateOptions{dnsNames: []string{testServerName},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, notBefore: now.Add(time.Hour), notAfter: now.Add(2 * time.Hour)},
		},
		{
			name:    "missing server-auth usage",
			options: testCertificateOptions{dnsNames: []string{testServerName}},
		},
		{
			name: "client-auth-only server",
			options: testCertificateOptions{dnsNames: []string{testServerName},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		},
		{
			name: "any-usage server",
			options: testCertificateOptions{dnsNames: []string{testServerName},
				extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		},
	}
	for _, test := range serverCases {
		t.Run(test.name, func(t *testing.T) {
			certificate := issueTestCertificate(t, material.ca, test.options)
			certPath := filepath.Join(material.directory, test.name+".crt")
			keyPath := filepath.Join(material.directory, test.name+".key")
			writeTestFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}))
			writeTestFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshalECPrivateKey(t, certificate.PrivateKey.(*ecdsa.PrivateKey))}))
			if _, err := loadMTLSConfig(certPath, keyPath, material.clientCA, []string{testAllowedIdentity}); err == nil {
				t.Fatal("loadMTLSConfig accepted semantically invalid server certificate")
			}
		})
	}

	for _, test := range []struct {
		name string
		ca   testCA
	}{
		{name: "expired client CA", ca: newTestCAWithValidity(t, "expired-ca", now.Add(-2*time.Hour), now.Add(-time.Hour))},
		{name: "future client CA", ca: newTestCAWithValidity(t, "future-ca", now.Add(time.Hour), now.Add(2*time.Hour))},
	} {
		t.Run(test.name, func(t *testing.T) {
			caPath := filepath.Join(material.directory, test.name+".crt")
			writeTestFile(t, caPath, test.ca.pem)
			if _, err := loadMTLSConfig(material.serverCert, material.serverKey, caPath, []string{testAllowedIdentity}); err == nil {
				t.Fatal("loadMTLSConfig accepted client CA outside its validity period")
			}
		})
	}
}

func TestLoadMTLSConfigPolicyAndFrozenAllowlist(t *testing.T) {
	identities := []string{testAllowedIdentity}
	material := newTestMTLSMaterial(t, identities)
	if material.serverConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2", material.serverConfig.MinVersion)
	}
	if material.serverConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", material.serverConfig.ClientAuth)
	}
	if material.serverConfig.ClientCAs == nil {
		t.Fatal("ClientCAs is nil")
	}

	identities[0] = "spiffe://agent-platform/replaced"
	identities = append(identities, "spiffe://agent-platform/added")
	clientErr, serverErr := runTLSHandshake(material.serverConfig, clientTLSConfig(material, &material.client))
	if clientErr != nil || serverErr != nil {
		t.Fatalf("allowlist mutation changed admission: client=%v server=%v", clientErr, serverErr)
	}
}

func TestLoadMTLSConfigRejectsTLSBefore12(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	clientConfig := clientTLSConfig(material, &material.client)
	clientConfig.MaxVersion = tls.VersionTLS11

	clientErr, serverErr := runTLSHandshake(material.serverConfig, clientConfig)
	if clientErr == nil && serverErr == nil {
		t.Fatal("TLS 1.1 handshake unexpectedly succeeded")
	}
}

func TestLoadMTLSConfigRejectsUnverifiedConnectionState(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	if err := material.serverConfig.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("VerifyConnection accepted state without a verified chain")
	}
	if err := material.serverConfig.VerifyConnection(tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{nil}}}); err == nil {
		t.Fatal("VerifyConnection accepted state without a verified leaf")
	}
}

func newTestMTLSMaterial(t *testing.T, identities []string) testMTLSMaterial {
	t.Helper()
	directory := t.TempDir()
	ca := newTestCA(t, "client-ca")
	serverCA := newTestCA(t, "server-ca")
	server := issueTestCertificate(t, serverCA, testCertificateOptions{
		dnsNames:    []string{testServerName},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	client := issueTestCertificate(t, ca, testCertificateOptions{
		uriStrings:  []string{testAllowedIdentity},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	serverCertPath := filepath.Join(directory, "server.crt")
	serverKeyPath := filepath.Join(directory, "server.key")
	clientCAPath := filepath.Join(directory, "client-ca.crt")
	writeTestFile(t, serverCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate[0]}))
	writeTestFile(t, serverKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshalECPrivateKey(t, server.PrivateKey.(*ecdsa.PrivateKey))}))
	writeTestFile(t, clientCAPath, ca.pem)

	serverConfig, err := loadMTLSConfig(serverCertPath, serverKeyPath, clientCAPath, identities)
	if err != nil {
		t.Fatalf("LoadMTLSConfig: %v", err)
	}
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverCA.certificate)

	return testMTLSMaterial{
		serverConfig: serverConfig,
		clientRoots:  serverRoots,
		client:       client,
		ca:           ca,
		directory:    directory,
		serverCert:   serverCertPath,
		serverKey:    serverKeyPath,
		clientCA:     clientCAPath,
	}
}

func newTestCA(t *testing.T, commonName string) testCA {
	return newTestCAWithValidity(t, commonName, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func newTestCAWithValidity(t *testing.T, commonName string, notBefore, notAfter time.Time) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return testCA{
		certificate: certificate,
		key:         key,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func issueTestCertificate(t *testing.T, ca testCA, options testCertificateOptions) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	if options.notBefore.IsZero() {
		options.notBefore = time.Now().Add(-time.Hour)
	}
	if options.notAfter.IsZero() {
		options.notAfter = time.Now().Add(time.Hour)
	}
	var uris []*url.URL
	for _, rawURI := range options.uriStrings {
		uri, err := url.Parse(rawURI)
		if err != nil {
			t.Fatalf("parse test URI: %v", err)
		}
		uris = append(uris, uri)
	}
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: options.commonName},
		NotBefore:      options.notBefore,
		NotAfter:       options.notAfter,
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    options.extKeyUsage,
		DNSNames:       append([]string(nil), options.dnsNames...),
		EmailAddresses: append([]string(nil), options.emails...),
		IPAddresses:    append([]net.IP(nil), options.ipAddresses...),
		URIs:           uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func marshalECPrivateKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC private key: %v", err)
	}
	return der
}

func writeTestFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}
	return contents
}

func padPEMToSize(t *testing.T, contents []byte, size int) []byte {
	t.Helper()
	if len(contents) > size {
		t.Fatalf("PEM material length %d exceeds test boundary %d", len(contents), size)
	}
	padded := append([]byte(nil), contents...)
	return append(padded, bytes.Repeat([]byte(" "), size-len(padded))...)
}

func testAllowedURIIdentities(count int) []string {
	identities := make([]string, count)
	for index := range identities {
		identities[index] = fmt.Sprintf("urn:test:provider-client:%d", index)
	}
	return identities
}

func clientTLSConfig(material testMTLSMaterial, clientCertificate *tls.Certificate) *tls.Config {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    material.clientRoots,
		ServerName: testServerName,
	}
	if clientCertificate != nil {
		config.Certificates = []tls.Certificate{*clientCertificate}
	}
	return config
}

func runTLSHandshake(serverConfig, clientConfig *tls.Config) (error, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err, err
	}
	defer listener.Close()

	deadline := time.Now().Add(5 * time.Second)
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(deadline)
		serverResult <- tls.Server(connection, serverConfig).Handshake()
	}()

	clientSide, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		_ = listener.Close()
		return err, err
	}
	defer clientSide.Close()
	_ = clientSide.SetDeadline(deadline)
	client := tls.Client(clientSide, clientConfig)
	clientErr := client.Handshake()
	serverErr := <-serverResult
	return clientErr, serverErr
}
