package providerapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

const remoteServerURI = "spiffe://sandbox-runtime.test/executor/browser"

func remoteTestMaterial(t *testing.T) (testCA, testCA, tls.Certificate, tls.Certificate, *tls.Config) {
	t.Helper()
	serverCA := newTestCA(t, "remote-server-ca")
	clientCA := newTestCA(t, "remote-client-ca")
	now := time.Now()
	server := issueTestCertificate(t, serverCA, testCertificateOptions{uriStrings: []string{remoteServerURI},
		dnsNames: []string{"executor.test"}, extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		notBefore: now.Add(-time.Minute), notAfter: now.Add(20 * time.Minute)})
	server.Certificate = append(server.Certificate, serverCA.certificate.Raw)
	client := issueTestCertificate(t, clientCA, testCertificateOptions{uriStrings: []string{testAllowedIdentity},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	roots := x509.NewCertPool()
	roots.AddCert(serverCA.certificate)
	clientConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "executor.test",
		Certificates: []tls.Certificate{client}}
	return serverCA, clientCA, server, client, clientConfig
}

func TestRemoteMTLSUsesLiveSignerAndFailsClosedOnLoss(t *testing.T) {
	serverCA, clientCA, server, _, clientConfig := remoteTestMaterial(t)
	var calls atomic.Int32
	var lost atomic.Bool
	config, err := LoadMTLSConfigRemote(serverCA.pem, clientCA.pem, RemoteClientIdentity{URI: testAllowedIdentity},
		RemoteServerIdentity{URI: remoteServerURI, DNSNames: []string{"executor.test"}, MaxTTL: time.Hour},
		func(context.Context) (tls.Certificate, error) {
			calls.Add(1)
			if lost.Load() {
				return tls.Certificate{}, errors.New("agent lost")
			}
			return server, nil
		}, time.Now)
	if err != nil || calls.Load() != 1 {
		t.Fatalf("bootstrap: %v calls=%d", err, calls.Load())
	}
	clientErr, serverErr := runTLSHandshake(config, clientConfig)
	if clientErr != nil || serverErr != nil || calls.Load() != 2 {
		t.Fatalf("live handshake: client=%v server=%v calls=%d", clientErr, serverErr, calls.Load())
	}
	lost.Store(true)
	clientErr, serverErr = runTLSHandshake(config, clientConfig)
	if clientErr == nil && serverErr == nil {
		t.Fatal("new handshake used stale certificate after signer loss")
	}
}

func TestRemoteMTLSRejectsIdentityIssuerAndSignerDrift(t *testing.T) {
	serverCA, clientCA, server, _, _ := remoteTestMaterial(t)
	otherCA := newTestCA(t, "other-ca")
	wrongIssuer := server
	wrongIssuer.Certificate = append([][]byte(nil), server.Certificate...)
	wrongIssuer.Certificate[1] = otherCA.certificate.Raw
	wrongSigner := server
	wrongSigner.PrivateKey = issueTestCertificate(t, serverCA, testCertificateOptions{}).PrivateKey
	wrongURI := RemoteServerIdentity{URI: "spiffe://sandbox-runtime.test/executor/other", DNSNames: []string{"executor.test"}, MaxTTL: time.Hour}
	for name, candidate := range map[string]struct {
		cert     tls.Certificate
		identity RemoteServerIdentity
		issuer   []byte
	}{
		"wrong URI":    {server, wrongURI, serverCA.pem},
		"wrong issuer": {wrongIssuer, RemoteServerIdentity{URI: remoteServerURI, DNSNames: []string{"executor.test"}, MaxTTL: time.Hour}, serverCA.pem},
		"wrong signer": {wrongSigner, RemoteServerIdentity{URI: remoteServerURI, DNSNames: []string{"executor.test"}, MaxTTL: time.Hour}, serverCA.pem},
		"wrong root":   {server, RemoteServerIdentity{URI: remoteServerURI, DNSNames: []string{"executor.test"}, MaxTTL: time.Hour}, otherCA.pem},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadMTLSConfigRemote(candidate.issuer, clientCA.pem, RemoteClientIdentity{URI: testAllowedIdentity}, candidate.identity,
				func(context.Context) (tls.Certificate, error) { return candidate.cert, nil }, time.Now)
			if err == nil {
				t.Fatal("remote certificate drift accepted")
			}
		})
	}
}

func TestRemoteMTLSRejectsExtraClientIdentity(t *testing.T) {
	serverCA, clientCA, server, _, clientConfig := remoteTestMaterial(t)
	config, err := LoadMTLSConfigRemote(serverCA.pem, clientCA.pem, RemoteClientIdentity{URI: testAllowedIdentity},
		RemoteServerIdentity{URI: remoteServerURI, DNSNames: []string{"executor.test"}, MaxTTL: time.Hour},
		func(context.Context) (tls.Certificate, error) { return server, nil }, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig.Certificates = []tls.Certificate{issueTestCertificate(t, clientCA, testCertificateOptions{
		uriStrings:  []string{testAllowedIdentity, "spiffe://sandbox-runtime.test/extra"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})}
	clientErr, serverErr := runTLSHandshake(config, clientConfig)
	if clientErr == nil && serverErr == nil {
		t.Fatal("client with extra URI identity was admitted")
	}
}
