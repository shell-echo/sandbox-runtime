package phase6vaultbootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const testIssuerID = "01234567-89ab-cdef-0123-456789abcdef"

func TestObserveIssuerRejectsBootstrapDrift(t *testing.T) {
	client, server, issuerDER, crlDER := issuerFixture(t)
	const serverName = "127.0.0.1"
	now := time.Now().UTC()
	mode := ""
	issuerReads := 0
	server.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != "short-lived-operator-token" {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		switch request.URL.Path {
		case "/v1/pki/config/issuers":
			issuerReads++
			writer.Header().Set("Content-Type", "application/json")
			switch {
			case mode == "duplicate":
				_, _ = writer.Write([]byte(`{"data":{"default":"` + testIssuerID + `","default":"` + testIssuerID + `"}}`))
			case mode == "changed" && issuerReads == 2:
				_, _ = writer.Write([]byte(`{"data":{"default":"fedcba98-7654-3210-fedc-ba9876543210"}}`))
			default:
				_, _ = writer.Write([]byte(`{"data":{"default":"` + testIssuerID + `"}}`))
			}
		case "/v1/pki/config/crl":
			writer.Header().Set("Content-Type", "application/json")
			if mode == "auto-rebuild" {
				_, _ = writer.Write([]byte(`{"data":{"disable":false,"auto_rebuild":true,"enable_delta":false}}`))
			} else {
				_, _ = writer.Write([]byte(`{"data":{"disable":false,"auto_rebuild":false,"enable_delta":false}}`))
			}
		case "/v1/pki/issuer/" + testIssuerID + "/der":
			writer.Header().Set("Content-Type", "application/pkix-cert")
			if mode == "invalid-issuer" {
				_, _ = writer.Write([]byte("not-a-certificate"))
			} else {
				_, _ = writer.Write(issuerDER)
			}
		case "/v1/pki/issuer/" + testIssuerID + "/crl/der":
			writer.Header().Set("Content-Type", "application/pkix-crl")
			switch mode {
			case "invalid-crl":
				_, _ = writer.Write([]byte("not-a-crl"))
			case "wrong-signature":
				corrupted := append([]byte(nil), crlDER...)
				corrupted[len(corrupted)-1] ^= 1
				_, _ = writer.Write(corrupted)
			default:
				_, _ = writer.Write(crlDER)
			}
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	for _, test := range []struct {
		name, mode string
		valid      bool
	}{
		{"fixed issuer and complete CRL", "", true},
		{"duplicate Vault member", "duplicate", false},
		{"non-immediate CRL", "auto-rebuild", false},
		{"invalid issuer DER", "invalid-issuer", false},
		{"invalid CRL DER", "invalid-crl", false},
		{"CRL signature mismatch", "wrong-signature", false},
		{"default alias drift", "changed", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode, issuerReads = test.mode, 0
			observed, err := ObserveIssuer(context.Background(), client, server.URL, serverName,
				[]byte("short-lived-operator-token"), now)
			if (err == nil) != test.valid {
				t.Fatalf("ObserveIssuer success = %v, want %v", err == nil, test.valid)
			}
			if test.valid && (observed.ID != testIssuerID || observed.Digest == "" ||
				observed.CRLNumber != "1" || observed.CRLNextUpdate.Before(now)) {
				t.Fatalf("verified issuer fields are incomplete: %#v", observed)
			}
		})
	}
	if _, err := ObserveIssuer(context.Background(), client, server.URL+"/", serverName, []byte("short-lived-operator-token"), now); err == nil {
		t.Fatal("noncanonical endpoint accepted")
	}
	unsafe := *client
	unsafeTransport := client.Transport.(*http.Transport).Clone()
	unsafeTransport.TLSClientConfig = unsafeTransport.TLSClientConfig.Clone()
	unsafeTransport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec -- rejection fixture
	unsafe.Transport = unsafeTransport
	if _, err := ObserveIssuer(context.Background(), &unsafe, server.URL, serverName, []byte("short-lived-operator-token"), now); err == nil {
		t.Fatal("unverified TLS client accepted")
	}
	wrongName := *client
	wrongTransport := client.Transport.(*http.Transport).Clone()
	wrongTransport.TLSClientConfig = wrongTransport.TLSClientConfig.Clone()
	wrongTransport.TLSClientConfig.ServerName = "other.sandbox-runtime.test"
	wrongName.Transport = wrongTransport
	if _, err := ObserveIssuer(context.Background(), &wrongName, server.URL, serverName, []byte("short-lived-operator-token"), now); err == nil {
		t.Fatal("substituted server identity accepted")
	}
	proxied := *client
	proxyTransport := client.Transport.(*http.Transport).Clone()
	proxyTransport.Proxy = http.ProxyFromEnvironment
	proxied.Transport = proxyTransport
	if _, err := ObserveIssuer(context.Background(), &proxied, server.URL, serverName, []byte("short-lived-operator-token"), now); err == nil {
		t.Fatal("proxy-capable bootstrap transport accepted")
	}
	if decodeVaultJSON([]byte(`{"data":`+nestedJSON(40)+`}`), new(any)) == nil {
		t.Fatal("deep Vault JSON accepted")
	}
}

func nestedJSON(depth int) string {
	value := "true"
	for range depth {
		value = "[" + value + "]"
	}
	return value
}

func issuerFixture(t *testing.T) (*http.Client, *httptest.Server, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sandbox-runtime.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverPair := issuerLeaf(t, ca, caKey, false)
	clientPair := issuerLeaf(t, ca, caKey, true)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
	}, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(http.NotFoundHandler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "127.0.0.1",
		Certificates: []tls.Certificate{clientPair},
	}}}
	t.Cleanup(client.CloseIdleConnections)
	return client, server, caDER, crlDER
}

func issuerLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, client bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return pair
}
