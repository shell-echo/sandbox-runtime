package providerapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/option"
	"github.com/shell-echo/sandbox-runtime/provider"
)

const admittedSPIFFEID = "spiffe://agent-platform.test/control-plane/sandbox"

type capabilityServiceFunc func(context.Context) (provider.Capabilities, error)

func (f capabilityServiceFunc) Capabilities(ctx context.Context) (provider.Capabilities, error) {
	return f(ctx)
}

func TestProviderServerMTLSCapabilityDiscovery(t *testing.T) {
	trustedCA := newTestCA(t, "trusted-ca")
	otherCA := newTestCA(t, "other-ca")
	serverCertificate := trustedCA.issue(t, certificateOptions{server: true})
	allowedClient := trustedCA.issue(t, certificateOptions{uris: []string{admittedSPIFFEID}})
	deniedClient := trustedCA.issue(t, certificateOptions{uris: []string{"spiffe://agent-platform.test/control-plane/other"}})
	ambiguousClient := trustedCA.issue(t, certificateOptions{uris: []string{
		admittedSPIFFEID,
		"spiffe://agent-platform.test/control-plane/other",
	}})
	expiredClient := trustedCA.issue(t, certificateOptions{
		uris:      []string{admittedSPIFFEID},
		notBefore: time.Now().Add(-2 * time.Hour),
		notAfter:  time.Now().Add(-time.Hour),
	})
	untrustedClient := otherCA.issue(t, certificateOptions{uris: []string{admittedSPIFFEID}})

	staticService, err := provider.NewStaticCapabilityService("spr_mtls_test", provider.Limits{
		MaxCPUMillis: 1000, MaxMemoryBytes: 512 << 20,
		MaxEphemeralStorageBytes: 64 << 20, MaxLeaseSeconds: 3600,
		MaxExecSeconds: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	service := capabilityServiceFunc(func(ctx context.Context) (provider.Capabilities, error) {
		calls.Add(1)
		return staticService.Capabilities(ctx)
	})

	srv, endpoint, errc := startProviderServer(t, serverCertificate, trustedCA.certificatePEM, service)
	defer stopProviderServer(t, srv, errc)

	allowedHTTPClient := newMTLSClient(t, trustedCA.certificatePEM, &allowedClient.certificate)
	response := getWithRetry(t, allowedHTTPClient, endpoint+"/v1/capabilities")
	if response.StatusCode != http.StatusOK {
		t.Fatalf("capability status = %d, want 200", response.StatusCode)
	}
	body := readResponseBody(t, response)
	if response.TLS == nil {
		t.Fatal("capability response has no TLS connection state")
	}
	if response.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version = %#x, want TLS 1.3", response.TLS.Version)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("Content-Type = %q", response.Header.Get("Content-Type"))
	}
	if bytes.Contains(body, []byte(`"success"`)) {
		t.Fatalf("Provider response used the local management envelope: %s", body)
	}
	if !bytes.Contains(body, []byte(`"capabilities":[]`)) || !bytes.Contains(body, []byte(`"runtime_profiles":[]`)) {
		t.Fatalf("empty capability collections must be arrays: %s", body)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("decode Provider document: %v", err)
	}
	if document["provider_revision_id"] != "spr_mtls_test" {
		t.Fatalf("unexpected Provider revision document: %s", body)
	}

	request, err := http.NewRequest(http.MethodGet, endpoint+"/v1/capabilities", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer invalid-and-irrelevant-for-discovery")
	response, err = allowedHTTPClient.Do(request)
	if err != nil {
		t.Fatalf("discovery with irrelevant bearer header: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("discovery with bearer header status = %d, want 200", response.StatusCode)
	}
	_ = response.Body.Close()
	if calls.Load() != 2 {
		t.Fatalf("capability calls = %d, want 2", calls.Load())
	}

	assertHTTPStatus(t, newMTLSClient(t, trustedCA.certificatePEM, &deniedClient.certificate), endpoint+"/v1/capabilities", http.StatusForbidden)
	assertHTTPStatus(t, newMTLSClient(t, trustedCA.certificatePEM, &ambiguousClient.certificate), endpoint+"/v1/capabilities", http.StatusForbidden)
	if calls.Load() != 2 {
		t.Fatalf("rejected identities dispatched capability service: calls = %d", calls.Load())
	}

	for name, client := range map[string]*http.Client{
		"missing certificate":   newMTLSClient(t, trustedCA.certificatePEM, nil),
		"untrusted certificate": newMTLSClient(t, trustedCA.certificatePEM, &untrustedClient.certificate),
		"expired certificate":   newMTLSClient(t, trustedCA.certificatePEM, &expiredClient.certificate),
	} {
		t.Run(name, func(t *testing.T) {
			response, err := client.Get(endpoint + "/v1/capabilities")
			if err == nil {
				_ = response.Body.Close()
				t.Fatal("expected TLS handshake failure")
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatalf("TLS-rejected requests dispatched capability service: calls = %d", calls.Load())
	}

	for _, request := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodPost, "/v1/sandboxes", http.StatusNotFound},
		{http.MethodPost, "/v1/capabilities", http.StatusMethodNotAllowed},
	} {
		req, err := http.NewRequest(request.method, endpoint+request.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := allowedHTTPClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", request.method, request.path, err)
		}
		if response.StatusCode != request.status {
			t.Errorf("%s %s status = %d, want %d", request.method, request.path, response.StatusCode, request.status)
		}
		_ = response.Body.Close()
	}
	if calls.Load() != 2 {
		t.Fatalf("unregistered routes dispatched capability service: calls = %d", calls.Load())
	}
}

func TestCapabilityHandlerMapsApplicationFailures(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"unavailable", provider.ErrUnavailable, http.StatusServiceUnavailable, "SANDBOX_UNAVAILABLE"},
		{"cancelled", context.Canceled, http.StatusServiceUnavailable, "SANDBOX_UNAVAILABLE"},
		{"unexpected", errors.New("boom"), http.StatusInternalServerError, "SANDBOX_INTERNAL_ERROR"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := capabilityHandler{service: capabilityServiceFunc(func(context.Context) (provider.Capabilities, error) {
				return provider.Capabilities{}, tc.err
			})}
			recorder := httptest.NewRecorder()
			handler.get(recorder, httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil))
			if recorder.Code != tc.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.status)
			}
			var response struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Code != tc.code {
				t.Fatalf("code = %q, want %q", response.Code, tc.code)
			}
		})
	}
}

func TestNewProviderServerRejectsUnsafeConfiguration(t *testing.T) {
	ca := newTestCA(t, "ca")
	serverCertificate := ca.issue(t, certificateOptions{server: true})
	directory := t.TempDir()
	certificateFile, privateKeyFile := serverCertificate.write(t, directory, "server")
	clientCAFile := writeFile(t, directory, "ca.pem", ca.certificatePEM)
	badFile := writeFile(t, directory, "bad.pem", []byte("not PEM"))
	oversizedFile := writeFile(t, directory, "oversized.pem", bytes.Repeat([]byte("x"), maxTLSFileBytes+1))
	base := Options{
		Listen: option.HTTP{Host: "127.0.0.1", Port: 8443},
		TLS: TLSOptions{
			CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
			ClientCAFile: clientCAFile, AllowedClientSPIFFEIDs: []string{admittedSPIFFEID},
		},
	}
	service := capabilityServiceFunc(func(context.Context) (provider.Capabilities, error) {
		return provider.Capabilities{}, nil
	})
	if _, err := NewServer(base, nil); err == nil {
		t.Fatal("expected nil capability service rejection")
	}

	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{"missing certificate path", func(o *Options) { o.TLS.CertificateFile = "" }},
		{"missing certificate file", func(o *Options) { o.TLS.CertificateFile = filepath.Join(directory, "missing.pem") }},
		{"invalid certificate", func(o *Options) { o.TLS.CertificateFile = badFile }},
		{"oversized certificate", func(o *Options) { o.TLS.CertificateFile = oversizedFile }},
		{"invalid client CA", func(o *Options) { o.TLS.ClientCAFile = badFile }},
		{"empty allowlist", func(o *Options) { o.TLS.AllowedClientSPIFFEIDs = nil }},
		{"invalid SPIFFE ID", func(o *Options) { o.TLS.AllowedClientSPIFFEIDs = []string{"https://example.test/client"} }},
		{"duplicate SPIFFE ID", func(o *Options) { o.TLS.AllowedClientSPIFFEIDs = []string{admittedSPIFFEID, admittedSPIFFEID} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			options := base
			options.TLS.AllowedClientSPIFFEIDs = append([]string(nil), base.TLS.AllowedClientSPIFFEIDs...)
			tc.mutate(&options)
			if _, err := NewServer(options, service); err == nil {
				t.Fatal("expected unsafe configuration rejection")
			}
		})
	}
}

type testCA struct {
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
	certificatePEM []byte
}

type certificateOptions struct {
	server    bool
	uris      []string
	notBefore time.Time
	notAfter  time.Time
}

type testCertificate struct {
	certificate tls.Certificate
	certPEM     []byte
	keyPEM      []byte
}

func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		certificate: certificate, privateKey: privateKey,
		certificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (ca testCA) issue(t *testing.T, options certificateOptions) testCertificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if options.notBefore.IsZero() {
		options.notBefore = now.Add(-time.Hour)
	}
	if options.notAfter.IsZero() {
		options.notAfter = now.Add(12 * time.Hour)
	}
	template := &x509.Certificate{
		SerialNumber: randomSerial(t), Subject: pkix.Name{CommonName: "test-leaf"},
		NotBefore: options.notBefore, NotAfter: options.notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if options.server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		for _, value := range options.uris {
			identity, err := url.Parse(value)
			if err != nil {
				t.Fatal(err)
			}
			template.URIs = append(template.URIs, identity)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate{certificate: certificate, certPEM: certPEM, keyPEM: keyPEM}
}

func (certificate testCertificate) write(t *testing.T, directory, prefix string) (string, string) {
	t.Helper()
	return writeFile(t, directory, prefix+".pem", certificate.certPEM),
		writeFile(t, directory, prefix+"-key.pem", certificate.keyPEM)
}

func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func writeFile(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startProviderServer(t *testing.T, serverCertificate testCertificate, clientCAPEM []byte, service provider.CapabilityService) (*Server, string, <-chan error) {
	t.Helper()
	directory := t.TempDir()
	certificateFile, privateKeyFile := serverCertificate.write(t, directory, "server")
	clientCAFile := writeFile(t, directory, "client-ca.pem", clientCAPEM)
	port := freePort(t)
	srv, err := NewServer(Options{
		Listen: option.HTTP{Host: "127.0.0.1", Port: port},
		TLS: TLSOptions{
			CertificateFile: certificateFile, PrivateKeyFile: privateKeyFile,
			ClientCAFile: clientCAFile, AllowedClientSPIFFEIDs: []string{admittedSPIFFEID},
		},
	}, service)
	if err != nil {
		t.Fatal(err)
	}
	errChannel := make(chan error, 1)
	go func() { errChannel <- srv.Startup() }()
	return srv, fmt.Sprintf("https://127.0.0.1:%d", port), errChannel
}

func stopProviderServer(t *testing.T, srv *Server, errChannel <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("shutdown Provider server: %v", err)
	}
	select {
	case err := <-errChannel:
		if err != nil {
			t.Errorf("Provider startup returned: %v", err)
		}
	case <-ctx.Done():
		t.Error("Provider server did not stop")
	}
}

func newMTLSClient(t *testing.T, serverCAPEM []byte, certificate *tls.Certificate) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverCAPEM) {
		t.Fatal("append server CA")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: config},
		Timeout:   3 * time.Second,
	}
}

func getWithRetry(t *testing.T, client *http.Client, endpoint string) *http.Response {
	t.Helper()
	var lastErr error
	for range 100 {
		response, err := client.Get(endpoint)
		if err == nil {
			return response
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Provider server never became ready: %v", lastErr)
	return nil
}

func assertHTTPStatus(t *testing.T, client *http.Client, endpoint string, want int) {
	t.Helper()
	response, err := client.Get(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status = %d, want %d: %s", response.StatusCode, want, body)
	}
}

func readResponseBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}
