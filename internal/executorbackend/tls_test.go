package executorbackend

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestExecutorRemoteTLSRejectsLocalFallbackAndUnsafeConfig(t *testing.T) {
	secure := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool(),
		GetCertificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
		VerifyConnection: func(tls.ConnectionState) error { return nil }}
	if selected, err := executorServerTLS(secure, "", "", "", nil); err != nil || selected == secure {
		t.Fatalf("secure remote config rejected or not cloned: %v", err)
	}
	for name, mutate := range map[string]func(*tls.Config){
		"old protocol": func(value *tls.Config) { value.MinVersion = tls.VersionTLS12 },
		"no mTLS":      func(value *tls.Config) { value.ClientAuth = tls.NoClientCert },
		"no signer":    func(value *tls.Config) { value.GetCertificate = nil },
		"local key":    func(value *tls.Config) { value.Certificates = []tls.Certificate{{}} },
		"no admission": func(value *tls.Config) { value.VerifyConnection = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := secure.Clone()
			mutate(candidate)
			if _, err := executorServerTLS(candidate, "", "", "", nil); err == nil {
				t.Fatal("unsafe remote config accepted")
			}
		})
	}
	if _, err := executorServerTLS(secure, "local.pem", "", "", nil); err == nil {
		t.Fatal("remote signer silently combined with local certificate")
	}
}
