package providerapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/shell-echo/sandbox-runtime/option"
)

func TestProviderTransportConstructorsAcceptOnlyExclusiveLiveMTLS(t *testing.T) {
	live := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		SessionTicketsDisabled: true, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:        x509.NewCertPool(),
		GetCertificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
		VerifyConnection: func(tls.ConnectionState) error { return nil },
	}
	construct := func(config *tls.Config) error {
		_, err := NewServer(context.Background(), TransportOptions{
			Address: option.HTTP{Host: "127.0.0.1", Port: 18444}, TLSConfig: config,
			AllowedClientURIIdentities: []string{testAllowedIdentity},
		}, validCapabilitySource(t))
		if err != nil {
			return err
		}
		_, err = NewPrivateServer(context.Background(), PrivateTransportOptions{
			Address: option.HTTP{Host: "127.0.0.1", Port: 18448}, TLSConfig: config,
			AllowedClientURIIdentities: []string{testAllowedIdentity},
			Handler:                    http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		})
		return err
	}
	if err := construct(live); err != nil {
		t.Fatalf("exclusive live Provider TLS rejected: %v", err)
	}
	for name, mutate := range map[string]func(*tls.Config){
		"static fallback":             func(value *tls.Config) { value.Certificates = []tls.Certificate{{}} },
		"session resumption":          func(value *tls.Config) { value.SessionTicketsDisabled = false },
		"TLS downgrade":               func(value *tls.Config) { value.MinVersion = tls.VersionTLS12 },
		"optional client certificate": func(value *tls.Config) { value.ClientAuth = tls.RequestClientCert },
		"missing client root":         func(value *tls.Config) { value.ClientCAs = nil },
		"missing peer check":          func(value *tls.Config) { value.VerifyConnection = nil },
		"alternate client hello config": func(value *tls.Config) {
			value.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return &tls.Config{MinVersion: tls.VersionTLS12}, nil }
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := live.Clone()
			mutate(candidate)
			if err := construct(candidate); err == nil {
				t.Fatal("unsafe Provider mTLS configuration was accepted")
			}
		})
	}
}

func TestLiveProviderListenersEnforceTheirOwnClientURIAllowlist(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	certificate := material.serverConfig.Certificates[0]
	live := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		SessionTicketsDisabled: true, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:        material.serverConfig.ClientCAs,
		GetCertificate:   func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &certificate, nil },
		VerifyConnection: func(tls.ConnectionState) error { return nil },
	}
	public, err := NewServer(context.Background(), TransportOptions{
		Address: option.HTTP{Host: "127.0.0.1", Port: 18444}, TLSConfig: live,
		AllowedClientURIIdentities: []string{testAllowedIdentity},
	}, validCapabilitySource(t))
	if err != nil {
		t.Fatal(err)
	}
	private, err := NewPrivateServer(context.Background(), PrivateTransportOptions{
		Address: option.HTTP{Host: "127.0.0.1", Port: 18448}, TLSConfig: live,
		AllowedClientURIIdentities: []string{testAllowedIdentity},
		Handler:                    http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong := issueTestCertificate(t, material.ca, testCertificateOptions{
		uriStrings:  []string{"spiffe://sandbox-runtime.test/wrong-role"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	for _, server := range []*tls.Config{public.http.TLSConfig, private.http.TLSConfig} {
		clientErr, serverErr := runTLSHandshake(server, clientTLSConfig(material, &material.client))
		if clientErr != nil || serverErr != nil {
			t.Fatalf("allowed client rejected: client=%v server=%v", clientErr, serverErr)
		}
		_, serverErr = runTLSHandshake(server, clientTLSConfig(material, &wrong))
		if serverErr == nil {
			t.Fatal("wrong client URI admitted under valid CA")
		}
	}
	if _, err := NewPrivateServer(context.Background(), PrivateTransportOptions{
		Address: option.HTTP{Host: "127.0.0.1", Port: 18448}, TLSConfig: live,
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}); err == nil {
		t.Fatal("private live TLS accepted an absent peer allowlist")
	}
}
