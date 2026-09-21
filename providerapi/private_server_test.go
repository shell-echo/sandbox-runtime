package providerapi

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/shell-echo/sandbox-runtime/option"
)

func TestNewPrivateServerFailsClosedBeforeBind(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	valid := PrivateTransportOptions{
		Address:               option.HTTP{Host: "127.0.0.1", Port: 9554},
		ServerCertificateFile: material.serverCert, ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.clientCA,
		AllowedClientURIIdentities: []string{testAllowedIdentity}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}
	for name, candidate := range map[string]PrivateTransportOptions{
		"nil context":      valid,
		"missing handler":  func() PrivateTransportOptions { value := valid; value.Handler = nil; return value }(),
		"invalid address":  func() PrivateTransportOptions { value := valid; value.Address.Port = 0; return value }(),
		"missing identity": func() PrivateTransportOptions { value := valid; value.AllowedClientURIIdentities = nil; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if name == "nil context" {
				ctx = nil
			}
			if _, err := NewPrivateServer(ctx, candidate); err == nil {
				t.Fatal("invalid private server was accepted")
			}
		})
	}
}

func TestPrivateServerWrapsBodyLimit(t *testing.T) {
	material := newTestMTLSMaterial(t, []string{testAllowedIdentity})
	server, err := NewPrivateServer(context.Background(), PrivateTransportOptions{
		Address: option.HTTP{Host: "127.0.0.1", Port: 9555}, ServerCertificateFile: material.serverCert,
		ServerPrivateKeyFile: material.serverKey, ClientCABundleFile: material.clientCA,
		AllowedClientURIIdentities: []string{testAllowedIdentity}, Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			body := make([]byte, 16)
			_, readErr := request.Body.Read(body)
			if readErr != nil {
				writer.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
		}), MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.http.Handler == nil || server.http.MaxHeaderBytes == 0 {
		t.Fatal("private server did not freeze transport limits")
	}
	server.listen = func(context.Context, string, string) (net.Listener, error) { return nil, context.Canceled }
	if err := server.Startup(context.Background()); err != nil {
		t.Fatalf("cancelled private server startup = %v", err)
	}
}
