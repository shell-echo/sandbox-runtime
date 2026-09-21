//go:build phase6slicegate

package productphase6gate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/shell-echo/sandbox-runtime/guestagent"
	guestdevelopment "github.com/shell-echo/sandbox-runtime/guestagent/development"
)

type guestFixture struct {
	guestID    string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	address    string
	server     *http.Server
	listener   net.Listener

	mu              sync.Mutex
	active          *websocket.Conn
	connections     int
	healthResponses int
	available       bool
}

func startGuestFixture(t *testing.T, ctx context.Context, environment *gateEnvironment) *guestFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(environment.tls.guestServerCert, environment.tls.guestServerKey)
	if err != nil {
		t.Fatal(err)
	}
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(environment.tls.ca.certificate)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &guestFixture{
		guestID:    "guest-phase6-slice4",
		privateKey: privateKey,
		publicKey:  publicKey,
		address:    listener.Addr().String(),
		listener:   listener,
		available:  true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/agent", fixture.serveGuest)
	fixture.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
	})
	go func() {
		_ = fixture.server.Serve(tlsListener)
	}()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = fixture.server.Shutdown(shutdownContext)
	}()
	t.Cleanup(func() {
		fixture.drop()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = fixture.server.Shutdown(shutdownContext)
	})
	return fixture
}

func (f *guestFixture) serveGuest(writer http.ResponseWriter, request *http.Request) {
	f.mu.Lock()
	available := f.available
	f.mu.Unlock()
	if !available {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || !hasGuestIdentity(request.TLS.PeerCertificates[0]) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols:    []string{guestagent.Subprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(guestagent.MaxMessageBytes)
	if connection.Subprotocol() != guestagent.Subprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}

	handshakeContext, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	challenge := guestagent.Challenge{
		Type:      "challenge",
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
		ExpiresAt: time.Now().UTC().Add(10 * time.Second).Format(time.RFC3339Nano),
	}
	if err := writeGuestMessage(handshakeContext, connection, challenge); err != nil {
		return
	}
	var hello guestagent.Hello
	if err := readGuestMessage(handshakeContext, connection, &hello); err != nil {
		return
	}
	authentication := guestagent.AuthRequest{Hello: hello, Challenge: challenge}
	signing, err := authentication.SigningBytes()
	if err != nil || hello.GuestID != f.guestID || hello.BindingGeneration != 1 || hello.ProtocolVersion != guestagent.ProtocolVersion {
		_ = connection.Close(websocket.StatusPolicyViolation, "invalid Guest identity")
		return
	}
	signature, err := authentication.SignatureBytes()
	if err != nil || !ed25519.Verify(f.publicKey, signing, signature) {
		_ = connection.Close(websocket.StatusPolicyViolation, "invalid Guest proof")
		return
	}
	welcome := guestagent.Welcome{Type: "welcome", ProtocolVersion: guestagent.ProtocolVersion, Capabilities: append([]string(nil), hello.Capabilities...), BindingGeneration: 1}
	if err := writeGuestMessage(handshakeContext, connection, welcome); err != nil {
		return
	}

	f.mu.Lock()
	f.connections++
	connectionNumber := f.connections
	f.active = connection
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		if f.active == connection {
			f.active = nil
		}
		f.mu.Unlock()
	}()

	requestID := fmt.Sprintf("phase6-health-%d", connectionNumber)
	healthRequest := guestagent.Request{
		Type:       "request",
		RequestID:  requestID,
		Operation:  guestdevelopment.CapabilityHealth,
		DeadlineAt: time.Now().UTC().Add(10 * time.Second).Format(time.RFC3339Nano),
		Payload:    json.RawMessage(`{}`),
	}
	if err := writeGuestMessage(handshakeContext, connection, healthRequest); err != nil {
		return
	}
	var response guestagent.Response
	if err := readGuestMessage(handshakeContext, connection, &response); err != nil || response.Type != "response" || response.RequestID != requestID || !response.OK {
		return
	}
	var health guestdevelopment.HealthResponse
	if guestagent.DecodeStrict(response.Payload, &health) != nil || !health.Live || len(health.Mounts) != 4 || len(health.Toolchains) != 1 {
		return
	}
	f.mu.Lock()
	f.healthResponses++
	f.mu.Unlock()

	for {
		if _, _, err := connection.Read(request.Context()); err != nil {
			return
		}
	}
}

func (f *guestFixture) url() string {
	return "wss://" + f.address + "/agent"
}

func (f *guestFixture) mounts() []guestdevelopment.Mount {
	return []guestdevelopment.Mount{
		{Path: "/inputs", Mode: "ro"},
		{Path: "/workspace", Mode: "rw"},
		{Path: "/outputs", Mode: "rw"},
		{Path: "/tmp", Mode: "rw"},
	}
}

func (f *guestFixture) toolchains() []guestdevelopment.Toolchain {
	return []guestdevelopment.Toolchain{{ID: "posix-shell", Version: "phase6-1", Digest: sha256Digest([]byte("phase6-posix-shell")), Executable: "/bin/sh"}}
}

func (f *guestFixture) drop() {
	f.mu.Lock()
	connection := f.active
	f.mu.Unlock()
	if connection != nil {
		_ = connection.Close(websocket.StatusGoingAway, "phase6 dependency interruption")
	}
}

func (f *guestFixture) setAvailable(available bool) {
	f.mu.Lock()
	f.available = available
	connection := f.active
	f.mu.Unlock()
	if !available && connection != nil {
		_ = connection.Close(websocket.StatusGoingAway, "phase6 dependency unavailable")
	}
}

func (f *guestFixture) snapshot() (connections, healthResponses int, connected bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connections, f.healthResponses, f.active != nil
}

func (f *guestFixture) close() error {
	f.drop()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := f.server.Shutdown(shutdownContext)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func hasGuestIdentity(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	for _, identity := range certificate.URIs {
		if identity.String() == "spiffe://phase6.example.test/guest" {
			return true
		}
	}
	return false
}

func writeGuestMessage(ctx context.Context, connection *websocket.Conn, value any) error {
	document, err := json.Marshal(value)
	if err != nil || int64(len(document)) > guestagent.MaxMessageBytes {
		return errors.New("invalid Guest fixture message")
	}
	return connection.Write(ctx, websocket.MessageText, document)
}

func readGuestMessage(ctx context.Context, connection *websocket.Conn, value any) error {
	messageType, document, err := connection.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		return errors.New("invalid Guest fixture frame")
	}
	return guestagent.DecodeStrict(document, value)
}
