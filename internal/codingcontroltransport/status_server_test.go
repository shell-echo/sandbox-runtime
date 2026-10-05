package codingcontroltransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/codingidentity"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle"
)

type testStatusPeer struct{ ready bool }

func (*testStatusPeer) Track(net.Conn, tls.ConnectionState) error { return nil }
func (*testStatusPeer) Forget(net.Conn)                           {}
func (p *testStatusPeer) Poll(context.Context) error              { return nil }
func (*testStatusPeer) PollInterval() time.Duration               { return time.Second }
func (p *testStatusPeer) Ready() bool                             { return p.ready }
func (*testStatusPeer) Close()                                    {}

func statusTestDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func testStatusConfig() statusServerConfig {
	return statusServerConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool(),
		Certificates: []tls.Certificate{{}}, VerifyConnection: func(tls.ConnectionState) error { return nil }},
		ListenAddress: "127.0.0.1:8444", ExpectedProviderURI: "spiffe://sandbox-runtime.test/provider-runtime",
		ProviderPrincipalDigest: statusTestDigest("a"), ProfileDigest: statusTestDigest("b"),
		ControlPolicyDigest: statusTestDigest("c"), OperationTimeout: 5 * time.Second,
		Ledger: new(dockercontrol.CodingReceiptLedger), Clock: time.Now}
}

func TestStatusServerRequiresPrivateTLSAndRejectsUnauthenticatedHTTP(t *testing.T) {
	config := testStatusConfig()
	peer := &testStatusPeer{ready: true}
	called := false
	project := func(*dockercontrol.CodingReceiptLedger, codingcontrolprotocol.Request, string, time.Time) (
		codingcontrolprotocol.Response, error) {
		called = true
		return codingcontrolprotocol.Response{}, nil
	}
	server, err := newStatusServer(config, peer, project)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*statusServerConfig){
		"plaintext": func(c *statusServerConfig) { c.TLSConfig = nil },
		"unauthenticated client": func(c *statusServerConfig) {
			copy := c.TLSConfig.Clone()
			copy.ClientAuth = tls.NoClientCert
			c.TLSConfig = copy
		},
		"missing CRL handshake hook": func(c *statusServerConfig) {
			copy := c.TLSConfig.Clone()
			copy.VerifyConnection = nil
			c.TLSConfig = copy
		},
		"wrong profile":       func(c *statusServerConfig) { c.ProfileDigest = "" },
		"wrong listener":      func(c *statusServerConfig) { c.ListenAddress = "" },
		"unbounded operation": func(c *statusServerConfig) { c.OperationTimeout = time.Minute },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testStatusConfig()
			change(&candidate)
			if _, err := newStatusServer(candidate, peer, project); err == nil {
				t.Fatal("unsafe status server configuration accepted")
			}
		})
	}
	request := httptest.NewRequest(http.MethodPost, "https://127.0.0.1:8444"+CodingStatusPath,
		strings.NewReader(`{"claimed_peer":"`+config.ProviderPrincipalDigest+`"}`))
	request.Header.Set("Content-Type", "application/json")
	writer := httptest.NewRecorder()
	server.handle(writer, request)
	if writer.Code != http.StatusForbidden || called {
		t.Fatalf("plaintext/header peer spoof returned %d, projector called=%t", writer.Code, called)
	}
	request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{{Raw: []byte{1}}}}
	writer = httptest.NewRecorder()
	server.handle(writer, request)
	if writer.Code != http.StatusForbidden || called {
		t.Fatalf("unverified TLS peer returned %d, projector called=%t", writer.Code, called)
	}
}

func statusTestAuthority(t *testing.T, at time.Time) (dockercontrol.CodingCreateAuthority,
	dockercontrol.CodingReceiptBinding) {
	t.Helper()
	plan := codingidentity.Plan{Protocol: codingidentity.Protocol, Version: codingidentity.Version,
		ProfileDigest: statusTestDigest("b"), OwnerDeployment: "provider-runtime",
		OwnerPrincipalDigest: statusTestDigest("a"), Namespace: "provider-coding",
		ControllerID: "provider-coding-controller", Template: "coding-sandbox-runtime",
		TemplateDigest: statusTestDigest("2"), ImageDigest: statusTestDigest("3"),
		ImageConfigDigest: statusTestDigest("4"), NetworkMode: "none",
		Limits:   codingidentity.Limits{MemoryBytes: 1 << 30, CPUMillis: 1000, PIDs: 64},
		Capacity: codingidentity.LocalCandidateCapacity,
		Slots: []codingidentity.Slot{
			{ID: "coding-0000", WorkloadUID: 57500, WorkloadGID: 57500,
				InputsVolume: "coding-0000-inputs", WorkspaceVolume: "coding-0000-workspace",
				OutputsVolume: "coding-0000-outputs"},
			{ID: "coding-0001", WorkloadUID: 57501, WorkloadGID: 57501,
				InputsVolume: "coding-0001-inputs", WorkspaceVolume: "coding-0001-workspace",
				OutputsVolume: "coding-0001-outputs"}}}
	request := lifecycle.CreateRequest{OperationID: "operation-1", AttemptID: "attempt-1",
		FencingToken: 7, IdempotencyKey: "key-1", RequestDigest: statusTestDigest("7"),
		Deadline: at.Add(time.Minute), Spec: lifecycle.SandboxSpec{
			SandboxID: "sandbox-1", TenantID: "tenant-1", WorkOrderID: "work-1",
			WorkspaceID: "workspace-1", ProviderRevisionID: "revision-1",
			RuntimeProfile: "sandbox-runtime-coding-shell-v1",
			Network:        lifecycle.NetworkPolicy{Mode: lifecycle.NetworkNone},
			SandboxSlotKey: "coding/slot-1", LeaseExpiresAt: at.Add(time.Hour)}}
	sandbox, operation, err := lifecycle.StartCreate(request, at)
	if err != nil {
		t.Fatal(err)
	}
	operation.State = lifecycle.OperationRunning
	allocation, err := codingidentity.DeriveAllocationID(sandbox.ProviderRevisionID,
		sandbox.TenantID, sandbox.ID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := codingidentity.TenantDigestForID(sandbox.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	ticket := codingidentity.Reservation{PlanDigest: planDigest, Slot: plan.Slots[0],
		Claim: codingidentity.Claim{TenantDigest: tenant, SandboxID: sandbox.ID,
			AllocationID: allocation, OperationID: operation.ID, AttemptID: operation.AttemptID,
			RequestDigest: request.RequestDigest, Generation: sandbox.Generation,
			Fence: operation.FencingToken}, SpecDigest: statusTestDigest("c"),
		Status: codingidentity.Creating}
	create, err := dockercontrol.NewCodingCreateAuthority(t.Context(), ticket, operation,
		sandbox, plan, statusTestDigest("c"), statusTestDigest("a"), at)
	if err != nil {
		t.Fatal(err)
	}
	binding := dockercontrol.CodingReceiptBinding{Plan: plan,
		SpecBySlot: map[string]string{plan.Slots[0].ID: statusTestDigest("c"),
			plan.Slots[1].ID: statusTestDigest("d")},
		ProfileDigest: plan.ProfileDigest, DaemonDigest: statusTestDigest("d"),
		DaemonEnvironmentDigest: statusTestDigest("e"), EndpointScopeDigest: statusTestDigest("f"),
		RuntimePlatform: "linux/arm64/v8", ControlPolicyDigest: create.ControlPolicyDigest,
		PeerPrincipalDigest: create.PeerPrincipalDigest, PlanDigest: planDigest, Capacity: 2}
	if binding.Validate() != nil {
		t.Fatal("invalid status fixture binding")
	}
	return create, binding
}

func TestProjectStatusUsesBoundLedgerAndDoesNotTreatMissingAsAbsence(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Millisecond)
	authority, binding := statusTestAuthority(t, at)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := dockercontrol.InitializeCodingReceiptLedger(t.Context(),
		filepath.Join(directory, "receipts.json"), binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus,
		Create: authority}
	result, err := projectStatus(ledger, request, authority.PeerPrincipalDigest, at.Add(time.Second))
	if err != nil || result.Status != codingcontrolprotocol.StatusNotFound ||
		result.ControlRevision != 0 || result.AbsenceDigest != "" ||
		result.AbsenceEvidenceDigest != "" || result.Validate(request) != nil {
		t.Fatalf("missing receipt misrepresented: %#v, %v", result, err)
	}
	if _, err := ledger.DispatchCodingCreate(t.Context(), authority,
		func(context.Context, dockercontrol.CodingCreateAuthority) error {
			return errors.New("physical unavailable")
		}); err == nil {
		t.Fatal("physical callback unexpectedly succeeded")
	}
	result, err = projectStatus(ledger, request, authority.PeerPrincipalDigest, at.Add(time.Second))
	if err != nil || result.Status != codingcontrolprotocol.StatusUnknown ||
		result.ControlRevision != 2 || result.ControlStateDigest == "" ||
		result.AbsenceDigest != "" || result.Validate(request) != nil {
		t.Fatalf("ambiguous create misrepresented: %#v, %v", result, err)
	}
	for name, change := range map[string]func(*codingcontrolprotocol.Request, *string){
		"wrong peer": func(_ *codingcontrolprotocol.Request, peer *string) { *peer = statusTestDigest("0") },
		"wrong policy": func(request *codingcontrolprotocol.Request, _ *string) {
			request.Create.ControlPolicyDigest = statusTestDigest("0")
		},
		"mutation action": func(request *codingcontrolprotocol.Request, _ *string) {
			request.Action = codingcontrolprotocol.ActionCreate
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad, peer := request, authority.PeerPrincipalDigest
			change(&bad, &peer)
			if _, err := projectStatus(ledger, bad, peer, at.Add(time.Second)); err == nil {
				t.Fatal("unbound status request accepted")
			}
		})
	}
}

func statusTestTLS(t *testing.T, providerURI string) (*tls.Config, *tls.Config, *atomic.Int32) {
	t.Helper()
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "test-only Control issuer"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate,
		&rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	makeLeaf := func(serial int64, usage x509.ExtKeyUsage, uri string) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial),
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if usage == x509.ExtKeyUsageServerAuth {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			template.URIs = []*url.URL{parsed}
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, template, root,
			&key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key, Leaf: leaf}
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	verified := new(atomic.Int32)
	server := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{makeLeaf(2, x509.ExtKeyUsageServerAuth, "")},
		VerifyConnection: func(tls.ConnectionState) error {
			verified.Add(1)
			return nil
		}}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{makeLeaf(3, x509.ExtKeyUsageClientAuth, providerURI)}}
	return server, client, verified
}

func TestStatusClientRejectsFallbackTransportAndUnboundOrigin(t *testing.T) {
	_, clientTLS, _ := statusTestTLS(t, "spiffe://sandbox-runtime.test/provider-runtime")
	clientTLS.VerifyConnection = func(tls.ConnectionState) error { return nil } // test-only
	transport := &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, ErrInvalidStatusClient
		},
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, ErrInvalidStatusClient
		}}
	config := statusClientConfig{Origin: "https://127.0.0.1:8444",
		ProviderPrincipalDigest: statusTestDigest("a"), ProfileDigest: statusTestDigest("b"),
		ControlPolicyDigest: statusTestDigest("c"), OperationTimeout: 5 * time.Second,
		Transport: transport}
	if _, err := newStatusClient(config); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*statusClientConfig){
		"plaintext": func(c *statusClientConfig) { c.Origin = "http://127.0.0.1:8444" },
		"redirect userinfo": func(c *statusClientConfig) {
			c.Origin = "https://attacker@127.0.0.1:8444"
		},
		"wrong profile": func(c *statusClientConfig) { c.ProfileDigest = "" },
		"missing hook": func(c *statusClientConfig) {
			clone := c.Transport.Clone()
			clone.TLSClientConfig = c.Transport.TLSClientConfig.Clone()
			clone.TLSClientConfig.VerifyConnection = nil
			c.Transport = clone
		},
		"fallback dial": func(c *statusClientConfig) {
			clone := c.Transport.Clone()
			clone.DialContext = nil
			c.Transport = clone
		},
		"missing secure dial": func(c *statusClientConfig) {
			clone := c.Transport.Clone()
			clone.DialTLSContext = nil
			c.Transport = clone
		},
		"keepalive": func(c *statusClientConfig) {
			clone := c.Transport.Clone()
			clone.DisableKeepAlives = false
			c.Transport = clone
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			mutate(&candidate)
			if _, err := newStatusClient(candidate); err == nil {
				t.Fatal("unsafe client configuration accepted")
			}
		})
	}
}

func TestStatusServerRealTLSHandshakeReadOnlyRoundTrip(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Millisecond)
	authority, binding := statusTestAuthority(t, at)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	ledger, err := dockercontrol.InitializeCodingReceiptLedger(t.Context(),
		filepath.Join(directory, "receipts.json"), binding, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, clientTLS, handshakes := statusTestTLS(t, "spiffe://sandbox-runtime.test/provider-runtime")
	config := testStatusConfig()
	config.TLSConfig = serverTLS
	config.ListenAddress = listener.Addr().String()
	config.Ledger = ledger
	server, err := newStatusServer(config, &testStatusPeer{ready: true}, projectStatus)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- server.Serve(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("status server shutdown: %v", err)
		}
	}()
	clientTLS.VerifyConnection = func(tls.ConnectionState) error { return nil } // test hook, not CRL
	transport := &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, ErrInvalidStatusClient
		},
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != config.ListenAddress {
				return nil, ErrInvalidStatusClient
			}
			return (&tls.Dialer{Config: clientTLS}).DialContext(ctx, network, address)
		}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID,
		Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionStatus,
		Create: authority}
	document, err := codingcontrolprotocol.EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	boundClient, err := newStatusClient(statusClientConfig{Origin: "https://" + config.ListenAddress,
		ProviderPrincipalDigest: authority.PeerPrincipalDigest, ProfileDigest: authority.ProfileDigest,
		ControlPolicyDigest: authority.ControlPolicyDigest, OperationTimeout: 5 * time.Second,
		Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(boundClient.Close)
	boundResponse, err := boundClient.Read(t.Context(), request)
	if err != nil || boundResponse.Status != codingcontrolprotocol.StatusNotFound ||
		boundResponse.AbsenceDigest != "" {
		t.Fatalf("bounded TLS client status = %#v, %v", boundResponse, err)
	}
	write := request
	write.Action = codingcontrolprotocol.ActionCreate
	if _, err := boundClient.Read(t.Context(), write); err == nil {
		t.Fatal("status client sent a write action")
	}
	wrongProfile := request
	wrongProfile.Create.ProfileDigest = statusTestDigest("0")
	if _, err := boundClient.Read(t.Context(), wrongProfile); err == nil {
		t.Fatal("status client sent wrong-profile authority")
	}
	makeRequest := func(body []byte, contentType string) (int, []byte) {
		t.Helper()
		httpRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			"https://"+config.ListenAddress+CodingStatusPath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		httpRequest.Header.Set("Content-Type", contentType)
		httpResponse, err := client.Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		defer httpResponse.Body.Close()
		responseBody, err := io.ReadAll(io.LimitReader(httpResponse.Body,
			codingcontrolprotocol.MaxResponseBytes+1))
		if err != nil {
			t.Fatal(err)
		}
		return httpResponse.StatusCode, responseBody
	}
	status, responseBody := makeRequest(document, "application/json")
	response, err := codingcontrolprotocol.DecodeResponse(responseBody, request)
	if status != http.StatusOK || err != nil || response.Status != codingcontrolprotocol.StatusNotFound ||
		response.AbsenceDigest != "" || handshakes.Load() == 0 {
		t.Fatalf("mTLS status = %d, response = %#v, err = %v, hook calls = %d",
			status, response, err, handshakes.Load())
	}
	if status, _ := makeRequest(document, "text/plain"); status != http.StatusBadRequest {
		t.Fatalf("wrong content type = %d", status)
	}
	request.Action = codingcontrolprotocol.ActionCreate
	document, err = codingcontrolprotocol.EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := makeRequest(document, "application/json"); status != http.StatusForbidden {
		t.Fatalf("write action reached read-only handler: %d", status)
	}
}
