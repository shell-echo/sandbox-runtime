package codingcontroltransport

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
)

// Real loopback mTLS, test certificates and a fake peer monitor: this does
// not constitute the Profile-v2 CRL or real Control/Docker release gate.
func mutationTestClient(t *testing.T, request codingcontrolprotocol.Request, handler http.HandlerFunc) *statusClient {
	t.Helper()
	serverTLS, clientTLS, _ := statusTestTLS(t, "spiffe://sandbox-runtime.test/provider-runtime")
	server := httptest.NewUnstartedServer(handler)
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)
	clientTLS.VerifyConnection = func(tls.ConnectionState) error { return nil }
	address := server.Listener.Addr().String()
	transport := &http.Transport{TLSClientConfig: clientTLS, DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, ErrInvalidStatusClient },
		DialTLSContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp" || target != address {
				return nil, ErrInvalidStatusClient
			}
			return (&tls.Dialer{Config: clientTLS}).DialContext(ctx, network, target)
		}}
	client, err := newStatusClient(statusClientConfig{Origin: server.URL, ProviderPrincipalDigest: request.Create.PeerPrincipalDigest,
		ProfileDigest: request.Create.ProfileDigest, ControlPolicyDigest: request.Create.ControlPolicyDigest,
		OperationTimeout: time.Second, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func mutationResponse(request codingcontrolprotocol.Request) codingcontrolprotocol.Response {
	r := codingcontrolprotocol.Response{Protocol: request.Protocol, Scope: request.Scope, Action: request.Action,
		Status: codingcontrolprotocol.StatusCompleted, CreateAuthorityDigest: request.Create.Digest(), EffectID: request.Create.EffectID,
		ControlRevision: 4, ControlStateDigest: statusTestDigest("3"), CompletionDigest: statusTestDigest("4"),
		CompletionEvidenceDigest: statusTestDigest("5"), UpdatedAt: time.Now().UTC()}
	if request.Cleanup != nil {
		r.Status = codingcontrolprotocol.StatusReleased
		r.CleanupAuthorityDigest = request.Cleanup.Digest()
		r.AbsenceDigest = statusTestDigest("6")
		r.AbsenceEvidenceDigest = statusTestDigest("7")
	}
	return r
}

type mutationPeer struct {
	testStatusPeer
	polls  int
	failAt int
}

func (p *mutationPeer) Poll(context.Context) error {
	p.polls++
	if p.polls == p.failAt {
		return ErrMutationUncertain
	}
	return nil
}

func TestTypedMutationBoundaryAndLostResponses(t *testing.T) {
	for _, action := range []string{codingcontrolprotocol.ActionCreate, codingcontrolprotocol.ActionCleanup} {
		for _, name := range []string{"ack", "lost reply", "redirect", "wrong action", "wrong effect", "pending", "future receipt", "truncated", "chunked", "gzip", "duplicate field", "pre CRL failure", "post CRL failure", "lifetime ended", "caller cancelled"} {
			t.Run(action+"/"+name, func(t *testing.T) {
				create, _, cleanup := statusTestAuthorities(t, time.Now().UTC().Add(-2*time.Second))
				request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID, Scope: codingcontrolprotocol.ScopeCoding, Action: action, Create: create}
				if action == codingcontrolprotocol.ActionCleanup {
					request.Cleanup = &cleanup
				}
				var calls atomic.Int32
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				lifetime, stop := context.WithCancel(t.Context())
				defer stop()
				client := mutationTestClient(t, request, func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					document, err := io.ReadAll(io.LimitReader(r.Body, codingcontrolprotocol.MaxRequestBytes+1))
					defer r.Body.Close()
					got, decodeErr := codingcontrolprotocol.DecodeRequest(document, time.Now().UTC(), create.PeerPrincipalDigest)
					want, _ := codingcontrolprotocol.EncodeRequest(request)
					if !bytes.Equal(document, want) || err != nil || decodeErr != nil || r.Method != http.MethodPost || r.URL.Path != CodingStatusPath || got.Create != create || got.Action != action ||
						(got.Cleanup != nil && (request.Cleanup == nil || *got.Cleanup != *request.Cleanup)) || (got.Cleanup == nil) != (request.Cleanup == nil) {
						t.Error("changed original envelope")
					}
					if name == "lost reply" {
						conn, _, _ := w.(http.Hijacker).Hijack()
						_ = conn.Close()
						return
					}
					if name == "redirect" {
						w.Header().Set("Location", CodingStatusPath)
						w.WriteHeader(http.StatusTemporaryRedirect)
						return
					}
					response := mutationResponse(request)
					switch name {
					case "wrong action":
						response.Action = codingcontrolprotocol.ActionStatus
					case "wrong effect":
						response.CreateAuthorityDigest = statusTestDigest("0")
					case "pending":
						if action == codingcontrolprotocol.ActionCleanup {
							response.Status = codingcontrolprotocol.StatusCleanupPending
							response.AbsenceDigest = ""
							response.AbsenceEvidenceDigest = ""
						} else {
							response.Status = codingcontrolprotocol.StatusUnknown
							response.CompletionDigest = ""
							response.CompletionEvidenceDigest = ""
						}
					case "future receipt":
						response.UpdatedAt = time.Now().Add(time.Hour)
					case "lifetime ended":
						stop()
					case "caller cancelled":
						cancel()
					}
					body, _ := json.Marshal(response)
					if name == "duplicate field" {
						body = append([]byte(`{"status":"completed",`), body[1:]...)
					}
					if name == "gzip" {
						var encoded bytes.Buffer
						compressor := gzip.NewWriter(&encoded)
						_, _ = compressor.Write(body)
						_ = compressor.Close()
						body = encoded.Bytes()
						w.Header().Set("Content-Encoding", "gzip")
					}
					w.Header().Set("Content-Type", "application/json")
					if name == "chunked" {
						w.(http.Flusher).Flush()
					} else {
						length := len(body)
						if name == "truncated" {
							length++
						}
						w.Header().Set("Content-Length", strconv.Itoa(length))
					}
					_, _ = w.Write(body)
				})
				peer := &mutationPeer{testStatusPeer: testStatusPeer{ready: true}}
				if name == "pre CRL failure" {
					peer.failAt = 1
				}
				if name == "post CRL failure" {
					peer.failAt = 2
				}
				err := dispatchMutation(ctx, lifetime, client, peer, time.Second, request)
				wantCalls := int32(1)
				if name == "pre CRL failure" {
					wantCalls = 0
				}
				if (err == nil) != (name == "ack") || calls.Load() != wantCalls {
					t.Fatalf("result %v, sends %d", err, calls.Load())
				}
			})
		}
	}
}

func TestControlMutationFactoryAndReadPortRemainClosed(t *testing.T) {
	if c, err := NewControlClientV2(t.Context(), phase6security.ProfileV2{}, phase6tls.PrivateServiceAuthorityV2{}, statusTestDigest("a")); err == nil || c != nil {
		t.Fatal("public Profile-v2 hold bypassed")
	}
	var c *ControlClientV2
	create, _, cleanup := statusTestAuthorities(t, time.Now().UTC().Add(-2*time.Second))
	if c.DispatchCodingCreateAuthority(t.Context(), create) == nil || c.DispatchCodingCleanupAuthority(t.Context(), create, cleanup) == nil {
		t.Fatal("nil client dispatched")
	}
	if _, err := c.Observe(t.Context(), codingcontrolprotocol.Request{}); err == nil {
		t.Fatal("nil read admitted")
	}
	c.Close()
}

func TestMutationRejectsExpiredOrMismatchedAuthorityBeforeSending(t *testing.T) {
	for _, name := range []string{"expired create", "expired cleanup", "wrong profile", "wrong policy", "wrong peer", "read action"} {
		t.Run(name, func(t *testing.T) {
			create, _, cleanup := statusTestAuthorities(t, time.Now().UTC().Add(-2*time.Second))
			request := codingcontrolprotocol.Request{Protocol: codingcontrolprotocol.ProtocolID, Scope: codingcontrolprotocol.ScopeCoding, Action: codingcontrolprotocol.ActionCreate, Create: create}
			var calls atomic.Int32
			client := mutationTestClient(t, request, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
			switch name {
			case "expired create":
				request.Create.ExpiresAt = time.Now().Add(-time.Second)
			case "expired cleanup":
				request.Action = codingcontrolprotocol.ActionCleanup
				cleanup.ExpiresAt = time.Now().Add(-time.Second)
				request.Cleanup = &cleanup
			case "wrong profile":
				request.Create.ProfileDigest = statusTestDigest("0")
			case "wrong policy":
				request.Create.ControlPolicyDigest = statusTestDigest("0")
			case "wrong peer":
				request.Create.PeerPrincipalDigest = statusTestDigest("0")
			case "read action":
				request.Action = codingcontrolprotocol.ActionStatus
			}
			if dispatchMutation(t.Context(), t.Context(), client, &testStatusPeer{ready: true}, time.Second, request) == nil || calls.Load() != 0 {
				t.Fatal("unsafe send")
			}
		})
	}
}
