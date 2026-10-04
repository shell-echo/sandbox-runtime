package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"github.com/shell-echo/sandbox-runtime/roleprocess"
)

type blockedReceiptAuth struct {
	once     sync.Once
	entered  chan struct{}
	release  chan struct{}
	observed chan struct{}
}

func (a *blockedReceiptAuth) Authenticate(context.Context, guestagent.AuthRequest) (guestagent.Identity, error) {
	a.once.Do(func() { close(a.entered) })
	<-a.release
	close(a.observed) // synchronous validated-row observation before handler return
	return guestagent.Identity{}, guestagent.ErrUnauthorized
}

func (*blockedReceiptAuth) CheckAuthority(context.Context, guestagent.Identity) error { return nil }
func (*blockedReceiptAuth) Disconnected(context.Context, guestagent.Identity) error   { return nil }

type receiptShutdownServer struct {
	shutdown func()
	err      error
}

func (s receiptShutdownServer) Startup(context.Context) error  { return nil }
func (s receiptShutdownServer) Shutdown(context.Context) error { s.shutdown(); return s.err }

type observedFinalizer struct {
	sealed  chan struct{}
	aborted chan struct{}
	once    sync.Once
}

func (f *observedFinalizer) Seal(context.Context) error {
	close(f.sealed)
	return nil
}

func (f *observedFinalizer) Abort() {
	f.once.Do(func() { close(f.aborted) })
}

func TestProductGuestReceiptShutdownJoinsRealBlockedAuthHandler(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "cancelled"}[canceled], func(t *testing.T) {
			auth := &blockedReceiptAuth{entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan struct{})}
			hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: auth,
				Observation: func(guestagent.Observation) {}})
			if err != nil {
				t.Fatal(err)
			}
			web := httptest.NewServer(hub)
			defer web.Close()
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			agent, err := guestagent.NewAgent(guestagent.AgentOptions{
				URL: "ws" + strings.TrimPrefix(web.URL, "http"), GuestID: "gst-receipt-test",
				BindingGeneration: 1, PrivateKey: key,
				Handlers: map[string]guestagent.OperationHandler{
					"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil },
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			runCtx, stopAgent := context.WithTimeout(t.Context(), 3*time.Second)
			defer stopAgent()
			agentDone := make(chan error, 1)
			go func() { agentDone <- agent.Run(runCtx) }()
			select {
			case <-auth.entered:
			case <-runCtx.Done():
				t.Fatal("actual Hub handler did not enter authentication")
			}
			finalizer := &observedFinalizer{sealed: make(chan struct{}), aborted: make(chan struct{})}
			stopped := make(chan struct{})
			wrapped := productGuestReceiptServer{Server: receiptShutdownServer{shutdown: func() {
				web.CloseClientConnections()
				close(stopped)
			}}, hub: hub, recorder: finalizer}
			shutdownCtx, stopShutdown := context.WithTimeout(t.Context(), 2*time.Second)
			defer stopShutdown()
			shutdownDone := make(chan error, 1)
			go func() { shutdownDone <- wrapped.Shutdown(shutdownCtx) }()
			select {
			case <-stopped:
			case <-shutdownCtx.Done():
				t.Fatal("transport drain did not begin")
			}
			select {
			case <-finalizer.sealed:
				t.Fatal("complete receipt was sealed before the actual auth handler returned")
			case <-time.After(25 * time.Millisecond):
			}
			if canceled {
				stopShutdown()
				select {
				case err := <-shutdownDone:
					if err == nil {
						t.Fatal("cancelled producer join was accepted")
					}
				case <-time.After(time.Second):
					t.Fatal("cancelled producer join did not terminate")
				}
				select {
				case <-finalizer.aborted:
				default:
					t.Fatal("cancelled producer join did not abort the receipt")
				}
			} else {
				select {
				case <-finalizer.aborted:
					t.Fatal("active producer was aborted without budget exhaustion")
				default:
				}
			}
			close(auth.release)
			select {
			case <-auth.observed:
			case <-runCtx.Done():
				t.Fatal("real auth callback did not complete")
			}
			if !canceled {
				select {
				case err := <-shutdownDone:
					if err != nil {
						t.Fatalf("joined handler shutdown: %v", err)
					}
				case <-shutdownCtx.Done():
					t.Fatal("joined handler shutdown exceeded inherited budget")
				}
				select {
				case <-finalizer.sealed:
				default:
					t.Fatal("joined handler was not sealed")
				}
			} else {
				select {
				case <-finalizer.sealed:
					t.Fatal("cancelled join emitted a complete seal")
				default:
				}
			}
			select {
			case err := <-agentDone:
				if err != nil && !errors.Is(err, guestagent.ErrUnauthorized) && !errors.Is(err, context.Canceled) {
					t.Fatalf("Guest agent result = %v", err)
				}
			case <-runCtx.Done():
				t.Fatal("Guest agent remained after handler release")
			}
		})
	}
}

func TestProductGuestRetirementJoinsWithoutReceiptAfterTransportShutdownError(t *testing.T) {
	auth := &blockedReceiptAuth{entered: make(chan struct{}), release: make(chan struct{}), observed: make(chan struct{})}
	hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: auth,
		Retirement: &guestagent.RetirementPolicy{Capacity: 1,
			Retire: func(context.Context, guestagent.Identity) (guestagent.RetirementDisposition, error) {
				return guestagent.RetirementReleased, nil
			},
			Readback: func(context.Context, guestagent.Identity) (guestagent.RetirementDisposition, error) {
				return guestagent.RetirementStillOwned, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewServer(hub)
	defer web.Close()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := guestagent.NewAgent(guestagent.AgentOptions{
		URL: "ws" + strings.TrimPrefix(web.URL, "http"), GuestID: "gst-receipt-test",
		BindingGeneration: 1, PrivateKey: key,
		Handlers: map[string]guestagent.OperationHandler{
			"guest.health": func(context.Context, json.RawMessage) (any, error) { return true, nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, stopAgent := context.WithTimeout(t.Context(), 3*time.Second)
	defer stopAgent()
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(runCtx) }()
	select {
	case <-auth.entered:
	case <-runCtx.Done():
		t.Fatal("actual Hub handler did not enter authentication")
	}
	transportError := errors.New("test transport drain failure")
	wrapped := productGuestReceiptServer{Server: receiptShutdownServer{
		shutdown: func() { web.CloseClientConnections() }, err: transportError},
		hub: hub, retirement: true}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- wrapped.Shutdown(ctx) }()
	select {
	case <-finished:
		t.Fatal("transport error skipped the active handler join")
	case <-time.After(25 * time.Millisecond):
	}
	close(auth.release)
	select {
	case <-auth.observed:
	case <-ctx.Done():
		t.Fatal("auth handler did not resume")
	}
	select {
	case err := <-finished:
		if !errors.Is(err, transportError) || hub.RetirementReady() {
			t.Fatalf("shutdown error/join/admission = %v ready=%t", err, hub.RetirementReady())
		}
	case <-ctx.Done():
		t.Fatal("shutdown did not join active handler within inherited budget")
	}
	select {
	case <-agentDone:
	case <-runCtx.Done():
		t.Fatal("agent remained after transport drain")
	}
}

func TestProductGuestRetirementCanceledShutdownClosesAdmissionWithoutReceipt(t *testing.T) {
	hub, err := guestagent.NewHub(guestagent.HubOptions{Authenticator: &blockedReceiptAuth{},
		Retirement: &guestagent.RetirementPolicy{Capacity: 1,
			Retire: func(context.Context, guestagent.Identity) (guestagent.RetirementDisposition, error) {
				return guestagent.RetirementReleased, nil
			},
			Readback: func(context.Context, guestagent.Identity) (guestagent.RetirementDisposition, error) {
				return guestagent.RetirementStillOwned, nil
			}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	wrapped := productGuestReceiptServer{Server: receiptShutdownServer{shutdown: func() {}}, hub: hub, retirement: true}
	if err := wrapped.Shutdown(ctx); err == nil || hub.RetirementReady() {
		t.Fatalf("canceled shutdown reopened admission: err=%v ready=%t", err, hub.RetirementReady())
	}
}

func TestGuestReceiptGraphSealsOnlyAfterAgentLifecycleJoins(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "joined", true: "cancelled"}[canceled], func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			finalizer := &observedFinalizer{sealed: make(chan struct{}), aborted: make(chan struct{})}
			graph := roleprocess.ApplicationGraph{
				Start:    func(context.Context) error { close(entered); <-release; return nil },
				Shutdown: func(context.Context) error { return nil },
			}
			if err := bindGuestReceiptGraph(&graph, finalizer); err != nil {
				t.Fatal(err)
			}
			started := make(chan error, 1)
			go func() { started <- graph.Start(t.Context()) }()
			<-entered
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			stopped := make(chan error, 1)
			go func() { stopped <- graph.Shutdown(ctx) }()
			select {
			case <-finalizer.sealed:
				t.Fatal("Guest receipt sealed before Agent.Run returned")
			case <-time.After(25 * time.Millisecond):
			}
			if canceled {
				cancel()
				if err := <-stopped; err == nil {
					t.Fatal("canceled Guest producer join was accepted")
				}
				select {
				case <-finalizer.aborted:
				default:
					t.Fatal("canceled Guest producer join did not abort")
				}
			}
			close(release)
			if err := <-started; err != nil {
				t.Fatal(err)
			}
			if !canceled {
				if err := <-stopped; err != nil {
					t.Fatal(err)
				}
				select {
				case <-finalizer.sealed:
				default:
					t.Fatal("joined Guest producer was not sealed")
				}
			} else {
				select {
				case <-finalizer.sealed:
					t.Fatal("canceled Guest producer join emitted a seal")
				default:
				}
			}
		})
	}
}
