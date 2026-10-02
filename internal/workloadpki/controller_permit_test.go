package workloadpki

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

type permitBlockedIssuer struct {
	fakeCertificateAuthority
	entered chan struct{}
	release chan struct{}
}

func (a *permitBlockedIssuer) Issue(ctx context.Context, policy Policy, csr []byte, ttl time.Duration) (IssuedCertificate, error) {
	close(a.entered)
	<-a.release
	return a.fakeCertificateAuthority.Issue(ctx, policy, csr, ttl)
}

// The first Err call is observed before the controller waits for its permit.
// Returning its pre-cancellation snapshot models cancellation at that boundary.
type permitObservedContext struct {
	context.Context
	entered chan struct{}
	proceed chan struct{}
	once    sync.Once
}

func (c *permitObservedContext) Err() error {
	err := c.Context.Err()
	c.observe()
	return err
}

func (c *permitObservedContext) Deadline() (time.Time, bool) {
	c.observe()
	return c.Context.Deadline()
}

func (c *permitObservedContext) observe() {
	c.once.Do(func() {
		close(c.entered)
		<-c.proceed
	})
}

func awaitPermitResult[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("controller operation did not complete within test safety deadline")
		var zero T
		return zero
	}
}

func TestControllerPermitCanceledAndExpiredWaitersDoNotMutate(t *testing.T) {
	for _, variant := range []struct {
		name     string
		v2       bool
		deadline bool
	}{
		{name: "v1-canceled"},
		{name: "v1-expired", deadline: true},
		{name: "v2-canceled", v2: true},
		{name: "v2-expired", v2: true, deadline: true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			fixture := newProtocolFixture(t)
			fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
			authority := &permitBlockedIssuer{fakeCertificateAuthority: fakeCertificateAuthority{fixture: fixture},
				entered: make(chan struct{}), release: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(authority.release) }) }
			defer release()
			controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"),
				Policies: []Policy{fixture.policy}, Authority: authority, ControllerKeyID: fixture.controllerID,
				ControllerKey: fixture.controllerPriv, Now: func() time.Time { return fixture.now },
				MaximumActive: 2, MaximumLedgerAge: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			defer controller.Close()
			issue, err := NewIssueRequest(fixture.policy, "permit-issue",
				base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{91}, 32)), fixture.now.Add(30*time.Second),
				10*time.Minute, fixture.csr, fixture.agentPrivate)
			if err != nil {
				t.Fatal(err)
			}
			issueDone := make(chan error, 1)
			go func() {
				response, handleErr := controller.Handle(context.Background(), issue, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
				response.Destroy()
				issueDone <- handleErr
			}()
			awaitPermitResult(t, authority.entered)
			if len(controller.permit) != 0 || len(controller.ledger.Replays) != 1 {
				t.Fatal("issuer call did not retain the single replay/authority permit")
			}
			var parent context.Context
			var cancel context.CancelFunc
			if variant.deadline {
				parent, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
			} else {
				parent, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			queued := &permitObservedContext{Context: parent, entered: make(chan struct{}), proceed: make(chan struct{})}
			result := make(chan error, 1)
			if variant.v2 {
				// Admission must end before source validation; no invalid fixture
				// can become an authorized source through this test path.
				controller.peerCRLProfile = &phase6security.Profile{}
				controller.peerCRLSources = &phase6security.PeerCRLSources{}
				request, requestErr := NewPeerCRLRequest(fixture.policy, "permit-peer-crl",
					base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{92}, 32)), fixture.now.Add(30*time.Second),
					"sha256:"+strings.Repeat("a", 64), "product-provider-contract", fixture.policy.Subject.Digest(),
					"outbound", "internal-server-ca", "sha256:"+strings.Repeat("b", 64), "provider-peer-ca",
					fixture.agentPrivate, fixture.now)
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				go func() {
					response, handleErr := controller.HandlePeerCRL(queued, request, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
					clear(response.IssuerDER)
					clear(response.CRLDER)
					result <- handleErr
				}()
			} else {
				request, requestErr := NewRevocationsRequest(fixture.policy, "permit-crl",
					base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{92}, 32)), fixture.now.Add(30*time.Second), fixture.agentPrivate)
				if requestErr != nil {
					t.Fatal(requestErr)
				}
				go func() {
					response, handleErr := controller.Handle(queued, request, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
					response.Destroy()
					result <- handleErr
				}()
			}
			awaitPermitResult(t, queued.entered)
			if parent.Err() != nil {
				t.Fatal("test context expired before the queued admission boundary")
			}
			close(queued.proceed)
			if variant.deadline {
				awaitPermitResult(t, parent.Done())
			} else {
				cancel()
			}
			want := context.Canceled
			if variant.deadline {
				want = context.DeadlineExceeded
			}
			if err := awaitPermitResult(t, result); !errors.Is(err, want) {
				t.Fatalf("queued operation = %v, want %v", err, want)
			}
			if len(controller.ledger.Replays) != 1 || authority.issueCalls != 0 {
				t.Fatal("canceled waiter mutated replay/authority state")
			}
			release()
			if err := awaitPermitResult(t, issueDone); err != nil {
				t.Fatalf("occupying issue: %v", err)
			}
			if variant.v2 {
				controller.peerCRLProfile, controller.peerCRLSources = nil, nil
			}
			normal, err := NewRevocationsRequest(fixture.policy, "permit-normal-crl",
				base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{93}, 32)), fixture.now.Add(30*time.Second), fixture.agentPrivate)
			if err != nil {
				t.Fatal(err)
			}
			response, err := controller.Handle(context.Background(), normal, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
			if err != nil || response.Status != StatusOK || len(controller.ledger.Replays) != 2 || len(controller.permit) != 1 {
				t.Fatalf("permit not reusable: response=%+v err=%v replays=%d", response, err, len(controller.ledger.Replays))
			}
			response.Destroy()
		})
	}
}

func TestControllerPermitRejectsCancelWhenPermitAlsoReady(t *testing.T) {
	controller := &Controller{permit: make(chan struct{}, 1)}
	controller.release()
	for i := 0; i < 100; i++ {
		base, cancel := context.WithCancel(context.Background())
		observed := &permitObservedContext{Context: base, entered: make(chan struct{}), proceed: make(chan struct{})}
		result := make(chan error, 1)
		go func() { result <- controller.acquire(observed) }()
		awaitPermitResult(t, observed.entered)
		cancel()
		close(observed.proceed)
		if err := awaitPermitResult(t, result); !errors.Is(err, context.Canceled) || len(controller.permit) != 1 {
			t.Fatalf("simultaneous ready admission = %v, permit=%d", err, len(controller.permit))
		}
	}
}

func TestControllerPermitQuiesceAndReapWaitsAreCancelable(t *testing.T) {
	fixture := newProtocolFixture(t)
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"),
		Policies: []Policy{fixture.policy}, Authority: &fakeCertificateAuthority{fixture: fixture},
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv,
		Now: func() time.Time { return fixture.now }, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if err := controller.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		call func(context.Context) error
	}{
		{name: "quiesce", call: controller.BeginQuiesce},
		{name: "reap", call: controller.Reap},
	} {
		t.Run(operation.name, func(t *testing.T) {
			base, cancel := context.WithCancel(context.Background())
			observed := &permitObservedContext{Context: base, entered: make(chan struct{}), proceed: make(chan struct{})}
			result := make(chan error, 1)
			go func() { result <- operation.call(observed) }()
			awaitPermitResult(t, observed.entered)
			cancel()
			close(observed.proceed)
			if err := awaitPermitResult(t, result); !errors.Is(err, context.Canceled) {
				t.Fatalf("queued %s = %v", operation.name, err)
			}
			if controller.quiescing || controller.ledger.QuiescedAt != nil || len(controller.ledger.Replays) != 0 {
				t.Fatal("canceled lifecycle waiter changed persistent state")
			}
		})
	}
	controller.release()
	if err := controller.BeginQuiesce(context.Background()); err != nil || !controller.quiescing || controller.ledger.QuiescedAt == nil {
		t.Fatalf("quiesce after canceled waiters = %v, ledger=%+v", err, controller.ledger)
	}
}

func TestControllerPermitWaitCannotOutliveSignedRequestDeadline(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"),
		Policies: []Policy{fixture.policy}, Authority: &fakeCertificateAuthority{fixture: fixture},
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv,
		Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	request, err := NewRevocationsRequest(fixture.policy, "permit-request-deadline",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{94}, 32)), fixture.now.Add(2*time.Second), fixture.agentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer controller.release()
	result := make(chan error, 1)
	go func() {
		response, handleErr := controller.Handle(context.Background(), request, fixture.policy.ExpectedUID, fixture.policy.ExpectedGID)
		response.Destroy()
		result <- handleErr
	}()
	if err := awaitPermitResult(t, result); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request deadline did not bound permit wait: %v", err)
	}
	if len(controller.ledger.Replays) != 0 || len(controller.permit) != 0 {
		t.Fatal("expired queued request mutated ledger or permit")
	}
}

func TestServerCloseCancelsQueuedControllerHandlerAndRemovesSocket(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"),
		Policies: []Policy{fixture.policy}, Authority: &fakeCertificateAuthority{fixture: fixture},
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv,
		Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	socket := filepath.Join(securePKIDirectory(t), "controller.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		InternalSelf: true, ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()),
		MaxConnections: 1, ReapInterval: time.Second}, controller)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	defer server.Close()
	if err := controller.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			controller.release()
		}
	}()
	client, err := NewProductionClient(ClientConfig{SocketPath: socket, ExpectedUID: uint32(os.Getuid()),
		ExpectedGID: uint32(os.Getgid()), DirectoryGID: uint32(os.Getgid()), InternalSelf: true,
		Policy: fixture.policy, AgentPrivateKey: fixture.agentPrivate, ControllerKeyID: fixture.controllerID,
		ControllerPublic: fixture.controllerPub, OperationTimeout: 3 * time.Second, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	clientDone := make(chan error, 1)
	go func() {
		snapshot, requestErr := client.Revocations(context.Background())
		snapshot.Destroy()
		clientDone <- requestErr
	}()
	// Receipt of the capacity token is a deterministic acceptance barrier;
	// put it back before the handler's deferred release.
	awaitPermitResult(t, server.capacity)
	server.capacity <- struct{}{}
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	if err := awaitPermitResult(t, closeDone); err != nil {
		t.Fatal(err)
	}
	controller.release()
	released = true
	if err := awaitPermitResult(t, clientDone); err == nil {
		t.Fatal("closed server returned an admitted CRL")
	}
	if err := awaitPermitResult(t, serveDone); err != nil {
		t.Fatalf("server exit: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket cleanup: %v", err)
	}
	if len(controller.ledger.Replays) != 0 || len(controller.permit) != 1 {
		t.Fatal("closed pending handler mutated ledger or lost permit")
	}
	controller.Close()
	controller.Close()
	if len(controller.controllerKey) != 0 || len(controller.policies) != 0 {
		t.Fatal("repeat controller close retained signing key or policies")
	}
}

func TestServerCloseCancelsQueuedPeerCRLHandler(t *testing.T) {
	fixture := newProtocolFixture(t)
	fixture.policy.ExpectedUID, fixture.policy.ExpectedGID = uint32(os.Getuid()), uint32(os.Getgid())
	controller, err := NewController(ControllerConfig{LedgerPath: filepath.Join(securePKIDirectory(t), "ledger.json"),
		Policies: []Policy{fixture.policy}, Authority: &fakeCertificateAuthority{fixture: fixture},
		ControllerKeyID: fixture.controllerID, ControllerKey: fixture.controllerPriv,
		Now: time.Now, MaximumActive: 2, MaximumLedgerAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	// The source mapping is deliberately invalid: shutdown must cancel admission
	// before any source lookup, and must never authorize this fixture.
	controller.peerCRLProfile = &phase6security.Profile{}
	controller.peerCRLSources = &phase6security.PeerCRLSources{}
	socket := filepath.Join(securePKIDirectory(t), "controller.sock")
	server, err := Listen(ServerConfig{SocketPath: socket, SocketUID: uint32(os.Getuid()), SocketGID: uint32(os.Getgid()),
		InternalSelf: true, ExpectedClientUID: uint32(os.Getuid()), ExpectedClientGID: uint32(os.Getgid()),
		MaxConnections: 1, ReapInterval: time.Second}, controller)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	defer server.Close()
	if err := controller.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	released := false
	defer func() {
		if !released {
			controller.release()
		}
	}()
	request, err := NewPeerCRLRequest(fixture.policy, "permit-close-peer-crl",
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{95}, 32)), fixture.now.Add(30*time.Second),
		"sha256:"+strings.Repeat("a", 64), "product-provider-contract", fixture.policy.Subject.Digest(),
		"outbound", "internal-server-ca", "sha256:"+strings.Repeat("b", 64), "provider-peer-ca",
		fixture.agentPrivate, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	document, err := EncodePeerCRLRequest(request, fixture.policy, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(connection, document, maxRequestBytes); err != nil {
		t.Fatal(err)
	}
	awaitPermitResult(t, server.capacity)
	server.capacity <- struct{}{}
	closeDone := make(chan error, 1)
	go func() { closeDone <- server.Close() }()
	if err := awaitPermitResult(t, closeDone); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(connection, maxResponseBytes); err == nil {
		t.Fatal("closed peer-CRL handler returned a source response")
	}
	controller.release()
	released = true
	if err := awaitPermitResult(t, serveDone); err != nil {
		t.Fatalf("server exit: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket cleanup: %v", err)
	}
	if len(controller.ledger.Replays) != 0 || len(controller.permit) != 1 {
		t.Fatal("closed peer-CRL handler mutated replay ledger or lost permit")
	}
}
