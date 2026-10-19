package codingcontroltransport

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/codingcontrolprotocol"
	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/internal/dockercontrol"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/provider/lifecycle/codingcontrol"
)

// RunStatusV2 opens only the existing, independently initialized Coding receipt
// ledger. It never initializes missing state or exposes Docker mutations. A
// future full Control command must own that same ledger, not start a second
// process that competes for its lifetime lock.
func RunStatusV2(ctx context.Context, p phase6security.ProfileV2, a phase6tls.PrivateServiceAuthorityV2, binding dockercontrol.CodingReceiptBinding) error {
	return runCodingV2(ctx, p, a, binding, nil)
}

// CodingMutationInputs contain exact operator-supplied source bytes, never
// paths or Docker options. Descriptor presence is not image availability or
// a substitute for the Profile's image supply/security admission gate.
type CodingMutationInputs struct {
	Documents     phase6security.ImageDescriptorDocuments `json:"documents"`
	SeccompPolicy []byte                                  `json:"seccomp_policy"`
}

// RunCodingV2 serves the existing canonical create/cleanup/status protocol.
// It opens the same existing ledger exclusively; it never initializes state,
// changes its daemon binding, pulls images, or removes historical Unknowns.
func RunCodingV2(ctx context.Context, p phase6security.ProfileV2, a phase6tls.PrivateServiceAuthorityV2, binding dockercontrol.CodingReceiptBinding, inputs CodingMutationInputs) error {
	return runCodingV2(ctx, p, a, binding, &inputs)
}

func runCodingV2(ctx context.Context, p phase6security.ProfileV2, a phase6tls.PrivateServiceAuthorityV2, binding dockercontrol.CodingReceiptBinding, inputs *CodingMutationInputs) error {
	if ctx == nil || ctx.Err() != nil || a.Scope != "coding" {
		return ErrInvalidStatusServer
	}
	b, err := p.PrivateServiceBoundary("coding", a.Address)
	if err != nil || binding.Validate() != nil || binding.ProfileDigest != p.ProfileDigest || binding.PeerPrincipalDigest != b.Provider.PrincipalDigest || p.CodingTemplate.BindPlan(binding.Plan) != nil {
		return ErrInvalidStatusServer
	}
	transport, probe, peer, err := phase6tls.PrivateServiceServerV2(p, a)
	if err != nil {
		return ErrInvalidStatusServer
	}
	defer peer.Close()
	operation, cancel := context.WithTimeout(ctx, a.OperationTimeout)
	err = probe(operation)
	cancel()
	if err != nil {
		return ErrInvalidStatusServer
	}
	ledger, err := dockercontrol.OpenCodingReceiptLedger(filepath.Join(p.DockerControl.ReceiptTarget, "coding-receipts.json"), binding)
	if err != nil {
		return ErrInvalidStatusServer
	}
	defer ledger.Close()
	server, err := newStatusServer(statusServerConfig{TLSConfig: transport, ListenAddress: b.Edge.TargetAddress, ExpectedProviderURI: b.Provider.TLS.URI,
		ProviderPrincipalDigest: b.Provider.PrincipalDigest, ProfileDigest: p.ProfileDigest, ControlPolicyDigest: binding.ControlPolicyDigest,
		OperationTimeout: a.OperationTimeout, Ledger: ledger, Clock: time.Now}, peer, projectStatus)
	if err != nil {
		return ErrInvalidStatusServer
	}
	defer server.Close()
	if inputs != nil {
		server.executor, err = dockercontrol.NewCodingExecutorV2(p, a.Address, binding, ledger, inputs.Documents, inputs.SeccompPolicy)
		if err != nil {
			return ErrInvalidStatusServer
		}
	}
	registry, err := connectiondrain.NewBounded(time.Duration(b.Edge.MaxConnectionSeconds)*time.Second, 2)
	if err != nil || registry.OnClose(peer.Forget) != nil {
		return ErrInvalidStatusServer
	}
	defer registry.Drain()
	listener, err := net.Listen("tcp", b.Edge.TargetAddress)
	if err != nil {
		return ErrInvalidStatusServer
	}
	defer listener.Close()
	bounded, err := registry.Wrap(listener)
	if err != nil {
		return ErrInvalidStatusServer
	}
	return server.Serve(ctx, bounded)
}

// StatusObserverV2 supplies the typed lifecycle Coordinator's read-only port.
// A status result is not a Docker permit or proof of absence. No configurable
// transport, peer substitute, redirect or arbitrary target is admitted.
type StatusObserverV2 struct {
	client   *statusClient
	peer     *phase6tls.PeerCRLGuard
	lifetime context.Context
	timeout  time.Duration
	cleanup  func()
	once     sync.Once
}

func NewStatusObserverV2(lifetime context.Context, p phase6security.ProfileV2, a phase6tls.PrivateServiceAuthorityV2, controlPolicyDigest string) (*StatusObserverV2, error) {
	if lifetime == nil || lifetime.Err() != nil || a.Scope != "coding" || !statusDigestPattern.MatchString(controlPolicyDigest) {
		return nil, ErrInvalidStatusClient
	}
	b, err := p.PrivateServiceBoundary("coding", a.Address)
	if err != nil {
		return nil, ErrInvalidStatusClient
	}
	transport, peer, err := phase6tls.PrivateServiceClientV2(p, a)
	if err != nil {
		return nil, ErrInvalidStatusClient
	}
	operation, cancel := context.WithTimeout(lifetime, a.OperationTimeout)
	err = peer.Bootstrap(operation)
	cancel()
	if err != nil || !peer.Ready() {
		peer.Close()
		transport.CloseIdleConnections()
		return nil, ErrInvalidStatusClient
	}
	client, err := newStatusClient(statusClientConfig{Origin: "https://" + b.Edge.TargetAddress, ProviderPrincipalDigest: b.Provider.PrincipalDigest,
		ProfileDigest: p.ProfileDigest, ControlPolicyDigest: controlPolicyDigest, OperationTimeout: a.OperationTimeout, Transport: transport})
	if err != nil {
		peer.Close()
		transport.CloseIdleConnections()
		return nil, ErrInvalidStatusClient
	}
	stop := connectiondrain.StartPeerPoll(lifetime, peer)
	closeOnCancel := context.AfterFunc(lifetime, peer.Close)
	return &StatusObserverV2{client: client, peer: peer, lifetime: lifetime, timeout: a.OperationTimeout, cleanup: func() { closeOnCancel(); stop(); peer.Close(); client.Close(); transport.CloseIdleConnections() }}, nil
}

func (o *StatusObserverV2) Observe(ctx context.Context, request codingcontrolprotocol.Request) (codingcontrolprotocol.Response, error) {
	empty := codingcontrolprotocol.Response{}
	if o == nil || o.client == nil || o.peer == nil || o.lifetime == nil || o.lifetime.Err() != nil || ctx == nil || ctx.Err() != nil {
		return empty, ErrInvalidStatusClient
	}
	operation, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	stop := context.AfterFunc(o.lifetime, cancel)
	defer stop()
	if o.peer.Poll(operation) != nil || !o.peer.Ready() {
		return empty, ErrInvalidStatusClient
	}
	response, err := o.client.Read(operation, request)
	if err != nil || o.peer.Poll(operation) != nil || !o.peer.Ready() || operation.Err() != nil || o.lifetime.Err() != nil {
		return empty, ErrInvalidStatusClient
	}
	return response, nil
}
func (o *StatusObserverV2) Close() {
	if o != nil {
		o.once.Do(func() {
			if o.cleanup != nil {
				o.cleanup()
			}
		})
	}
}

var _ codingcontrol.Observer = (*StatusObserverV2)(nil)
