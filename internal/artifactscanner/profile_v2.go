package artifactscanner

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
)

// NewRemoteMalwareCheckerV2 is the dedicated Provider composition. Callers
// cannot substitute a second dialer or fake peer monitor. The lifetime owns
// polling and Close must be called before releasing its signer resources.
func NewRemoteMalwareCheckerV2(lifetime context.Context, p phase6security.ProfileV2, a phase6tls.PrivateServiceAuthorityV2) (*RemoteMalwareChecker, error) {
	if lifetime == nil || lifetime.Err() != nil || a.Scope != "scanner" {
		return nil, ErrInvalidScanProtocol
	}
	b, err := p.PrivateServiceBoundary("scanner", a.Address)
	if err != nil {
		return nil, ErrInvalidScanProtocol
	}
	transport, peer, err := phase6tls.PrivateServiceClientV2(p, a)
	if err != nil {
		return nil, err
	}
	operation, cancel := context.WithTimeout(lifetime, a.OperationTimeout)
	err = peer.Bootstrap(operation)
	cancel()
	if err != nil || !peer.Ready() {
		peer.Close()
		transport.CloseIdleConnections()
		return nil, ErrInvalidScanProtocol
	}
	remote, err := NewRemoteMalwareChecker(RemoteConfig{BaseURL: "https://" + b.Edge.TargetAddress, GuardedTransport: transport, Peer: peer,
		ProfileDigest: p.ProfileDigest, ExpectedRuleSetDigest: p.ArtifactScanner.RuleManifestDigest, OperationTimeout: a.OperationTimeout, Clock: time.Now})
	if err != nil {
		peer.Close()
		transport.CloseIdleConnections()
		return nil, err
	}
	remote.lifetime = lifetime
	stop := connectiondrain.StartPeerPoll(lifetime, peer)
	closeOnCancel := context.AfterFunc(lifetime, peer.Close)
	remote.cleanup = func() { closeOnCancel(); stop(); peer.Close(); transport.CloseIdleConnections() }
	return remote, nil
}
