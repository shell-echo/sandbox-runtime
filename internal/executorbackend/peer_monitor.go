package executorbackend

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/connectiondrain"
)

func newExecutorPeerRegistry(remote *tls.Config, monitor connectiondrain.PeerMonitor,
	probe func(context.Context) error, maxAge time.Duration) (*connectiondrain.Registry, error) {
	if remote == nil {
		if monitor != nil || probe != nil || maxAge != 0 {
			return nil, errors.New("static executor TLS cannot carry a live peer monitor")
		}
		return nil, nil
	}
	if monitor == nil || probe == nil || maxAge < time.Second || maxAge > time.Hour ||
		monitor.PollInterval() < 100*time.Millisecond || monitor.PollInterval() > time.Minute {
		return nil, errors.New("live executor TLS requires bounded peer revocation")
	}
	registry, err := connectiondrain.New(maxAge)
	if err != nil || registry.OnClose(monitor.Forget) != nil {
		return nil, errors.New("executor peer connection cleanup is unavailable")
	}
	return registry, nil
}

func executorPeerReady(ctx context.Context, monitor connectiondrain.PeerMonitor,
	probe func(context.Context) error) error {
	if monitor == nil {
		return nil
	}
	if probe == nil || probe(ctx) != nil || monitor.Poll(ctx) != nil || !monitor.Ready() {
		return errors.New("executor live TLS peer revocation is unavailable")
	}
	return nil
}

func wrapExecutorPeerListener(listener net.Listener, registry *connectiondrain.Registry) (net.Listener, error) {
	if registry == nil {
		return listener, nil
	}
	return registry.Wrap(listener)
}
