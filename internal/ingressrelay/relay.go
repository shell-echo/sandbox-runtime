// Package ingressrelay forwards only two profile-pinned public TCP listeners
// to their isolated Product and Gateway endpoints. It has no HTTP, TLS,
// credentials, DNS, CONNECT, SOCKS or dynamic upstream selection.
package ingressrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Mapping struct {
	ID              string
	FrontendAddress string
	UpstreamAddress string
	MaxConnections  int
	DialTimeout     time.Duration
	IdleTimeout     time.Duration
	MaxLifetime     time.Duration
	DrainTimeout    time.Duration
	BufferBytes     int
}

type Config struct {
	Mappings []Mapping
}

type Relay struct {
	config Config
	mu     sync.Mutex
	active map[net.Conn]struct{}
	listen func(context.Context, string, string) (net.Listener, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func New(config Config) (*Relay, error) { return newRelay(config, false) }

func newRelay(config Config, allowLoopback bool) (*Relay, error) {
	if len(config.Mappings) != 2 || config.Mappings[0].ID != "gateway-public" || config.Mappings[1].ID != "product-public" {
		return nil, errors.New("ingress relay requires exactly two ordered public mappings")
	}
	frontends := make(map[string]bool, 2)
	upstreams := make(map[string]bool, 2)
	var frontendIP netip.Addr
	for _, mapping := range config.Mappings {
		frontend, err := validAddress(mapping.FrontendAddress, allowLoopback)
		if err != nil || !frontend.Addr().IsPrivate() && !(allowLoopback && frontend.Addr().IsLoopback()) {
			return nil, errors.New("invalid ingress relay frontend")
		}
		upstream, err := validAddress(mapping.UpstreamAddress, allowLoopback)
		if err != nil || !upstream.Addr().IsPrivate() && !(allowLoopback && upstream.Addr().IsLoopback()) {
			return nil, errors.New("invalid ingress relay upstream")
		}
		if frontendIP.IsValid() && frontendIP != frontend.Addr() || frontend == upstream ||
			frontends[mapping.FrontendAddress] || upstreams[mapping.UpstreamAddress] {
			return nil, errors.New("ingress relay endpoints overlap")
		}
		frontendIP = frontend.Addr()
		frontends[mapping.FrontendAddress] = true
		upstreams[mapping.UpstreamAddress] = true
		if mapping.MaxConnections < 1 || mapping.MaxConnections > 1024 ||
			mapping.DialTimeout < 100*time.Millisecond || mapping.DialTimeout > 10*time.Second ||
			mapping.IdleTimeout < time.Second || mapping.IdleTimeout > 5*time.Minute ||
			mapping.MaxLifetime < time.Second || mapping.MaxLifetime > time.Hour ||
			mapping.DrainTimeout < time.Second || mapping.DrainTimeout > time.Minute ||
			mapping.BufferBytes < 4<<10 || mapping.BufferBytes > 64<<10 {
			return nil, errors.New("invalid ingress relay limits")
		}
	}
	return &Relay{config: config, active: make(map[net.Conn]struct{}),
		listen: (&net.ListenConfig{}).Listen,
		dial:   (&net.Dialer{}).DialContext}, nil
}

func validAddress(value string, allowLoopback bool) (netip.AddrPort, error) {
	parsed, err := netip.ParseAddrPort(value)
	if err != nil || !parsed.Addr().Is4() || !parsed.Addr().IsValid() || parsed.Port() == 0 ||
		parsed.Addr().IsUnspecified() || parsed.Addr().IsMulticast() || parsed.Addr().IsLinkLocalUnicast() ||
		(parsed.Addr().IsLoopback() && !allowLoopback) || parsed.String() != value {
		return netip.AddrPort{}, errors.New("ingress relay requires a canonical explicit IPv4 endpoint")
	}
	return parsed, nil
}

func (r *Relay) Serve(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("ingress relay context is required")
	}
	listeners := make([]net.Listener, 0, 2)
	for _, mapping := range r.config.Mappings {
		listener, err := r.listen(ctx, "tcp4", mapping.FrontendAddress)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return errors.New("bind ingress relay frontend")
		}
		listeners = append(listeners, listener)
	}
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsOut := make(chan error, 2)
	var accepts sync.WaitGroup
	var sessions sync.WaitGroup
	for index, mapping := range r.config.Mappings {
		accepts.Add(1)
		go func(listener net.Listener, mapping Mapping) {
			defer accepts.Done()
			errorsOut <- r.accept(serveCtx, listener, mapping, &sessions)
		}(listeners[index], mapping)
	}
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errorsOut:
	}
	cancel()
	for _, listener := range listeners {
		_ = listener.Close()
	}
	r.closeActive()
	accepts.Wait()
	done := make(chan struct{})
	go func() { sessions.Wait(); close(done) }()
	drain := r.config.Mappings[0].DrainTimeout
	if r.config.Mappings[1].DrainTimeout > drain {
		drain = r.config.Mappings[1].DrainTimeout
	}
	select {
	case <-done:
	case <-time.After(drain):
		return errors.New("ingress relay drain exceeded bound")
	}
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, context.Canceled) {
		return errors.New("ingress relay accept failed")
	}
	return nil
}

func (r *Relay) accept(ctx context.Context, listener net.Listener, mapping Mapping, sessions *sync.WaitGroup) error {
	capacity := make(chan struct{}, mapping.MaxConnections)
	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			_ = client.Close()
			return ctx.Err()
		}
		select {
		case capacity <- struct{}{}:
		default:
			_ = client.Close()
			continue
		}
		r.track(client, true)
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer func() { <-capacity; r.track(client, false); _ = client.Close() }()
			r.session(ctx, client, mapping)
		}()
	}
}

func (r *Relay) session(ctx context.Context, client net.Conn, mapping Mapping) {
	dialCtx, cancel := context.WithTimeout(ctx, mapping.DialTimeout)
	upstream, err := r.dial(dialCtx, "tcp4", mapping.UpstreamAddress)
	cancel()
	if err != nil {
		return
	}
	r.track(upstream, true)
	defer func() { r.track(upstream, false); _ = upstream.Close() }()
	expired := time.AfterFunc(mapping.MaxLifetime, func() { _ = client.Close(); _ = upstream.Close() })
	defer expired.Stop()
	results := make(chan error, 2)
	go func() { results <- copyBounded(upstream, client, mapping.BufferBytes, mapping.IdleTimeout) }()
	go func() { results <- copyBounded(client, upstream, mapping.BufferBytes, mapping.IdleTimeout) }()
	first := <-results
	if first != nil {
		_ = client.Close()
		_ = upstream.Close()
	}
	<-results
}

func copyBounded(destination, source net.Conn, bufferBytes int, idle time.Duration) error {
	buffer := make([]byte, bufferBytes)
	for {
		_ = source.SetReadDeadline(time.Now().Add(idle))
		read, readErr := source.Read(buffer)
		if read > 0 {
			_ = destination.SetWriteDeadline(time.Now().Add(idle))
			written, writeErr := destination.Write(buffer[:read])
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			if tcp, ok := destination.(*net.TCPConn); ok {
				return tcp.CloseWrite()
			}
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (r *Relay) track(connection net.Conn, add bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if add {
		r.active[connection] = struct{}{}
	} else {
		delete(r.active, connection)
	}
}

func (r *Relay) closeActive() {
	r.mu.Lock()
	connections := make([]net.Conn, 0, len(r.active))
	for connection := range r.active {
		connections = append(connections, connection)
	}
	r.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (r *Relay) ActiveConnections() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}
