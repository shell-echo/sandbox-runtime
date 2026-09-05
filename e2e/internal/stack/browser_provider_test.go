package stack

import (
	"context"
	"errors"
	"slices"
	"testing"

	browserreference "github.com/shell-echo/sandbox-runtime/provider/browser/reference"
)

type browserProviderServerStub struct {
	startupContext  context.Context
	shutdownContext context.Context
	startupErr      error
	shutdownErr     error
}

func (s *browserProviderServerStub) Startup(ctx context.Context) error {
	s.startupContext = ctx
	return s.startupErr
}

func (s *browserProviderServerStub) Shutdown(ctx context.Context) error {
	s.shutdownContext = ctx
	return s.shutdownErr
}

type browserProviderResolverStub struct {
	context   context.Context
	reference string
	endpoint  browserreference.Endpoint
	err       error
}

func (r *browserProviderResolverStub) Resolve(ctx context.Context, reference string) (browserreference.Endpoint, error) {
	r.context = ctx
	r.reference = reference
	return r.endpoint, r.err
}

func TestBrowserProviderDelegatesServerAndResolver(t *testing.T) {
	startupErr := errors.New("startup failed")
	shutdownErr := errors.New("shutdown failed")
	resolveErr := errors.New("resolve failed")
	server := &browserProviderServerStub{startupErr: startupErr, shutdownErr: shutdownErr}
	endpoint := browserreference.Endpoint{Reference: "ref:browser-session:opaque-1"}
	resolver := &browserProviderResolverStub{endpoint: endpoint, err: resolveErr}
	provider := &BrowserProvider{server: server, resolver: resolver}

	startupContext := context.WithValue(context.Background(), struct{ name string }{"startup"}, "value")
	if err := provider.Startup(startupContext); !errors.Is(err, startupErr) || server.startupContext != startupContext {
		t.Fatalf("Startup() = %v, context delegated = %t", err, server.startupContext == startupContext)
	}
	shutdownContext := context.WithValue(context.Background(), struct{ name string }{"shutdown"}, "value")
	if err := provider.Shutdown(shutdownContext); !errors.Is(err, shutdownErr) || server.shutdownContext != shutdownContext {
		t.Fatalf("Shutdown() = %v, context delegated = %t", err, server.shutdownContext == shutdownContext)
	}
	resolveContext := context.WithValue(context.Background(), struct{ name string }{"resolve"}, "value")
	resolved, err := provider.Resolve(resolveContext, endpoint.Reference)
	if !errors.Is(err, resolveErr) || resolved.Reference != endpoint.Reference {
		t.Fatalf("Resolve() = (%#v, %v)", resolved, err)
	}
	if resolver.context != resolveContext || resolver.reference != endpoint.Reference {
		t.Fatalf("Resolve() delegated context/reference = (%t, %q)", resolver.context == resolveContext, resolver.reference)
	}
}

func TestBrowserProviderCloseRunsOwnedResourcesInReverseOnce(t *testing.T) {
	firstErr := errors.New("first close failed")
	lastErr := errors.New("last close failed")
	var order []string
	provider := &BrowserProvider{}
	provider.addCloser(func() error {
		order = append(order, "first")
		return firstErr
	})
	provider.addCloser(func() error {
		order = append(order, "middle")
		return nil
	})
	provider.addCloser(func() error {
		order = append(order, "last")
		return lastErr
	})

	err := provider.Close()
	if !errors.Is(err, firstErr) || !errors.Is(err, lastErr) {
		t.Fatalf("Close() error = %v", err)
	}
	if want := []string{"last", "middle", "first"}; !slices.Equal(order, want) {
		t.Fatalf("Close() order = %v, want %v", order, want)
	}
	if repeated := provider.Close(); repeated != err {
		t.Fatalf("second Close() error = %v, want %v", repeated, err)
	}
	if want := []string{"last", "middle", "first"}; !slices.Equal(order, want) {
		t.Fatalf("second Close() repeated resources: %v", order)
	}
}

func TestBrowserProviderUnavailableFailsClosed(t *testing.T) {
	var provider *BrowserProvider
	if err := provider.Startup(context.Background()); err == nil {
		t.Fatal("nil BrowserProvider Startup() succeeded")
	}
	if err := provider.Shutdown(context.Background()); err == nil {
		t.Fatal("nil BrowserProvider Shutdown() succeeded")
	}
	if _, err := provider.Resolve(context.Background(), "ref:browser-session:opaque-1"); !errors.Is(err, browserreference.ErrUnavailable) {
		t.Fatalf("nil BrowserProvider Resolve() error = %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("nil BrowserProvider Close() error = %v", err)
	}
}
