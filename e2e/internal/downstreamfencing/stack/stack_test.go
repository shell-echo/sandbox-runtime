package stack

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type lifecycleStub struct {
	started     chan struct{}
	startupErr  error
	startupOnce sync.Once
	mu          sync.Mutex
	starts      int
	shutdowns   int
}

type stubbornLifecycleStub struct {
	started  chan struct{}
	release  chan struct{}
	exited   chan struct{}
	startErr error
}

func newStubbornLifecycleStub() *stubbornLifecycleStub {
	return &stubbornLifecycleStub{started: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
}

func (s *stubbornLifecycleStub) Startup(context.Context) error {
	close(s.started)
	<-s.release
	close(s.exited)
	return s.startErr
}

func (s *stubbornLifecycleStub) Shutdown(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func newLifecycleStub() *lifecycleStub { return &lifecycleStub{started: make(chan struct{})} }

func (s *lifecycleStub) Startup(ctx context.Context) error {
	s.mu.Lock()
	s.starts++
	s.mu.Unlock()
	s.startupOnce.Do(func() { close(s.started) })
	if s.startupErr != nil {
		return s.startupErr
	}
	<-ctx.Done()
	return nil
}

func (s *lifecycleStub) Shutdown(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdowns++
	return nil
}

func (s *lifecycleStub) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts, s.shutdowns
}

func TestStackRunsProviderAndIngressConcurrentlyAndClosesOnce(t *testing.T) {
	provider := newLifecycleStub()
	ingress := newLifecycleStub()
	providerCloses, redisCloses := 0, 0
	stack := &Stack{
		provider: provider, ingress: ingress,
		closeProvider: func() error { providerCloses++; return nil },
		closeRedis:    func() error { redisCloses++; return nil },
	}
	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- stack.Run(ctx) }()
	for name, started := range map[string]<-chan struct{}{"Provider": provider.started, "ingress": ingress.started} {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("%s was not started", name)
		}
	}
	cancel()
	select {
	case err := <-runResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run() did not stop")
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stack.Close(); err != nil {
		t.Fatal(err)
	}
	providerStarts, providerStops := provider.counts()
	ingressStarts, ingressStops := ingress.counts()
	if providerStarts != 1 || ingressStarts != 1 || providerStops != 1 || ingressStops != 1 || providerCloses != 1 || redisCloses != 1 {
		t.Fatalf("lifecycle counts = Provider %d/%d, ingress %d/%d, closes %d/%d", providerStarts, providerStops, ingressStarts, ingressStops, providerCloses, redisCloses)
	}
	if err := stack.Run(context.Background()); err == nil {
		t.Fatal("closed stack restarted")
	}
}

func TestStackStopsBothComponentsWhenOneListenerFails(t *testing.T) {
	startupErr := errors.New("bind failed")
	provider := newLifecycleStub()
	ingress := newLifecycleStub()
	ingress.startupErr = startupErr
	stack := &Stack{provider: provider, ingress: ingress}
	if err := stack.Run(t.Context()); !errors.Is(err, startupErr) {
		t.Fatalf("Run() error = %v", err)
	}
	providerStarts, providerStops := provider.counts()
	ingressStarts, ingressStops := ingress.counts()
	if providerStarts != 1 || ingressStarts != 1 || providerStops != 1 || ingressStops != 1 {
		t.Fatalf("failure lifecycle counts = Provider %d/%d, ingress %d/%d", providerStarts, providerStops, ingressStarts, ingressStops)
	}
}

func TestStackRunReturnsWhenOtherComponentIgnoresCancellation(t *testing.T) {
	startupErr := errors.New("bind failed")
	provider := newStubbornLifecycleStub()
	ingress := newLifecycleStub()
	ingress.startupErr = startupErr
	stack := &Stack{provider: provider, ingress: ingress, stopTimeout: 25 * time.Millisecond}
	startedAt := time.Now()
	err := stack.Run(t.Context())
	if !errors.Is(err, startupErr) || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("Run() error = %v", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("Run() took %s", elapsed)
	}
	close(provider.release)
	select {
	case <-provider.exited:
	case <-time.After(time.Second):
		t.Fatal("stubborn component did not exit after test release")
	}
}

func TestRedisClientUsesBoundedRESP2WithoutRetries(t *testing.T) {
	client, err := newRedisClient("redis://e2e:secret@127.0.0.1:1/0", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	options := client.Options()
	if options.Protocol != 2 || options.MaxRetries != 0 || !options.ContextTimeoutEnabled || !options.DisableIdentity ||
		options.DialTimeout != 200*time.Millisecond || options.ReadTimeout != 200*time.Millisecond ||
		options.WriteTimeout != 200*time.Millisecond || options.PoolTimeout != 200*time.Millisecond {
		t.Fatalf("unsafe Redis options: %#v", options)
	}
}
