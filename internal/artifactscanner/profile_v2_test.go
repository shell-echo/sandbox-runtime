package artifactscanner

import (
	"context"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"github.com/shell-echo/sandbox-runtime/internal/phase6tls"
	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

func TestRemoteScannerV2RetainsHold(t *testing.T) {
	if c, err := NewRemoteMalwareCheckerV2(context.Background(), phase6security.ProfileV2{}, phase6tls.PrivateServiceAuthorityV2{Scope: "scanner"}); err == nil || c != nil {
		t.Fatal("held profile admitted")
	}
}
func TestRemoteScannerLifetimeCancelsActiveRequestAndClosesOnce(t *testing.T) {
	rulesDigest := scanDigest([]byte("verified-rules"))
	engine := &scannerTestEngine{verdict: MalwareClean, started: make(chan struct{}, 1), release: make(chan struct{})}
	base, material, stop := startScannerTestService(t, engine, &scannerTestRules{digest: rulesDigest})
	defer stop()
	remote := testRemoteScanner(t, base, material.client, rulesDigest)
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	remote.lifetime = lifetime
	cleaned := 0
	remote.cleanup = func() { cleaned++ }
	content := []byte(`{"ok":true}`)
	request := scannerTestRequest(content)
	finished := make(chan error, 1)
	go func() { _, err := remote.CheckContent(context.Background(), request, content); finished <- err }()
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("scan did not start")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled Provider lifetime returned clean")
		}
	case <-time.After(time.Second):
		t.Fatal("lifetime did not cancel active request")
	}
	close(engine.release)
	if remote.CheckSupport(context.Background(), request) == nil {
		t.Fatal("canceled lifetime remained ready")
	}
	if status, err := remote.CheckContent(context.Background(), request, content); err == nil || status != artifact.CheckNotRun {
		t.Fatal("canceled lifetime scanned again")
	}
	_ = remote.Close()
	_ = remote.Close()
	if cleaned != 1 {
		t.Fatal("cleanup not exactly once")
	}
}
