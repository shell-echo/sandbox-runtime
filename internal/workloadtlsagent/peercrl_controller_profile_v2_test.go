package workloadtlsagent

import (
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestV2ControllerPeerProviderRejectsBeforeControllerIO(t *testing.T) {
	client := &hotPeerController{}
	profile, sources := phase6security.ProfileV2{}, phase6security.PeerCRLSources{}
	provider, err := NewControllerPeerCRLProviderV2(profile, sources, sources.Digest(), "unbound", client, time.Now)
	if err == nil || provider != nil {
		t.Fatal("invalid v2 profile produced provider")
	}
	for _, owner := range []string{"", "product-runtime", "provider-runtime"} {
		provider, err = NewPostgresControllerPeerCRLProviderV2(profile, sources, sources.Digest(), owner, "unbound", client, time.Now)
		if err == nil || provider != nil {
			t.Fatal("invalid v2 profile produced PostgreSQL provider")
		}
	}
	if client.called != 0 {
		t.Fatal("rejected admission called controller")
	}
}
