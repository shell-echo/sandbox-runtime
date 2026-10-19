package trustanchor

import (
	"context"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func TestRetainDirectoryRejectsUnboundInput(t *testing.T) {
	now := time.Now()
	for name, input := range map[string]struct {
		ctx    context.Context
		anchor phase6security.TrustAnchor
		now    time.Time
	}{
		"nil context":       {nil, phase6security.TrustAnchor{}, now},
		"zero anchor":       {context.Background(), phase6security.TrustAnchor{}, now},
		"zero time":         {context.Background(), phase6security.TrustAnchor{ID: "internal-server-ca"}, time.Time{}},
		"legacy file mount": {context.Background(), phase6security.TrustAnchor{ID: "internal-server-ca", TargetPath: "/run/trust/internal-server-ca/bundle.pem"}, now},
	} {
		t.Run(name, func(t *testing.T) {
			session, err := RetainDirectory(input.ctx, input.anchor, input.now)
			if err == nil || session != nil {
				t.Fatal("unbound trust anchor accepted")
			}
		})
	}
}
