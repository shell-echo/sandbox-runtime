package phase6egress

import (
	"context"
	"time"

	"github.com/shell-echo/sandbox-runtime/gateway"
)

// WitnessRoleGatedAuthority rejects a stale or failed local ACL observation
// before every Browser activation and CDP write. The wrapped authority still
// performs its existing exact-member Redis and PostgreSQL witness checks.
type WitnessRoleGatedAuthority struct {
	Role *WitnessRoleGuard
	Next gateway.DownstreamFenceAuthority
}

func (a WitnessRoleGatedAuthority) AuthorizeAction(ctx context.Context, subject gateway.DownstreamFenceSubject,
	fence gateway.DownstreamFence, window time.Duration) (gateway.DownstreamFenceDecision, error) {
	if a.Role == nil || a.Next == nil || a.Role.CheckReady() != nil {
		return gateway.DownstreamFenceDecision{}, gateway.ErrDownstreamUnavailable
	}
	return a.Next.AuthorizeAction(ctx, subject, fence, window)
}

var _ gateway.DownstreamFenceAuthority = WitnessRoleGatedAuthority{}
