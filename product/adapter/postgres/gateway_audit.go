package productpostgres

import (
	"context"
	"strings"

	"github.com/shell-echo/sandbox-runtime/gateway"
	"github.com/shell-echo/sandbox-runtime/product"
	productgateway "github.com/shell-echo/sandbox-runtime/product/adapter/gateway"
)

type GatewayAuditRepository struct {
	store *Store
	ids   product.IDGenerator
}

func NewGatewayAuditRepository(store *Store, ids product.IDGenerator) (*GatewayAuditRepository, error) {
	if store == nil || ids == nil {
		return nil, product.ErrInvalid
	}
	return &GatewayAuditRepository{store: store, ids: ids}, nil
}

func (r *GatewayAuditRepository) RecordGatewayEvent(ctx context.Context, binding product.GatewayBinding, event gateway.AuditEvent) error {
	if r == nil || r.store == nil || ctx == nil || event.TenantID != binding.TenantID || event.GrantID != binding.ConnectionID {
		return product.ErrStoreUnavailable
	}
	eventID, err := r.ids.NewID("aud")
	if err != nil {
		return product.ErrStoreUnavailable
	}
	outcome := "allowed"
	if event.Type == gateway.AuditDenied {
		outcome = "denied"
	} else if strings.Contains(string(event.Type), "failed") || strings.Contains(string(event.Type), "unavailable") {
		outcome = "failed"
	}
	opCtx, cancel := context.WithTimeout(ctx, r.store.operationTimeout)
	defer cancel()
	_, err = r.store.pool.Exec(opCtx, `INSERT INTO sandbox_runtime_product.security_audit(event_id,tenant_id,actor_type,actor_id,action,resource_type,resource_id,outcome,reason_code,request_id,occurred_at)VALUES($1,$2,$3,$4,$5,'connection_grant',$6,$7,$8,$1,$9)`, eventID, binding.TenantID, string(binding.Actor.Type), binding.Actor.ID, "gateway."+string(event.Type), binding.ConnectionID, outcome, string(event.Type), event.At)
	if err != nil {
		return product.ErrStoreUnavailable
	}
	return nil
}

var _ productgateway.AuditStore = (*GatewayAuditRepository)(nil)
