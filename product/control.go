package product

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type ControlLeaseCommand struct {
	TenantID                 string
	Actor                    ActorRef
	WorkspaceID              string
	LeaseID                  string
	EventID                  string
	AuditID                  string
	IdempotencyKey           string
	RequestDigest            [32]byte
	Path                     string
	ExpectedWorkspaceVersion int64
	Scope                    ControlScope
	Fence                    int64
	Duration                 time.Duration
	Reason                   string
}

type ControlLeaseStore interface {
	AcquireControlLease(context.Context, ControlLeaseCommand) (ControlLease, bool, error)
	RenewControlLease(context.Context, ControlLeaseCommand) (ControlLease, bool, error)
	ReleaseControlLease(context.Context, ControlLeaseCommand) (bool, error)
}

type ControlService struct {
	store ControlLeaseStore
	ids   IDGenerator
}

func NewControlService(store ControlLeaseStore, ids IDGenerator) (*ControlService, error) {
	if nilInterface(store) || nilInterface(ids) {
		return nil, ErrInvalid
	}
	return &ControlService{store: store, ids: ids}, nil
}

func (s *ControlService) Acquire(ctx context.Context, tenantID string, actor ActorRef, workspaceID, idempotencyKey string, request AcquireControlLeaseRequest) (ControlLease, bool, error) {
	if err := validateControlInput(ctx, s, tenantID, actor, workspaceID, idempotencyKey); err != nil {
		return ControlLease{}, false, err
	}
	if request.ExpectedWorkspaceVersion < 1 || request.Scope.Validate(workspaceID) != nil || request.DurationSeconds < 5 || request.DurationSeconds > 120 {
		return ControlLease{}, false, ErrInvalid
	}
	leaseID, err := s.ids.NewID("ctl")
	if err != nil {
		return ControlLease{}, false, ErrStoreUnavailable
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return ControlLease{}, false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return ControlLease{}, false, ErrStoreUnavailable
	}
	digest, err := controlDigest(request)
	if err != nil {
		return ControlLease{}, false, ErrInvalid
	}
	return s.store.AcquireControlLease(ctx, ControlLeaseCommand{TenantID: tenantID, Actor: actor, WorkspaceID: workspaceID, LeaseID: leaseID, EventID: eventID, AuditID: auditID,
		IdempotencyKey: idempotencyKey, RequestDigest: digest, Path: "/api/v1/workspaces/" + workspaceID + "/control-leases", ExpectedWorkspaceVersion: request.ExpectedWorkspaceVersion,
		Scope: request.Scope, Duration: time.Duration(request.DurationSeconds) * time.Second})
}

func (s *ControlService) Renew(ctx context.Context, tenantID string, actor ActorRef, workspaceID, leaseID, idempotencyKey string, request RenewControlLeaseRequest) (ControlLease, bool, error) {
	if err := validateControlInput(ctx, s, tenantID, actor, workspaceID, idempotencyKey); err != nil {
		return ControlLease{}, false, err
	}
	if !validIdentifier(leaseID) || request.Fence < 1 || request.DurationSeconds < 5 || request.DurationSeconds > 120 {
		return ControlLease{}, false, ErrInvalid
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return ControlLease{}, false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return ControlLease{}, false, ErrStoreUnavailable
	}
	digest, err := controlDigest(request)
	if err != nil {
		return ControlLease{}, false, ErrInvalid
	}
	return s.store.RenewControlLease(ctx, ControlLeaseCommand{TenantID: tenantID, Actor: actor, WorkspaceID: workspaceID, LeaseID: leaseID, EventID: eventID, AuditID: auditID,
		IdempotencyKey: idempotencyKey, RequestDigest: digest, Path: "/api/v1/workspaces/" + workspaceID + "/control-leases/" + leaseID + ":renew", Fence: request.Fence, Duration: time.Duration(request.DurationSeconds) * time.Second})
}

func (s *ControlService) Release(ctx context.Context, tenantID string, actor ActorRef, workspaceID, leaseID, idempotencyKey string, fence int64, reason string) (bool, error) {
	if err := validateControlInput(ctx, s, tenantID, actor, workspaceID, idempotencyKey); err != nil {
		return false, err
	}
	if !validIdentifier(leaseID) || fence < 1 || len(reason) < 1 || len(reason) > 256 {
		return false, ErrInvalid
	}
	eventID, err := s.ids.NewID("evt")
	if err != nil {
		return false, ErrStoreUnavailable
	}
	auditID, err := s.ids.NewID("aud")
	if err != nil {
		return false, ErrStoreUnavailable
	}
	digest, err := controlDigest(struct {
		Fence  int64  `json:"fence"`
		Reason string `json:"reason"`
	}{fence, reason})
	if err != nil {
		return false, ErrInvalid
	}
	return s.store.ReleaseControlLease(ctx, ControlLeaseCommand{TenantID: tenantID, Actor: actor, WorkspaceID: workspaceID, LeaseID: leaseID, EventID: eventID, AuditID: auditID,
		IdempotencyKey: idempotencyKey, RequestDigest: digest, Path: "/api/v1/workspaces/" + workspaceID + "/control-leases/" + leaseID + ":release", Fence: fence, Reason: reason})
}

func validateControlInput(ctx context.Context, service *ControlService, tenantID string, actor ActorRef, workspaceID, key string) error {
	if service == nil || service.store == nil || ctx == nil || !validIdentifier(tenantID) || actor.Validate() != nil || !validIdentifier(workspaceID) || !validIdempotencyKey(key) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}
func controlDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func IsControlConflict(err error) bool {
	return errors.Is(err, ErrControlConflict) || errors.Is(err, ErrControlStale) || errors.Is(err, ErrVersionConflict)
}
func controlPath(scope ControlScope) string { return fmt.Sprintf("%s:%s", scope.Type, scope.ID) }
