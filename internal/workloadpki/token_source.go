package workloadpki

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

type CredentialClient interface {
	Issue(context.Context, time.Duration) (CredentialLease, error)
	Renew(context.Context, CredentialLease, time.Duration) (CredentialLease, error)
	Revoke(context.Context, CredentialLease) error
}

type CredentialLease struct {
	ID         string
	Revision   int64
	IssuedAt   time.Time
	ExpiresAt  time.Time
	Renewable  bool
	Credential []byte
}

func (l *CredentialLease) Destroy() {
	if l != nil {
		clear(l.Credential)
		l.Credential = nil
	}
}

type CredentialTokenSourceConfig struct {
	Client CredentialClient
	TTL    time.Duration
	Now    func() time.Time
}

type CredentialTokenSource struct {
	mu       sync.Mutex
	client   CredentialClient
	ttl      time.Duration
	now      func() time.Time
	lease    CredentialLease
	closed   bool
	closeErr error
}

func NewCredentialTokenSource(config CredentialTokenSourceConfig) (*CredentialTokenSource, error) {
	if config.Client == nil || config.TTL < time.Minute || config.TTL > 15*time.Minute || config.Now == nil || config.Now().IsZero() {
		return nil, ErrUnavailable
	}
	return &CredentialTokenSource{client: config.Client, ttl: config.TTL, now: config.Now}, nil
}

func (s *CredentialTokenSource) Token(ctx context.Context) (VaultToken, error) {
	if s == nil || ctx == nil {
		return VaultToken{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return VaultToken{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return VaultToken{}, ErrUnavailable
	}
	now := s.now().UTC()
	if len(s.lease.Credential) == 0 {
		lease, err := s.client.Issue(ctx, s.ttl)
		if err != nil {
			lease.Destroy()
			return VaultToken{}, normalizeCredentialError(err)
		}
		if validateCredentialLease(lease, s.now().UTC(), s.ttl) != nil {
			lease.Destroy()
			return VaultToken{}, ErrUnavailable
		}
		s.lease = lease
	} else {
		rotationDeadline := s.lease.IssuedAt.Add(s.lease.ExpiresAt.Sub(s.lease.IssuedAt) * 2 / 3)
		if !now.Before(rotationDeadline) {
			replacement, err := s.client.Renew(ctx, s.lease, s.ttl)
			if err != nil {
				replacement.Destroy()
				return VaultToken{}, normalizeCredentialError(err)
			}
			if validateCredentialLease(replacement, s.now().UTC(), s.ttl) != nil || replacement.Revision != s.lease.Revision+1 || replacement.ID != s.lease.ID {
				replacement.Destroy()
				return VaultToken{}, ErrUnavailable
			}
			s.lease.Destroy()
			s.lease = replacement
		}
	}
	return VaultToken{Value: append([]byte(nil), s.lease.Credential...), ExpiresAt: s.lease.ExpiresAt,
		Revision: "credential-" + strconv.FormatInt(s.lease.Revision, 10)}, nil
}

func (s *CredentialTokenSource) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if len(s.lease.Credential) == 0 {
		return nil
	}
	err := s.client.Revoke(ctx, s.lease)
	s.lease.Destroy()
	s.lease = CredentialLease{}
	s.closeErr = normalizeCredentialError(err)
	return s.closeErr
}

func validateCredentialLease(lease CredentialLease, now time.Time, requested time.Duration) error {
	if lease.ID == "" || lease.Revision < 1 || len(lease.Credential) < 1 || !lease.Renewable || lease.IssuedAt.After(now) ||
		!lease.ExpiresAt.After(now) || !lease.ExpiresAt.After(lease.IssuedAt) || lease.ExpiresAt.Sub(lease.IssuedAt) > requested+time.Second {
		return ErrUnavailable
	}
	return nil
}

func normalizeCredentialError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ErrUnavailable
}
