package workloadpki

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeCredentialClient struct {
	now        *time.Time
	revision   int64
	issueCalls int
	renewCalls int
	revokes    int
	failRenew  bool
	invalid    bool
}

func (f *fakeCredentialClient) Issue(context.Context, time.Duration) (CredentialLease, error) {
	f.issueCalls++
	f.revision = 1
	if f.invalid {
		return CredentialLease{ID: "lease_certificate_controller", Revision: f.revision, IssuedAt: *f.now,
			ExpiresAt: f.now.Add(9 * time.Minute), Renewable: true}, nil
	}
	return CredentialLease{ID: "lease_certificate_controller", Revision: f.revision, IssuedAt: *f.now,
		ExpiresAt: f.now.Add(9 * time.Minute), Renewable: true, Credential: []byte("vault-token-1")}, nil
}

func (f *fakeCredentialClient) Renew(context.Context, CredentialLease, time.Duration) (CredentialLease, error) {
	f.renewCalls++
	if f.failRenew {
		return CredentialLease{}, ErrUnavailable
	}
	f.revision++
	return CredentialLease{ID: "lease_certificate_controller", Revision: f.revision, IssuedAt: *f.now,
		ExpiresAt: f.now.Add(9 * time.Minute), Renewable: true, Credential: []byte("vault-token-2")}, nil
}

func (f *fakeCredentialClient) Revoke(context.Context, CredentialLease) error {
	f.revokes++
	return nil
}

func TestCredentialTokenSourceRotatesAtTwoThirdsAndRevokesOnClose(t *testing.T) {
	now := time.Now().UTC()
	client := &fakeCredentialClient{now: &now}
	source, err := NewCredentialTokenSource(CredentialTokenSourceConfig{Client: client, TTL: 10 * time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Token(context.Background())
	if err != nil || string(first.Value) != "vault-token-1" || first.Revision != "credential-1" {
		t.Fatalf("first Token() = %#v, %v", first, err)
	}
	first.Destroy()
	now = now.Add(5 * time.Minute)
	second, err := source.Token(context.Background())
	if err != nil || string(second.Value) != "vault-token-1" || client.renewCalls != 0 {
		t.Fatalf("pre-rotation Token() = %#v, %v renew=%d", second, err, client.renewCalls)
	}
	second.Destroy()
	now = now.Add(time.Minute)
	third, err := source.Token(context.Background())
	if err != nil || string(third.Value) != "vault-token-2" || third.Revision != "credential-2" || client.renewCalls != 1 {
		t.Fatalf("rotated Token() = %#v, %v renew=%d", third, err, client.renewCalls)
	}
	third.Destroy()
	if err := source.Close(context.Background()); err != nil || client.revokes != 1 {
		t.Fatalf("Close() error=%v revokes=%d", err, client.revokes)
	}
	if _, err := source.Token(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("closed Token() error=%v", err)
	}
}

func TestCredentialTokenSourceFailsClosedAtRotationDeadline(t *testing.T) {
	now := time.Now().UTC()
	client := &fakeCredentialClient{now: &now, failRenew: true}
	source, err := NewCredentialTokenSource(CredentialTokenSourceConfig{Client: client, TTL: 10 * time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	initial.Destroy()
	now = now.Add(6 * time.Minute)
	if token, err := source.Token(context.Background()); !errors.Is(err, ErrUnavailable) || len(token.Value) != 0 {
		t.Fatalf("rotation failure Token() = %#v, %v", token, err)
	}
}

func TestCredentialTokenSourceRejectsStructurallyInvalidSuccessfulIssue(t *testing.T) {
	now := time.Now().UTC()
	source, err := NewCredentialTokenSource(CredentialTokenSourceConfig{Client: &fakeCredentialClient{now: &now, invalid: true},
		TTL: 10 * time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if token, err := source.Token(context.Background()); !errors.Is(err, ErrUnavailable) || len(token.Value) != 0 {
		t.Fatalf("Token() = %#v, %v", token, err)
	}
}
