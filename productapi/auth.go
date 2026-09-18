package productapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"reflect"

	"github.com/shell-echo/sandbox-runtime/product"
)

var ErrUnauthenticated = errors.New("product authentication failed")

type Principal struct {
	TenantID string
	Actor    product.ActorRef
}

type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

type StaticToken struct {
	Token     string
	Principal Principal
}

type StaticAuthenticator struct {
	bindings []StaticToken
}

func NewStaticAuthenticator(bindings []StaticToken) (*StaticAuthenticator, error) {
	if len(bindings) < 1 || len(bindings) > 128 {
		return nil, product.ErrInvalid
	}
	copyBindings := append([]StaticToken(nil), bindings...)
	for index, binding := range copyBindings {
		if len(binding.Token) < 32 || len(binding.Token) > 4096 || binding.Principal.Actor.Validate() != nil || binding.Principal.TenantID == "" {
			return nil, product.ErrInvalid
		}
		for prior := 0; prior < index; prior++ {
			if subtle.ConstantTimeCompare([]byte(binding.Token), []byte(copyBindings[prior].Token)) == 1 {
				return nil, product.ErrInvalid
			}
		}
	}
	return &StaticAuthenticator{bindings: copyBindings}, nil
}

func (a *StaticAuthenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || token == "" {
		return Principal{}, ErrUnauthenticated
	}
	for _, binding := range a.bindings {
		if len(token) == len(binding.Token) && subtle.ConstantTimeCompare([]byte(token), []byte(binding.Token)) == 1 {
			return binding.Principal, nil
		}
	}
	return Principal{}, ErrUnauthenticated
}

func IsNilAuthenticator(value Authenticator) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}
