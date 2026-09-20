// Package identityfile loads the frozen development identity bindings used by
// the first deployable Product process slice. It is not a production identity
// provider.
package identityfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
	"github.com/shell-echo/sandbox-runtime/product"
	"github.com/shell-echo/sandbox-runtime/productapi"
)

const (
	Version          = "sandbox-runtime-product-static-identities-v1"
	maxDocumentBytes = 256 << 10
	maxBindings      = 128
)

type document struct {
	Version  string    `json:"version"`
	Bindings []binding `json:"bindings"`
}

type binding struct {
	Token     string            `json:"token"`
	TenantID  string            `json:"tenant_id"`
	ActorType product.ActorType `json:"actor_type"`
	ActorID   string            `json:"actor_id"`
	Role      productapi.Role   `json:"role"`
}

// Load reads and validates one strict, bounded, mode-0600 identity document.
// Bindings are frozen in memory for the process lifetime; rotation is restart-
// based in this development slice.
func Load(path string) (*productapi.StaticAuthenticator, error) {
	raw, err := secretfile.Read(path, maxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("load Product identity bindings: %w", err)
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decoded document
	if err := decoder.Decode(&decoded); err != nil {
		return nil, errors.New("decode Product identity bindings")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, errors.New("decode Product identity bindings")
	}
	if decoded.Version != Version || len(decoded.Bindings) < 1 || len(decoded.Bindings) > maxBindings {
		return nil, errors.New("invalid Product identity bindings authority")
	}
	bindings := make([]productapi.StaticToken, 0, len(decoded.Bindings))
	for _, item := range decoded.Bindings {
		bindings = append(bindings, productapi.StaticToken{
			Token: item.Token,
			Principal: productapi.Principal{
				TenantID: item.TenantID,
				Actor:    product.ActorRef{Type: item.ActorType, ID: item.ActorID},
				Role:     item.Role,
			},
		})
	}
	authenticator, err := productapi.NewStaticAuthenticator(bindings)
	if err != nil {
		return nil, errors.New("invalid Product identity binding")
	}
	return authenticator, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}
