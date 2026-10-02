// productmaterialobserver is an ephemeral, non-release Product owner-side
// witness. It never prints or persists resolved material bytes.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6egress"
	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
	"github.com/shell-echo/sandbox-runtime/productapi/tokenidentity"
)

type input struct {
	SocketPath     string                            `json:"socket_path"`
	AgentUID       uint32                            `json:"agent_uid"`
	AgentGID       uint32                            `json:"agent_gid"`
	OwnerUID       uint32                            `json:"owner_uid"`
	OwnerGID       uint32                            `json:"owner_gid"`
	Binding        secretref.Binding                 `json:"binding"`
	ExpectedDigest string                            `json:"expected_digest"`
	Target         *phase6egress.BoundPostgresTarget `json:"target,omitempty"`
}

func main() {
	if stage, resolveMillis := run(); stage != "" {
		_, _ = fmt.Fprintf(os.Stderr, "product-identity-observation stage=%s resolve_ms=%d\n", stage, resolveMillis)
		os.Exit(1)
	}
}

func run() (string, int64) {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, (8<<10)+1))
	if err != nil || len(document) == 0 || len(document) > 8<<10 {
		return "input", -1
	}
	defer clear(document)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value input
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return "input", -1
	}
	canonical, err := json.Marshal(value)
	valid := err == nil && bytes.Equal(canonical, document)
	clear(canonical)
	if !valid || uint32(os.Getuid()) != value.OwnerUID || uint32(os.Getgid()) != value.OwnerGID ||
		value.AgentUID == value.OwnerUID || value.AgentGID == value.OwnerGID ||
		value.Binding.Validate() != nil ||
		(value.Binding.Purpose != secretref.PurposeIdentityKeyRing &&
			value.Binding.Purpose != secretref.PurposePostgresRuntimeDSN) ||
		value.Binding.Role != secretref.RoleProduct || len(value.ExpectedDigest) != len("sha256:")+64 {
		return "identity-or-binding", -1
	}
	if value.Binding.Purpose == secretref.PurposeIdentityKeyRing && value.Target != nil ||
		value.Binding.Purpose == secretref.PurposePostgresRuntimeDSN && (value.Target == nil ||
			value.Target.Host != "postgres.sandbox-runtime.test" || value.Target.Port != 5432 ||
			value.Target.Database != "product" || value.Target.User != "product_runtime") {
		return "identity-or-binding", -1
	}
	layout := restrictedunix.Layout{DirectoryMode: 0o710, SocketMode: 0o666,
		OwnerUID: value.AgentUID, DirectoryGID: value.OwnerGID}
	if !restrictedunix.ValidateParent(value.SocketPath, layout) {
		return "parent-layout", -1
	}
	if !restrictedunix.ValidateSocket(value.SocketPath, layout) {
		return "socket-layout", -1
	}
	client, err := workloadagent.NewProductionV2(workloadagent.Config{SocketPath: value.SocketPath,
		ExpectedUID: value.AgentUID, ExpectedGID: value.AgentGID, Role: secretref.RoleProduct,
		OperationTimeout: 15 * time.Second, Now: time.Now}, value.OwnerGID)
	if err != nil {
		return "client-init", -1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	material, err := client.ResolveSecret(ctx, value.Binding)
	resolveMillis := time.Since(started).Milliseconds()
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			return "resolve-canceled", resolveMillis
		case errors.Is(err, context.DeadlineExceeded):
			return "resolve-deadline", resolveMillis
		case errors.Is(err, secretref.ErrRevoked):
			return "resolve-revoked", resolveMillis
		case errors.Is(err, secretref.ErrExpired):
			return "resolve-expired", resolveMillis
		default:
			return "resolve-unavailable", resolveMillis
		}
	}
	defer material.Destroy()
	if material.Binding != value.Binding {
		return "material-binding", resolveMillis
	}
	if material.Validate(time.Now().UTC()) != nil {
		return "material-window", resolveMillis
	}
	digest := sha256.Sum256(material.Bytes)
	if "sha256:"+hex.EncodeToString(digest[:]) != value.ExpectedDigest {
		return "material-digest", resolveMillis
	}
	if value.Binding.Purpose == secretref.PurposePostgresRuntimeDSN {
		config, err := phase6egress.ParseBoundPostgresDSN(material.Bytes, *value.Target)
		if err != nil || config == nil || config.ConnConfig == nil {
			return "dsn", resolveMillis
		}
		config.ConnConfig.Password = ""
		_, _ = fmt.Fprintln(os.Stdout, "product-dsn-material-resolved=exact-vault-dsn")
	} else {
		if _, err := tokenidentity.LoadMaterial(material.Bytes, "https://identity.product.example.test",
			"urn:shell-echo:sandbox-runtime:product-api:production", 20*time.Second, 10*time.Minute); err != nil {
			return "key-ring", resolveMillis
		}
		_, _ = fmt.Fprintln(os.Stdout, "product-identity-material-resolved=exact-vault-key-ring")
	}
	return "", resolveMillis
}
