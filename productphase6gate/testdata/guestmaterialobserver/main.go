// guestmaterialobserver is an ephemeral, non-release owner-side witness for
// the Slice 6 Docker gate. It never prints or persists resolved key bytes.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/restrictedunix"
	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/internal/secretref/workloadagent"
)

type input struct {
	SocketPath              string            `json:"socket_path"`
	AgentUID                uint32            `json:"agent_uid"`
	AgentGID                uint32            `json:"agent_gid"`
	OwnerUID                uint32            `json:"owner_uid"`
	OwnerGID                uint32            `json:"owner_gid"`
	Binding                 secretref.Binding `json:"binding"`
	ExpectedPublicKeyDigest string            `json:"expected_public_key_digest"`
}

func main() {
	if stage, resolveMillis := run(); stage != "" {
		_, _ = fmt.Fprintf(os.Stderr, "guest-material-observation stage=%s resolve_ms=%d\n", stage, resolveMillis)
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
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF ||
		uint32(os.Getuid()) != value.OwnerUID || uint32(os.Getgid()) != value.OwnerGID ||
		value.AgentUID == value.OwnerUID || value.AgentGID == value.OwnerGID ||
		value.Binding.Validate() != nil || value.Binding.Purpose != secretref.PurposeGuestSigningKey ||
		value.Binding.Role != secretref.RoleGuest || len(value.ExpectedPublicKeyDigest) != len("sha256:")+64 {
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
		ExpectedUID: value.AgentUID, ExpectedGID: value.AgentGID, Role: secretref.RoleGuest,
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
	if len(material.Bytes) != ed25519.PrivateKeySize {
		return "material-size", resolveMillis
	}
	public := ed25519.PrivateKey(material.Bytes).Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	if "sha256:"+hex.EncodeToString(digest[:]) != value.ExpectedPublicKeyDigest {
		return "public-digest", resolveMillis
	}
	_, _ = fmt.Fprintln(os.Stdout, "guest-material-resolved=exact-vault-key")
	return "", resolveMillis
}
