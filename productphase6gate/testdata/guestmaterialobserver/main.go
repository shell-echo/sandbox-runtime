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
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "guest material observation failed")
		os.Exit(1)
	}
}

func run() error {
	document, err := io.ReadAll(io.LimitReader(os.Stdin, (8<<10)+1))
	if err != nil || len(document) == 0 || len(document) > 8<<10 {
		return errors.New("invalid owner-side input")
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
		return errors.New("invalid owner-side identity or binding")
	}
	client, err := workloadagent.NewProductionV2(workloadagent.Config{SocketPath: value.SocketPath,
		ExpectedUID: value.AgentUID, ExpectedGID: value.AgentGID, Role: secretref.RoleGuest,
		OperationTimeout: 15 * time.Second, Now: time.Now}, value.OwnerGID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	material, err := client.ResolveSecret(ctx, value.Binding)
	if err != nil {
		return err
	}
	defer material.Destroy()
	if material.Binding != value.Binding || material.Validate(time.Now().UTC()) != nil ||
		len(material.Bytes) != ed25519.PrivateKeySize {
		return errors.New("resolved material does not match the exact Guest binding")
	}
	public := ed25519.PrivateKey(material.Bytes).Public().(ed25519.PublicKey)
	digest := sha256.Sum256(public)
	if "sha256:"+hex.EncodeToString(digest[:]) != value.ExpectedPublicKeyDigest {
		return errors.New("resolved Guest key differs from Vault create-only material")
	}
	_, _ = fmt.Fprintln(os.Stdout, "guest-material-resolved=exact-vault-key")
	return nil
}
