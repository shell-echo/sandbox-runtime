package phase6profilebuilder

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
)

var errInvalidOperatorPrivateKey = errors.New("invalid Phase 6 operator private-key source")

// readSlice6OperatorPrivateKey reads only the public half from a raw private
// source. The private bytes are zeroed before return and never reach a profile.
func readSlice6OperatorPrivateKey(path string) (ed25519.PublicKey, error) {
	if !cleanAbsolute(path) {
		return nil, errInvalidOperatorPrivateKey
	}
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		parent.Mode().Perm() != 0o700 || !slice6OwnedByCurrentUser(parent) {
		return nil, errInvalidOperatorPrivateKey
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm() != 0o600 || before.Size() != ed25519.PrivateKeySize || !slice6OwnedByCurrentUser(before) {
		return nil, errInvalidOperatorPrivateKey
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errInvalidOperatorPrivateKey
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errInvalidOperatorPrivateKey
	}
	secret, err := io.ReadAll(io.LimitReader(file, ed25519.PrivateKeySize+1))
	defer clear(secret)
	after, afterErr := os.Lstat(path)
	parentAfter, parentErr := os.Lstat(parentPath)
	if err != nil || afterErr != nil || parentErr != nil || len(secret) != ed25519.PrivateKeySize ||
		!os.SameFile(opened, after) || !os.SameFile(parent, parentAfter) ||
		before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) ||
		parentAfter.Mode().Perm() != 0o700 || !slice6OwnedByCurrentUser(parentAfter) {
		return nil, errInvalidOperatorPrivateKey
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(secret[:ed25519.SeedSize]), secret) {
		return nil, errInvalidOperatorPrivateKey
	}
	return bytes.Clone(ed25519.PrivateKey(secret).Public().(ed25519.PublicKey)), nil
}

// readSlice6OperatorPublicKey reads an external actor's raw public key. The
// builder never opens requester, approver or operator signing private keys.
func readSlice6OperatorPublicKey(path string) (ed25519.PublicKey, error) {
	if !cleanAbsolute(path) {
		return nil, errInvalidOperatorPrivateKey
	}
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		parent.Mode().Perm() != 0o700 || !slice6OwnedByCurrentUser(parent) {
		return nil, errInvalidOperatorPrivateKey
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm() != 0o400 || before.Size() != ed25519.PublicKeySize || !slice6OwnedByCurrentUser(before) {
		return nil, errInvalidOperatorPrivateKey
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errInvalidOperatorPrivateKey
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errInvalidOperatorPrivateKey
	}
	public, err := io.ReadAll(io.LimitReader(file, ed25519.PublicKeySize+1))
	after, afterErr := os.Lstat(path)
	parentAfter, parentErr := os.Lstat(parentPath)
	if err != nil || afterErr != nil || parentErr != nil || len(public) != ed25519.PublicKeySize ||
		!os.SameFile(opened, after) || !os.SameFile(parent, parentAfter) ||
		before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) ||
		parentAfter.Mode().Perm() != 0o700 || !slice6OwnedByCurrentUser(parentAfter) {
		return nil, errInvalidOperatorPrivateKey
	}
	return ed25519.PublicKey(public), nil
}
