// Package artifactverify verifies immutable release inputs before a process
// binds a listener. It deliberately does not fetch artifacts or trust mutable
// tags; deployment code supplies local files and an explicit signature key.
package artifactverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var (
	ErrInvalidManifest = errors.New("invalid artifact manifest")
	ErrDigestMismatch  = errors.New("artifact digest mismatch")
	ErrSignature       = errors.New("artifact manifest signature invalid")
)

type File struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Mode   uint32 `json:"mode"`
}

type Manifest struct {
	Version   int    `json:"version"`
	Revision  string `json:"revision"`
	Artifacts []File `json:"artifacts"`
}

func (m Manifest) Validate() error {
	if m.Version != 1 || strings.TrimSpace(m.Revision) == "" || len(m.Revision) > 128 || len(m.Artifacts) == 0 || len(m.Artifacts) > 256 {
		return ErrInvalidManifest
	}
	seen := make(map[string]struct{}, len(m.Artifacts))
	for _, file := range m.Artifacts {
		if file.Name == "" || len(file.Name) > 128 || filepath.Base(file.Name) != file.Name || strings.ContainsAny(file.Name, "\x00/\\\r\n") || file.Path == "" || !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || !digestPattern.MatchString(file.Digest) || file.Mode&0o777 != 0o600 {
			return ErrInvalidManifest
		}
		if _, exists := seen[file.Name]; exists {
			return ErrInvalidManifest
		}
		seen[file.Name] = struct{}{}
	}
	return nil
}

func Verify(m Manifest) error {
	if err := m.Validate(); err != nil {
		return err
	}
	for _, file := range m.Artifacts {
		contents, err := secretfile.Read(file.Path, 64<<20)
		if err != nil {
			return ErrDigestMismatch
		}
		digest := sha256.Sum256(contents)
		if "sha256:"+hex.EncodeToString(digest[:]) != file.Digest {
			return ErrDigestMismatch
		}
	}
	return nil
}

// VerifyFiles verifies the manifest, detached Ed25519 signature, and public
// key from bounded mode-0600 files. It is the startup-facing API for a role
// process; no mutable tag or remote fetch is involved.
func VerifyFiles(manifestPath, signaturePath, publicKeyPath string) (Manifest, error) {
	manifestBytes, err := secretfile.Read(manifestPath, 1<<20)
	if err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, ErrInvalidManifest
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Manifest{}, ErrInvalidManifest
	}
	signature, err := secretfile.Read(signaturePath, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Manifest{}, ErrSignature
	}
	publicKey, err := secretfile.Read(publicKeyPath, ed25519.PublicKeySize)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return Manifest{}, ErrSignature
	}
	if err := Verify(manifest); err != nil {
		return Manifest{}, err
	}
	if err := VerifySignature(manifest, ed25519.PublicKey(publicKey), signature); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func VerifySignature(m Manifest, publicKey ed25519.PublicKey, signature []byte) error {
	if err := m.Validate(); err != nil || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return ErrSignature
	}
	document, err := json.Marshal(m)
	if err != nil || !ed25519.Verify(publicKey, document, signature) {
		return ErrSignature
	}
	return nil
}
