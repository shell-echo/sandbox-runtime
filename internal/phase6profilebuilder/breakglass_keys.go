package phase6profilebuilder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"reflect"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidBreakGlassKeySupply = errors.New("invalid Phase 6 Slice 6 break-glass key supply")

// BreakGlassKeySupply retains only public halves and source paths. Four
// external actor files are public-only; only the controller signer and the
// existing credential identities are read from private sources.
type BreakGlassKeySupply struct {
	credentialPaths  map[string]string
	independentPaths map[string]string
	credentialKeys   map[string]ed25519.PublicKey
	independentKeys  map[string]ed25519.PublicKey
}

func LoadSlice6BreakGlassKeySupply(credentialPaths, independentPaths map[string]string) (BreakGlassKeySupply, error) {
	credentialIDs := phase6security.Slice6DesiredCredentialKeyIDs()
	independentIDs := phase6security.Slice6DesiredBreakGlassIndependentKeyIDs()
	if len(credentialPaths) != len(credentialIDs) || len(independentPaths) != len(independentIDs) {
		return BreakGlassKeySupply{}, ErrInvalidBreakGlassKeySupply
	}
	supply := BreakGlassKeySupply{credentialPaths: make(map[string]string, len(credentialIDs)),
		independentPaths: make(map[string]string, len(independentIDs)),
		credentialKeys:   make(map[string]ed25519.PublicKey, len(credentialIDs)),
		independentKeys:  make(map[string]ed25519.PublicKey, len(independentIDs))}
	seenPaths := make(map[string]bool, len(credentialIDs)+len(independentIDs))
	for _, id := range credentialIDs {
		path, ok := credentialPaths[id]
		if !ok || seenPaths[path] {
			return BreakGlassKeySupply{}, ErrInvalidBreakGlassKeySupply
		}
		seenPaths[path] = true
		key, err := readSlice6OperatorPrivateKey(path)
		if err != nil {
			return BreakGlassKeySupply{}, ErrInvalidBreakGlassKeySupply
		}
		supply.credentialPaths[id], supply.credentialKeys[id] = path, key
	}
	for _, id := range independentIDs {
		path, ok := independentPaths[id]
		if !ok || seenPaths[path] {
			return BreakGlassKeySupply{}, ErrInvalidBreakGlassKeySupply
		}
		seenPaths[path] = true
		var key ed25519.PublicKey
		var err error
		if id == "break-glass-controller-signer" {
			key, err = readSlice6OperatorPrivateKey(path)
		} else {
			key, err = readSlice6OperatorPublicKey(path)
		}
		if err != nil {
			return BreakGlassKeySupply{}, ErrInvalidBreakGlassKeySupply
		}
		supply.independentPaths[id], supply.independentKeys[id] = path, key
	}
	if _, err := phase6security.BuildSlice6BreakGlassKeyAuthority(supply.independentKeys, supply.credentialKeys); err != nil {
		return BreakGlassKeySupply{}, ErrInvalidBreakGlassKeySupply
	}
	return supply, nil
}

func (s BreakGlassKeySupply) VerifySources() error {
	current, err := LoadSlice6BreakGlassKeySupply(s.credentialPaths, s.independentPaths)
	if err != nil || len(current.credentialKeys) != len(s.credentialKeys) ||
		len(current.independentKeys) != len(s.independentKeys) {
		return ErrInvalidBreakGlassKeySupply
	}
	for id, key := range current.credentialKeys {
		if !bytes.Equal(key, s.credentialKeys[id]) {
			return ErrInvalidBreakGlassKeySupply
		}
	}
	for id, key := range current.independentKeys {
		if !bytes.Equal(key, s.independentKeys[id]) {
			return ErrInvalidBreakGlassKeySupply
		}
	}
	return nil
}

type KeyedStaticDraft struct {
	StaticDraft
	BreakGlassKeyAuthority       phase6security.Slice6BreakGlassKeyAuthority
	BreakGlassKeys               BreakGlassKeySupply
	BreakGlassExecutableArtifact phase6security.Slice6BreakGlassExecutableArtifact
	operatorBinaryPath           string
}

func bindSlice6BreakGlassKeyDraft(static StaticDraft, keys BreakGlassKeySupply) (KeyedStaticDraft, error) {
	for _, other := range []map[string]ed25519.PublicKey{static.EgressKeys.keys, static.CertificateKeys.keys} {
		for _, key := range other {
			for _, bound := range []map[string]ed25519.PublicKey{keys.credentialKeys, keys.independentKeys} {
				for _, candidate := range bound {
					if bytes.Equal(key, candidate) {
						return KeyedStaticDraft{}, ErrInvalidBreakGlassKeySupply
					}
				}
			}
		}
	}
	authority, err := phase6security.BuildSlice6BreakGlassKeyAuthority(keys.independentKeys, keys.credentialKeys)
	if err != nil {
		return KeyedStaticDraft{}, ErrInvalidBreakGlassKeySupply
	}
	return KeyedStaticDraft{StaticDraft: static, BreakGlassKeyAuthority: authority, BreakGlassKeys: keys}, nil
}

func (d KeyedStaticDraft) VerifySources(ctx context.Context, now time.Time) error {
	if d.StaticDraft.VerifySources(ctx, now) != nil || d.BreakGlassKeys.VerifySources() != nil {
		return ErrInvalidBreakGlassKeySupply
	}
	want, err := bindSlice6BreakGlassKeyDraft(d.StaticDraft, d.BreakGlassKeys)
	if err != nil || !reflect.DeepEqual(d.BreakGlassKeyAuthority, want.BreakGlassKeyAuthority) {
		return ErrInvalidBreakGlassKeySupply
	}
	if verifySlice6OperatorBinarySource(d.operatorBinaryPath, d.BreakGlassExecutableArtifact) != nil ||
		d.BreakGlassExecutableArtifact.SourceRevision != d.ImageSupply.RuntimeRevision ||
		d.BreakGlassExecutableArtifact.SourceTreeDigest != d.ImageSupply.RuntimeTreeDigest ||
		d.BreakGlassExecutableArtifact.Platform != d.ImageSupply.Platform {
		return ErrInvalidBreakGlassArtifact
	}
	return nil
}
