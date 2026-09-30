package phase6profilebuilder

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

var ErrInvalidTrustAnchorSupply = errors.New("invalid Phase 6 trust-anchor supply")

const maximumSlice6CABundleBytes = 256 << 10

// TrustAnchorSupply holds exact operator bootstrap CA bytes. It does not
// attest the operator, Vault issuer, running mount, or an issued leaf. The
// final gate must re-open its frozen artifacts and observe every deployment.
type TrustAnchorSupply struct {
	anchors []phase6security.TrustAnchor
	bundles map[string][]byte
	paths   map[string]string
}

// TrustDraft is the next non-launchable layer after resource/seccomp binding.
// It binds reviewed consumers and CA digests, but still lacks the complete
// role mounts, edges, authority keys, external services and runtime evidence.
type TrustDraft struct {
	ResourceDraft
	TrustAnchors []phase6security.TrustAnchor
	AnchorSupply TrustAnchorSupply
}

// LoadSlice6TrustAnchorSupply reads every reviewed CA bundle from a private
// operator-owned source directory. The source paths are never emitted into
// the stable security profile; their checked byte snapshots are retained for
// controlled mounting and must be independently reverified at final freeze.
func LoadSlice6TrustAnchorSupply(paths map[string]string, now time.Time) (TrustAnchorSupply, error) {
	templates := phase6security.Slice6DesiredFinalTrustAnchorTemplates()
	if now.IsZero() || len(paths) != len(templates) {
		return TrustAnchorSupply{}, ErrInvalidTrustAnchorSupply
	}
	result := TrustAnchorSupply{anchors: make([]phase6security.TrustAnchor, 0, len(templates)),
		bundles: make(map[string][]byte, len(templates)), paths: make(map[string]string, len(templates))}
	for _, template := range templates {
		path, found := paths[template.ID]
		if !found {
			return TrustAnchorSupply{}, ErrInvalidTrustAnchorSupply
		}
		bundle, err := readSlice6OperatorCABundle(path, now)
		if err != nil {
			return TrustAnchorSupply{}, err
		}
		sum := sha256.Sum256(bundle)
		template.BundleDigest = "sha256:" + hex.EncodeToString(sum[:])
		result.anchors = append(result.anchors, template)
		result.bundles[template.ID] = bundle
		result.paths[template.ID] = path
	}
	return result, nil
}

// VerifySources reopens every original operator file before profile freeze.
// Changed or unavailable CA bytes invalidate this candidate; a prior checked
// snapshot is not permission to combine a later source state with this run.
func (s TrustAnchorSupply) VerifySources(now time.Time) error {
	if now.IsZero() || len(s.paths) != len(s.anchors) || len(s.bundles) != len(s.anchors) ||
		len(s.anchors) != len(phase6security.Slice6DesiredFinalTrustAnchorTemplates()) {
		return ErrInvalidTrustAnchorSupply
	}
	for _, anchor := range s.anchors {
		original, originalErr := s.BundleBytes(anchor.ID)
		path, found := s.paths[anchor.ID]
		if originalErr != nil || !found {
			return ErrInvalidTrustAnchorSupply
		}
		current, err := readSlice6OperatorCABundle(path, now)
		if err != nil || !bytes.Equal(original, current) {
			return ErrInvalidTrustAnchorSupply
		}
	}
	return nil
}

// BundleBytes returns a copy of the checked original PEM bytes, not a path
// that a launcher may reopen after validation.
func (s TrustAnchorSupply) BundleBytes(id string) ([]byte, error) {
	bundle, found := s.bundles[id]
	if !found || len(bundle) == 0 {
		return nil, ErrInvalidTrustAnchorSupply
	}
	sum := sha256.Sum256(bundle)
	bound := false
	for _, anchor := range s.anchors {
		if anchor.ID == id && anchor.BundleDigest == "sha256:"+hex.EncodeToString(sum[:]) {
			bound = true
			break
		}
	}
	if !bound {
		return nil, ErrInvalidTrustAnchorSupply
	}
	return bytes.Clone(bundle), nil
}

// BindSlice6TrustAnchorDraft adds only the reviewed CA mounts to the prior
// source-bound resource draft. It rejects any preexisting trust-anchor mount
// or overlapping target instead of silently granting another CA reader.
func BindSlice6TrustAnchorDraft(draft ResourceDraft, supply TrustAnchorSupply, now time.Time) (TrustDraft, error) {
	templates := phase6security.Slice6DesiredFinalTrustAnchorTemplates()
	if len(supply.anchors) != len(templates) || len(supply.bundles) != len(templates) ||
		len(supply.paths) != len(templates) || supply.VerifySources(now) != nil ||
		len(draft.Principals) != len(phase6security.Slice6DesiredDeploymentNames()) ||
		draft.Supply.VerifyProfilePolicies(phase6security.Profile{Principals: draft.Principals}) != nil {
		return TrustDraft{}, ErrInvalidTrustAnchorSupply
	}
	bound := append([]phase6security.Principal(nil), draft.Principals...)
	indexes := make(map[string]int, len(bound))
	for index := range bound {
		if _, duplicate := indexes[bound[index].Name]; duplicate {
			return TrustDraft{}, ErrInvalidTrustAnchorSupply
		}
		indexes[bound[index].Name] = index
		bound[index].Mounts = append([]phase6security.Mount(nil), bound[index].Mounts...)
		for _, mount := range bound[index].Mounts {
			if mount.Kind == "trust_anchor" {
				return TrustDraft{}, ErrInvalidTrustAnchorSupply
			}
		}
	}
	anchors := make([]phase6security.TrustAnchor, 0, len(templates))
	for index, template := range templates {
		anchor := supply.anchors[index]
		bundle, known := supply.bundles[anchor.ID]
		sum := sha256.Sum256(bundle)
		if !known || len(bundle) == 0 || anchor.ID != template.ID || anchor.Purpose != template.Purpose ||
			anchor.TrustDomain != template.TrustDomain || anchor.ArtifactID != template.ArtifactID ||
			anchor.StorageID != template.StorageID || anchor.TargetPath != template.TargetPath ||
			anchor.WriterAuthority != template.WriterAuthority || anchor.OwnerUID != 0 || anchor.OwnerGID != 0 ||
			!slices.Equal(anchor.Consumers, template.Consumers) ||
			anchor.BundleDigest != "sha256:"+hex.EncodeToString(sum[:]) {
			return TrustDraft{}, ErrInvalidTrustAnchorSupply
		}
		anchors = append(anchors, anchor)
		anchors[len(anchors)-1].Consumers = append([]string(nil), anchor.Consumers...)
		for _, consumer := range anchor.Consumers {
			principalIndex, found := indexes[consumer]
			if !found {
				return TrustDraft{}, ErrInvalidTrustAnchorSupply
			}
			for _, existing := range bound[principalIndex].Mounts {
				if existing.StorageID == anchor.StorageID ||
					overlappingMountTarget(existing.Target, anchor.TargetPath) {
					return TrustDraft{}, ErrInvalidTrustAnchorSupply
				}
			}
			bound[principalIndex].Mounts = append(bound[principalIndex].Mounts, phase6security.Mount{
				Target: anchor.TargetPath, Kind: "trust_anchor", ReadOnly: true, StorageID: anchor.StorageID})
		}
	}
	copyDraft := draft
	copyDraft.Principals = bound
	return TrustDraft{ResourceDraft: copyDraft, TrustAnchors: anchors, AnchorSupply: supply}, nil
}

func readSlice6OperatorCABundle(path string, now time.Time) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, ErrInvalidTrustAnchorSupply
	}
	parentPath := filepath.Dir(path)
	parent, err := os.Lstat(parentPath)
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 ||
		parent.Mode().Perm() != 0o700 || !slice6OwnedByCurrentUser(parent) {
		return nil, ErrInvalidTrustAnchorSupply
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Mode().Perm()&0o222 != 0 || before.Size() < 1 || before.Size() > maximumSlice6CABundleBytes ||
		!slice6OwnedByCurrentUser(before) {
		return nil, ErrInvalidTrustAnchorSupply
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrInvalidTrustAnchorSupply
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrInvalidTrustAnchorSupply
	}
	bundle, err := io.ReadAll(io.LimitReader(file, maximumSlice6CABundleBytes+1))
	after, afterErr := os.Lstat(path)
	parentAfter, parentErr := os.Lstat(parentPath)
	if err != nil || afterErr != nil || parentErr != nil || len(bundle) != int(before.Size()) ||
		!os.SameFile(opened, after) || !os.SameFile(parent, parentAfter) ||
		before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) ||
		parentAfter.Mode().Perm() != 0o700 || !slice6OwnedByCurrentUser(parentAfter) ||
		!slice6ValidCABundle(bundle, now) {
		clear(bundle)
		return nil, ErrInvalidTrustAnchorSupply
	}
	return bundle, nil
}

func slice6OwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

func slice6ValidCABundle(bundle []byte, now time.Time) bool {
	remaining, count := bundle, 0
	seen := make(map[[32]byte]bool)
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return false
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || count >= 32 {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
			certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return false
		}
		sum := sha256.Sum256(block.Bytes)
		if seen[sum] {
			return false
		}
		seen[sum] = true
		count++
		remaining = rest
	}
	return count > 0
}
