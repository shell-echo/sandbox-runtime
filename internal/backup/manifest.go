// Package backup defines the portable, integrity-bound restore plan. It does
// not perform backups; operators supply immutable artifacts and an isolated
// target before a restore can be authorized.
package backup

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var (
	ErrInvalidPlan  = errors.New("invalid backup restore plan")
	ErrUnsafeTarget = errors.New("backup restore target is not isolated")
)

type Artifact struct {
	Reference string
	Digest    string
	Version   string
}

type Manifest struct {
	Version              int
	CreatedAt            time.Time
	SourceIdentity       string
	DatabaseBaseBackup   Artifact
	DatabaseWAL          []Artifact
	ObjectVersions       []Artifact
	CoordinationSnapshot Artifact
	EncryptionKeyRefs    []string
}

type RestorePlan struct {
	Manifest       Manifest
	TargetIdentity string
	TargetIsolated bool
	Cutover        bool
}

// ArtifactReader is implemented by an object-store or backup-volume adapter.
// The restore planner never receives a client with write authority.
type ArtifactReader interface {
	Read(context.Context, string, int64) ([]byte, error)
}

func (m Manifest) Validate(now time.Time) error {
	if m.Version != 1 || m.CreatedAt.IsZero() || now.IsZero() || m.CreatedAt.After(now) || strings.TrimSpace(m.SourceIdentity) == "" || len(m.SourceIdentity) > 256 {
		return ErrInvalidPlan
	}
	if err := validateArtifact(m.DatabaseBaseBackup); err != nil || len(m.DatabaseWAL) == 0 || len(m.ObjectVersions) == 0 {
		return ErrInvalidPlan
	}
	if err := validateArtifact(m.CoordinationSnapshot); err != nil {
		return ErrInvalidPlan
	}
	for _, artifact := range append(append([]Artifact(nil), m.DatabaseWAL...), m.ObjectVersions...) {
		if err := validateArtifact(artifact); err != nil {
			return ErrInvalidPlan
		}
	}
	if len(m.EncryptionKeyRefs) == 0 || len(m.EncryptionKeyRefs) > 32 {
		return ErrInvalidPlan
	}
	for _, reference := range m.EncryptionKeyRefs {
		if !strings.HasPrefix(reference, "kms://") || len(reference) > 512 || strings.ContainsAny(reference, "\x00\r\n") {
			return ErrInvalidPlan
		}
	}
	return nil
}

func (p RestorePlan) Validate(now time.Time) error {
	if err := p.Manifest.Validate(now); err != nil {
		return err
	}
	if strings.TrimSpace(p.TargetIdentity) == "" || p.TargetIdentity == p.Manifest.SourceIdentity || len(p.TargetIdentity) > 256 {
		return ErrUnsafeTarget
	}
	if !p.TargetIsolated || p.Cutover {
		return ErrUnsafeTarget
	}
	return nil
}

func (p RestorePlan) Steps(now time.Time) ([]string, error) {
	if err := p.Validate(now); err != nil {
		return nil, err
	}
	return []string{"verify_manifest", "restore_database_base", "replay_database_wal", "restore_object_versions", "reconstruct_coordination", "restore_encryption_keys", "reconcile_authority", "operator_cutover"}, nil
}

// VerifyArtifacts checks every referenced backup object before any restore
// step can be scheduled. The bounded reader and digest comparison make stale,
// truncated, and substituted objects fail closed.
func (p RestorePlan) VerifyArtifacts(ctx context.Context, reader ArtifactReader, maxBytes int64, now time.Time) error {
	if ctx == nil || reader == nil || maxBytes < 1 || maxBytes > 1<<40 {
		return ErrInvalidPlan
	}
	if err := p.Validate(now); err != nil {
		return err
	}
	artifacts := []Artifact{p.Manifest.DatabaseBaseBackup}
	artifacts = append(artifacts, p.Manifest.DatabaseWAL...)
	artifacts = append(artifacts, p.Manifest.ObjectVersions...)
	artifacts = append(artifacts, p.Manifest.CoordinationSnapshot)
	for _, artifact := range artifacts {
		if err := ctx.Err(); err != nil {
			return err
		}
		contents, err := reader.Read(ctx, artifact.Reference, maxBytes)
		if err != nil {
			return ErrInvalidPlan
		}
		digest := sha256.Sum256(contents)
		if got := "sha256:" + fmt.Sprintf("%x", digest[:]); got != artifact.Digest {
			return ErrInvalidPlan
		}
	}
	return nil
}

func validateArtifact(value Artifact) error {
	if strings.TrimSpace(value.Reference) == "" || len(value.Reference) > 512 || strings.ContainsAny(value.Reference, "\x00\r\n") || !digestPattern.MatchString(value.Digest) || strings.TrimSpace(value.Version) == "" || len(value.Version) > 128 {
		return ErrInvalidPlan
	}
	return nil
}
