// Package provider owns application policy and models for the Sandbox Provider
// boundary. It deliberately contains no transport or runtime-driver concerns.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// APIVersion is the Provider protocol version represented by a capability
// snapshot.
type APIVersion string

const APIVersionV1 APIVersion = "v1"

// SnapshotLevel identifies the state covered by compatibility metadata.
type SnapshotLevel string

const (
	SnapshotLevelWorkspace  SnapshotLevel = "workspace"
	SnapshotLevelFilesystem SnapshotLevel = "filesystem"
	SnapshotLevelProcess    SnapshotLevel = "process"
)

// CompatibilitySuiteID identifies the suite described by compatibility
// metadata. Metadata does not advertise or authorize a runtime capability.
type CompatibilitySuiteID string

const CompatibilitySuiteSandboxProvider CompatibilitySuiteID = "sandbox-provider"

const maxSnapshotRestoreProfiles = 32

// SHA256Digest is a lowercase, algorithm-qualified SHA-256 digest.
type SHA256Digest string

// SnapshotRestoreProfile is content-addressed compatibility metadata. Its
// presence alone does not advertise snapshot or restore support.
type SnapshotRestoreProfile struct {
	ProfileID    string
	Level        SnapshotLevel
	SuiteID      CompatibilitySuiteID
	SuiteVersion string
	SuiteDigest  SHA256Digest
}

// Limits contains the hard limits declared by this Provider revision.
type Limits struct {
	MaxCPUMillis             int64
	MaxMemoryBytes           int64
	MaxEphemeralStorageBytes int64
	MaxWorkspaceBytes        *int64
	MaxGPUCount              *int64
	MaxLeaseSeconds          int64
	MaxExecSeconds           int64
}

// CapabilitySnapshot is the immutable-at-source capability document consumed
// by Provider adapters. Callers receive defensive copies and may mutate their
// copy without changing future reads.
type CapabilitySnapshot struct {
	ProviderRevisionID      string
	APIVersion              APIVersion
	SnapshotRestoreProfiles []SnapshotRestoreProfile
	Limits                  Limits
}

var (
	suiteVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// NewCapabilitySnapshot validates and freezes the honest P1.1b startup model.
// It contains no capability or runtime-profile model because P1.1b advertises
// neither; the future wire adapter is responsible for encoding both as empty
// arrays in the Contract document.
func NewCapabilitySnapshot(providerRevisionID string, limits Limits, profiles []SnapshotRestoreProfile) (CapabilitySnapshot, error) {
	snapshot := CapabilitySnapshot{
		ProviderRevisionID:      providerRevisionID,
		APIVersion:              APIVersionV1,
		SnapshotRestoreProfiles: append([]SnapshotRestoreProfile(nil), profiles...),
		Limits:                  cloneLimits(limits),
	}
	if err := validateCapabilitySnapshot(snapshot); err != nil {
		return CapabilitySnapshot{}, err
	}
	return snapshot, nil
}

// CapabilityReader is the focused application port for capability discovery.
type CapabilityReader interface {
	CapabilitySnapshot(context.Context) (CapabilitySnapshot, error)
}

// StaticCapabilitySource serves an immutable startup snapshot.
type StaticCapabilitySource struct {
	snapshot CapabilitySnapshot
}

// NewStaticCapabilitySource takes ownership of a validated defensive copy.
func NewStaticCapabilitySource(snapshot CapabilitySnapshot) (*StaticCapabilitySource, error) {
	snapshot = cloneCapabilitySnapshot(snapshot)
	if err := validateCapabilitySnapshot(snapshot); err != nil {
		return nil, fmt.Errorf("validate static capability snapshot: %w", err)
	}
	return &StaticCapabilitySource{snapshot: snapshot}, nil
}

// CapabilitySnapshot returns a caller-safe copy of the startup snapshot.
func (s *StaticCapabilitySource) CapabilitySnapshot(ctx context.Context) (CapabilitySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return CapabilitySnapshot{}, err
	}
	if s == nil {
		return CapabilitySnapshot{}, errors.New("capability source is nil")
	}
	return cloneCapabilitySnapshot(s.snapshot), nil
}

func validateCapabilitySnapshot(snapshot CapabilitySnapshot) error {
	if !utf8.ValidString(snapshot.ProviderRevisionID) || strings.TrimSpace(snapshot.ProviderRevisionID) == "" {
		return errors.New("provider revision ID must be valid UTF-8 and not empty")
	}
	if snapshot.APIVersion != APIVersionV1 {
		return fmt.Errorf("unsupported API version %q", snapshot.APIVersion)
	}
	if err := validateLimits(snapshot.Limits); err != nil {
		return err
	}
	if len(snapshot.SnapshotRestoreProfiles) == 0 {
		return errors.New("at least one snapshot/restore compatibility profile is required")
	}
	if len(snapshot.SnapshotRestoreProfiles) > maxSnapshotRestoreProfiles {
		return fmt.Errorf("snapshot/restore compatibility profiles must not exceed %d", maxSnapshotRestoreProfiles)
	}

	profilesByID := make(map[string]SnapshotRestoreProfile, len(snapshot.SnapshotRestoreProfiles))
	for index, profile := range snapshot.SnapshotRestoreProfiles {
		if err := validateSnapshotRestoreProfile(profile); err != nil {
			return fmt.Errorf("snapshot/restore compatibility profile %d: %w", index, err)
		}
		if previous, exists := profilesByID[profile.ProfileID]; exists {
			if previous == profile {
				return fmt.Errorf("duplicate snapshot/restore compatibility profile %q", profile.ProfileID)
			}
			return fmt.Errorf("conflicting snapshot/restore compatibility profile %q", profile.ProfileID)
		}
		profilesByID[profile.ProfileID] = profile
	}
	return nil
}

func validateLimits(limits Limits) error {
	required := []struct {
		name  string
		value int64
	}{
		{"max CPU millis", limits.MaxCPUMillis},
		{"max memory bytes", limits.MaxMemoryBytes},
		{"max ephemeral storage bytes", limits.MaxEphemeralStorageBytes},
		{"max lease seconds", limits.MaxLeaseSeconds},
		{"max exec seconds", limits.MaxExecSeconds},
	}
	for _, limit := range required {
		if limit.value <= 0 {
			return fmt.Errorf("%s must be positive", limit.name)
		}
	}
	if limits.MaxWorkspaceBytes != nil && *limits.MaxWorkspaceBytes <= 0 {
		return errors.New("max workspace bytes must be positive when present")
	}
	if limits.MaxGPUCount != nil && *limits.MaxGPUCount < 0 {
		return errors.New("max GPU count must be nonnegative when present")
	}
	return nil
}

func validateSnapshotRestoreProfile(profile SnapshotRestoreProfile) error {
	if !utf8.ValidString(profile.ProfileID) || strings.TrimSpace(profile.ProfileID) == "" {
		return errors.New("profile ID must be valid UTF-8 and not empty")
	}
	if utf8.RuneCountInString(profile.ProfileID) > 200 {
		return errors.New("profile ID must not exceed 200 characters")
	}
	switch profile.Level {
	case SnapshotLevelWorkspace, SnapshotLevelFilesystem, SnapshotLevelProcess:
	default:
		return fmt.Errorf("invalid snapshot level %q", profile.Level)
	}
	if profile.SuiteID != CompatibilitySuiteSandboxProvider {
		return fmt.Errorf("invalid compatibility suite ID %q", profile.SuiteID)
	}
	if !suiteVersionPattern.MatchString(profile.SuiteVersion) {
		return fmt.Errorf("invalid compatibility suite version %q", profile.SuiteVersion)
	}
	if !digestPattern.MatchString(string(profile.SuiteDigest)) {
		return errors.New("invalid compatibility suite digest")
	}
	return nil
}

func cloneCapabilitySnapshot(snapshot CapabilitySnapshot) CapabilitySnapshot {
	snapshot.SnapshotRestoreProfiles = append([]SnapshotRestoreProfile(nil), snapshot.SnapshotRestoreProfiles...)
	snapshot.Limits = cloneLimits(snapshot.Limits)
	return snapshot
}

func cloneLimits(limits Limits) Limits {
	limits.MaxWorkspaceBytes = cloneInt64(limits.MaxWorkspaceBytes)
	limits.MaxGPUCount = cloneInt64(limits.MaxGPUCount)
	return limits
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
