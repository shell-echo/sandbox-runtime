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

const (
	maxSnapshotRestoreProfiles = 32
	maxCapabilities            = 64
	maxCapabilityVersions      = 16
	maxCapabilityProfiles      = 64
	maxRuntimeProfiles         = 64
)

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

// Capability describes one advertised Provider capability and its immutable
// capability-profile identifiers.
type Capability struct {
	ID       string
	Versions []string
	Profiles []string
}

// RuntimeProfile identifies a runtime class and the capability profiles it can
// serve. It is metadata only; advertising one does not start a runtime.
type RuntimeProfile struct {
	ID                   string
	IsolationClass       string
	RuntimeClassName     string
	Architecture         []string
	CapabilityProfileIDs []string
}

// CapabilitySnapshot is the immutable-at-source capability document consumed
// by Provider adapters. Callers receive defensive copies and may mutate their
// copy without changing future reads.
type CapabilitySnapshot struct {
	ProviderRevisionID      string
	APIVersion              APIVersion
	Capabilities            []Capability
	RuntimeProfiles         []RuntimeProfile
	SnapshotRestoreProfiles []SnapshotRestoreProfile
	Limits                  Limits
}

var (
	suiteVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	capabilityIDPattern = regexp.MustCompile(`^sandbox\.[a-z0-9-]+$`)
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

// NewCapabilitySnapshot validates and freezes the default-disabled startup
// model. It intentionally advertises neither capabilities nor runtime profiles.
func NewCapabilitySnapshot(providerRevisionID string, limits Limits, profiles []SnapshotRestoreProfile) (CapabilitySnapshot, error) {
	return NewCapabilitySnapshotWithAdvertisements(providerRevisionID, limits, nil, nil, profiles)
}

// NewCapabilitySnapshotWithAdvertisements validates and freezes a capability
// snapshot. A terminal capability is valid only when each of its advertised
// profiles maps to an advertised runtime profile.
func NewCapabilitySnapshotWithAdvertisements(providerRevisionID string, limits Limits, capabilities []Capability, runtimeProfiles []RuntimeProfile, profiles []SnapshotRestoreProfile) (CapabilitySnapshot, error) {
	snapshot := CapabilitySnapshot{
		ProviderRevisionID:      providerRevisionID,
		APIVersion:              APIVersionV1,
		Capabilities:            cloneCapabilities(capabilities),
		RuntimeProfiles:         cloneRuntimeProfiles(runtimeProfiles),
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
	if err := validateCapabilityAdvertisements(snapshot.Capabilities, snapshot.RuntimeProfiles); err != nil {
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

func validateCapabilityAdvertisements(capabilities []Capability, runtimeProfiles []RuntimeProfile) error {
	if len(capabilities) > maxCapabilities {
		return fmt.Errorf("capabilities must not exceed %d", maxCapabilities)
	}
	if len(runtimeProfiles) > maxRuntimeProfiles {
		return fmt.Errorf("runtime profiles must not exceed %d", maxRuntimeProfiles)
	}

	capabilitiesByID := make(map[string]Capability, len(capabilities))
	profileIDs := make(map[string]struct{})
	for index, capability := range capabilities {
		if !capabilityIDPattern.MatchString(capability.ID) {
			return fmt.Errorf("capability %d has an invalid ID %q", index, capability.ID)
		}
		if _, exists := capabilitiesByID[capability.ID]; exists {
			return fmt.Errorf("duplicate capability %q", capability.ID)
		}
		if capability.Versions == nil {
			return fmt.Errorf("capability %q versions must be a non-nil array", capability.ID)
		}
		if len(capability.Versions) > maxCapabilityVersions {
			return fmt.Errorf("capability %q versions must not exceed %d", capability.ID, maxCapabilityVersions)
		}
		versions := make(map[string]struct{}, len(capability.Versions))
		for _, version := range capability.Versions {
			if !identifierPattern.MatchString(version) {
				return fmt.Errorf("capability %q has an invalid version %q", capability.ID, version)
			}
			if _, exists := versions[version]; exists {
				return fmt.Errorf("capability %q repeats version %q", capability.ID, version)
			}
			versions[version] = struct{}{}
		}
		if len(capability.Profiles) > maxCapabilityProfiles {
			return fmt.Errorf("capability %q profiles must not exceed %d", capability.ID, maxCapabilityProfiles)
		}
		profiles := make(map[string]struct{}, len(capability.Profiles))
		for _, profileID := range capability.Profiles {
			if !identifierPattern.MatchString(profileID) {
				return fmt.Errorf("capability %q has an invalid profile ID %q", capability.ID, profileID)
			}
			if _, exists := profiles[profileID]; exists {
				return fmt.Errorf("capability %q repeats profile ID %q", capability.ID, profileID)
			}
			if _, exists := profileIDs[profileID]; exists {
				return fmt.Errorf("capability profile ID %q is not globally unique", profileID)
			}
			profiles[profileID] = struct{}{}
			profileIDs[profileID] = struct{}{}
		}
		if capability.ID == "sandbox.terminal" && (len(capability.Versions) == 0 || len(capability.Profiles) == 0) {
			return errors.New("terminal capability must advertise at least one version and profile")
		}
		capabilitiesByID[capability.ID] = capability
	}
	terminal, terminalAdvertised := capabilitiesByID["sandbox.terminal"]
	if !terminalAdvertised {
		if len(capabilities) != 0 {
			return errors.New("P2.3c0 permits only terminal capability advertisements")
		}
		if len(runtimeProfiles) != 0 {
			return errors.New("runtime profiles require an advertised terminal capability")
		}
		return nil
	}
	if len(capabilities) != 1 {
		return errors.New("P2.3c0 permits only one terminal capability advertisement")
	}

	mappedProfiles := make(map[string]struct{})
	runtimeIDs := make(map[string]struct{}, len(runtimeProfiles))
	for index, runtimeProfile := range runtimeProfiles {
		if !identifierPattern.MatchString(runtimeProfile.ID) {
			return fmt.Errorf("runtime profile %d has an invalid ID %q", index, runtimeProfile.ID)
		}
		if _, exists := runtimeIDs[runtimeProfile.ID]; exists {
			return fmt.Errorf("duplicate runtime profile %q", runtimeProfile.ID)
		}
		runtimeIDs[runtimeProfile.ID] = struct{}{}
		if !validIsolationClass(runtimeProfile.IsolationClass) {
			return fmt.Errorf("runtime profile %q has an invalid isolation class %q", runtimeProfile.ID, runtimeProfile.IsolationClass)
		}
		if runtimeProfile.RuntimeClassName != "" && (!utf8.ValidString(runtimeProfile.RuntimeClassName) || strings.TrimSpace(runtimeProfile.RuntimeClassName) == "") {
			return fmt.Errorf("runtime profile %q has an invalid runtime class name", runtimeProfile.ID)
		}
		architectures := make(map[string]struct{}, len(runtimeProfile.Architecture))
		for _, architecture := range runtimeProfile.Architecture {
			if architecture != "amd64" && architecture != "arm64" {
				return fmt.Errorf("runtime profile %q has an invalid architecture %q", runtimeProfile.ID, architecture)
			}
			if _, exists := architectures[architecture]; exists {
				return fmt.Errorf("runtime profile %q repeats architecture %q", runtimeProfile.ID, architecture)
			}
			architectures[architecture] = struct{}{}
		}
		if len(runtimeProfile.CapabilityProfileIDs) > maxCapabilityProfiles {
			return fmt.Errorf("runtime profile %q capability profiles must not exceed %d", runtimeProfile.ID, maxCapabilityProfiles)
		}
		for _, profileID := range runtimeProfile.CapabilityProfileIDs {
			if _, exists := profileIDs[profileID]; !exists {
				return fmt.Errorf("runtime profile %q references unadvertised capability profile %q", runtimeProfile.ID, profileID)
			}
			if _, exists := mappedProfiles[profileID]; exists {
				return fmt.Errorf("capability profile %q maps to more than one runtime profile", profileID)
			}
			mappedProfiles[profileID] = struct{}{}
		}
	}

	for _, profileID := range terminal.Profiles {
		if _, mapped := mappedProfiles[profileID]; !mapped {
			return fmt.Errorf("terminal capability profile %q has no advertised runtime profile", profileID)
		}
	}
	return nil
}

func validIsolationClass(value string) bool {
	switch value {
	case "container", "hardened-container", "microvm", "virtual-machine", "local-process":
		return true
	default:
		return false
	}
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
	snapshot.Capabilities = cloneCapabilities(snapshot.Capabilities)
	snapshot.RuntimeProfiles = cloneRuntimeProfiles(snapshot.RuntimeProfiles)
	snapshot.SnapshotRestoreProfiles = append([]SnapshotRestoreProfile(nil), snapshot.SnapshotRestoreProfiles...)
	snapshot.Limits = cloneLimits(snapshot.Limits)
	return snapshot
}

func cloneCapabilities(source []Capability) []Capability {
	result := make([]Capability, len(source))
	for index, capability := range source {
		result[index] = Capability{
			ID:       capability.ID,
			Versions: append([]string(nil), capability.Versions...),
			Profiles: append([]string(nil), capability.Profiles...),
		}
	}
	return result
}

func cloneRuntimeProfiles(source []RuntimeProfile) []RuntimeProfile {
	result := make([]RuntimeProfile, len(source))
	for index, profile := range source {
		result[index] = RuntimeProfile{
			ID:                   profile.ID,
			IsolationClass:       profile.IsolationClass,
			RuntimeClassName:     profile.RuntimeClassName,
			Architecture:         append([]string(nil), profile.Architecture...),
			CapabilityProfileIDs: append([]string(nil), profile.CapabilityProfileIDs...),
		}
	}
	return result
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
