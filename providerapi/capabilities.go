package providerapi

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/provider"
	providerv1 "github.com/shell-echo/sandbox-runtime/providerapi/v1"
)

const maxSnapshotRestoreProfiles = 32

var (
	suiteVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// mapCapabilities explicitly projects the application-owned startup snapshot
// into the Provider v1 wire model. P1.1b deliberately advertises no runtime
// capability or runtime profile.
func mapCapabilities(snapshot provider.CapabilitySnapshot) providerv1.Capabilities {
	profiles := make([]providerv1.SnapshotRestoreProfile, len(snapshot.SnapshotRestoreProfiles))
	for index, profile := range snapshot.SnapshotRestoreProfiles {
		profiles[index] = providerv1.SnapshotRestoreProfile{
			ProfileID:    profile.ProfileID,
			Level:        providerv1.SnapshotLevel(profile.Level),
			SuiteID:      providerv1.SandboxSuiteID(profile.SuiteID),
			SuiteVersion: profile.SuiteVersion,
			SuiteDigest:  providerv1.SHA256Digest(profile.SuiteDigest),
		}
	}

	return providerv1.Capabilities{
		ProviderRevisionID:     snapshot.ProviderRevisionID,
		APIVersion:             providerv1.APIVersion(snapshot.APIVersion),
		Capabilities:           make([]providerv1.Capability, 0),
		RuntimeProfiles:        make([]providerv1.RuntimeProfile, 0),
		SnapshotRestoreProfile: profiles,
		Limits: providerv1.ProviderLimits{
			MaxCPUMillis:             snapshot.Limits.MaxCPUMillis,
			MaxMemoryBytes:           snapshot.Limits.MaxMemoryBytes,
			MaxEphemeralStorageBytes: snapshot.Limits.MaxEphemeralStorageBytes,
			MaxWorkspaceBytes:        cloneInt64(snapshot.Limits.MaxWorkspaceBytes),
			MaxGPUCount:              cloneInt64(snapshot.Limits.MaxGPUCount),
			MaxLeaseSeconds:          snapshot.Limits.MaxLeaseSeconds,
			MaxExecSeconds:           snapshot.Limits.MaxExecSeconds,
		},
	}
}

// validateCapabilities enforces the locked capability Schema constraints used
// by P1.1b and its stricter zero-advertisement policy. It is a local fail-closed
// boundary, not a replacement for validation against the locked Contract.
func validateCapabilities(document providerv1.Capabilities) error {
	if !utf8.ValidString(document.ProviderRevisionID) || strings.TrimSpace(document.ProviderRevisionID) == "" {
		return errors.New("provider revision ID must be valid UTF-8 and not empty")
	}
	if document.APIVersion != providerv1.APIVersionV1 {
		return fmt.Errorf("unsupported API version %q", document.APIVersion)
	}
	if document.Capabilities == nil || len(document.Capabilities) != 0 {
		return errors.New("P1.1b capabilities must be a non-nil empty array")
	}
	if document.RuntimeProfiles == nil || len(document.RuntimeProfiles) != 0 {
		return errors.New("P1.1b runtime profiles must be a non-nil empty array")
	}
	if err := validateLimits(document.Limits); err != nil {
		return err
	}
	if len(document.SnapshotRestoreProfile) == 0 {
		return errors.New("at least one snapshot/restore compatibility profile is required")
	}
	if len(document.SnapshotRestoreProfile) > maxSnapshotRestoreProfiles {
		return fmt.Errorf("snapshot/restore compatibility profiles must not exceed %d", maxSnapshotRestoreProfiles)
	}

	profilesByID := make(map[string]providerv1.SnapshotRestoreProfile, len(document.SnapshotRestoreProfile))
	for index, profile := range document.SnapshotRestoreProfile {
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

func validateLimits(limits providerv1.ProviderLimits) error {
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

func validateSnapshotRestoreProfile(profile providerv1.SnapshotRestoreProfile) error {
	if !utf8.ValidString(profile.ProfileID) || strings.TrimSpace(profile.ProfileID) == "" {
		return errors.New("profile ID must be valid UTF-8 and not empty")
	}
	if utf8.RuneCountInString(profile.ProfileID) > 200 {
		return errors.New("profile ID must not exceed 200 characters")
	}
	switch profile.Level {
	case providerv1.SnapshotWorkspace, providerv1.SnapshotFilesystem, providerv1.SnapshotProcess:
	default:
		return fmt.Errorf("invalid snapshot level %q", profile.Level)
	}
	if profile.SuiteID != providerv1.SandboxSuiteProvider {
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

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
