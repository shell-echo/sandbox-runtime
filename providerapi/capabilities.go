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

const (
	maxSnapshotRestoreProfiles = 32
	maxCapabilities            = 64
	maxCapabilityVersions      = 16
	maxCapabilityProfiles      = 64
	maxRuntimeProfiles         = 64
)

var (
	suiteVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	capabilityIDPattern = regexp.MustCompile(`^sandbox\.[a-z0-9-]+$`)
	identifierPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
)

// mapCapabilities explicitly projects the application-owned startup snapshot
// into the Provider v1 wire model. The default snapshot remains disabled, while
// an explicit terminal advertisement carries an exact profile mapping.
func mapCapabilities(snapshot provider.CapabilitySnapshot) providerv1.Capabilities {
	capabilities := make([]providerv1.Capability, len(snapshot.Capabilities))
	for index, capability := range snapshot.Capabilities {
		capabilities[index] = providerv1.Capability{
			ID:       providerv1.CapabilityID(capability.ID),
			Versions: append([]string(nil), capability.Versions...),
			Profiles: append([]string(nil), capability.Profiles...),
		}
	}
	runtimeProfiles := make([]providerv1.RuntimeProfile, len(snapshot.RuntimeProfiles))
	for index, profile := range snapshot.RuntimeProfiles {
		architectures := make([]providerv1.Architecture, len(profile.Architecture))
		for architectureIndex, architecture := range profile.Architecture {
			architectures[architectureIndex] = providerv1.Architecture(architecture)
		}
		runtimeProfiles[index] = providerv1.RuntimeProfile{
			ID:                   profile.ID,
			IsolationClass:       providerv1.IsolationClass(profile.IsolationClass),
			RuntimeClassName:     profile.RuntimeClassName,
			Architecture:         architectures,
			CapabilityProfileIDs: append([]string(nil), profile.CapabilityProfileIDs...),
		}
	}
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
		Capabilities:           capabilities,
		RuntimeProfiles:        runtimeProfiles,
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

// validateCapabilities enforces the locked capability Schema constraints and
// terminal profile relationship. It is a local fail-closed boundary, not a
// replacement for validation against the locked Contract.
func validateCapabilities(document providerv1.Capabilities) error {
	if !utf8.ValidString(document.ProviderRevisionID) || strings.TrimSpace(document.ProviderRevisionID) == "" {
		return errors.New("provider revision ID must be valid UTF-8 and not empty")
	}
	if document.APIVersion != providerv1.APIVersionV1 {
		return fmt.Errorf("unsupported API version %q", document.APIVersion)
	}
	if err := validateCapabilityAdvertisements(document.Capabilities, document.RuntimeProfiles); err != nil {
		return err
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

func validateCapabilityAdvertisements(capabilities []providerv1.Capability, runtimeProfiles []providerv1.RuntimeProfile) error {
	if capabilities == nil {
		return errors.New("capabilities must be a non-nil array")
	}
	if runtimeProfiles == nil {
		return errors.New("runtime profiles must be a non-nil array")
	}
	if len(capabilities) > maxCapabilities {
		return fmt.Errorf("capabilities must not exceed %d", maxCapabilities)
	}
	if len(runtimeProfiles) > maxRuntimeProfiles {
		return fmt.Errorf("runtime profiles must not exceed %d", maxRuntimeProfiles)
	}

	capabilitiesByID := make(map[providerv1.CapabilityID]providerv1.Capability, len(capabilities))
	profileIDs := make(map[string]struct{})
	for index, capability := range capabilities {
		if !capabilityIDPattern.MatchString(string(capability.ID)) {
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
		if capability.ID == providerv1.CapabilityTerminal && (len(capability.Versions) == 0 || len(capability.Profiles) == 0) {
			return errors.New("terminal capability must advertise at least one version and profile")
		}
		capabilitiesByID[capability.ID] = capability
	}
	terminal, terminalAdvertised := capabilitiesByID[providerv1.CapabilityTerminal]
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
		architectures := make(map[providerv1.Architecture]struct{}, len(runtimeProfile.Architecture))
		for _, architecture := range runtimeProfile.Architecture {
			if architecture != providerv1.ArchitectureAMD64 && architecture != providerv1.ArchitectureARM64 {
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

func validIsolationClass(value providerv1.IsolationClass) bool {
	switch value {
	case providerv1.IsolationContainer, providerv1.IsolationHardenedContainer, providerv1.IsolationMicroVM, providerv1.IsolationVirtualMachine, providerv1.IsolationLocalProcess:
		return true
	default:
		return false
	}
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
