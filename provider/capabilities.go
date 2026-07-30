// Package provider owns Provider-local application policy and models. It has
// no dependency on HTTP, Provider wire DTOs, repositories, or runtime drivers.
package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

const (
	APIVersionV1 = "v1"

	CapabilityWorkspaceSnapshot  = "sandbox.snapshot.workspace"
	CapabilityFilesystemSnapshot = "sandbox.snapshot.filesystem"
	CapabilityProcessSnapshot    = "sandbox.snapshot.process"
	CapabilityRestore            = "sandbox.restore"

	IsolationContainer         = "container"
	IsolationHardenedContainer = "hardened-container"
	IsolationMicroVM           = "microvm"
	IsolationVirtualMachine    = "virtual-machine"
	IsolationLocalProcess      = "local-process"

	ArchitectureAMD64 = "amd64"
	ArchitectureARM64 = "arm64"

	SnapshotWorkspace  = "workspace"
	SnapshotFilesystem = "filesystem"
	SnapshotProcess    = "process"

	SandboxSuiteProvider       = "sandbox-provider"
	LockedSandboxSuiteVersion  = "1.0.0"
	LockedSandboxSuiteDigest   = "sha256:bdebf6fba1cd41072a46b47de451bf039485047e9a9478fad2d6c69ee8ff38b7"
	WorkspaceSnapshotProfileID = "sandbox-snapshot-workspace-v1"
)

var allowedCapabilities = map[string]struct{}{
	"sandbox.exec": {}, "sandbox.terminal": {}, "sandbox.browser": {},
	"sandbox.desktop": {}, "sandbox.port-forward": {},
	"sandbox.workspace.persistent": {}, CapabilityWorkspaceSnapshot: {},
	CapabilityFilesystemSnapshot: {}, CapabilityProcessSnapshot: {},
	CapabilityRestore: {}, "sandbox.network-policy": {}, "sandbox.gpu": {},
	"sandbox.nested-container": {}, "sandbox.user-namespace": {},
}

// ErrUnavailable lets a capability source distinguish a temporary discovery
// outage from an unexpected internal failure at the transport boundary.
var ErrUnavailable = errors.New("Provider capabilities unavailable")

// CapabilityService is the application port used by Provider discovery.
type CapabilityService interface {
	Capabilities(context.Context) (Capabilities, error)
}

// Capabilities is the Provider-local application projection. Transport maps it
// explicitly into the versioned wire DTO before encoding a response.
type Capabilities struct {
	ProviderRevisionID     string
	APIVersion             string
	Capabilities           []Capability
	RuntimeProfiles        []RuntimeProfile
	SnapshotRestoreProfile []SnapshotRestoreProfile
	Limits                 Limits
}

type Capability struct {
	ID       string
	Versions []string
	Profiles []string
}

type RuntimeProfile struct {
	ID               string
	IsolationClass   string
	RuntimeClassName string
	Architectures    []string
}

type SnapshotRestoreProfile struct {
	ProfileID    string
	Level        string
	SuiteID      string
	SuiteVersion string
	SuiteDigest  string
}

type Limits struct {
	MaxCPUMillis             int64
	MaxMemoryBytes           int64
	MaxEphemeralStorageBytes int64
	MaxWorkspaceBytes        *int64
	MaxGPUCount              *int64
	MaxLeaseSeconds          int64
	MaxExecSeconds           int64
}

// Validate enforces the application invariants needed to project a safe
// Provider response. Locked Schema validation remains a separate Contract gate.
func (c Capabilities) Validate() error {
	if strings.TrimSpace(c.ProviderRevisionID) != c.ProviderRevisionID || c.ProviderRevisionID == "" || len(c.ProviderRevisionID) > 200 {
		return errors.New("provider revision ID must be a non-empty value of at most 200 bytes")
	}
	if c.APIVersion != APIVersionV1 {
		return fmt.Errorf("API version %q is not supported", c.APIVersion)
	}
	if err := validateCapabilities(c.Capabilities); err != nil {
		return err
	}
	if err := validateRuntimeProfiles(c.RuntimeProfiles); err != nil {
		return err
	}
	if err := validateSnapshotProfiles(c.SnapshotRestoreProfile); err != nil {
		return err
	}
	if err := validateSnapshotAdvertisement(c.Capabilities, c.SnapshotRestoreProfile); err != nil {
		return err
	}
	return c.Limits.validate()
}

func validateCapabilities(capabilities []Capability) error {
	seen := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if _, ok := allowedCapabilities[capability.ID]; !ok {
			return fmt.Errorf("capability %q is not in the Provider v1 vocabulary", capability.ID)
		}
		if _, duplicate := seen[capability.ID]; duplicate {
			return fmt.Errorf("capability %q is duplicated", capability.ID)
		}
		seen[capability.ID] = struct{}{}
		if len(capability.Versions) == 0 {
			return fmt.Errorf("capability %q requires at least one version", capability.ID)
		}
		if err := validateUniqueStrings("capability version", capability.Versions); err != nil {
			return err
		}
		if err := validateUniqueStrings("capability profile", capability.Profiles); err != nil {
			return err
		}
	}
	return nil
}

func validateRuntimeProfiles(profiles []RuntimeProfile) error {
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if profile.ID == "" || len(profile.ID) > 200 {
			return errors.New("runtime profile ID must be between 1 and 200 bytes")
		}
		if _, duplicate := seen[profile.ID]; duplicate {
			return fmt.Errorf("runtime profile %q is duplicated", profile.ID)
		}
		seen[profile.ID] = struct{}{}
		switch profile.IsolationClass {
		case IsolationContainer, IsolationHardenedContainer, IsolationMicroVM,
			IsolationVirtualMachine, IsolationLocalProcess:
		default:
			return fmt.Errorf("runtime profile %q has invalid isolation class", profile.ID)
		}
		if err := validateUniqueStrings("runtime architecture", profile.Architectures); err != nil {
			return err
		}
		for _, architecture := range profile.Architectures {
			if architecture != ArchitectureAMD64 && architecture != ArchitectureARM64 {
				return fmt.Errorf("runtime profile %q has invalid architecture", profile.ID)
			}
		}
	}
	return nil
}

func validateSnapshotProfiles(profiles []SnapshotRestoreProfile) error {
	if len(profiles) == 0 || len(profiles) > 32 {
		return errors.New("between 1 and 32 snapshot restore profiles are required")
	}
	seen := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		if profile.ProfileID == "" || len(profile.ProfileID) > 200 {
			return errors.New("snapshot restore profile ID must be between 1 and 200 bytes")
		}
		if _, duplicate := seen[profile.ProfileID]; duplicate {
			return fmt.Errorf("snapshot restore profile %q is duplicated", profile.ProfileID)
		}
		seen[profile.ProfileID] = struct{}{}
		switch profile.Level {
		case SnapshotWorkspace, SnapshotFilesystem, SnapshotProcess:
		default:
			return fmt.Errorf("snapshot restore profile %q has invalid level", profile.ProfileID)
		}
		if profile.SuiteID != SandboxSuiteProvider || profile.SuiteVersion != LockedSandboxSuiteVersion || profile.SuiteDigest != LockedSandboxSuiteDigest {
			return fmt.Errorf("snapshot restore profile %q does not bind the locked Sandbox Suite", profile.ProfileID)
		}
	}
	return nil
}

func validateSnapshotAdvertisement(capabilities []Capability, profiles []SnapshotRestoreProfile) error {
	levels := make(map[string]struct{}, len(profiles))
	for _, profile := range profiles {
		levels[profile.Level] = struct{}{}
	}
	for _, capability := range capabilities {
		var level string
		switch capability.ID {
		case CapabilityWorkspaceSnapshot:
			level = SnapshotWorkspace
		case CapabilityFilesystemSnapshot:
			level = SnapshotFilesystem
		case CapabilityProcessSnapshot:
			level = SnapshotProcess
		case CapabilityRestore:
			if len(profiles) == 0 {
				return errors.New("restore capability requires a snapshot restore profile")
			}
		}
		if level != "" {
			if _, ok := levels[level]; !ok {
				return fmt.Errorf("snapshot capability %q lacks a matching profile", capability.ID)
			}
		}
	}
	return nil
}

func validateUniqueStrings(name string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > 200 {
			return fmt.Errorf("%s must be between 1 and 200 bytes", name)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("%s %q is duplicated", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (l Limits) validate() error {
	if l.MaxCPUMillis <= 0 || l.MaxMemoryBytes <= 0 || l.MaxEphemeralStorageBytes <= 0 || l.MaxLeaseSeconds <= 0 || l.MaxExecSeconds <= 0 {
		return errors.New("required Provider limits must be greater than zero")
	}
	if l.MaxWorkspaceBytes != nil && *l.MaxWorkspaceBytes <= 0 {
		return errors.New("maximum workspace bytes must be greater than zero when set")
	}
	if l.MaxGPUCount != nil && *l.MaxGPUCount < 0 {
		return errors.New("maximum GPU count must not be negative when set")
	}
	return nil
}

type staticCapabilityService struct {
	capabilities Capabilities
}

// NewStaticCapabilityService returns an immutable discovery service. P1.1b
// intentionally advertises no runtime capability until its Provider behavior
// exists; the locked workspace profile is compatibility metadata, not restore
// authorization.
func NewStaticCapabilityService(providerRevisionID string, limits Limits) (CapabilityService, error) {
	capabilities := Capabilities{
		ProviderRevisionID: providerRevisionID,
		APIVersion:         APIVersionV1,
		Capabilities:       []Capability{},
		RuntimeProfiles:    []RuntimeProfile{},
		SnapshotRestoreProfile: []SnapshotRestoreProfile{{
			ProfileID:    WorkspaceSnapshotProfileID,
			Level:        SnapshotWorkspace,
			SuiteID:      SandboxSuiteProvider,
			SuiteVersion: LockedSandboxSuiteVersion,
			SuiteDigest:  LockedSandboxSuiteDigest,
		}},
		Limits: limits,
	}
	if err := capabilities.Validate(); err != nil {
		return nil, err
	}
	return &staticCapabilityService{capabilities: cloneCapabilities(capabilities)}, nil
}

func (s *staticCapabilityService) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	return cloneCapabilities(s.capabilities), nil
}

func cloneCapabilities(value Capabilities) Capabilities {
	cloned := value
	cloned.Capabilities = make([]Capability, len(value.Capabilities))
	for i, capability := range value.Capabilities {
		cloned.Capabilities[i] = capability
		cloned.Capabilities[i].Versions = append([]string(nil), capability.Versions...)
		cloned.Capabilities[i].Profiles = append([]string(nil), capability.Profiles...)
	}
	cloned.RuntimeProfiles = make([]RuntimeProfile, len(value.RuntimeProfiles))
	for i, profile := range value.RuntimeProfiles {
		cloned.RuntimeProfiles[i] = profile
		cloned.RuntimeProfiles[i].Architectures = append([]string(nil), profile.Architectures...)
	}
	cloned.SnapshotRestoreProfile = append([]SnapshotRestoreProfile(nil), value.SnapshotRestoreProfile...)
	return cloned
}
