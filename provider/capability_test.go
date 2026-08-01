package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestNewCapabilitySnapshotAcceptsHonestZeroCapabilityModel(t *testing.T) {
	workspace := int64(4096)
	gpu := int64(0)
	snapshot, err := NewCapabilitySnapshot("revision-1", validLimits(&workspace, &gpu), []SnapshotRestoreProfile{
		validProfile("sandbox-snapshot-workspace-v1", SnapshotLevelWorkspace),
	})
	if err != nil {
		t.Fatalf("NewCapabilitySnapshot() error = %v", err)
	}
	if snapshot.APIVersion != APIVersionV1 {
		t.Fatalf("API version = %q, want %q", snapshot.APIVersion, APIVersionV1)
	}
	if snapshot.Limits.MaxGPUCount == nil || *snapshot.Limits.MaxGPUCount != 0 {
		t.Fatalf("max GPU count = %v, want explicit zero", snapshot.Limits.MaxGPUCount)
	}
}

func TestNewCapabilitySnapshotRejectsInvalidRevision(t *testing.T) {
	for _, revision := range []string{"", " ", "\t\n", string([]byte{0xff})} {
		t.Run(strings.ReplaceAll(revision, " ", "space"), func(t *testing.T) {
			if _, err := NewCapabilitySnapshot(revision, validLimits(nil, nil), validProfiles()); err == nil {
				t.Fatal("NewCapabilitySnapshot() error = nil, want revision rejection")
			}
		})
	}
}

func TestNewCapabilitySnapshotRejectsRequiredLimitBoundaries(t *testing.T) {
	tests := map[string]func(*Limits){
		"CPU/zero":           func(l *Limits) { l.MaxCPUMillis = 0 },
		"CPU/negative":       func(l *Limits) { l.MaxCPUMillis = -1 },
		"memory/zero":        func(l *Limits) { l.MaxMemoryBytes = 0 },
		"memory/negative":    func(l *Limits) { l.MaxMemoryBytes = -1 },
		"ephemeral/zero":     func(l *Limits) { l.MaxEphemeralStorageBytes = 0 },
		"ephemeral/negative": func(l *Limits) { l.MaxEphemeralStorageBytes = -1 },
		"lease/zero":         func(l *Limits) { l.MaxLeaseSeconds = 0 },
		"lease/negative":     func(l *Limits) { l.MaxLeaseSeconds = -1 },
		"exec/zero":          func(l *Limits) { l.MaxExecSeconds = 0 },
		"exec/negative":      func(l *Limits) { l.MaxExecSeconds = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			limits := validLimits(nil, nil)
			mutate(&limits)
			if _, err := NewCapabilitySnapshot("revision-1", limits, validProfiles()); err == nil {
				t.Fatal("NewCapabilitySnapshot() error = nil, want limit rejection")
			}
		})
	}
}

func TestNewCapabilitySnapshotOptionalLimitSemantics(t *testing.T) {
	tests := []struct {
		name      string
		workspace *int64
		gpu       *int64
		wantError bool
	}{
		{name: "omitted"},
		{name: "workspace positive", workspace: int64Pointer(1)},
		{name: "workspace zero", workspace: int64Pointer(0), wantError: true},
		{name: "workspace negative", workspace: int64Pointer(-1), wantError: true},
		{name: "GPU zero", gpu: int64Pointer(0)},
		{name: "GPU positive", gpu: int64Pointer(1)},
		{name: "GPU negative", gpu: int64Pointer(-1), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewCapabilitySnapshot("revision-1", validLimits(test.workspace, test.gpu), validProfiles())
			if (err != nil) != test.wantError {
				t.Fatalf("NewCapabilitySnapshot() error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestNewCapabilitySnapshotRejectsInvalidProfiles(t *testing.T) {
	tests := map[string]func(*SnapshotRestoreProfile){
		"empty profile ID": func(p *SnapshotRestoreProfile) { p.ProfileID = "" },
		"blank profile ID": func(p *SnapshotRestoreProfile) { p.ProfileID = " " },
		"invalid UTF-8 ID": func(p *SnapshotRestoreProfile) { p.ProfileID = string([]byte{0xff}) },
		"long profile ID":  func(p *SnapshotRestoreProfile) { p.ProfileID = strings.Repeat("a", 201) },
		"invalid level":    func(p *SnapshotRestoreProfile) { p.Level = "memory" },
		"invalid suite ID": func(p *SnapshotRestoreProfile) { p.SuiteID = "another-suite" },
		"invalid version":  func(p *SnapshotRestoreProfile) { p.SuiteVersion = "v1" },
		"uppercase digest": func(p *SnapshotRestoreProfile) { p.SuiteDigest = SHA256Digest("sha256:" + strings.Repeat("A", 64)) },
		"short digest":     func(p *SnapshotRestoreProfile) { p.SuiteDigest = "sha256:abcd" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			profile := validProfile("profile-1", SnapshotLevelWorkspace)
			mutate(&profile)
			if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), []SnapshotRestoreProfile{profile}); err == nil {
				t.Fatal("NewCapabilitySnapshot() error = nil, want profile rejection")
			}
		})
	}

	if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), nil); err == nil {
		t.Fatal("NewCapabilitySnapshot() error = nil, want empty profile rejection")
	}
}

func TestNewCapabilitySnapshotProfileIDCharacterLimit(t *testing.T) {
	accepted := validProfile(strings.Repeat("界", 200), SnapshotLevelWorkspace)
	if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), []SnapshotRestoreProfile{accepted}); err != nil {
		t.Fatalf("200-character profile ID rejected: %v", err)
	}

	rejected := validProfile(strings.Repeat("界", 201), SnapshotLevelWorkspace)
	if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), []SnapshotRestoreProfile{rejected}); err == nil {
		t.Fatal("201-character profile ID accepted")
	}
}

func TestNewCapabilitySnapshotRejectsDuplicateAndConflictingProfiles(t *testing.T) {
	profile := validProfile("profile-1", SnapshotLevelWorkspace)
	if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), []SnapshotRestoreProfile{profile, profile}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v, want duplicate rejection", err)
	}

	conflict := profile
	conflict.Level = SnapshotLevelFilesystem
	if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), []SnapshotRestoreProfile{profile, conflict}); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflict error = %v, want conflict rejection", err)
	}
}

func TestNewCapabilitySnapshotProfileCountLimit(t *testing.T) {
	profiles := make([]SnapshotRestoreProfile, 0, maxSnapshotRestoreProfiles+1)
	for index := 0; index < maxSnapshotRestoreProfiles; index++ {
		profiles = append(profiles, validProfile(fmt.Sprintf("profile-%d", index), SnapshotLevelWorkspace))
	}
	if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), profiles); err != nil {
		t.Fatalf("%d profiles rejected: %v", maxSnapshotRestoreProfiles, err)
	}

	profiles = append(profiles, validProfile("profile-over-limit", SnapshotLevelWorkspace))
	if _, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), profiles); err == nil {
		t.Fatalf("%d profiles accepted", maxSnapshotRestoreProfiles+1)
	}
}

func TestCapabilitySnapshotDefensiveCopies(t *testing.T) {
	workspace := int64(4096)
	gpu := int64(0)
	profiles := []SnapshotRestoreProfile{validProfile("profile-1", SnapshotLevelWorkspace)}
	snapshot, err := NewCapabilitySnapshot("revision-1", validLimits(&workspace, &gpu), profiles)
	if err != nil {
		t.Fatal(err)
	}

	workspace = 1
	gpu = 2
	profiles[0].ProfileID = "mutated-input"
	if *snapshot.Limits.MaxWorkspaceBytes != 4096 || *snapshot.Limits.MaxGPUCount != 0 || snapshot.SnapshotRestoreProfiles[0].ProfileID != "profile-1" {
		t.Fatalf("constructor input changed snapshot: %#v", snapshot)
	}

	source, err := NewStaticCapabilitySource(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ProviderRevisionID = "mutated-snapshot"
	*snapshot.Limits.MaxWorkspaceBytes = 2
	snapshot.SnapshotRestoreProfiles[0].ProfileID = "mutated-snapshot"

	first, err := source.CapabilitySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first.ProviderRevisionID = "mutated-return"
	*first.Limits.MaxWorkspaceBytes = 3
	first.SnapshotRestoreProfiles[0].ProfileID = "mutated-return"

	second, err := source.CapabilitySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.ProviderRevisionID != "revision-1" || *second.Limits.MaxWorkspaceBytes != 4096 || second.SnapshotRestoreProfiles[0].ProfileID != "profile-1" {
		t.Fatalf("returned mutation changed source snapshot: %#v", second)
	}
}

func TestStaticCapabilitySourceRejectsInvalidExportedSnapshotMutation(t *testing.T) {
	snapshot, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), validProfiles())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*CapabilitySnapshot){
		"API version":      func(s *CapabilitySnapshot) { s.APIVersion = "v2" },
		"required profile": func(s *CapabilitySnapshot) { s.SnapshotRestoreProfiles = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			invalid := snapshot
			mutate(&invalid)
			if _, err := NewStaticCapabilitySource(invalid); err == nil {
				t.Fatal("NewStaticCapabilitySource() error = nil, want invalid snapshot rejection")
			}
		})
	}
}

func TestStaticCapabilitySourceContextAndNilSafety(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot, err := NewCapabilitySnapshot("revision-1", validLimits(nil, nil), validProfiles())
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewStaticCapabilitySource(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.CapabilitySnapshot(ctx); err != context.Canceled {
		t.Fatalf("CapabilitySnapshot() error = %v, want %v", err, context.Canceled)
	}
	var nilSource *StaticCapabilitySource
	if _, err := nilSource.CapabilitySnapshot(context.Background()); err == nil {
		t.Fatal("nil CapabilitySnapshot() error = nil")
	}
}

func TestStaticCapabilitySourceConcurrentReads(t *testing.T) {
	snapshot, err := NewCapabilitySnapshot("revision-1", validLimits(int64Pointer(4096), int64Pointer(0)), validProfiles())
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewStaticCapabilitySource(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	const readers = 64
	var waitGroup sync.WaitGroup
	waitGroup.Add(readers)
	for index := 0; index < readers; index++ {
		go func(index int) {
			defer waitGroup.Done()
			read, readErr := source.CapabilitySnapshot(context.Background())
			if readErr != nil {
				t.Errorf("CapabilitySnapshot() error = %v", readErr)
				return
			}
			read.SnapshotRestoreProfiles[0].ProfileID = "mutated"
			*read.Limits.MaxGPUCount = int64(index)
		}(index)
	}
	waitGroup.Wait()

	final, err := source.CapabilitySnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if final.SnapshotRestoreProfiles[0].ProfileID != "sandbox-snapshot-workspace-v1" || *final.Limits.MaxGPUCount != 0 {
		t.Fatalf("concurrent mutation changed source: %#v", final)
	}
}

func validLimits(workspace, gpu *int64) Limits {
	return Limits{
		MaxCPUMillis:             1000,
		MaxMemoryBytes:           1 << 30,
		MaxEphemeralStorageBytes: 1 << 30,
		MaxWorkspaceBytes:        workspace,
		MaxGPUCount:              gpu,
		MaxLeaseSeconds:          3600,
		MaxExecSeconds:           300,
	}
}

func validProfiles() []SnapshotRestoreProfile {
	return []SnapshotRestoreProfile{validProfile("sandbox-snapshot-workspace-v1", SnapshotLevelWorkspace)}
}

func validProfile(id string, level SnapshotLevel) SnapshotRestoreProfile {
	return SnapshotRestoreProfile{
		ProfileID:    id,
		Level:        level,
		SuiteID:      CompatibilitySuiteSandboxProvider,
		SuiteVersion: "1.0.0",
		SuiteDigest:  SHA256Digest("sha256:" + strings.Repeat("a", 64)),
	}
}

func int64Pointer(value int64) *int64 {
	return &value
}
