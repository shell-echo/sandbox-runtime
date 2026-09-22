package image

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	Phase5ProductionReleaseManifestPath   = "phase5-production-release-manifest.json"
	Phase5ProductionReleaseManifestDigest = "sha256:a03c1426058ef6fe18a70329610d0495d267cd1aa9513e650367e3f9a8857887"
	Phase5InstalledSetDigest              = "sha256:6b5fc1ece685456ed20f474c9af9547c597210f9105f7f12e9cf21d8377db4b5"
)

// Phase5ProductionReleaseManifest is the immutable build-input identity for
// the signed Phase 5 Desktop publication. It intentionally remains separate
// from Manifest, which describes the non-release Phase 6 local candidate and
// includes the newer session broker inputs.
type Phase5ProductionReleaseManifest struct {
	SchemaVersion    string                          `json:"schema_version"`
	ProfileID        string                          `json:"profile_id"`
	RuntimeClassName string                          `json:"runtime_class_name"`
	Source           Phase5ProductionReleaseSource   `json:"source"`
	Packages         Phase5ProductionReleasePackages `json:"packages"`
	Broker           Phase5ProductionReleaseBroker   `json:"broker"`
	Display          Display                         `json:"display"`
	Security         Security                        `json:"security"`
	Mounts           []Mount                         `json:"mounts"`
	Network          Network                         `json:"network"`
	Outputs          Outputs                         `json:"reproducible_outputs"`
	Provenance       Provenance                      `json:"provenance"`
}

type Phase5ProductionReleaseSource struct {
	Repository  string                                     `json:"repository"`
	Release     string                                     `json:"release"`
	IndexDigest string                                     `json:"index_digest"`
	Manifests   map[string]Phase5ProductionReleasePlatform `json:"manifests"`
}

type Phase5ProductionReleasePlatform struct {
	Digest                  string `json:"digest"`
	Architecture            string `json:"architecture"`
	Variant                 string `json:"variant,omitempty"`
	PackageArchiveSetDigest string `json:"package_archive_set_digest"`
}

type Phase5ProductionReleasePackages struct {
	Repositories       []string  `json:"repositories"`
	Required           []Package `json:"required"`
	InstalledSetDigest string    `json:"installed_set_digest"`
}

type Phase5ProductionReleaseBroker struct {
	Path           string   `json:"path"`
	Socket         string   `json:"socket"`
	Protocol       string   `json:"protocol"`
	Methods        []string `json:"methods"`
	MaxRequest     int      `json:"max_request_bytes"`
	MaxResponse    int      `json:"max_response_bytes"`
	MaxConnections int      `json:"max_connections"`
}

func LoadPhase5ProductionRelease(path string) (Phase5ProductionReleaseManifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Phase5ProductionReleaseManifest{}, fmt.Errorf("read Phase 5 production Desktop image manifest: %w", err)
	}
	return ParsePhase5ProductionRelease(data)
}

func ParsePhase5ProductionRelease(data []byte) (Phase5ProductionReleaseManifest, error) {
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return Phase5ProductionReleaseManifest{}, invalid("Phase 5 production release document size is invalid")
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	if digest != Phase5ProductionReleaseManifestDigest {
		return Phase5ProductionReleaseManifest{}, invalid("Phase 5 production release manifest digest is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Phase5ProductionReleaseManifest
	if err := decoder.Decode(&manifest); err != nil {
		return Phase5ProductionReleaseManifest{}, invalid("decode Phase 5 production release: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return Phase5ProductionReleaseManifest{}, invalid("trailing Phase 5 production release JSON value")
	} else if !errors.Is(err, io.EOF) {
		return Phase5ProductionReleaseManifest{}, invalid("trailing Phase 5 production release input: %v", err)
	}
	if err := manifest.Validate(); err != nil {
		return Phase5ProductionReleaseManifest{}, err
	}
	return manifest, nil
}

func (m Phase5ProductionReleaseManifest) Validate() error {
	if m.SchemaVersion != SchemaVersion || m.ProfileID != ProfileID || m.RuntimeClassName != RuntimeClassName {
		return invalid("Phase 5 production release schema/profile/runtime class identity is invalid")
	}
	if m.Source.Repository != SourceRepository || m.Source.Release != SourceRelease ||
		m.Source.IndexDigest != SourceIndexDigest || !digestPattern.MatchString(m.Source.IndexDigest) {
		return invalid("Phase 5 production release source identity is invalid")
	}
	wantPlatforms := map[string]Phase5ProductionReleasePlatform{
		"linux/amd64": {
			Digest:                  "sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3",
			Architecture:            "amd64",
			PackageArchiveSetDigest: "sha256:591fef77f3bdbac861ef71ad7cfca7ef6e86a0ac092a7c10084118af10f40097",
		},
		"linux/arm64/v8": {
			Digest:                  "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c",
			Architecture:            "arm64",
			Variant:                 "v8",
			PackageArchiveSetDigest: "sha256:28468a7b60dc3228ae95f738e7083f6c41b02d381aa1ae6f42afe8424e9a4727",
		},
	}
	if len(m.Source.Manifests) != len(wantPlatforms) {
		return invalid("Phase 5 production release platform matrix is invalid")
	}
	for platform, want := range wantPlatforms {
		got, ok := m.Source.Manifests[platform]
		if !ok || got != want || !digestPattern.MatchString(got.Digest) || !digestPattern.MatchString(got.PackageArchiveSetDigest) {
			return invalid("Phase 5 production release platform manifest %q is invalid", platform)
		}
	}
	wantRepositories := []string{"https://dl-cdn.alpinelinux.org/alpine/v3.23/main", "https://dl-cdn.alpinelinux.org/alpine/v3.23/community"}
	wantPackages := []Package{
		{Name: "xvfb", Version: "21.1.23-r0"},
		{Name: "openbox", Version: "3.6.1-r8"},
		{Name: "xterm", Version: "403-r0"},
		{Name: "xdotool", Version: "4.20251130.1-r0"},
		{Name: "xdpyinfo", Version: "1.4.0-r0"},
		{Name: "xset", Version: "1.2.5-r1"},
		{Name: "xwd", Version: "1.0.9-r2"},
		{Name: "font-dejavu", Version: "2.37-r6"},
	}
	if !equal(m.Packages.Repositories, wantRepositories) || !equal(m.Packages.Required, wantPackages) || m.Packages.InstalledSetDigest != Phase5InstalledSetDigest {
		return invalid("Phase 5 production release package authority is invalid")
	}
	wantBroker := Phase5ProductionReleaseBroker{Path: BrokerPath, Socket: BrokerSocket, Protocol: BrokerProtocol, Methods: []string{"probe", "describe"}, MaxRequest: 4096, MaxResponse: 8192, MaxConnections: 16}
	if m.Broker.Path != wantBroker.Path || m.Broker.Socket != wantBroker.Socket || m.Broker.Protocol != wantBroker.Protocol ||
		!equal(m.Broker.Methods, wantBroker.Methods) || m.Broker.MaxRequest != wantBroker.MaxRequest ||
		m.Broker.MaxResponse != wantBroker.MaxResponse || m.Broker.MaxConnections != wantBroker.MaxConnections {
		return invalid("Phase 5 production release broker authority is invalid")
	}
	wantDisplay := Display{Server: "/usr/bin/Xvfb", WindowManager: "/usr/bin/openbox", Display: ":99", Reference: DisplayReference, Width: 1280, Height: 720, Depth: 24, TCPListen: false, AudioOutput: false, UserLaunchOverrides: "rejected"}
	if m.Display != wantDisplay {
		return invalid("Phase 5 production release display authority is invalid")
	}
	wantSecurity := Security{UID: RequiredUID, GID: RequiredGID, RootFilesystem: "read_only", NoNewPrivileges: true, Capabilities: "drop_all", Privileged: false, Seccomp: "runtime_default", IPC: "private", Devices: []string{}, DeviceRequests: "none", ContainerIsolationRequired: true}
	if m.Security.UID != wantSecurity.UID || m.Security.GID != wantSecurity.GID || m.Security.RootFilesystem != wantSecurity.RootFilesystem ||
		m.Security.NoNewPrivileges != wantSecurity.NoNewPrivileges || m.Security.Capabilities != wantSecurity.Capabilities ||
		m.Security.Privileged != wantSecurity.Privileged || m.Security.Seccomp != wantSecurity.Seccomp || m.Security.IPC != wantSecurity.IPC ||
		len(m.Security.Devices) != 0 || m.Security.DeviceRequests != wantSecurity.DeviceRequests ||
		m.Security.ContainerIsolationRequired != wantSecurity.ContainerIsolationRequired {
		return invalid("Phase 5 production release security policy is invalid")
	}
	wantMounts := []Mount{{Path: "/inputs", Mode: "ro", Required: true}, {Path: "/workspace", Mode: "rw", Required: true}, {Path: "/outputs", Mode: "rw", Required: true}, {Path: "/tmp", Mode: "rw", Required: true}}
	if !equal(m.Mounts, wantMounts) {
		return invalid("Phase 5 production release mount authority is invalid")
	}
	if m.Network != (Network{Mode: "restricted", EgressGatewayRequired: true, BrokerUnixOnly: true, ListeningTCPPorts: 0}) {
		return invalid("Phase 5 production release network authority is invalid")
	}
	wantOutputs := map[string]Output{
		"linux/amd64":    {ImageDigest: "sha256:47999b3fb061fee77a1d1ab53d8bc9045d5082dc00cc6e9626ff6e0e113721d6", Evidence: "double_cross_build"},
		"linux/arm64/v8": {ImageDigest: "sha256:ec8da6b3e48d145a960d1faa3a5a7202c43221de0f3a7d73e6f62783cc92efe6", Evidence: "native_build_after_double_build_and_smoke"},
	}
	if m.Outputs.VCSReference != "slice4-output" || len(m.Outputs.Platforms) != len(wantOutputs) {
		return invalid("Phase 5 production release reproducible output authority is invalid")
	}
	for platform, want := range wantOutputs {
		got, ok := m.Outputs.Platforms[platform]
		if !ok || got != want || !digestPattern.MatchString(got.ImageDigest) {
			return invalid("Phase 5 production release reproducible output %q is invalid", platform)
		}
	}
	if m.Provenance.UpstreamSource != "https://github.com/alpinelinux/docker-alpine" ||
		m.Provenance.UpstreamIndexDigest != m.Source.IndexDigest ||
		m.Provenance.BuildContext != "profiles/desktop/image" || m.Provenance.GoVersion != "go1.26.5" ||
		!m.Provenance.ReproducibleInputs || !m.Provenance.NativeDoubleBuildRequired ||
		!m.Provenance.SignedAttestationRequiredForAdapter ||
		m.Provenance.IndependentVerificationWorkflowPath != "github.com/shell-echo/sandbox-runtime/.github/workflows/desktop-image.yml" {
		return invalid("Phase 5 production release provenance boundary is invalid")
	}
	return nil
}
