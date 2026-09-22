// Package image validates the repository-owned Desktop runtime image inputs.
// It is not a Provider wire package and does not advertise Desktop capability.
package image

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const (
	LocalCandidateManifestPath = "phase6-local-candidate-manifest.json"
	DockerfilePath             = "Dockerfile"
	BuildScriptPath            = "build.sh"
	EntrypointPath             = "entrypoint.sh"
	PublicationWorkflowPath    = "../../../.github/workflows/desktop-image.yml"
	SchemaVersion              = "sandbox.runtime/desktop-image/v1"
	ProfileID                  = "sandbox-runtime-desktop-v1"
	RuntimeClassName           = "sandbox-runtime-desktop"
	SourceRepository           = "docker.io/library/alpine"
	SourceRelease              = "3.23"
	SourceIndexDigest          = "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
	BrokerPath                 = "/usr/local/libexec/sandbox-runtime/desktop-broker"
	Entrypoint                 = "/usr/local/bin/desktop-runtime"
	BrokerSocket               = "/tmp/sandbox-runtime-desktop-broker.sock"
	BrokerProtocol             = "sandbox.runtime/desktop-broker/v1"
	SessionBrokerProtocol      = "sandbox.runtime/desktop-session/v1"
	DisplayReference           = "ref:desktop-display:primary"
	RequiredUID                = 1000
	RequiredGID                = 1000
	MaxManifestBytes           = 64 << 10
)

var (
	ErrInvalidManifest = errors.New("invalid Desktop image manifest")
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type Manifest struct {
	SchemaVersion    string     `json:"schema_version"`
	ProfileID        string     `json:"profile_id"`
	RuntimeClassName string     `json:"runtime_class_name"`
	Source           Source     `json:"source"`
	Packages         Packages   `json:"packages"`
	Broker           Broker     `json:"broker"`
	Display          Display    `json:"display"`
	Security         Security   `json:"security"`
	Mounts           []Mount    `json:"mounts"`
	Network          Network    `json:"network"`
	Outputs          Outputs    `json:"reproducible_outputs"`
	Provenance       Provenance `json:"provenance"`
}

type Source struct {
	Repository  string              `json:"repository"`
	Release     string              `json:"release"`
	IndexDigest string              `json:"index_digest"`
	Manifests   map[string]Platform `json:"manifests"`
}

type Platform struct {
	Digest                  string `json:"digest"`
	Architecture            string `json:"architecture"`
	Variant                 string `json:"variant,omitempty"`
	PackageArchiveSetDigest string `json:"package_archive_set_digest"`
	InstalledSetDigest      string `json:"installed_set_digest"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Packages struct {
	Repositories []string  `json:"repositories"`
	Required     []Package `json:"required"`
}

type Broker struct {
	Path               string   `json:"path"`
	Socket             string   `json:"socket"`
	Protocol           string   `json:"protocol"`
	Methods            []string `json:"methods"`
	SessionProtocol    string   `json:"session_protocol"`
	SessionMethods     []string `json:"session_methods"`
	MaxRequest         int      `json:"max_request_bytes"`
	MaxResponse        int      `json:"max_response_bytes"`
	MaxConnections     int      `json:"max_connections"`
	SessionMaxDocument int      `json:"session_max_document_bytes"`
	SessionMaxFrame    int      `json:"session_max_frame_bytes"`
	SessionMaxQueue    int      `json:"session_max_queue"`
}

type Display struct {
	Server              string `json:"server"`
	WindowManager       string `json:"window_manager"`
	Display             string `json:"display"`
	Reference           string `json:"reference"`
	Width               int    `json:"width"`
	Height              int    `json:"height"`
	Depth               int    `json:"depth"`
	TCPListen           bool   `json:"tcp_listen"`
	AudioOutput         bool   `json:"audio_output"`
	UserLaunchOverrides string `json:"user_launch_overrides"`
}

type Security struct {
	UID                        int      `json:"uid"`
	GID                        int      `json:"gid"`
	RootFilesystem             string   `json:"root_filesystem"`
	NoNewPrivileges            bool     `json:"no_new_privileges"`
	Capabilities               string   `json:"capabilities"`
	Privileged                 bool     `json:"privileged"`
	Seccomp                    string   `json:"seccomp"`
	IPC                        string   `json:"ipc"`
	Devices                    []string `json:"devices"`
	DeviceRequests             string   `json:"device_requests"`
	ContainerIsolationRequired bool     `json:"container_isolation_required"`
}

type Mount struct {
	Path     string `json:"path"`
	Mode     string `json:"mode"`
	Required bool   `json:"required"`
}

type Network struct {
	Mode                  string `json:"mode"`
	EgressGatewayRequired bool   `json:"egress_gateway_required"`
	BrokerUnixOnly        bool   `json:"broker_unix_only"`
	ListeningTCPPorts     int    `json:"listening_tcp_ports"`
}

type Output struct {
	ImageDigest string `json:"image_digest"`
	Evidence    string `json:"evidence"`
}

type Outputs struct {
	VCSReference string            `json:"vcs_reference"`
	Platforms    map[string]Output `json:"platforms"`
}

type Provenance struct {
	UpstreamSource                      string `json:"upstream_source"`
	UpstreamIndexDigest                 string `json:"upstream_index_digest"`
	BuildContext                        string `json:"build_context"`
	GoVersion                           string `json:"go_version"`
	ReproducibleInputs                  bool   `json:"reproducible_inputs"`
	NativeDoubleBuildRequired           bool   `json:"native_double_build_required"`
	SignedAttestationRequiredForAdapter bool   `json:"signed_attestation_required_for_adapter"`
	IndependentVerificationWorkflowPath string `json:"independent_verification_workflow_path"`
}

func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Manifest{}, fmt.Errorf("read Desktop image manifest: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (Manifest, error) {
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return Manifest{}, invalid("document size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, invalid("decode: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return Manifest{}, invalid("trailing JSON value")
	} else if !errors.Is(err, io.EOF) {
		return Manifest{}, invalid("trailing input: %v", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion || m.ProfileID != ProfileID || m.RuntimeClassName != RuntimeClassName {
		return invalid("schema/profile/runtime class identity is invalid")
	}
	if m.Source.Repository != SourceRepository || m.Source.Release != SourceRelease ||
		m.Source.IndexDigest != SourceIndexDigest || !digestPattern.MatchString(m.Source.IndexDigest) {
		return invalid("source identity is invalid")
	}
	wantPlatforms := map[string]Platform{
		"linux/amd64": {
			Digest:                  "sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3",
			Architecture:            "amd64",
			PackageArchiveSetDigest: "sha256:872446c241d2c85db9995b1e12ca4246954f76883108f1e16415d8a0e711c4a6",
			InstalledSetDigest:      "sha256:ea4e22c1f7011c6cfc975d64c5f2d110b3432bc5ae78064b94f7afa752e0a588",
		},
		"linux/arm64/v8": {
			Digest:       "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c",
			Architecture: "arm64", Variant: "v8",
			PackageArchiveSetDigest: "sha256:f6a17c5b4031b4068ae345333cdfc3d09a3ef30dfe77a461f13306d3cf5ac656",
			InstalledSetDigest:      "sha256:25e5d714836bacf2e421a1d586d7c8d64a65887036989cc08810697a6dd8ec31",
		},
	}
	if len(m.Source.Manifests) != len(wantPlatforms) {
		return invalid("platform matrix is invalid")
	}
	for platform, want := range wantPlatforms {
		got, ok := m.Source.Manifests[platform]
		if !ok || got != want || !digestPattern.MatchString(got.Digest) || !digestPattern.MatchString(got.PackageArchiveSetDigest) {
			return invalid("platform manifest %q is invalid", platform)
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
		{Name: "ffmpeg", Version: "8.0.1-r1"},
	}
	if !equal(m.Packages.Repositories, wantRepositories) || !equal(m.Packages.Required, wantPackages) {
		return invalid("package authority is invalid")
	}
	wantBroker := Broker{Path: BrokerPath, Socket: BrokerSocket, Protocol: BrokerProtocol, Methods: []string{"probe", "describe"}, SessionProtocol: SessionBrokerProtocol, SessionMethods: []string{"open", "video.rtp", "input", "stream.configure", "stream.resync", "keyframe", "close"}, MaxRequest: 4096, MaxResponse: 8192, MaxConnections: 16, SessionMaxDocument: 64 << 10, SessionMaxFrame: 16 << 10, SessionMaxQueue: 32}
	if m.Broker.Path != wantBroker.Path || m.Broker.Socket != wantBroker.Socket || m.Broker.Protocol != wantBroker.Protocol ||
		!equal(m.Broker.Methods, wantBroker.Methods) || m.Broker.MaxRequest != wantBroker.MaxRequest ||
		m.Broker.MaxResponse != wantBroker.MaxResponse || m.Broker.MaxConnections != wantBroker.MaxConnections || m.Broker.SessionProtocol != wantBroker.SessionProtocol ||
		!equal(m.Broker.SessionMethods, wantBroker.SessionMethods) || m.Broker.SessionMaxDocument != wantBroker.SessionMaxDocument || m.Broker.SessionMaxFrame != wantBroker.SessionMaxFrame || m.Broker.SessionMaxQueue != wantBroker.SessionMaxQueue {
		return invalid("broker protocol authority is invalid")
	}
	wantDisplay := Display{Server: "/usr/bin/Xvfb", WindowManager: "/usr/bin/openbox", Display: ":99", Reference: DisplayReference, Width: 1280, Height: 720, Depth: 24, TCPListen: false, AudioOutput: false, UserLaunchOverrides: "rejected"}
	if m.Display != wantDisplay {
		return invalid("display authority is invalid")
	}
	wantSecurity := Security{UID: RequiredUID, GID: RequiredGID, RootFilesystem: "read_only", NoNewPrivileges: true, Capabilities: "drop_all", Privileged: false, Seccomp: "runtime_default", IPC: "private", Devices: []string{}, DeviceRequests: "none", ContainerIsolationRequired: true}
	if m.Security.UID != wantSecurity.UID || m.Security.GID != wantSecurity.GID || m.Security.RootFilesystem != wantSecurity.RootFilesystem ||
		m.Security.NoNewPrivileges != wantSecurity.NoNewPrivileges || m.Security.Capabilities != wantSecurity.Capabilities ||
		m.Security.Privileged != wantSecurity.Privileged || m.Security.Seccomp != wantSecurity.Seccomp || m.Security.IPC != wantSecurity.IPC ||
		len(m.Security.Devices) != 0 || m.Security.DeviceRequests != wantSecurity.DeviceRequests ||
		m.Security.ContainerIsolationRequired != wantSecurity.ContainerIsolationRequired {
		return invalid("security policy is invalid")
	}
	wantMounts := []Mount{{Path: "/inputs", Mode: "ro", Required: true}, {Path: "/workspace", Mode: "rw", Required: true}, {Path: "/outputs", Mode: "rw", Required: true}, {Path: "/tmp", Mode: "rw", Required: true}}
	if !equal(m.Mounts, wantMounts) {
		return invalid("mount authority is invalid")
	}
	if m.Network != (Network{Mode: "restricted", EgressGatewayRequired: true, BrokerUnixOnly: true, ListeningTCPPorts: 0}) {
		return invalid("network authority is invalid")
	}
	wantOutputs := map[string]Output{
		"linux/amd64":    {ImageDigest: "sha256:47999b3fb061fee77a1d1ab53d8bc9045d5082dc00cc6e9626ff6e0e113721d6", Evidence: "double_cross_build"},
		"linux/arm64/v8": {ImageDigest: "sha256:ec8da6b3e48d145a960d1faa3a5a7202c43221de0f3a7d73e6f62783cc92efe6", Evidence: "native_build_after_double_build_and_smoke"},
	}
	if m.Outputs.VCSReference != "slice4-output" || len(m.Outputs.Platforms) != len(wantOutputs) {
		return invalid("reproducible output authority is invalid")
	}
	for platform, want := range wantOutputs {
		got, ok := m.Outputs.Platforms[platform]
		if !ok || got != want || !digestPattern.MatchString(got.ImageDigest) {
			return invalid("reproducible output %q is invalid", platform)
		}
	}
	if m.Provenance.UpstreamSource != "https://github.com/alpinelinux/docker-alpine" ||
		m.Provenance.UpstreamIndexDigest != m.Source.IndexDigest ||
		m.Provenance.BuildContext != "profiles/desktop/image" || m.Provenance.GoVersion != "go1.26.5" ||
		!m.Provenance.ReproducibleInputs || !m.Provenance.NativeDoubleBuildRequired ||
		!m.Provenance.SignedAttestationRequiredForAdapter ||
		m.Provenance.IndependentVerificationWorkflowPath != "github.com/shell-echo/sandbox-runtime/.github/workflows/desktop-image.yml" {
		return invalid("provenance boundary is invalid")
	}
	return nil
}

func equal[T comparable](actual, expected []T) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidManifest, fmt.Sprintf(format, args...))
}
