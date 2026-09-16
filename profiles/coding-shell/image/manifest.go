// Package image validates the repository-owned coding/shell runtime image
// inputs. It is not a Provider wire package and does not advertise capability.
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
	"strings"
)

const (
	ManifestPath            = "manifest.json"
	DockerfilePath          = "Dockerfile"
	BuildScriptPath         = "build.sh"
	PublicationWorkflowPath = "../../../.github/workflows/coding-shell-image.yml"
	SchemaVersion           = "sandbox.runtime/coding-shell-image/v1"
	ProfileID               = "sandbox-runtime-coding-shell-v1"
	RuntimeClassName        = "sandbox-runtime-coding-shell"
	SourceRepository        = "docker.io/library/alpine"
	SourceTag               = "3.23"
	SourceIndexDigest       = "sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
	ShellPath               = "/bin/sh"
	TerminalBrokerPath      = "/usr/local/libexec/sandbox-runtime/terminal-broker"
	RequiredUID             = 65532
	RequiredGID             = 65532
	MaxManifestBytes        = 64 << 10
)

var (
	ErrInvalidManifest = errors.New("invalid coding/shell image manifest")
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	requiredCommand    = []string{"/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"}
)

type Manifest struct {
	SchemaVersion    string     `json:"schema_version"`
	ProfileID        string     `json:"profile_id"`
	RuntimeClassName string     `json:"runtime_class_name"`
	Source           Source     `json:"source"`
	Runtime          Runtime    `json:"runtime"`
	Security         Security   `json:"security"`
	Mounts           []Mount    `json:"mounts"`
	Network          Network    `json:"network"`
	Provenance       Provenance `json:"provenance"`
}

type Source struct {
	Repository  string              `json:"repository"`
	Tag         string              `json:"tag"`
	IndexDigest string              `json:"index_digest"`
	Manifests   map[string]Platform `json:"manifests"`
}

type Platform struct {
	Digest       string `json:"digest"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type Runtime struct {
	ShellPath          string   `json:"shell_path"`
	TerminalBrokerPath string   `json:"terminal_broker_path"`
	Command            []string `json:"command"`
}

type Security struct {
	UID                        int    `json:"uid"`
	GID                        int    `json:"gid"`
	RootFilesystem             string `json:"root_filesystem"`
	NoNewPrivileges            bool   `json:"no_new_privileges"`
	Capabilities               string `json:"capabilities"`
	ContainerIsolationRequired bool   `json:"container_isolation_required"`
}

type Mount struct {
	Path     string `json:"path"`
	Mode     string `json:"mode"`
	Required bool   `json:"required"`
}

type Network struct {
	Mode string `json:"mode"`
}

type Provenance struct {
	UpstreamSource                         string `json:"upstream_source"`
	UpstreamIndexDigest                    string `json:"upstream_index_digest"`
	BuildContext                           string `json:"build_context"`
	GoVersion                              string `json:"go_version"`
	ReproducibleInputs                     bool   `json:"reproducible_inputs"`
	AttestationRequiredBeforeQualification bool   `json:"attestation_required_before_qualification"`
}

func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Manifest{}, fmt.Errorf("read coding/shell image manifest: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (Manifest, error) {
	if len(data) == 0 || len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: document size is invalid", ErrInvalidManifest)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: decode: %v", ErrInvalidManifest, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return Manifest{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidManifest)
	} else if !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("%w: trailing input: %v", ErrInvalidManifest, err)
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
	if m.Source.Repository != SourceRepository || m.Source.Tag != SourceTag || m.Source.IndexDigest != SourceIndexDigest || !digestPattern.MatchString(m.Source.IndexDigest) {
		return invalid("source identity is invalid")
	}
	wantPlatforms := map[string]Platform{
		"linux/amd64":    {Digest: "sha256:1beb0dc0a51de7ff38e3b5274078a2e0b81113ba5c7535e1a03d5913a5edbda3", Architecture: "amd64"},
		"linux/arm64/v8": {Digest: "sha256:d858bb5442632a31bd4bca6c5e601dbe6b536fd7942092ea6a08a0a95805693c", Architecture: "arm64", Variant: "v8"},
	}
	if len(m.Source.Manifests) != len(wantPlatforms) {
		return invalid("platform matrix is invalid")
	}
	for platform, want := range wantPlatforms {
		got, ok := m.Source.Manifests[platform]
		if !ok || got != want || !digestPattern.MatchString(got.Digest) {
			return invalid("platform manifest %q is invalid", platform)
		}
	}
	if m.Runtime.ShellPath != ShellPath || m.Runtime.TerminalBrokerPath != TerminalBrokerPath || strings.Join(m.Runtime.Command, "\x00") != strings.Join(requiredCommand, "\x00") {
		return invalid("runtime command authority is invalid")
	}
	wantSecurity := Security{UID: RequiredUID, GID: RequiredGID, RootFilesystem: "read_only", NoNewPrivileges: true, Capabilities: "drop_all", ContainerIsolationRequired: true}
	if m.Security != wantSecurity {
		return invalid("security policy is invalid")
	}
	wantMounts := []Mount{
		{Path: "/inputs", Mode: "ro", Required: true},
		{Path: "/workspace", Mode: "rw", Required: true},
		{Path: "/outputs", Mode: "rw", Required: true},
		{Path: "/tmp", Mode: "rw", Required: true},
	}
	if len(m.Mounts) != len(wantMounts) {
		return invalid("stable mount set is invalid")
	}
	for index := range wantMounts {
		if m.Mounts[index] != wantMounts[index] {
			return invalid("stable mount %d is invalid", index)
		}
	}
	if m.Network != (Network{Mode: "none"}) {
		return invalid("network policy is invalid")
	}
	if m.Provenance.UpstreamSource != "https://github.com/alpinelinux/docker-alpine" ||
		m.Provenance.UpstreamIndexDigest != m.Source.IndexDigest ||
		m.Provenance.BuildContext != "profiles/coding-shell/image" ||
		m.Provenance.GoVersion != "go1.26.5" ||
		!m.Provenance.ReproducibleInputs || !m.Provenance.AttestationRequiredBeforeQualification {
		return invalid("provenance boundary is incomplete")
	}
	return nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidManifest, fmt.Sprintf(format, args...))
}
