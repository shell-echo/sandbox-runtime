// Package blocks defines the internal manifest and registry used to describe
// runnable runtime blocks. It is not a Provider wire package.
package blocks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"go.yaml.in/yaml/v3"
)

const (
	APIVersion = "sandbox.runtime/v1alpha1"
	Kind       = "Block"

	MaxManifestBytes = 256 << 10
	MaxManifestCount = 256
	MaxCommandArgs   = 128
	MaxArgumentBytes = 4096
	MaxCapabilities  = 32
	MaxDescription   = 1000
)

var (
	ErrInvalidManifest = errors.New("invalid block manifest")
	ErrInvalidRegistry = errors.New("invalid block registry")

	blockNamePattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// Manifest is the internal description of one runnable block. Its fields are
// deliberately separate from Provider API DTOs and local instance models.
type Manifest struct {
	APIVersion   string       `json:"apiVersion" yaml:"apiVersion"`
	Kind         string       `json:"kind" yaml:"kind"`
	Metadata     Metadata     `json:"metadata" yaml:"metadata"`
	Runtime      RuntimeSpec  `json:"runtime" yaml:"runtime"`
	Capabilities []Capability `json:"capabilities" yaml:"capabilities"`
}

// Metadata identifies a block independently of its image or runtime profile.
type Metadata struct {
	Name        string `json:"name" yaml:"name"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// RuntimeSpec contains only provider-neutral launch inputs. Image references
// must be content-addressed before a manifest enters a registry.
type RuntimeSpec struct {
	RuntimeProfile   string   `json:"runtime_profile" yaml:"runtime_profile"`
	Image            string   `json:"image" yaml:"image"`
	Command          []string `json:"command,omitempty" yaml:"command,omitempty"`
	WorkingDirectory string   `json:"working_directory,omitempty" yaml:"working_directory,omitempty"`
}

// Capability is an internal capability declaration. It does not advertise or
// authorize a Provider capability by itself.
type Capability struct {
	ID      string `json:"id" yaml:"id"`
	Version string `json:"version" yaml:"version"`
	Profile string `json:"profile,omitempty" yaml:"profile,omitempty"`
}

// Validate checks the closed internal manifest shape and security bounds.
func (m Manifest) Validate() error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("%w: apiVersion must be %q", ErrInvalidManifest, APIVersion)
	}
	if m.Kind != Kind {
		return fmt.Errorf("%w: kind must be %q", ErrInvalidManifest, Kind)
	}
	if !blockNamePattern.MatchString(m.Metadata.Name) {
		return fmt.Errorf("%w: metadata.name must be a lowercase block identifier", ErrInvalidManifest)
	}
	if !versionPattern.MatchString(m.Metadata.Version) {
		return fmt.Errorf("%w: metadata.version must be numeric semantic version", ErrInvalidManifest)
	}
	if !utf8.ValidString(m.Metadata.Description) || len(m.Metadata.Description) > MaxDescription {
		return fmt.Errorf("%w: metadata.description is invalid or exceeds %d bytes", ErrInvalidManifest, MaxDescription)
	}
	if !identifierPattern.MatchString(m.Runtime.RuntimeProfile) {
		return fmt.Errorf("%w: runtime.runtime_profile is invalid", ErrInvalidManifest)
	}
	if err := validatePinnedImage(m.Runtime.Image); err != nil {
		return fmt.Errorf("%w: runtime.image: %v", ErrInvalidManifest, err)
	}
	if err := validateCommand(m.Runtime.Command); err != nil {
		return fmt.Errorf("%w: runtime.command: %v", ErrInvalidManifest, err)
	}
	if err := validateWorkingDirectory(m.Runtime.WorkingDirectory); err != nil {
		return fmt.Errorf("%w: runtime.working_directory: %v", ErrInvalidManifest, err)
	}
	if len(m.Capabilities) == 0 || len(m.Capabilities) > MaxCapabilities {
		return fmt.Errorf("%w: capabilities count must be between 1 and %d", ErrInvalidManifest, MaxCapabilities)
	}
	seen := make(map[string]struct{}, len(m.Capabilities))
	for index, capability := range m.Capabilities {
		if !identifierPattern.MatchString(capability.ID) {
			return fmt.Errorf("%w: capabilities[%d].id is invalid", ErrInvalidManifest, index)
		}
		if !versionPattern.MatchString(capability.Version) {
			return fmt.Errorf("%w: capabilities[%d].version must be numeric semantic version", ErrInvalidManifest, index)
		}
		if capability.Profile != "" && !identifierPattern.MatchString(capability.Profile) {
			return fmt.Errorf("%w: capabilities[%d].profile is invalid", ErrInvalidManifest, index)
		}
		if _, exists := seen[capability.ID]; exists {
			return fmt.Errorf("%w: duplicate capability %q", ErrInvalidManifest, capability.ID)
		}
		seen[capability.ID] = struct{}{}
	}
	return nil
}

// Parse strictly decodes one YAML or JSON manifest.
func Parse(data []byte) (Manifest, error) {
	if len(data) == 0 {
		return Manifest{}, fmt.Errorf("%w: document is empty", ErrInvalidManifest)
	}
	if len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: document exceeds %d bytes", ErrInvalidManifest, MaxManifestBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("%w: decode document: %v", ErrInvalidManifest, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Manifest{}, fmt.Errorf("%w: document contains multiple YAML values", ErrInvalidManifest)
	} else if !errors.Is(err, io.EOF) {
		return Manifest{}, fmt.Errorf("%w: decode document trailer: %v", ErrInvalidManifest, err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// LoadFile reads and parses one regular manifest file. Symlinks are rejected
// so a registry cannot escape its configured directory through a file alias.
func LoadFile(ctx context.Context, path string) (Manifest, error) {
	if ctx == nil {
		return Manifest{}, errors.New("block manifest load context is required")
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open block manifest: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, fmt.Errorf("%w: manifest path is a symlink", ErrInvalidManifest)
	}
	if !info.Mode().IsRegular() {
		return Manifest{}, fmt.Errorf("%w: manifest path is not a regular file", ErrInvalidManifest)
	}
	if info.Size() > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("%w: manifest exceeds %d bytes", ErrInvalidManifest, MaxManifestBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open block manifest: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read block manifest: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	return Parse(data)
}

// Registry is a read-only, deterministic collection of validated manifests.
type Registry struct {
	manifests map[string]Manifest
	names     []string
}

// NewRegistry validates and copies manifests into a read-only registry.
func NewRegistry(manifests []Manifest) (*Registry, error) {
	if len(manifests) > MaxManifestCount {
		return nil, fmt.Errorf("%w: manifest count exceeds %d", ErrInvalidRegistry, MaxManifestCount)
	}
	registry := &Registry{manifests: make(map[string]Manifest, len(manifests))}
	for index, manifest := range manifests {
		if err := manifest.Validate(); err != nil {
			return nil, fmt.Errorf("%w: manifest %d: %v", ErrInvalidRegistry, index, err)
		}
		if _, exists := registry.manifests[manifest.Metadata.Name]; exists {
			return nil, fmt.Errorf("%w: duplicate block name %q", ErrInvalidRegistry, manifest.Metadata.Name)
		}
		registry.manifests[manifest.Metadata.Name] = cloneManifest(manifest)
		registry.names = append(registry.names, manifest.Metadata.Name)
	}
	sort.Strings(registry.names)
	return registry, nil
}

// LoadDir loads direct child manifest files from one regular directory.
func LoadDir(ctx context.Context, directory string) (*Registry, error) {
	if ctx == nil {
		return nil, errors.New("block registry load context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("open block manifest directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: manifest root must be a real directory", ErrInvalidRegistry)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read block manifest directory: %w", err)
	}
	manifests := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: manifest directory contains symlink %q", ErrInvalidRegistry, entry.Name())
		}
		if entry.IsDir() {
			return nil, fmt.Errorf("%w: manifest directory contains nested path %q", ErrInvalidRegistry, entry.Name())
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if extension != ".yaml" && extension != ".yml" && extension != ".json" {
			continue
		}
		manifest, err := LoadFile(ctx, filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("load %q: %w", entry.Name(), err)
		}
		manifests = append(manifests, manifest)
		if len(manifests) > MaxManifestCount {
			return nil, fmt.Errorf("%w: manifest count exceeds %d", ErrInvalidRegistry, MaxManifestCount)
		}
	}
	return NewRegistry(manifests)
}

// Get returns a defensive copy of the named manifest.
func (r *Registry) Get(name string) (Manifest, bool) {
	if r == nil {
		return Manifest{}, false
	}
	manifest, ok := r.manifests[name]
	if !ok {
		return Manifest{}, false
	}
	return cloneManifest(manifest), true
}

// List returns all manifests in stable name order. Returned values are copies.
func (r *Registry) List() []Manifest {
	if r == nil {
		return nil
	}
	manifests := make([]Manifest, 0, len(r.names))
	for _, name := range r.names {
		manifests = append(manifests, cloneManifest(r.manifests[name]))
	}
	return manifests
}

func validatePinnedImage(value string) error {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value || value == "" {
		return errors.New("image reference is blank or invalid UTF-8")
	}
	named, err := reference.ParseNormalizedNamed(value)
	if err != nil {
		return errors.New("image reference is invalid")
	}
	digested, ok := named.(reference.Digested)
	if !ok || digested.Digest().Algorithm() != digest.SHA256 || digested.Digest().Validate() != nil {
		return errors.New("image reference must be pinned by a valid sha256 digest")
	}
	return nil
}

func validateCommand(command []string) error {
	if len(command) > MaxCommandArgs {
		return fmt.Errorf("argument count exceeds %d", MaxCommandArgs)
	}
	for index, argument := range command {
		if argument == "" || !utf8.ValidString(argument) || strings.IndexByte(argument, 0) >= 0 {
			return fmt.Errorf("argument %d is empty, invalid UTF-8, or contains NUL", index)
		}
		if len(argument) > MaxArgumentBytes {
			return fmt.Errorf("argument %d exceeds %d bytes", index, MaxArgumentBytes)
		}
	}
	return nil
}

func validateWorkingDirectory(value string) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 || pathpkg.Clean(value) != value {
		return errors.New("working directory must be a clean absolute path")
	}
	if value != "/workspace" && !strings.HasPrefix(value, "/workspace/") && value != "/tmp" && !strings.HasPrefix(value, "/tmp/") {
		return errors.New("working directory must be under /workspace or /tmp")
	}
	return nil
}

func cloneManifest(manifest Manifest) Manifest {
	manifest.Runtime.Command = append([]string(nil), manifest.Runtime.Command...)
	manifest.Capabilities = append([]Capability(nil), manifest.Capabilities...)
	return manifest
}
