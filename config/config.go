// Package config loads application configuration and commits it into typed,
// package-level config values.
//
// Configuration comes from three sources, in increasing precedence: the
// built-in defaults, an optional TOML file, and environment variables. The file
// is optional — if no path is given and the default file is absent, the
// defaults (plus any environment overrides) are used. Environment variables use
// the SANDBOX_RUNTIME_ prefix with "_" replacing ".", e.g.
// SANDBOX_RUNTIME_LOGGER_LEVEL sets logger.level and
// SANDBOX_RUNTIME_LOGGER_FILE_MAX_SIZE sets logger.file.max_size.
//
// Each config section registers a loader via register (from its init). Load
// reads the sources once, runs every loader to parse and validate its section,
// and only then applies the results, so a validation failure in any section
// aborts the whole load.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// envPrefix is prepended to every environment variable, e.g. SANDBOX_RUNTIME_LOGGER_LEVEL.
const envPrefix = "SANDBOX_RUNTIME"

// commit applies a validated config section to its package global. It runs only
// after every loader has validated and may return an error. Commits run in
// registration order, so a failing commit leaves earlier ones already applied.
type commit func() error

// loader parses and validates one config section, returning its commit.
type loader func(v *viper.Viper) (commit, error)

// Default locations for the config file and its template.
const (
	DefaultPath         = "config.toml"
	DefaultTemplatePath = "config.tpl.toml"
)

// loaders holds every registered section loader, populated by package inits.
var loaders []loader

// register adds a section loader; it is called from each section's init.
func register(l loader) {
	loaders = append(loaders, l)
}

// newViper returns a viper whose environment mapping uses the SANDBOX_RUNTIME_
// prefix with "." replaced by "_". Environment values reach the config through
// the explicit per-key BindEnv calls in bindEnvDefaults (AutomaticEnv is not used
// because Unmarshal does not consult it).
func newViper() *viper.Viper {
	v := viper.New()
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	return v
}

// Load reads configuration and commits it into the package globals. The file at
// path is optional: when path is empty it falls back to DefaultPath, and a
// missing default file is not an error (defaults plus environment overrides are
// used). An explicitly requested file that is missing, or any malformed file,
// is fatal. Environment variables always override file and default values.
func Load(path string) error {
	v := newViper()

	explicit := path != ""
	if !explicit {
		path = DefaultPath
	}
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		// A missing default file is fine; an explicitly requested file that is
		// missing, or any parse error, is fatal.
		if explicit || !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("read config: %w", err)
		}
	}

	// Parse and validate every section first; only if all succeed do we apply
	// the commits.
	commits := make([]commit, 0, len(loaders))
	for _, l := range loaders {
		commit, err := l(v)
		if err != nil {
			return err
		}
		if commit != nil {
			commits = append(commits, commit)
		}
	}
	for _, commit := range commits {
		if err := commit(); err != nil {
			return err
		}
	}

	return nil
}

// bindEnvDefaults registers, for every leaf key under section (derived from the
// default struct), both the default value and an environment-variable binding
// on v. This is required because viper's Unmarshal does not read environment
// variables on its own: SetDefault makes the key known so it has a value
// without a file, and BindEnv ties it to the SANDBOX_RUNTIME_-prefixed variable so it
// can override the default and file values.
func bindEnvDefaults(v *viper.Viper, section string, defaults any) error {
	var nested map[string]any
	if err := mapstructure.Decode(defaults, &nested); err != nil {
		return err
	}

	flat := make(map[string]any)
	flattenKeys(section, nested, flat)

	for key, val := range flat {
		v.SetDefault(key, val)
		if err := v.BindEnv(key); err != nil {
			return err
		}
	}
	return nil
}

// flattenKeys flattens a nested map into dotted keys, e.g.
// {"file":{"max_size":100}} under prefix "logger" becomes
// {"logger.file.max_size":100}.
func flattenKeys(prefix string, m map[string]any, out map[string]any) {
	for k, val := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := val.(map[string]any); ok {
			flattenKeys(key, sub, out)
		} else {
			out[key] = val
		}
	}
}
