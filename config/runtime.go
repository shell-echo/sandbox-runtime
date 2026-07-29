package config

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

const (
	defaultRuntimeDriver                       = RuntimeFakeDriver
	defaultRuntimeDockerImage                  = "alpine:3.23"
	defaultRuntimeDockerPullPolicy             = DockerPullIfNotPresent
	defaultRuntimeDockerMemoryBytes      int64 = 512 << 20
	defaultRuntimeDockerNanoCPUs         int64 = 1_000_000_000
	defaultRuntimeDockerPidsLimit        int64 = 256
	defaultRuntimeDockerOperationTimeout       = 30
	defaultRuntimeDockerPullTimeout            = 300
	defaultRuntimeDockerStopTimeout            = 10
	defaultRuntimeDockerUser                   = "65532:65532"
	defaultRuntimeDockerNamespace              = "default"
)

var defaultRuntimeDockerCommand = []string{"/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"}

// RuntimeDriver identifies the configured runtime backend.
type RuntimeDriver string

const (
	RuntimeFakeDriver   RuntimeDriver = "fake"
	RuntimeDockerDriver RuntimeDriver = "docker"
)

// DockerPullPolicy controls when the Docker driver pulls its configured image.
type DockerPullPolicy string

const (
	DockerPullNever        DockerPullPolicy = "never"
	DockerPullIfNotPresent DockerPullPolicy = "if_not_present"
	DockerPullAlways       DockerPullPolicy = "always"
)

// RuntimeDockerConfig contains process-wide defaults for Docker-backed shell
// instances. Per-instance policy belongs in the instance model once the API
// exposes resource customization.
type RuntimeDockerConfig struct {
	Host                    string           `mapstructure:"host"`
	Image                   string           `mapstructure:"image"`
	PullPolicy              DockerPullPolicy `mapstructure:"pull_policy"`
	MemoryBytes             int64            `mapstructure:"memory_bytes"`
	NanoCPUs                int64            `mapstructure:"nano_cpus"`
	PidsLimit               int64            `mapstructure:"pids_limit"`
	OperationTimeoutSeconds int              `mapstructure:"operation_timeout_seconds"`
	PullTimeoutSeconds      int              `mapstructure:"pull_timeout_seconds"`
	StopTimeoutSeconds      int              `mapstructure:"stop_timeout_seconds"`
	User                    string           `mapstructure:"user"`
	Command                 []string         `mapstructure:"command"`
	Namespace               string           `mapstructure:"namespace"`
	ControllerID            string           `mapstructure:"controller_id"`
}

// RuntimeConfig selects the runtime backend and configures its implementation.
type RuntimeConfig struct {
	Driver RuntimeDriver       `mapstructure:"driver"`
	Docker RuntimeDockerConfig `mapstructure:"docker"`
}

func (c *RuntimeConfig) validate() error {
	switch c.Driver {
	case RuntimeFakeDriver, RuntimeDockerDriver:
	default:
		return fmt.Errorf("runtime.driver %q invalid (%s|%s)", c.Driver, RuntimeFakeDriver, RuntimeDockerDriver)
	}
	if c.Driver != RuntimeDockerDriver {
		return nil
	}
	if c.Docker.Image == "" {
		return errors.New("runtime.docker.image is required")
	}
	switch c.Docker.PullPolicy {
	case DockerPullNever, DockerPullIfNotPresent, DockerPullAlways:
	default:
		return fmt.Errorf("runtime.docker.pull_policy %q invalid", c.Docker.PullPolicy)
	}
	if c.Docker.MemoryBytes <= 0 {
		return errors.New("runtime.docker.memory_bytes must be greater than zero")
	}
	if c.Docker.NanoCPUs <= 0 {
		return errors.New("runtime.docker.nano_cpus must be greater than zero")
	}
	if c.Docker.PidsLimit <= 0 {
		return errors.New("runtime.docker.pids_limit must be greater than zero")
	}
	if c.Docker.OperationTimeoutSeconds <= 0 {
		return errors.New("runtime.docker.operation_timeout_seconds must be greater than zero")
	}
	if c.Docker.PullTimeoutSeconds <= 0 {
		return errors.New("runtime.docker.pull_timeout_seconds must be greater than zero")
	}
	if c.Docker.StopTimeoutSeconds < 0 {
		return errors.New("runtime.docker.stop_timeout_seconds must not be negative")
	}
	if c.Docker.User == "" {
		return errors.New("runtime.docker.user is required")
	}
	if len(c.Docker.Command) == 0 {
		return errors.New("runtime.docker.command is required")
	}
	if c.Docker.Namespace == "" {
		return errors.New("runtime.docker.namespace is required")
	}
	if c.Docker.ControllerID == "" {
		return errors.New("runtime.docker.controller_id is required")
	}
	return nil
}

func (c *RuntimeConfig) load(v *viper.Viper) error {
	if err := bindEnvDefaults(v, "runtime", defaultRuntimeConfig()); err != nil {
		return fmt.Errorf("bind config %q: %w", "runtime", err)
	}

	var wrap struct {
		Runtime RuntimeConfig `mapstructure:"runtime"`
	}
	if err := v.Unmarshal(&wrap); err != nil {
		return fmt.Errorf("parse config %q: %w", "runtime", err)
	}
	*c = wrap.Runtime
	return c.validate()
}

func defaultRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		Driver: defaultRuntimeDriver,
		Docker: RuntimeDockerConfig{
			Image:                   defaultRuntimeDockerImage,
			PullPolicy:              defaultRuntimeDockerPullPolicy,
			MemoryBytes:             defaultRuntimeDockerMemoryBytes,
			NanoCPUs:                defaultRuntimeDockerNanoCPUs,
			PidsLimit:               defaultRuntimeDockerPidsLimit,
			OperationTimeoutSeconds: defaultRuntimeDockerOperationTimeout,
			PullTimeoutSeconds:      defaultRuntimeDockerPullTimeout,
			StopTimeoutSeconds:      defaultRuntimeDockerStopTimeout,
			User:                    defaultRuntimeDockerUser,
			Command:                 append([]string(nil), defaultRuntimeDockerCommand...),
			Namespace:               defaultRuntimeDockerNamespace,
		},
	}
}

// Runtime is the committed runtime configuration, initialized to defaults and
// replaced only after Load validates every registered section.
var Runtime = defaultRuntimeConfig()

func init() {
	register(func(v *viper.Viper) (commit, error) {
		c := &RuntimeConfig{}
		if err := c.load(v); err != nil {
			return nil, err
		}
		return func() error { Runtime = c; return nil }, nil
	})
}
