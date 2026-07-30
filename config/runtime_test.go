package config

import "testing"

func TestRuntimeConfigValidate(t *testing.T) {
	valid := *defaultRuntimeConfig()
	valid.Driver = RuntimeDockerDriver
	valid.Docker.ControllerID = "controller-test"
	tests := []struct {
		name   string
		mutate func(*RuntimeConfig)
	}{
		{"driver", func(c *RuntimeConfig) { c.Driver = "unknown" }},
		{"image", func(c *RuntimeConfig) { c.Docker.Image = "" }},
		{"pull policy", func(c *RuntimeConfig) { c.Docker.PullPolicy = "sometimes" }},
		{"memory", func(c *RuntimeConfig) { c.Docker.MemoryBytes = 0 }},
		{"cpus", func(c *RuntimeConfig) { c.Docker.NanoCPUs = 0 }},
		{"pids", func(c *RuntimeConfig) { c.Docker.PidsLimit = 0 }},
		{"operation timeout", func(c *RuntimeConfig) { c.Docker.OperationTimeoutSeconds = 0 }},
		{"pull timeout", func(c *RuntimeConfig) { c.Docker.PullTimeoutSeconds = 0 }},
		{"stop timeout", func(c *RuntimeConfig) { c.Docker.StopTimeoutSeconds = -1 }},
		{"user", func(c *RuntimeConfig) { c.Docker.User = "" }},
		{"command", func(c *RuntimeConfig) { c.Docker.Command = nil }},
		{"namespace", func(c *RuntimeConfig) { c.Docker.Namespace = "" }},
		{"controller ID", func(c *RuntimeConfig) { c.Docker.ControllerID = "" }},
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("default config: %v", err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			if err := cfg.validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRuntimeConfigLoadEnvironment(t *testing.T) {
	snapshotGlobals(t)
	chdirTemp(t)
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DRIVER", "docker")
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DOCKER_HOST", "tcp://docker.example:2376")
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DOCKER_IMAGE", "example/shell:v1")
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DOCKER_PULL_POLICY", "never")
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DOCKER_MEMORY_BYTES", "268435456")
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DOCKER_OPERATION_TIMEOUT_SECONDS", "12")
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DOCKER_PULL_TIMEOUT_SECONDS", "34")
	t.Setenv("SANDBOX_RUNTIME_RUNTIME_DOCKER_CONTROLLER_ID", "controller-env")

	if err := Load(""); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if Runtime.Driver != RuntimeDockerDriver || Runtime.Docker.Host != "tcp://docker.example:2376" {
		t.Fatalf("Runtime = %+v", Runtime)
	}
	if Runtime.Docker.Image != "example/shell:v1" || Runtime.Docker.PullPolicy != DockerPullNever {
		t.Fatalf("Runtime.Docker = %+v", Runtime.Docker)
	}
	if Runtime.Docker.MemoryBytes != 268435456 {
		t.Fatalf("MemoryBytes = %d", Runtime.Docker.MemoryBytes)
	}
	if Runtime.Docker.OperationTimeoutSeconds != 12 || Runtime.Docker.PullTimeoutSeconds != 34 {
		t.Fatalf("Docker timeouts = %d/%d", Runtime.Docker.OperationTimeoutSeconds, Runtime.Docker.PullTimeoutSeconds)
	}
	if Runtime.Docker.ControllerID != "controller-env" {
		t.Fatalf("ControllerID = %q", Runtime.Docker.ControllerID)
	}
}
