package qualificationoperator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	CodingShellImage = "ghcr.io/shell-echo/sandbox-runtime-coding-shell@sha256:1996e44f8ddc464f22556bd57f1c69079fe6b1a821b65bd9be24f86619c31bb1"
	ProviderRevision = "qualification-provider-2026-09"
)

var ErrProviderProcess = errors.New("qualification Provider process failed")

type ProviderConfiguration struct {
	Executable, ConfigurationFile, StateRoot, RuntimeStateRoot string
	ProviderPort, APIPort                                      int
	Namespace, ControllerID                                    string
	Credentials                                                *Credentials
}

type ProviderProcess struct {
	configuration ProviderConfiguration
	command       *exec.Cmd
	stderr        bytes.Buffer
}

func PrepareProviderConfiguration(configuration ProviderConfiguration) error {
	if configuration.Executable == "" || configuration.ConfigurationFile == "" || configuration.StateRoot == "" || configuration.RuntimeStateRoot == "" ||
		configuration.ProviderPort < 1 || configuration.APIPort < 1 || configuration.ProviderPort == configuration.APIPort ||
		configuration.Namespace == "" || configuration.ControllerID == "" || configuration.Credentials == nil {
		return ErrProviderProcess
	}
	if err := os.MkdirAll(configuration.StateRoot, 0o700); err != nil {
		return ErrProviderProcess
	}
	path := func(name string) string { return filepath.Join(configuration.StateRoot, name) }
	keys := configuration.Credentials.ProviderAdmissionPublicKeyFiles
	document := fmt.Sprintf(`[application]
name = 'sandbox-runtime-qualification'
mode = 'development'

[logger]
level = 'error'
add_source = false

[server.api]
host = '127.0.0.1'
port = %d

[server.provider.transport]
enabled = true
server_certificate_file = %s
server_private_key_file = %s
client_ca_bundle_file = %s
allowed_client_uri_identities = [%s, %s]

[server.provider.transport.address]
host = '127.0.0.1'
port = %d

[server.provider.capability]
provider_revision_id = %s
coding_shell_enabled = true

[server.provider.capability.limits]
max_cpu_millis = 1000
max_memory_bytes = 268435456
max_ephemeral_storage_bytes = 268435456
max_workspace_bytes = 268435456
max_gpu_count = 0
max_lease_seconds = 1800
max_exec_seconds = 300

[[server.provider.capability.snapshot_restore_profiles]]
profile_id = 'sandbox-snapshot-workspace-v1'
level = 'workspace'
suite_id = 'sandbox-provider'
suite_version = '1.0.0'
suite_digest = 'sha256:7db1d28d35ca193632c395247cc71eeaaff48b027964b9ea9da247eaad5e3991'

[server.provider.protected_admission]
enabled = true
issuer = %s
provider_instance_audience = %s
guard_state_file = %s

[[server.provider.protected_admission.trusted_verification_keys]]
id = 'qualification-controller_a'
algorithm = 'EdDSA'
public_key_file = %s

[[server.provider.protected_admission.trusted_verification_keys]]
id = 'qualification-controller_b'
algorithm = 'EdDSA'
public_key_file = %s

[server.provider.lifecycle]
enabled = true
driver = 'docker'

[server.provider.lifecycle.repository]
driver = 'file'

[server.provider.lifecycle.repository.file]
path = %s

[server.provider.lifecycle.docker]
host = ''
image = %s
pull_policy = 'if_not_present'
memory_bytes = 268435456
nano_cpus = 500000000
pids_limit = 64
tmpfs_bytes = 268435456
operation_timeout_seconds = 30
pull_timeout_seconds = 300
stop_timeout_seconds = 10
user = '65532:65532'
command = ['/bin/sh', '-c', "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]
data_root = %s
namespace = %s
controller_id = %s

[server.provider.exec]
enabled = true
repository_file = %s

[server.provider.terminal]
enabled = true
connect_enabled = true
session_repository_file = %s
reference_registry_file = %s
runtime_profile_id = 'sandbox-runtime-coding-shell-v1'
capability_profile_id = 'terminal-v1'
broker_path = '/usr/local/libexec/sandbox-runtime/terminal-broker'
shell_path = '/bin/sh'
max_sessions_per_sandbox = 4
max_sessions_per_controller = 64
shutdown_cleanup_seconds = 10

[server.provider.artifact]
enabled = true
repository_file = %s
staging_root = %s
active_content_command = ['/bin/true']
malware_command = ['/bin/true']

[server.provider.usage]
enabled = true
repository_file = %s

[runtime]
driver = 'fake'

[repository]
driver = 'memory'
`, configuration.APIPort,
		tomlString(configuration.Credentials.ProviderServerCertificateFile), tomlString(configuration.Credentials.ProviderServerPrivateKeyFile), tomlString(configuration.Credentials.ProviderCAFile),
		tomlString(configuration.Credentials.ProviderSubjects["controller_a"]), tomlString(configuration.Credentials.ProviderSubjects["controller_b"]), configuration.ProviderPort,
		tomlString(ProviderRevision), tomlString(ProviderIssuer), tomlString(ProviderAudience), tomlString(path("admission-guard.json")),
		tomlString(keys["controller_a"]), tomlString(keys["controller_b"]), tomlString(path("lifecycle.json")), tomlString(CodingShellImage),
		tomlString(configuration.RuntimeStateRoot), tomlString(configuration.Namespace), tomlString(configuration.ControllerID), tomlString(path("exec.json")),
		tomlString(path("terminal-sessions.json")), tomlString(path("terminal-references.json")), tomlString(path("artifacts.json")), tomlString(path("artifact-staging")), tomlString(path("usage.json")))
	if err := os.WriteFile(configuration.ConfigurationFile, []byte(document), 0o600); err != nil {
		return ErrProviderProcess
	}
	return nil
}

func StartProvider(ctx context.Context, configuration ProviderConfiguration) (*ProviderProcess, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrProviderProcess
	}
	command := exec.Command(configuration.Executable, "--config", configuration.ConfigurationFile, "serve")
	command.Env = []string{}
	command.Dir = configuration.StateRoot
	configureProcessGroup(command)
	process := &ProviderProcess{configuration: configuration, command: command}
	command.Stdout = nil
	command.Stderr = &process.stderr
	if err := command.Start(); err != nil {
		return nil, ErrProviderProcess
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(configuration.ProviderPort)), 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return process, nil
		}
		if exited, _ := processExited(command.Process); exited {
			_ = command.Wait()
			return nil, ErrProviderProcess
		}
		select {
		case <-ctx.Done():
			_ = process.Stop()
			return nil, errors.Join(ErrProviderProcess, context.Cause(ctx))
		case <-time.After(25 * time.Millisecond):
		}
	}
	_ = process.Stop()
	return nil, ErrProviderProcess
}

func (p *ProviderProcess) Stop() error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	_ = p.command.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- p.command.Wait() }()
	select {
	case err := <-done:
		if err != nil && !isSignalExit(err) {
			return ErrProviderProcess
		}
		return nil
	case <-time.After(15 * time.Second):
		_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
		<-done
		return ErrProviderProcess
	}
}

func tomlString(value string) string { return strconv.Quote(value) }

func configureProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func processExited(process *os.Process) (bool, error) {
	if process == nil {
		return true, nil
	}
	err := process.Signal(syscall.Signal(0))
	return err != nil, err
}

func isSignalExit(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && !exit.ProcessState.Success()
}
