package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

type engine interface {
	ping(context.Context) error
	ensureImage(context.Context, string, PullPolicy) error
	create(context.Context, createRequest) (string, error)
	inspect(context.Context, string) (containerInfo, error)
	start(context.Context, string) error
	remove(context.Context, string) error
	close() error
}

type bindMount struct {
	source   string
	target   string
	readonly bool
}

type createRequest struct {
	name             string
	image            string
	command          []string
	workingDirectory string
	labels           map[string]string
	memoryBytes      int64
	nanoCPUs         int64
	pidsLimit        int64
	stopTimeout      int
	init             *bool
	user             string
	readonly         bool
	tmpfs            map[string]string
	mounts           []bindMount
}

type containerInfo struct {
	id         string
	labels     map[string]string
	status     string
	running    bool
	paused     bool
	restarting bool
	dead       bool
}

type execEngine interface {
	execCreate(context.Context, string, execCreateRequest) (string, error)
	execStart(context.Context, string, bool) error
	execAttach(context.Context, string) (io.ReadCloser, error)
	execInspect(context.Context, string) (execInfo, error)
}

type terminalEngine interface {
	execCreate(context.Context, string, execCreateRequest) (string, error)
	execStart(context.Context, string, bool) error
	execInspect(context.Context, string) (execInfo, error)
	execAttachTerminal(context.Context, string) (terminalConnection, error)
}

type terminalConnection interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type execCreateRequest struct {
	user             string
	workingDirectory string
	command          []string
	environment      []string
	attachStdin      bool
	attachStdout     bool
	attachStderr     bool
	tty              bool
}

type execInfo struct {
	id          string
	containerID string
	running     bool
	exitCode    int
}

type mobyEngine struct {
	client    *client.Client
	pullToken chan struct{}
}

func newMobyEngine(host string) (*mobyEngine, error) {
	options := []client.Opt{client.FromEnv}
	if host != "" {
		options = append(options, client.WithHost(host))
	}
	apiClient, err := client.New(options...)
	if err != nil {
		return nil, err
	}
	pullToken := make(chan struct{}, 1)
	pullToken <- struct{}{}
	return &mobyEngine{client: apiClient, pullToken: pullToken}, nil
}

func (e *mobyEngine) ping(ctx context.Context) error {
	result, err := e.client.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	if err != nil {
		return err
	}
	if result.OSType != "" && result.OSType != "linux" {
		return fmt.Errorf("unsupported Docker engine OS")
	}
	return nil
}

func (e *mobyEngine) ensureImage(ctx context.Context, image string, policy PullPolicy) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-e.pullToken:
	}
	defer func() { e.pullToken <- struct{}{} }()
	if policy == PullNever {
		return nil
	}
	if policy == PullIfNotPresent {
		if _, err := e.client.ImageInspect(ctx, image); err == nil {
			return nil
		} else if !cerrdefs.IsNotFound(err) {
			return err
		}
	}
	response, err := e.client.ImagePull(ctx, image, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer response.Close()
	return response.Wait(ctx)
}

func (e *mobyEngine) create(ctx context.Context, request createRequest) (string, error) {
	pidsLimit := request.pidsLimit
	mounts := make([]mount.Mount, len(request.mounts))
	for index, item := range request.mounts {
		mounts[index] = mount.Mount{Type: mount.TypeBind, Source: item.source, Target: item.target, ReadOnly: item.readonly}
	}
	result, err := e.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: request.name,
		Config: &container.Config{
			Image: request.image, Cmd: request.command, WorkingDir: request.workingDirectory,
			Labels: request.labels, StopTimeout: &request.stopTimeout, User: request.user,
		},
		HostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode("none"), CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}, Init: request.init,
			AutoRemove: false, ReadonlyRootfs: request.readonly, Tmpfs: request.tmpfs, Mounts: mounts,
			LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "10m", "max-file": "3"}},
			Resources: container.Resources{
				Memory: request.memoryBytes, MemorySwap: request.memoryBytes,
				NanoCPUs: request.nanoCPUs, PidsLimit: &pidsLimit,
			},
		},
	})
	if err != nil {
		return "", err
	}
	return result.ID, nil
}

func (e *mobyEngine) inspect(ctx context.Context, id string) (containerInfo, error) {
	result, err := e.client.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return containerInfo{}, err
	}
	response := result.Container
	if response.State == nil || response.Config == nil {
		return containerInfo{}, errorsIncompleteInspect
	}
	return containerInfo{
		id: response.ID, labels: response.Config.Labels, status: string(response.State.Status),
		running: response.State.Running, paused: response.State.Paused,
		restarting: response.State.Restarting, dead: response.State.Dead,
	}, nil
}

func (e *mobyEngine) start(ctx context.Context, id string) error {
	_, err := e.client.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}

func (e *mobyEngine) remove(ctx context.Context, id string) error {
	_, err := e.client.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	return err
}

func (e *mobyEngine) execCreate(ctx context.Context, containerID string, request execCreateRequest) (string, error) {
	result, err := e.client.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		User: request.user, Privileged: false, TTY: request.tty,
		AttachStdin: request.attachStdin, AttachStdout: request.attachStdout, AttachStderr: request.attachStderr,
		Env:        append([]string(nil), request.environment...),
		WorkingDir: request.workingDirectory, Cmd: append([]string(nil), request.command...),
	})
	if err != nil {
		return "", err
	}
	return result.ID, nil
}

func (e *mobyEngine) execStart(ctx context.Context, execID string, detach bool) error {
	_, err := e.client.ExecStart(ctx, execID, client.ExecStartOptions{Detach: detach})
	return err
}

func (e *mobyEngine) execAttach(ctx context.Context, execID string) (io.ReadCloser, error) {
	response, err := e.client.ExecAttach(ctx, execID, client.ExecAttachOptions{})
	if err != nil {
		return nil, err
	}
	return &hijackedExecStream{reader: response.Reader, close: response.Close}, nil
}

func (e *mobyEngine) execAttachTerminal(ctx context.Context, execID string) (terminalConnection, error) {
	response, err := e.client.ExecAttach(ctx, execID, client.ExecAttachOptions{})
	if err != nil {
		return nil, err
	}
	return &hijackedTerminalStream{reader: response.Reader, connection: response.Conn, close: response.Close}, nil
}

func (e *mobyEngine) execInspect(ctx context.Context, execID string) (execInfo, error) {
	result, err := e.client.ExecInspect(ctx, execID, client.ExecInspectOptions{})
	if err != nil {
		return execInfo{}, err
	}
	return execInfo{id: result.ID, containerID: result.ContainerID, running: result.Running, exitCode: result.ExitCode}, nil
}

type hijackedExecStream struct {
	reader io.Reader
	close  func()
}

func (s *hijackedExecStream) Read(value []byte) (int, error) { return s.reader.Read(value) }
func (s *hijackedExecStream) Close() error {
	s.close()
	return nil
}

type hijackedTerminalStream struct {
	reader     io.Reader
	connection net.Conn
	close      func()
	closeOnce  sync.Once
}

func (s *hijackedTerminalStream) Read(value []byte) (int, error) {
	return s.reader.Read(value)
}

func (s *hijackedTerminalStream) Write(value []byte) (int, error) {
	return s.connection.Write(value)
}

func (s *hijackedTerminalStream) SetReadDeadline(deadline time.Time) error {
	return s.connection.SetReadDeadline(deadline)
}

func (s *hijackedTerminalStream) SetWriteDeadline(deadline time.Time) error {
	return s.connection.SetWriteDeadline(deadline)
}

func (s *hijackedTerminalStream) Close() error {
	s.closeOnce.Do(s.close)
	return nil
}

func (e *mobyEngine) close() error { return e.client.Close() }

var (
	errorsIncompleteInspect        = errors.New("incomplete Docker inspection")
	_                       engine = (*mobyEngine)(nil)
)
