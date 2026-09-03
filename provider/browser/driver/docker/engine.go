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
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type engine interface {
	ping(context.Context) error
	ensureImage(context.Context, string, PullPolicy) error
	inspectImage(context.Context, string) (imageInfo, error)
	create(context.Context, createRequest) (string, error)
	inspect(context.Context, string) (containerInfo, error)
	start(context.Context, string) error
	remove(context.Context, string) error
	attachRelay(context.Context, string) (relayConnection, error)
	close() error
}

type imageInfo struct {
	repositoryDigests []string
	descriptorDigest  string
	labels            map[string]string
	user              string
	entrypoint        []string
	command           []string
	workingDirectory  string
	architecture      string
	variant           string
	operatingSystem   string
	exposedPorts      int
}

type createRequest struct {
	name             string
	image            string
	labels           map[string]string
	user             string
	workingDirectory string
	memoryBytes      int64
	nanoCPUs         int64
	pidsLimit        int64
	inputsBytes      int64
	tmpfsBytes       int64
	workspaceBytes   int64
	outputsBytes     int64
	stopTimeout      int
	networkName      string
	seccompProfile   string
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

type relayConnection interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
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
		return errors.New("unsupported Docker engine OS")
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

func (e *mobyEngine) inspectImage(ctx context.Context, image string) (imageInfo, error) {
	result, err := e.client.ImageInspect(ctx, image)
	if err != nil {
		return imageInfo{}, err
	}
	if result.Config == nil {
		return imageInfo{}, errors.New("incomplete Browser image inspection")
	}
	descriptorDigest := ""
	if result.Descriptor != nil {
		descriptorDigest = result.Descriptor.Digest.String()
	}
	return imageInfo{
		repositoryDigests: append([]string(nil), result.RepoDigests...), descriptorDigest: descriptorDigest,
		labels: cloneStrings(result.Config.Labels), user: result.Config.User,
		entrypoint: append([]string(nil), result.Config.Entrypoint...), command: append([]string(nil), result.Config.Cmd...),
		workingDirectory: result.Config.WorkingDir, architecture: result.Architecture,
		variant: result.Variant, operatingSystem: result.Os, exposedPorts: len(result.Config.ExposedPorts),
	}, nil
}

func (e *mobyEngine) create(ctx context.Context, request createRequest) (string, error) {
	pidsLimit := request.pidsLimit
	result, err := e.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: request.name,
		Config: &container.Config{
			Image: request.image, User: request.user, WorkingDir: request.workingDirectory,
			Labels: cloneStrings(request.labels), StopTimeout: &request.stopTimeout,
		},
		HostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(request.networkName),
			CapDrop:     []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true", "seccomp=" + request.seccompProfile},
			AutoRemove: false, ReadonlyRootfs: true,
			Tmpfs: map[string]string{
				"/inputs":    fmt.Sprintf("ro,noexec,nosuid,nodev,size=%d,mode=0555", request.inputsBytes),
				"/tmp":       fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=1777", request.tmpfsBytes),
				"/workspace": fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700", request.workspaceBytes),
				"/outputs":   fmt.Sprintf("rw,noexec,nosuid,nodev,size=%d,mode=0700", request.outputsBytes),
			},
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
		return containerInfo{}, errors.New("incomplete Browser container inspection")
	}
	return containerInfo{
		id: response.ID, labels: cloneStrings(response.Config.Labels), status: string(response.State.Status),
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

func (e *mobyEngine) attachRelay(ctx context.Context, containerID string) (relayConnection, error) {
	created, err := e.client.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		User: BrowserUser, Privileged: false, TTY: false,
		AttachStdin: true, AttachStdout: true, AttachStderr: true,
		WorkingDir: "/workspace",
		Cmd:        []string{BrowserRelayPath, "STDIO", "TCP4:127.0.0.1:9222,connect-timeout=5"},
	})
	if err != nil {
		return nil, err
	}
	response, err := e.client.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()
	stream := &hijackedRelayStream{reader: reader, writer: writer, connection: response.Conn, closeResponse: response.Close}
	go stream.demultiplex(response.Reader)
	return stream, nil
}

func (e *mobyEngine) close() error { return e.client.Close() }

type hijackedRelayStream struct {
	reader        *io.PipeReader
	writer        *io.PipeWriter
	connection    net.Conn
	closeResponse func()
	closeOnce     sync.Once
}

func (s *hijackedRelayStream) demultiplex(source io.Reader) {
	_, err := stdcopy.StdCopy(s.writer, io.Discard, source)
	_ = s.writer.CloseWithError(err)
	s.closeTransport()
}

func (s *hijackedRelayStream) Read(value []byte) (int, error)  { return s.reader.Read(value) }
func (s *hijackedRelayStream) Write(value []byte) (int, error) { return s.connection.Write(value) }
func (s *hijackedRelayStream) SetReadDeadline(deadline time.Time) error {
	return s.connection.SetReadDeadline(deadline)
}
func (s *hijackedRelayStream) SetWriteDeadline(deadline time.Time) error {
	return s.connection.SetWriteDeadline(deadline)
}
func (s *hijackedRelayStream) Close() error {
	s.closeTransport()
	return s.reader.Close()
}
func (s *hijackedRelayStream) closeTransport() {
	s.closeOnce.Do(s.closeResponse)
}

func cloneStrings(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

var _ engine = (*mobyEngine)(nil)
