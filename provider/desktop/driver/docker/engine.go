package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"

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
	describe(context.Context, string) ([]byte, error)
	close() error
}

type imageInfo struct {
	id                string
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
	environment       []string
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
	dnsResolver      string
}

type containerInfo struct {
	id, imageID, imageReference string
	labels                      map[string]string
	user, workingDirectory      string
	entrypoint, command         []string
	environment                 []string
	stopTimeout                 int
	exposedPorts                int
	status                      string
	running                     bool
	paused                      bool
	restarting                  bool
	dead                        bool
	privileged                  bool
	autoRemove                  bool
	readOnlyRoot                bool
	publishAllPorts             bool
	portBindings                int
	binds, mounts               int
	tmpfs                       map[string]string
	dns                         []netip.Addr
	capAdd, capDrop             []string
	securityOptions             []string
	memoryBytes, memorySwap     int64
	nanoCPUs, pidsLimit         int64
	deviceMappings              int
	deviceCgroupRules           int
	deviceRequests              int
	dnsOptions, dnsSearch       int
	extraHosts, groupAdd, links int
	sysctls                     int
	networkMode                 string
	pidMode, ipcMode            string
	cgroupnsMode                string
	usernsMode, utsMode         string
	restartPolicy               string
	logType                     string
	logConfig                   map[string]string
	networks                    map[string]netip.Addr
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
		return imageInfo{}, errors.New("incomplete Desktop image inspection")
	}
	descriptorDigest := ""
	if result.Descriptor != nil {
		descriptorDigest = result.Descriptor.Digest.String()
	}
	return imageInfo{
		id:                result.ID,
		repositoryDigests: append([]string(nil), result.RepoDigests...), descriptorDigest: descriptorDigest,
		labels: cloneStrings(result.Config.Labels), user: result.Config.User,
		entrypoint: append([]string(nil), result.Config.Entrypoint...), command: append([]string(nil), result.Config.Cmd...),
		workingDirectory: result.Config.WorkingDir, architecture: result.Architecture,
		variant: result.Variant, operatingSystem: result.Os, exposedPorts: len(result.Config.ExposedPorts),
		environment: append([]string(nil), result.Config.Env...),
	}, nil
}

func (e *mobyEngine) create(ctx context.Context, request createRequest) (string, error) {
	pidsLimit := request.pidsLimit
	dnsResolver, err := netip.ParseAddr(request.dnsResolver)
	if err != nil || !dnsResolver.Is4() || !dnsResolver.IsPrivate() {
		return "", errors.New("invalid Desktop DNS resolver")
	}
	result, err := e.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: request.name,
		Config: &container.Config{
			Image: request.image, User: request.user, WorkingDir: request.workingDirectory,
			Labels: cloneStrings(request.labels), StopTimeout: &request.stopTimeout,
		},
		HostConfig: &container.HostConfig{
			NetworkMode:  container.NetworkMode(request.networkName),
			DNS:          []netip.Addr{dnsResolver},
			CgroupnsMode: container.CgroupnsModePrivate,
			IpcMode:      container.IPCModePrivate,
			CapDrop:      []string{"ALL"}, SecurityOpt: []string{"no-new-privileges:true"},
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
	if response.State == nil || response.Config == nil || response.HostConfig == nil || response.NetworkSettings == nil {
		return containerInfo{}, errors.New("incomplete Desktop container inspection")
	}
	info := containerInfo{
		id: response.ID, imageID: response.Image, imageReference: response.Config.Image,
		labels: cloneStrings(response.Config.Labels), user: response.Config.User,
		workingDirectory: response.Config.WorkingDir, entrypoint: append([]string(nil), response.Config.Entrypoint...),
		command: append([]string(nil), response.Config.Cmd...), environment: append([]string(nil), response.Config.Env...),
		exposedPorts: len(response.Config.ExposedPorts), status: string(response.State.Status),
		running: response.State.Running, paused: response.State.Paused,
		restarting: response.State.Restarting, dead: response.State.Dead,
		privileged: response.HostConfig.Privileged, autoRemove: response.HostConfig.AutoRemove,
		readOnlyRoot: response.HostConfig.ReadonlyRootfs, publishAllPorts: response.HostConfig.PublishAllPorts,
		portBindings: len(response.HostConfig.PortBindings), binds: len(response.HostConfig.Binds), mounts: len(response.HostConfig.Mounts),
		tmpfs: cloneStrings(response.HostConfig.Tmpfs), dns: append([]netip.Addr(nil), response.HostConfig.DNS...),
		capAdd: append([]string(nil), response.HostConfig.CapAdd...), capDrop: append([]string(nil), response.HostConfig.CapDrop...),
		securityOptions: append([]string(nil), response.HostConfig.SecurityOpt...), memoryBytes: response.HostConfig.Memory,
		memorySwap: response.HostConfig.MemorySwap, nanoCPUs: response.HostConfig.NanoCPUs,
		deviceMappings: len(response.HostConfig.Devices), deviceCgroupRules: len(response.HostConfig.DeviceCgroupRules), deviceRequests: len(response.HostConfig.DeviceRequests),
		dnsOptions: len(response.HostConfig.DNSOptions), dnsSearch: len(response.HostConfig.DNSSearch), extraHosts: len(response.HostConfig.ExtraHosts),
		groupAdd: len(response.HostConfig.GroupAdd), links: len(response.HostConfig.Links), sysctls: len(response.HostConfig.Sysctls),
		networkMode: string(response.HostConfig.NetworkMode), pidMode: string(response.HostConfig.PidMode), ipcMode: string(response.HostConfig.IpcMode),
		cgroupnsMode: string(response.HostConfig.CgroupnsMode), usernsMode: string(response.HostConfig.UsernsMode), utsMode: string(response.HostConfig.UTSMode),
		restartPolicy: string(response.HostConfig.RestartPolicy.Name), logType: response.HostConfig.LogConfig.Type,
		logConfig: cloneStrings(response.HostConfig.LogConfig.Config), networks: make(map[string]netip.Addr, len(response.NetworkSettings.Networks)),
	}
	if response.Config.StopTimeout != nil {
		info.stopTimeout = *response.Config.StopTimeout
	}
	if response.HostConfig.PidsLimit != nil {
		info.pidsLimit = *response.HostConfig.PidsLimit
	}
	for name, endpoint := range response.NetworkSettings.Networks {
		if endpoint != nil {
			info.networks[name] = endpoint.IPAddress
		}
	}
	return info, nil
}

func (e *mobyEngine) start(ctx context.Context, id string) error {
	_, err := e.client.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}

func (e *mobyEngine) remove(ctx context.Context, id string) error {
	_, err := e.client.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	return err
}

func (e *mobyEngine) describe(ctx context.Context, containerID string) ([]byte, error) {
	created, err := e.client.ExecCreate(ctx, containerID, client.ExecCreateOptions{
		User: DesktopUser, Privileged: false, TTY: false,
		AttachStdin: false, AttachStdout: true, AttachStderr: true,
		WorkingDir: "/workspace",
		Cmd:        []string{desktopBrokerPath, "describe", "--socket", desktopBrokerSocket},
	})
	if err != nil {
		return nil, err
	}
	response, err := e.client.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return nil, err
	}
	defer response.Close()
	stdout := &limitedBuffer{limit: maxBrokerExecBytes}
	stderr := &limitedBuffer{limit: maxBrokerExecBytes}
	if _, err := stdcopy.StdCopy(stdout, stderr, response.Reader); err != nil {
		return nil, err
	}
	result, err := e.client.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil || result.Running || result.ExitCode != 0 || stderr.Len() != 0 || stdout.Len() == 0 {
		return nil, errors.New("desktop broker describe failed")
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func (e *mobyEngine) close() error { return e.client.Close() }

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 || len(value) > remaining {
		return 0, errors.New("desktop broker output exceeds its limit")
	}
	return b.Buffer.Write(value)
}

func cloneStrings(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

var _ engine = (*mobyEngine)(nil)
