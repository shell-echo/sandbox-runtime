package docker

import (
	"context"
	"fmt"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type engine interface {
	ping(context.Context) error
	ensureImage(context.Context, string, PullPolicy) error
	create(context.Context, createRequest) (string, error)
	inspect(context.Context, string) (containerInfo, error)
	listManaged(context.Context, string, string) ([]managedContainer, error)
	start(context.Context, string) error
	stop(context.Context, string, int) error
	remove(context.Context, string) error
	close() error
}

type createRequest struct {
	name        string
	image       string
	command     []string
	labels      map[string]string
	memoryBytes int64
	nanoCPUs    int64
	pidsLimit   int64
	stopTimeout int
	init        *bool
	user        string
	readonly    bool
	tmpfs       map[string]string
}

type containerInfo struct {
	id         string
	labels     map[string]string
	status     string
	running    bool
	paused     bool
	restarting bool
	dead       bool
	exitCode   int
	oomKilled  bool
	error      string
}

type managedContainer struct {
	labels    map[string]string
	createdAt time.Time
}

type mobyEngine struct {
	client    *client.Client
	pullToken chan struct{}
}

func newMobyEngine(host string) (*mobyEngine, error) {
	options := []client.Opt{client.FromEnv}
	if host != "" {
		// Keep Docker TLS environment settings while allowing the project
		// configuration to override only the endpoint.
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
		return fmt.Errorf("unsupported Docker engine OS %q", result.OSType)
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
	result, err := e.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: request.name,
		Config: &container.Config{
			Image:       request.image,
			Cmd:         request.command,
			Labels:      request.labels,
			StopTimeout: &request.stopTimeout,
			User:        request.user,
		},
		HostConfig: &container.HostConfig{
			NetworkMode:    container.NetworkMode("none"),
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			Init:           request.init,
			AutoRemove:     false,
			ReadonlyRootfs: request.readonly,
			Tmpfs:          request.tmpfs,
			LogConfig: container.LogConfig{
				Type:   "local",
				Config: map[string]string{"max-size": "10m", "max-file": "3"},
			},
			Resources: container.Resources{
				Memory:     request.memoryBytes,
				MemorySwap: request.memoryBytes,
				NanoCPUs:   request.nanoCPUs,
				PidsLimit:  &pidsLimit,
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
		return containerInfo{}, fmt.Errorf("docker inspect returned incomplete container data")
	}
	return containerInfo{
		id:         response.ID,
		labels:     response.Config.Labels,
		status:     string(response.State.Status),
		running:    response.State.Running,
		paused:     response.State.Paused,
		restarting: response.State.Restarting,
		dead:       response.State.Dead,
		exitCode:   response.State.ExitCode,
		oomKilled:  response.State.OOMKilled,
		error:      response.State.Error,
	}, nil
}

func (e *mobyEngine) listManaged(ctx context.Context, namespace, controllerID string) ([]managedContainer, error) {
	filters := make(client.Filters).
		Add("label", managedLabel+"=true").
		Add("label", namespaceLabel+"="+namespace).
		Add("label", controllerLabel+"="+controllerID)
	result, err := e.client.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return nil, err
	}
	containers := make([]managedContainer, 0, len(result.Items))
	for _, item := range result.Items {
		containers = append(containers, managedContainer{
			labels: item.Labels, createdAt: time.Unix(item.Created, 0).UTC(),
		})
	}
	return containers, nil
}

func (e *mobyEngine) start(ctx context.Context, id string) error {
	_, err := e.client.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}

func (e *mobyEngine) stop(ctx context.Context, id string, timeout int) error {
	_, err := e.client.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &timeout})
	return err
}

func (e *mobyEngine) remove(ctx context.Context, id string) error {
	_, err := e.client.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	return err
}

func (e *mobyEngine) close() error {
	return e.client.Close()
}

var _ engine = (*mobyEngine)(nil)
