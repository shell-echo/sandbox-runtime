package docker

import (
	"context"
	"errors"
	"net/netip"
	"sort"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

type mobyEngine struct{ client *client.Client }

func newMobyEngine(host string) (*mobyEngine, error) {
	options := []client.Opt{client.FromEnv}
	if host != "" {
		options = append(options, client.WithHost(host))
	}
	apiClient, err := client.New(options...)
	if err != nil {
		return nil, err
	}
	return &mobyEngine{client: apiClient}, nil
}

func (e *mobyEngine) ping(ctx context.Context) error {
	result, err := e.client.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	if err == nil && result.OSType != "" && result.OSType != "linux" {
		return errors.New("unsupported Docker engine OS")
	}
	return err
}

func (e *mobyEngine) inspectImage(ctx context.Context, reference string) (imageInfo, error) {
	result, err := e.client.ImageInspect(ctx, reference)
	if err != nil {
		return imageInfo{}, err
	}
	if result.Config == nil {
		return imageInfo{}, errors.New("incomplete gateway image inspection")
	}
	var healthcheck []string
	if result.Config.Healthcheck != nil {
		healthcheck = append(healthcheck, result.Config.Healthcheck.Test...)
	}
	info := imageInfo{
		id: result.ID, repositoryDigests: append([]string(nil), result.RepoDigests...), labels: cloneMap(result.Config.Labels),
		user: result.Config.User, entrypoint: append([]string(nil), result.Config.Entrypoint...),
		command: append([]string(nil), result.Config.Cmd...), workingDirectory: result.Config.WorkingDir,
		exposedPorts: len(result.Config.ExposedPorts), volumes: len(result.Config.Volumes),
		environment: append([]string(nil), result.Config.Env...), healthcheck: healthcheck,
		operatingSystem: result.Os, architecture: result.Architecture, variant: result.Variant,
	}
	if result.Config.Healthcheck != nil {
		info.healthInterval = result.Config.Healthcheck.Interval
		info.healthTimeout = result.Config.Healthcheck.Timeout
		info.healthStart = result.Config.Healthcheck.StartPeriod
		info.healthRetries = result.Config.Healthcheck.Retries
	}
	return info, nil
}

func (e *mobyEngine) inspectNetwork(ctx context.Context, name string) (networkInfo, error) {
	result, err := e.client.NetworkInspect(ctx, name, client.NetworkInspectOptions{})
	if err != nil {
		return networkInfo{}, err
	}
	value := result.Network
	info := networkInfo{
		id: value.ID, name: value.Name, driver: value.Driver, scope: value.Scope,
		enableIPv4: value.EnableIPv4, enableIPv6: value.EnableIPv6, internal: value.Internal,
		attachable: value.Attachable, ingress: value.Ingress, configOnly: value.ConfigOnly,
		labels: cloneMap(value.Labels),
	}
	for _, configured := range value.IPAM.Config {
		info.ipam = append(info.ipam, ipamInfo{subnet: configured.Subnet, gateway: configured.Gateway})
	}
	for _, endpoint := range value.Containers {
		info.containers = append(info.containers, endpointInfo{name: endpoint.Name, address: endpoint.IPv4Address.Addr()})
	}
	sort.Slice(info.containers, func(i, j int) bool { return info.containers[i].name < info.containers[j].name })
	return info, nil
}

func (e *mobyEngine) createNetwork(ctx context.Context, request networkRequest) error {
	subnet, err := netip.ParsePrefix(request.subnet)
	if err != nil {
		return err
	}
	dockerGateway, err := netip.ParseAddr(request.dockerGateway)
	if err != nil {
		return err
	}
	enableIPv4, enableIPv6 := true, false
	_, err = e.client.NetworkCreate(ctx, request.name, client.NetworkCreateOptions{
		Driver: "bridge", Scope: "local", EnableIPv4: &enableIPv4, EnableIPv6: &enableIPv6,
		Internal: true, Attachable: false, Ingress: false, Labels: cloneMap(request.labels),
		Options: map[string]string{"com.docker.network.bridge.enable_icc": "true"},
		IPAM:    &network.IPAM{Driver: "default", Config: []network.IPAMConfig{{Subnet: subnet, Gateway: dockerGateway}}},
	})
	return err
}

func (e *mobyEngine) removeNetwork(ctx context.Context, name string) error {
	_, err := e.client.NetworkRemove(ctx, name, client.NetworkRemoveOptions{})
	return err
}

func (e *mobyEngine) inspectContainer(ctx context.Context, name string) (containerInfo, error) {
	result, err := e.client.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
	if err != nil {
		return containerInfo{}, err
	}
	value := result.Container
	if value.Config == nil || value.HostConfig == nil || value.State == nil || value.NetworkSettings == nil {
		return containerInfo{}, errors.New("incomplete gateway container inspection")
	}
	health := ""
	if value.State.Health != nil {
		health = string(value.State.Health.Status)
	}
	info := containerInfo{
		id: value.ID, name: value.Name, labels: cloneMap(value.Config.Labels), user: value.Config.User,
		imageID: value.Image, image: value.Config.Image,
		entrypoint: append([]string(nil), value.Config.Entrypoint...), command: append([]string(nil), value.Config.Cmd...),
		workingDirectory: value.Config.WorkingDir, environment: append([]string(nil), value.Config.Env...),
		exposedPorts: len(value.Config.ExposedPorts), running: value.State.Running, paused: value.State.Paused,
		restarting: value.State.Restarting, dead: value.State.Dead, health: health,
		privileged: value.HostConfig.Privileged, autoRemove: value.HostConfig.AutoRemove,
		readOnlyRoot: value.HostConfig.ReadonlyRootfs, publishAllPorts: value.HostConfig.PublishAllPorts,
		portBindings: len(value.HostConfig.PortBindings), binds: len(value.HostConfig.Binds), mounts: len(value.HostConfig.Mounts),
		tmpfs: cloneMap(value.HostConfig.Tmpfs), dns: len(value.HostConfig.DNS), extraHosts: len(value.HostConfig.ExtraHosts),
		capAdd: append([]string(nil), value.HostConfig.CapAdd...), capDrop: append([]string(nil), value.HostConfig.CapDrop...),
		securityOptions: append([]string(nil), value.HostConfig.SecurityOpt...), memoryBytes: value.HostConfig.Memory,
		nanoCPUs: value.HostConfig.NanoCPUs, networkMode: string(value.HostConfig.NetworkMode),
		pidMode: string(value.HostConfig.PidMode), ipcMode: string(value.HostConfig.IpcMode),
		sysctls:       cloneMap(value.HostConfig.Sysctls),
		restartPolicy: string(value.HostConfig.RestartPolicy.Name), logType: value.HostConfig.LogConfig.Type,
		logConfig: cloneMap(value.HostConfig.LogConfig.Config),
		networks:  make(map[string]netip.Addr, len(value.NetworkSettings.Networks)),
	}
	if value.Config.StopTimeout != nil {
		info.stopTimeout = *value.Config.StopTimeout
	}
	if value.HostConfig.PidsLimit != nil {
		info.pidsLimit = *value.HostConfig.PidsLimit
	}
	for name, endpoint := range value.NetworkSettings.Networks {
		if endpoint != nil {
			address := endpoint.IPAddress
			if !address.IsValid() && endpoint.IPAMConfig != nil {
				address = endpoint.IPAMConfig.IPv4Address
			}
			info.networks[name] = address
		}
	}
	return info, nil
}

func (e *mobyEngine) createContainer(ctx context.Context, request containerRequest) error {
	address, err := netip.ParseAddr(request.internalAddress)
	if err != nil {
		return err
	}
	pidsLimit := request.pidsLimit
	stopTimeout := request.stopTimeout
	environment := make([]string, 0, len(request.environment))
	for key, value := range request.environment {
		environment = append(environment, key+"="+value)
	}
	sort.Strings(environment)
	_, err = e.client.ContainerCreate(ctx, client.ContainerCreateOptions{
		Name: request.name,
		Config: &container.Config{
			Image: request.image, Labels: cloneMap(request.labels), Env: environment, StopTimeout: &stopTimeout,
		},
		HostConfig: &container.HostConfig{
			NetworkMode: container.NetworkMode(request.internalNetwork), CapDrop: []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"}, ReadonlyRootfs: true, AutoRemove: false,
			Sysctls:   map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"},
			Tmpfs:     map[string]string{"/tmp": "rw,noexec,nosuid,nodev,size=16777216,mode=1777"},
			LogConfig: container.LogConfig{Type: "local", Config: map[string]string{"max-size": "10m", "max-file": "3"}},
			Resources: container.Resources{
				Memory: request.memoryBytes, MemorySwap: request.memoryBytes,
				NanoCPUs: request.nanoCPUs, PidsLimit: &pidsLimit,
			},
		},
		NetworkingConfig: &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
			request.internalNetwork: {IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: address}},
		}},
	})
	return err
}

func (e *mobyEngine) connectNetwork(ctx context.Context, networkName, containerName string) error {
	_, err := e.client.NetworkConnect(ctx, networkName, client.NetworkConnectOptions{
		Container: containerName, EndpointConfig: &network.EndpointSettings{GwPriority: 1},
	})
	return err
}

func (e *mobyEngine) startContainer(ctx context.Context, name string) error {
	_, err := e.client.ContainerStart(ctx, name, client.ContainerStartOptions{})
	return err
}

func (e *mobyEngine) removeContainer(ctx context.Context, name string) error {
	_, err := e.client.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	return err
}

func (e *mobyEngine) close() error { return e.client.Close() }

func cloneMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
