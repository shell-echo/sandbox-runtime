package docker

import (
	"context"
	"net/netip"
	"time"
)

type engine interface {
	ping(context.Context) error
	inspectImage(context.Context, string) (imageInfo, error)
	inspectNetwork(context.Context, string) (networkInfo, error)
	createNetwork(context.Context, networkRequest) error
	removeNetwork(context.Context, string) error
	inspectContainer(context.Context, string) (containerInfo, error)
	createContainer(context.Context, containerRequest) error
	connectNetwork(context.Context, string, string) error
	startContainer(context.Context, string) error
	removeContainer(context.Context, string) error
	close() error
}

type imageInfo struct {
	id                string
	repositoryDigests []string
	labels            map[string]string
	user              string
	entrypoint        []string
	command           []string
	workingDirectory  string
	exposedPorts      int
	volumes           int
	environment       []string
	healthcheck       []string
	healthInterval    time.Duration
	healthTimeout     time.Duration
	healthStart       time.Duration
	healthRetries     int
	operatingSystem   string
	architecture      string
	variant           string
}

type ipamInfo struct {
	subnet  netip.Prefix
	gateway netip.Addr
}

type endpointInfo struct {
	name    string
	address netip.Addr
}

type networkInfo struct {
	id, name, driver, scope string
	enableIPv4, enableIPv6  bool
	internal, attachable    bool
	ingress, configOnly     bool
	labels                  map[string]string
	ipam                    []ipamInfo
	containers              []endpointInfo
}

type networkRequest struct {
	name, subnet, dockerGateway string
	labels                      map[string]string
}

type containerRequest struct {
	name, image, imageID, internalNetwork, internalAddress string
	labels, environment                                    map[string]string
	memoryBytes, nanoCPUs, pidsLimit                       int64
	stopTimeout                                            int
}

type containerInfo struct {
	id, name            string
	imageID, image      string
	labels              map[string]string
	user                string
	entrypoint, command []string
	workingDirectory    string
	stopTimeout         int
	environment         []string
	exposedPorts        int
	running, paused     bool
	restarting, dead    bool
	health              string
	privileged          bool
	autoRemove          bool
	readOnlyRoot        bool
	publishAllPorts     bool
	portBindings        int
	binds, mounts       int
	tmpfs               map[string]string
	dns, extraHosts     int
	capAdd, capDrop     []string
	securityOptions     []string
	memoryBytes         int64
	nanoCPUs            int64
	pidsLimit           int64
	networkMode         string
	pidMode, ipcMode    string
	sysctls             map[string]string
	restartPolicy       string
	logType             string
	logConfig           map[string]string
	networks            map[string]netip.Addr
}
