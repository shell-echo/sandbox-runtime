package qualificationoperator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationharness"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationprofile"
)

const (
	managedLabel    = "io.github.shell-echo.sandbox-runtime.managed"
	namespaceLabel  = "io.github.shell-echo.sandbox-runtime.namespace"
	controllerLabel = "io.github.shell-echo.sandbox-runtime.controller-id"
	sandboxLabel    = "io.github.shell-echo.sandbox-runtime.provider-sandbox-id"
	generationLabel = "io.github.shell-echo.sandbox-runtime.generation"
	specDigestLabel = "io.github.shell-echo.sandbox-runtime.provider-spec-digest"
)

var ErrDockerObservation = errors.New("qualification Docker observation failed")

type dockerContainer struct {
	ID      string            `json:"Id"`
	ImageID string            `json:"ImageID"`
	Labels  map[string]string `json:"Labels"`
}

type dockerContainerInspection struct {
	ID         string `json:"Id"`
	Image      string `json:"Image"`
	HostConfig *struct {
		Memory         int64             `json:"Memory"`
		MemorySwap     int64             `json:"MemorySwap"`
		NanoCPUs       int64             `json:"NanoCpus"`
		PidsLimit      *int64            `json:"PidsLimit"`
		ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
		NetworkMode    string            `json:"NetworkMode"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		Tmpfs          map[string]string `json:"Tmpfs"`
	} `json:"HostConfig"`
}

// DockerResources is an out-of-band, run-label-scoped inspector and teardown
// operator. Backend IDs are used only inside the deletion boundary and never
// appear in its harness projections.
type DockerResources struct {
	client                      *http.Client
	namespace, controller       string
	teardownArtifactDigest      string
	teardownConfigurationDigest string
	stopProvider                func() error
	expected                    qualificationprofile.RuntimeLimits
}

func NewDockerResources(socketPath, namespace, controller, teardownArtifactDigest, teardownConfigurationDigest string, expected qualificationprofile.RuntimeLimits, stopProvider func() error) (*DockerResources, error) {
	if socketPath == "" || namespace == "" || controller == "" || teardownArtifactDigest == "" || teardownConfigurationDigest == "" || stopProvider == nil {
		return nil, ErrDockerObservation
	}
	if expected.SandboxCPUMillis < 1 || expected.SandboxMemoryBytes < 1 || expected.SandboxEphemeralStorageBytes < 1 || expected.SandboxPIDs < 1 {
		return nil, ErrDockerObservation
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &DockerResources{
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second}, namespace: namespace, controller: controller,
		teardownArtifactDigest: teardownArtifactDigest, teardownConfigurationDigest: teardownConfigurationDigest, expected: expected, stopProvider: stopProvider,
	}, nil
}

func (d *DockerResources) Inspect(ctx context.Context, scope qualificationharness.QueryScope) (qualificationharness.Inspection, error) {
	containers, err := d.list(ctx)
	if err != nil {
		return qualificationharness.Inspection{}, ErrDockerObservation
	}
	entries := make([]qualificationharness.ResourceEntry, 0, len(containers))
	for _, container := range containers {
		inspection, err := d.inspect(ctx, container.ID)
		if err != nil || !validDockerRuntime(inspection, d.expected) {
			return qualificationharness.Inspection{}, ErrDockerObservation
		}
		tmpfsBytes, _ := dockerTmpfsBytes(inspection.HostConfig.Tmpfs["/tmp"])
		identity := map[string]any{
			"format_version": 1, "resource_kind": "runtime_allocations", "image_identity": container.ImageID,
			"generation": container.Labels[generationLabel], "provider_spec_digest": container.Labels[specDigestLabel],
			"cpu_millis": inspection.HostConfig.NanoCPUs / 1_000_000, "memory_bytes": inspection.HostConfig.Memory,
			"ephemeral_storage_bytes": tmpfsBytes, "pids": *inspection.HostConfig.PidsLimit,
			"readonly_rootfs": inspection.HostConfig.ReadonlyRootfs, "network_mode": inspection.HostConfig.NetworkMode,
		}
		digest, err := canonicalSHA256(identity)
		if err != nil {
			return qualificationharness.Inspection{}, ErrDockerObservation
		}
		stable := sha256.Sum256([]byte(strings.Join([]string{container.Labels[sandboxLabel], container.Labels[generationLabel], container.Labels[specDigestLabel]}, "\x00")))
		entries = append(entries, qualificationharness.ResourceEntry{
			ResourceKind: "runtime_allocations", StableObserverID: "runtime-" + hex.EncodeToString(stable[:12]), IdentityDigest: digest,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ResourceKind == entries[j].ResourceKind {
			return entries[i].StableObserverID < entries[j].StableObserverID
		}
		return entries[i].ResourceKind < entries[j].ResourceKind
	})
	return qualificationharness.Inspection{QueryScopeDigest: scope.Digest, Complete: true, Entries: entries}, nil
}

func (d *DockerResources) inspect(ctx context.Context, id string) (dockerContainerInspection, error) {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/?&#") {
		return dockerContainerInspection{}, ErrDockerObservation
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+id+"/json", nil)
	if err != nil {
		return dockerContainerInspection{}, err
	}
	response, err := d.client.Do(request)
	if err != nil {
		return dockerContainerInspection{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return dockerContainerInspection{}, ErrDockerObservation
	}
	var result dockerContainerInspection
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	if err := decoder.Decode(&result); err != nil || result.ID != id || result.HostConfig == nil {
		return dockerContainerInspection{}, ErrDockerObservation
	}
	return result, nil
}

func validDockerRuntime(actual dockerContainerInspection, expected qualificationprofile.RuntimeLimits) bool {
	if actual.HostConfig == nil || actual.HostConfig.PidsLimit == nil || actual.HostConfig.NanoCPUs != int64(expected.SandboxCPUMillis)*1_000_000 ||
		actual.HostConfig.Memory != int64(expected.SandboxMemoryBytes) || actual.HostConfig.MemorySwap != int64(expected.SandboxMemoryBytes) ||
		*actual.HostConfig.PidsLimit != int64(expected.SandboxPIDs) || !actual.HostConfig.ReadonlyRootfs || actual.HostConfig.NetworkMode != "none" ||
		!containsString(actual.HostConfig.CapDrop, "ALL") || !containsString(actual.HostConfig.SecurityOpt, "no-new-privileges:true") {
		return false
	}
	tmpfsBytes, ok := dockerTmpfsBytes(actual.HostConfig.Tmpfs["/tmp"])
	return ok && tmpfsBytes == int64(expected.SandboxEphemeralStorageBytes)
}

func dockerTmpfsBytes(options string) (int64, bool) {
	for _, option := range strings.Split(options, ",") {
		value, found := strings.CutPrefix(option, "size=")
		if !found {
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		return parsed, err == nil && parsed > 0
	}
	return 0, false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (d *DockerResources) Teardown(ctx context.Context, directive qualificationharness.TeardownDirective) (qualificationharness.TeardownReceipt, error) {
	receipt := qualificationharness.TeardownReceipt{
		RuntimeCommitmentDigest: directive.RuntimeCommitmentDigest, Authority: directive.Authority,
		QueryScopeDigest: directive.QueryScopeDigest, TeardownArtifactDigest: d.teardownArtifactDigest,
		TeardownConfigurationDigest: d.teardownConfigurationDigest,
	}
	receipt.Attempts++
	if err := d.stopProvider(); err != nil {
		return receipt, ErrDockerObservation
	}
	for attempt := 0; attempt < 3; attempt++ {
		containers, err := d.list(ctx)
		if err != nil {
			return receipt, ErrDockerObservation
		}
		if len(containers) == 0 {
			receipt.Completed = true
			return receipt, nil
		}
		for _, container := range containers {
			if err := d.remove(ctx, container.ID); err != nil {
				return receipt, ErrDockerObservation
			}
		}
		if attempt < 2 {
			receipt.Attempts++
		}
	}
	containers, err := d.list(ctx)
	if err != nil {
		return receipt, ErrDockerObservation
	}
	receipt.Completed = len(containers) == 0
	return receipt, nil
}

// EmergencyCleanup is the same closed selector used by Teardown, without
// minting a harness receipt. It is only a failure-path reclamation aid.
func (d *DockerResources) EmergencyCleanup(ctx context.Context) error {
	if d == nil {
		return nil
	}
	_ = d.stopProvider()
	containers, err := d.list(ctx)
	if err != nil {
		return ErrDockerObservation
	}
	var result error
	for _, container := range containers {
		result = errors.Join(result, d.remove(ctx, container.ID))
	}
	return result
}

func (d *DockerResources) list(ctx context.Context) ([]dockerContainer, error) {
	filters, err := json.Marshal(map[string][]string{"label": []string{
		managedLabel + "=true", namespaceLabel + "=" + d.namespace, controllerLabel + "=" + d.controller,
	}})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?all=1&filters="+url.QueryEscape(string(filters)), nil)
	if err != nil {
		return nil, err
	}
	response, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil, ErrDockerObservation
	}
	var result []dockerContainer
	decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
	if err := decoder.Decode(&result); err != nil || len(result) > 8 {
		return nil, ErrDockerObservation
	}
	for _, container := range result {
		if container.ID == "" || len(container.ID) > 128 || container.Labels[managedLabel] != "true" ||
			container.Labels[namespaceLabel] != d.namespace || container.Labels[controllerLabel] != d.controller {
			return nil, ErrDockerObservation
		}
	}
	return result, nil
}

func (d *DockerResources) remove(ctx context.Context, id string) error {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/?&#") {
		return ErrDockerObservation
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://docker/containers/"+id+"?force=1&v=1", nil)
	if err != nil {
		return err
	}
	response, err := d.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return ErrDockerObservation
	}
	return nil
}

func canonicalSHA256(value any) (string, error) {
	document, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
