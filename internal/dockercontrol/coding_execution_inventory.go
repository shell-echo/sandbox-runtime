package dockercontrol

import (
	"context"
	"maps"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

func readExecutionInventory(ctx context.Context, api *client.Client, b executionBinding, a executionCreate, docs phase6security.ImageDescriptorDocuments) (executionInventory, error) {
	var result executionInventory
	r := a.resources(b)
	if ctx == nil || ctx.Err() != nil || api == nil {
		return result, ErrInvalidCodingInventory
	}
	labels := map[string]map[string]string{}
	for i, name := range []string{r.Preparation, r.Resident} {
		role := []string{"preparation", "resident"}[i]
		expected, err := executionContainerLabels(b, a, role, docs)
		if err != nil {
			return result, ErrInvalidCodingInventory
		}
		labels[role] = expected
		item := executionInventoryObject{Role: role, Name: name}
		value, err := api.ContainerInspect(ctx, name, client.ContainerInspectOptions{})
		if cerrdefs.IsNotFound(err) {
			result.Containers[i] = item
			continue
		}
		v := value.Container
		if err != nil || !codingArchiveRuntimeID.MatchString(v.ID) || v.Name != "/"+name || v.Config == nil || !maps.Equal(expected, v.Config.Labels) {
			return result, ErrInvalidCodingInventory
		}
		item.ID, item.Present, item.LabelsDigest = v.ID, true, executionDigest("labels", v.Config.Labels)
		result.Containers[i] = item
	}
	for i, name := range r.Volumes {
		role := executionVolumeRoles[i]
		expected := executionLabels(b, a, role)
		options := executionVolumeOptions(b, r, i)
		value, err := api.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
		v := value.Volume
		if err != nil || v.Name != name || v.Driver != "local" || v.Scope != "local" || !maps.Equal(expected, v.Labels) || !executionOptionsMatch(options, v.Options) {
			return result, ErrInvalidCodingInventory
		}
		result.Volumes[i] = executionInventoryObject{Role: role, Name: name, ID: name, Present: true, Driver: "local", Scope: "local", LabelsDigest: executionDigest("labels", expected), OptionsDigest: executionDigest("volume-options", options)}
	}
	filters := make(client.Filters).Add("label", executionScopeLabel+"="+a.digest())
	containers, err := api.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return result, ErrInvalidCodingInventory
	}
	seen := map[string]bool{}
	for _, item := range containers.Items {
		matched := false
		for _, want := range result.Containers {
			if want.Present && item.ID == want.ID && len(item.Names) == 1 && item.Names[0] == "/"+want.Name &&
				matchCodingContainerListLabels(labels[want.Role], item.Labels) == nil && !seen[want.Name] {
				seen[want.Name], matched = true, true
				break
			}
		}
		if !matched {
			return result, ErrInvalidCodingInventory
		}
	}
	for _, want := range result.Containers {
		if seen[want.Name] != want.Present {
			return result, ErrInvalidCodingInventory
		}
	}
	volumes, err := api.VolumeList(ctx, client.VolumeListOptions{Filters: filters})
	if err != nil || len(volumes.Warnings) != 0 || len(volumes.Items) != 4 {
		return result, ErrInvalidCodingInventory
	}
	seen = map[string]bool{}
	for _, item := range volumes.Items {
		matched := false
		for i, want := range result.Volumes {
			if item.Name == want.Name && item.Driver == "local" && item.Scope == "local" && !seen[want.Name] &&
				maps.Equal(executionLabels(b, a, want.Role), item.Labels) && executionOptionsMatch(executionVolumeOptions(b, r, i), item.Options) {
				seen[want.Name], matched = true, true
				break
			}
		}
		if !matched {
			return result, ErrInvalidCodingInventory
		}
	}
	return result, nil
}
