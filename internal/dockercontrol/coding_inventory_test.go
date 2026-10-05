package dockercontrol

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
)

type fakeCodingInventoryReader struct {
	scriptedCodingInfo
	containers       map[string]client.ContainerInspectResult
	volumes          map[string]client.VolumeInspectResult
	listedContainers client.ContainerListResult
	listedVolumes    client.VolumeListResult
	inspectError     error
	inspectCalls     int
}

func (f *fakeCodingInventoryReader) ContainerInspect(_ context.Context, name string,
	_ client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	f.inspectCalls++
	if f.inspectError != nil {
		return client.ContainerInspectResult{}, f.inspectError
	}
	value, ok := f.containers[name]
	if !ok {
		return client.ContainerInspectResult{}, cerrdefs.ErrNotFound
	}
	return value, nil
}

func (f *fakeCodingInventoryReader) VolumeInspect(_ context.Context, name string,
	_ client.VolumeInspectOptions) (client.VolumeInspectResult, error) {
	f.inspectCalls++
	value, ok := f.volumes[name]
	if !ok {
		return client.VolumeInspectResult{}, cerrdefs.ErrNotFound
	}
	return value, nil
}

func (f *fakeCodingInventoryReader) ContainerList(_ context.Context,
	_ client.ContainerListOptions) (client.ContainerListResult, error) {
	return f.listedContainers, nil
}

func (f *fakeCodingInventoryReader) VolumeList(_ context.Context,
	_ client.VolumeListOptions) (client.VolumeListResult, error) {
	return f.listedVolumes, nil
}

func testCodingInventoryFixture(t *testing.T) (CodingResourceSet,
	map[CodingResourceRole]map[string]string, *fakeCodingInventoryReader) {
	t.Helper()
	a, plan, _ := testReceiptAuthority(t)
	set, err := NewCodingResourceSet(testReceiptBinding(a, plan), a)
	if err != nil {
		t.Fatal(err)
	}
	reader := &fakeCodingInventoryReader{containers: map[string]client.ContainerInspectResult{},
		volumes: map[string]client.VolumeInspectResult{}}
	expected := map[CodingResourceRole]map[string]string{}
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		bindingLabels, _ := set.Labels(role)
		labels, err := mergeCodingContainerLabels(map[string]string{
			"org.opencontainers.image.title":               "pinned-image-title",
			"io.github.shell-echo.sandbox-runtime.profile": "sandbox-runtime-coding-shell-v1"}, bindingLabels)
		if err != nil {
			t.Fatal(err)
		}
		expected[role] = labels
	}
	return set, expected, reader
}

func populateCodingInventory(t *testing.T, set CodingResourceSet,
	expected map[CodingResourceRole]map[string]string, reader *fakeCodingInventoryReader) {
	t.Helper()
	for _, role := range []CodingResourceRole{CodingPreparationRole, CodingRuntimeRole} {
		name, _ := set.ContainerName(role)
		id := "container-id-" + string(role)
		reader.containers[name] = client.ContainerInspectResult{Container: container.InspectResponse{
			ID: id, Name: "/" + name, Config: &container.Config{Labels: expected[role]}}}
		reader.listedContainers.Items = append(reader.listedContainers.Items,
			container.Summary{ID: id, Names: []string{"/" + name}, Labels: expected[role]})
	}
	for _, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := set.VolumeName(role)
		labels, _ := set.Labels(role)
		item := volume.Volume{Name: name, Driver: "local", Scope: "local", Labels: labels}
		reader.volumes[name] = client.VolumeInspectResult{Volume: item}
		reader.listedVolumes.Items = append(reader.listedVolumes.Items, item)
	}
}

func TestCodingReadOnlyInventoryExactFiveObjectSet(t *testing.T) {
	set, expected, reader := testCodingInventoryFixture(t)
	var empty CodingResourceInventory
	if err := readCodingInventoryObjects(context.Background(), reader, set, expected, &empty); err != nil {
		t.Fatalf("empty exact namespace: %v", err)
	}
	for _, item := range empty.Containers {
		if item.Present || item.Name == "" || item.ID != "" {
			t.Fatalf("false present container: %#v", item)
		}
	}
	for _, item := range empty.Volumes {
		if item.Present || item.Name == "" || item.ID != "" {
			t.Fatalf("false present volume: %#v", item)
		}
	}
	populateCodingInventory(t, set, expected, reader)
	var present CodingResourceInventory
	if err := readCodingInventoryObjects(context.Background(), reader, set, expected, &present); err != nil {
		t.Fatalf("five exact owned resources rejected: %v", err)
	}
	for _, item := range present.Containers {
		if !item.Present || item.ID == "" {
			t.Fatalf("present container not recorded: %#v", item)
		}
	}
	for _, item := range present.Volumes {
		if !item.Present || item.ID != item.Name {
			t.Fatalf("present volume not recorded: %#v", item)
		}
	}
}

func TestCodingContainerListOnlyDesktopMetadataIsNotOwnershipAuthority(t *testing.T) {
	const listOnlyKey = "desktop.docker.io/ports.scheme"
	set, expected, reader := testCodingInventoryFixture(t)
	populateCodingInventory(t, set, expected, reader)
	for index := range reader.listedContainers.Items {
		reader.listedContainers.Items[index].Labels = maps.Clone(reader.listedContainers.Items[index].Labels)
		reader.listedContainers.Items[index].Labels[listOnlyKey] = "v2"
	}
	var inventory CodingResourceInventory
	if err := readCodingInventoryObjects(t.Context(), reader, set, expected, &inventory); err != nil {
		t.Fatalf("actual Docker Desktop list-only projection rejected: %v", err)
	}
	for _, item := range inventory.Containers {
		if item.LabelsDigest != codingInventoryLabelsDigest(expected[item.Role]) {
			t.Fatal("list-only value entered the private ownership projection")
		}
	}
	for _, mutation := range []struct {
		name string
		edit func(CodingResourceSet, *fakeCodingInventoryReader)
	}{
		{"same key in inspect", func(s CodingResourceSet, r *fakeCodingInventoryReader) {
			name, _ := s.ContainerName(CodingRuntimeRole)
			item := r.containers[name]
			config := *item.Container.Config
			config.Labels = maps.Clone(config.Labels)
			config.Labels[listOnlyKey] = "v2"
			item.Container.Config = &config
			r.containers[name] = item
		}},
		{"other extra list key", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			r.listedContainers.Items[1].Labels["foreign.tenant"] = "x"
		}},
		{"oversized informational value", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			r.listedContainers.Items[1].Labels[listOnlyKey] = strings.Repeat("x", 4097)
		}},
		{"missing expected list key", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			delete(r.listedContainers.Items[1].Labels, codingEffectLabel)
		}},
		{"conflicting expected list value", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			r.listedContainers.Items[1].Labels[codingEffectLabel] = "foreign"
		}},
		{"wrong list id", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			r.listedContainers.Items[1].ID = "foreign"
		}},
		{"wrong list name", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			r.listedContainers.Items[1].Names = []string{"/foreign"}
		}},
		{"duplicate effect object", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			r.listedContainers.Items = append(r.listedContainers.Items, r.listedContainers.Items[1])
		}},
		{"extra effect object", func(_ CodingResourceSet, r *fakeCodingInventoryReader) {
			r.listedContainers.Items = append(r.listedContainers.Items,
				container.Summary{ID: "foreign", Names: []string{"/foreign"}, Labels: map[string]string{codingEffectLabel: "foreign"}})
		}},
		{"inspect absent while list present", func(s CodingResourceSet, r *fakeCodingInventoryReader) {
			name, _ := s.ContainerName(CodingRuntimeRole)
			delete(r.containers, name)
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			freshSet, freshExpected, fresh := testCodingInventoryFixture(t)
			populateCodingInventory(t, freshSet, freshExpected, fresh)
			for index := range fresh.listedContainers.Items {
				fresh.listedContainers.Items[index].Labels = maps.Clone(fresh.listedContainers.Items[index].Labels)
				fresh.listedContainers.Items[index].Labels[listOnlyKey] = "v2"
			}
			mutation.edit(freshSet, fresh)
			var result CodingResourceInventory
			if err := readCodingInventoryObjects(t.Context(), fresh, freshSet, freshExpected, &result); !errors.Is(err, ErrInvalidCodingInventory) {
				t.Fatalf("list/inspect authority drift admitted: %v", err)
			}
		})
	}
}

func TestCodingReadOnlyInventoryRejectsForeignAndIncompleteViews(t *testing.T) {
	for name, mutate := range map[string]func(*fakeCodingInventoryReader, CodingResourceSet){
		"missing list item": func(reader *fakeCodingInventoryReader, _ CodingResourceSet) {
			reader.listedContainers.Items = reader.listedContainers.Items[:1]
		},
		"extra container": func(reader *fakeCodingInventoryReader, _ CodingResourceSet) {
			reader.listedContainers.Items = append(reader.listedContainers.Items,
				container.Summary{ID: "late-id", Names: []string{"/late-effect-object"}})
		},
		"extra volume": func(reader *fakeCodingInventoryReader, _ CodingResourceSet) {
			reader.listedVolumes.Items = append(reader.listedVolumes.Items,
				volume.Volume{Name: "late-effect-volume", Driver: "local"})
		},
		"foreign same-name container": func(reader *fakeCodingInventoryReader, set CodingResourceSet) {
			name, _ := set.ContainerName(CodingRuntimeRole)
			value := reader.containers[name]
			value.Container.Config.Labels = map[string]string{codingEffectLabel: "foreign"}
			reader.containers[name] = value
		},
		"extra inherited label": func(reader *fakeCodingInventoryReader, set CodingResourceSet) {
			name, _ := set.ContainerName(CodingRuntimeRole)
			value := reader.containers[name]
			labels := map[string]string{}
			for key, item := range value.Container.Config.Labels {
				labels[key] = item
			}
			labels["unexpected"] = "value"
			value.Container.Config.Labels = labels
			reader.containers[name] = value
		},
		"foreign same-name volume": func(reader *fakeCodingInventoryReader, set CodingResourceSet) {
			name, _ := set.VolumeName(CodingWorkspaceRole)
			value := reader.volumes[name]
			value.Volume.Labels = map[string]string{codingEffectLabel: "foreign"}
			reader.volumes[name] = value
		},
		"volume list warning": func(reader *fakeCodingInventoryReader, _ CodingResourceSet) {
			reader.listedVolumes.Warnings = []string{"daemon volume warning"}
		},
		"inspect error": func(reader *fakeCodingInventoryReader, _ CodingResourceSet) {
			reader.inspectError = errors.New("ambiguous daemon error")
		},
	} {
		t.Run(name, func(t *testing.T) {
			set, expected, reader := testCodingInventoryFixture(t)
			populateCodingInventory(t, set, expected, reader)
			mutate(reader, set)
			var inventory CodingResourceInventory
			if err := readCodingInventoryObjects(context.Background(), reader, set, expected, &inventory); !errors.Is(err, ErrInvalidCodingInventory) {
				t.Fatalf("unsafe inventory admitted: %v", err)
			}
		})
	}
	set, expected, reader := testCodingInventoryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var inventory CodingResourceInventory
	if err := readCodingInventoryObjects(ctx, reader, set, expected, &inventory); !errors.Is(err, ErrInvalidCodingInventory) || reader.inspectCalls != 0 {
		t.Fatalf("cancelled inventory read: %v, inspections=%d", err, reader.inspectCalls)
	}
}
