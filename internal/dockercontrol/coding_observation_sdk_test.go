package dockercontrol

import (
	"context"
	"errors"
	"net/http"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

func codingInventorySDKFixture(t *testing.T, base http.RoundTripper,
	set CodingResourceSet) *client.Client {
	t.Helper()
	transport := &codingObservationTransport{base: base, set: set,
		endpointHost: "/run/docker.sock", requestHost: client.DummyHost}
	api, err := client.New(client.WithHost("unix:///run/docker.sock"),
		client.WithHTTPClient(&http.Client{Transport: transport}), client.WithAPIVersion("1.55"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = api.Close() })
	return api
}

func codingSDKResponse(status int, body, media string) *http.Response {
	response := codingTransportResponse(status, body, int64(len(body)))
	if media != "" {
		response.Header.Set("Content-Type", media)
	}
	return response
}

func TestCodingInventorySDKRejectsMalformedInspect404(t *testing.T) {
	for _, target := range []CodingResourceRole{CodingPreparationRole, CodingInputsRole} {
		for name, document := range map[string]struct{ body, media string }{
			"truncated":         {`{`, "application/json"},
			"empty":             {``, "application/json"},
			"missing message":   {`{}`, "application/json"},
			"empty message":     {`{"message":""}`, "application/json"},
			"wrong type":        {`{"message":17}`, "application/json"},
			"duplicate message": {`{"message":"x","message":"y"}`, "application/json"},
			"wrong media":       {`{"message":"not found"}`, "text/plain"},
		} {
			t.Run(string(target)+"/"+name, func(t *testing.T) {
				set, expected, _ := testCodingInventoryFixture(t)
				targetPath := ""
				if target == CodingPreparationRole {
					name, _ := set.ContainerName(target)
					targetPath = "/v1.55/containers/" + name + "/json"
				} else {
					name, _ := set.VolumeName(target)
					targetPath = "/v1.55/volumes/" + name
				}
				api := codingInventorySDKFixture(t, codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					if request.URL.Path == targetPath {
						return codingSDKResponse(http.StatusNotFound, document.body, document.media), nil
					}
					return codingSDKResponse(http.StatusNotFound, `{"message":"not found"}`, "application/json"), nil
				}), set)
				var directErr error
				if target == CodingPreparationRole {
					name, _ := set.ContainerName(target)
					_, directErr = api.ContainerInspect(t.Context(), name, client.ContainerInspectOptions{})
				} else {
					name, _ := set.VolumeName(target)
					_, directErr = api.VolumeInspect(t.Context(), name, client.VolumeInspectOptions{})
				}
				if directErr == nil || cerrdefs.IsNotFound(directErr) {
					t.Fatalf("malformed 404 became SDK absence: %v", directErr)
				}
				var inventory CodingResourceInventory
				if err := readCodingInventoryObjects(t.Context(), api, set, expected, &inventory); !errors.Is(err, ErrInvalidCodingInventory) {
					t.Fatalf("malformed 404 became inventory absence: %v", err)
				}
			})
		}
	}
}

func TestCodingInventorySDKRejectsInvalidListShapes(t *testing.T) {
	for name, override := range map[string]struct{ path, body string }{
		"valid empty":              {"", ""},
		"container null":           {"/v1.55/containers/json", `null`},
		"container object":         {"/v1.55/containers/json", `{}`},
		"volume null":              {"/v1.55/volumes", `null`},
		"volume missing":           {"/v1.55/volumes", `{}`},
		"volume null field":        {"/v1.55/volumes", `{"Volumes":null}`},
		"volume object field":      {"/v1.55/volumes", `{"Volumes":{}}`},
		"volume duplicate field":   {"/v1.55/volumes", `{"Volumes":[],"Volumes":[]}`},
		"volume invalid warning":   {"/v1.55/volumes", `{"Volumes":[],"Warnings":{}}`},
		"volume lowercase after":   {"/v1.55/volumes", `{"Volumes":[{"Name":"foreign"}],"volumes":[]}`},
		"volume lowercase before":  {"/v1.55/volumes", `{"volumes":[],"Volumes":[{"Name":"foreign"}]}`},
		"warning lowercase after":  {"/v1.55/volumes", `{"Volumes":[],"Warnings":["error"],"warnings":null}`},
		"warning lowercase before": {"/v1.55/volumes", `{"Volumes":[],"warnings":null,"Warnings":["error"]}`},
	} {
		t.Run(name, func(t *testing.T) {
			set, expected, _ := testCodingInventoryFixture(t)
			api := codingInventorySDKFixture(t, codingRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path == override.path {
					return codingSDKResponse(http.StatusOK, override.body, "application/json"), nil
				}
				if request.URL.Path == "/v1.55/containers/json" {
					return codingSDKResponse(http.StatusOK, `[]`, "application/json"), nil
				}
				if request.URL.Path == "/v1.55/volumes" {
					return codingSDKResponse(http.StatusOK, `{"Volumes":[],"Warnings":null}`, "application/json"), nil
				}
				return codingSDKResponse(http.StatusNotFound, `{"message":"not found"}`, "application/json"), nil
			}), set)
			var inventory CodingResourceInventory
			err := readCodingInventoryObjects(context.Background(), api, set, expected, &inventory)
			if name == "valid empty" {
				if err != nil {
					t.Fatalf("valid empty daemon inventory rejected: %v", err)
				}
				for _, item := range inventory.Containers {
					if item.Present {
						t.Fatal("empty container list reported presence")
					}
				}
				for _, item := range inventory.Volumes {
					if item.Present {
						t.Fatal("empty volume list reported presence")
					}
				}
			} else if !errors.Is(err, ErrInvalidCodingInventory) {
				t.Fatalf("incomplete list became empty inventory: %v", err)
			}
		})
	}
}
