package dockercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/volume"
)

func TestCodingCreationPlanBindsAllWriteInputs(t *testing.T) {
	f := testCodingCompletionFixture(t)
	p, err := newCodingCreationPlan(f.observer.binding, f.receipt.Authority, f.observer.template, f.observer.documents, f.observer.policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body    []byte
		runtime bool
	}{{p.prepBody, false}, {p.runtimeBody, true}} {
		var request container.CreateRequest
		if json.Unmarshal(tc.body, &request) != nil || request.Config == nil || request.HostConfig == nil {
			t.Fatal("invalid create document")
		}
		c, h := request.Config, request.HostConfig
		if h.ReadonlyRootfs != tc.runtime || h.NetworkMode != "none" || h.Privileged || len(h.Binds) != 0 || len(h.GroupAdd) != 0 || len(h.Mounts) != 3 || len(h.CapAdd) != 0 || len(h.CapDrop) != 1 || h.CapDrop[0] != "ALL" || len(h.SecurityOpt) != 2 || h.SecurityOpt[0] != "no-new-privileges:true" || h.SecurityOpt[1] != "seccomp="+string(f.observer.policy) {
			t.Fatal("unreviewed container capability")
		}
		if c.Image != f.observer.template.Image.Reference || c.User != fmt.Sprintf("%d:%d", p.slot.WorkloadUID, p.slot.WorkloadGID) || c.Tty || c.OpenStdin || len(c.ExposedPorts) != 0 || len(c.Entrypoint) != 0 || request.NetworkingConfig != nil {
			t.Fatal("unreviewed workload source or endpoint")
		}
		if !slices.Equal(c.Env, f.observer.template.Environment) || c.WorkingDir != f.observer.template.WorkingDirectory ||
			(tc.runtime && !slices.Equal(c.Cmd, f.observer.template.Command)) || h.Memory != f.observer.template.Limits.MemoryBytes ||
			h.MemorySwap != h.Memory || h.NanoCPUs != f.observer.template.Limits.CPUMillis*1_000_000 || h.PidsLimit == nil ||
			*h.PidsLimit != f.observer.template.Limits.PIDs || len(h.PortBindings) != 0 || h.PublishAllPorts ||
			len(h.Devices) != 0 || len(h.DeviceRequests) != 0 || len(h.VolumesFrom) != 0 || h.AutoRemove || h.RestartPolicy.Name != "no" {
			t.Fatal("frozen resources or execution inputs drifted")
		}
		if !tc.runtime && (len(c.Cmd) != 1 || c.Cmd[0] != "/bin/false") {
			t.Fatal("prep can execute workload")
		}
		for _, mount := range h.Mounts {
			if mount.Type != "volume" || mount.VolumeOptions == nil || mount.VolumeOptions.NoCopy != tc.runtime || mount.BindOptions != nil {
				t.Fatal("unreviewed mount")
			}
		}
		if _, ok := c.Labels["io.github.shell-echo.sandbox-runtime.phase"]; ok {
			t.Fatal("probe-only label leaked")
		}
	}
	badDocuments := f.observer.documents
	badDocuments.Config = append(bytes.Clone(badDocuments.Config), ' ')
	if _, err := newCodingCreationPlan(f.observer.binding, f.receipt.Authority, f.observer.template, badDocuments, f.observer.policy); err == nil {
		t.Fatal("changed raw OCI accepted")
	}
	if _, err := newCodingCreationPlan(f.observer.binding, f.receipt.Authority, f.observer.template, f.observer.documents, []byte("changed")); err == nil {
		t.Fatal("changed seccomp accepted")
	}
	badBinding := f.observer.binding
	badBinding.RuntimePlatform = "linux/amd64"
	if _, err := newCodingCreationPlan(badBinding, f.receipt.Authority, f.observer.template, f.observer.documents, f.observer.policy); err == nil {
		t.Fatal("foreign platform accepted")
	}
}

func TestCodingCreationRejectsAmbiguousResponsesWithoutRetry(t *testing.T) {
	f := testCodingCompletionFixture(t)
	p, err := newCodingCreationPlan(f.observer.binding, f.receipt.Authority, f.observer.template, f.observer.documents, f.observer.policy)
	if err != nil {
		t.Fatal(err)
	}
	good := `{"Id":"` + strings.Repeat("b", 64) + `","Warnings":[]}`
	for _, tc := range []struct {
		name   string
		step   int
		mutate func(*http.Response)
	}{
		{"redirect", 3, func(r *http.Response) { r.StatusCode = 307 }},
		{"large", 3, func(r *http.Response) { r.ContentLength = MaxCodingObservationResponseBytes + 1 }},
		{"truncated", 3, func(r *http.Response) { r.ContentLength++ }},
		{"compressed", 3, func(r *http.Response) { r.Header.Set("Content-Encoding", "gzip") }},
		{"wrong-type", 3, func(r *http.Response) { r.Header.Set("Content-Type", "text/plain") }},
		{"duplicate-id", 3, func(r *http.Response) {
			b := `{"Id":"` + strings.Repeat("c", 64) + `",` + good[1:]
			r.Body = io.NopCloser(strings.NewReader(b))
			r.ContentLength = int64(len(b))
		}},
		{"empty-id", 3, func(r *http.Response) {
			b := `{"Id":"","Warnings":[]}`
			r.Body = io.NopCloser(strings.NewReader(b))
			r.ContentLength = int64(len(b))
		}},
		{"warning", 3, func(r *http.Response) {
			b := strings.Replace(good, `[]`, `["warning"]`, 1)
			r.Body = io.NopCloser(strings.NewReader(b))
			r.ContentLength = int64(len(b))
		}},
		{"delete-body", 5, func(r *http.Response) { r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = 1 }},
		{"delete-unknown-length", 5, func(r *http.Response) { r.ContentLength = -1 }},
		{"delete-chunked", 5, func(r *http.Response) { r.TransferEncoding = []string{"chunked"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			w := &codingUnixCreation{plan: p, platform: f.observer.template.Image.Platform, step: tc.step, prepID: strings.Repeat("b", 64), wire: codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				r := codingSDKResponse(201, good, "application/json")
				if tc.step == 5 {
					r = codingSDKResponse(204, "", "")
				}
				tc.mutate(r)
				return r, nil
			})}
			if w.next(t.Context()) == nil || w.next(t.Context()) == nil || calls != 1 {
				t.Fatal("uncertain response admitted or retried")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w := &codingUnixCreation{plan: p, wire: codingRoundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("cancelled send"); return nil, nil })}
	if w.next(ctx) == nil {
		t.Fatal("cancelled request admitted")
	}
}

func TestCodingCreationAcceptsCompleteBoundedChunkedJSON(t *testing.T) {
	f := testCodingCompletionFixture(t)
	p, err := newCodingCreationPlan(f.observer.binding, f.receipt.Authority, f.observer.template, f.observer.documents, f.observer.policy)
	if err != nil {
		t.Fatal(err)
	}
	w := &codingUnixCreation{plan: p, platform: f.observer.template.Image.Platform, step: 3, wire: codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
		r := codingSDKResponse(201, `{"Id":"`+strings.Repeat("b", 64)+`","Warnings":[]}`, "application/json")
		r.ContentLength = -1
		r.TransferEncoding = []string{"chunked"}
		return r, nil
	})}
	if w.next(t.Context()) != nil || w.prepID != strings.Repeat("b", 64) {
		t.Fatal("complete chunked JSON rejected")
	}
}

func TestCodingCreationRejectsAmbiguousVolumeResponse(t *testing.T) {
	f := testCodingCompletionFixture(t)
	p, err := newCodingCreationPlan(f.observer.binding, f.receipt.Authority, f.observer.template, f.observer.documents, f.observer.policy)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := p.set.VolumeName(CodingInputsRole)
	labels, _ := p.set.Labels(CodingInputsRole)
	document, _ := json.Marshal(volume.Volume{Name: name, Driver: "local", Scope: "local", Labels: labels})
	var key, value string
	for key, value = range labels {
		break
	}
	encodedKey, _ := json.Marshal(key)
	encodedValue, _ := json.Marshal(value)
	for _, tc := range []struct{ name, body string }{
		{"case-alias", strings.Replace(string(document), `"Name":"`+name+`"`, `"Name":"wrong","name":"`+name+`"`, 1)},
		{"duplicate-label", strings.Replace(string(document), string(encodedKey)+":"+string(encodedValue), string(encodedKey)+`:"wrong",`+string(encodedKey)+":"+string(encodedValue), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			w := &codingUnixCreation{plan: p, platform: f.observer.template.Image.Platform, wire: codingRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return codingSDKResponse(201, tc.body, "application/json"), nil
			})}
			if w.next(t.Context()) == nil {
				t.Fatal("ambiguous volume response accepted")
			}
			if w.next(t.Context()) == nil || calls != 1 {
				t.Fatal("ambiguous volume response did not poison capability")
			}
		})
	}
}
