package dockercontrol

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
)

// This daemon models physical effects independently of response success. A
// lost response can leave resources behind; the tests must retain Unknown.
type codingCreationDaemon struct {
	fixture                               codingCompletionFixture
	plan                                  codingCreationPlan
	writes                                []string
	volumes                               int
	prep, runtime, prepared, started      bool
	failStep                              int
	missingImage, wrongRoot, wrongRuntime bool
	ledger                                *CodingReceiptLedger
}

func testCodingCreationDaemon(t *testing.T) (*codingCreationDaemon, *codingUnixCreation) {
	t.Helper()
	f := testCodingCompletionFixture(t)
	p, err := newCodingCreationPlan(f.observer.binding, f.receipt.Authority, f.observer.template, f.observer.documents, f.observer.policy)
	if err != nil {
		t.Fatal(err)
	}
	path := testReceiptPath(t)
	ledger, err := InitializeCodingReceiptLedger(t.Context(), path, f.observer.binding, testCleanNamespace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	d := &codingCreationDaemon{fixture: f, plan: p, failStep: -1, ledger: ledger}
	f.observer.bounded.base = codingRoundTripFunc(func(r *http.Request) (*http.Response, error) { return d.read(t, r) })
	w := &codingUnixCreation{plan: p, platform: f.observer.template.Image.Platform,
		wire: codingRoundTripFunc(func(r *http.Request) (*http.Response, error) { return d.write(t, r) })}
	return d, w
}

func (d *codingCreationDaemon) read(t *testing.T, r *http.Request) (*http.Response, error) {
	t.Helper()
	if r.Method != "GET" {
		t.Fatal("observer gained a write operation")
	}
	path := r.URL.Path
	notFound := func() (*http.Response, error) {
		return codingSDKResponse(404, `{"message":"not found"}`, "application/json"), nil
	}
	if strings.HasPrefix(path, "/v1.55/images/") && d.missingImage {
		return notFound()
	}
	prepID, runtimeID := strings.Repeat("b", 64), strings.Repeat("a", 64)
	if path == "/v1.55/containers/"+prepID+"/archive" {
		if !d.prep || !d.prepared {
			t.Fatal("archive before checked preparation")
		}
		target := r.URL.Query().Get("path")
		return codingArchiveResponse(t, target, codingArchiveFixture(t, target, func(h *tar.Header) {
			if d.wrongRoot {
				h.Uid++
			}
		})), nil
	}
	if path == "/v1.55/containers/"+d.plan.prepName+"/json" {
		if !d.prep {
			return notFound()
		}
		u := *r.URL
		u.Path = "/v1.55/containers/" + d.plan.runtimeName + "/json"
		copyRequest := r.Clone(r.Context())
		copyRequest.URL = &u
		response, err := d.fixture.respond(copyRequest)
		if err != nil {
			return nil, err
		}
		var observed container.InspectResponse
		if json.NewDecoder(response.Body).Decode(&observed) != nil {
			t.Fatal("fixture decode")
		}
		response.Body.Close()
		var create container.CreateRequest
		if json.Unmarshal(d.plan.prepBody, &create) != nil {
			t.Fatal("prep decode")
		}
		observed.ID, observed.Name, observed.Config, observed.HostConfig = prepID, "/"+d.plan.prepName, create.Config, create.HostConfig
		observed.State = &container.State{Status: "created", StartedAt: "0001-01-01T00:00:00Z", FinishedAt: "0001-01-01T00:00:00Z"}
		data, _ := json.Marshal(observed)
		return codingSDKResponse(200, string(data), "application/json"), nil
	}
	if path == "/v1.55/containers/"+d.plan.runtimeName+"/json" && !d.runtime {
		return notFound()
	}
	for i, role := range []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole} {
		name, _ := d.plan.set.VolumeName(role)
		if path == "/v1.55/volumes/"+name && d.volumes <= i {
			return notFound()
		}
	}
	response, err := d.fixture.respond(r)
	if err != nil {
		return nil, err
	}
	if path == "/v1.55/containers/json" {
		response.Body.Close()
		var list []container.Summary
		for _, entry := range []struct {
			role     CodingResourceRole
			present  bool
			name, id string
		}{
			{CodingPreparationRole, d.prep, d.plan.prepName, prepID}, {CodingRuntimeRole, d.runtime, d.plan.runtimeName, runtimeID},
		} {
			if entry.present {
				labels, _ := d.plan.set.ContainerLabels(entry.role, d.fixture.observer.template, d.fixture.observer.documents)
				list = append(list, container.Summary{ID: entry.id, Names: []string{"/" + entry.name}, Labels: labels})
			}
		}
		if list == nil {
			list = []container.Summary{}
		}
		data, _ := json.Marshal(list)
		return codingSDKResponse(200, string(data), "application/json"), nil
	}
	if path == "/v1.55/volumes" {
		var value struct {
			Volumes  []json.RawMessage
			Warnings []string
		}
		if json.NewDecoder(response.Body).Decode(&value) != nil {
			t.Fatal("volume fixture")
		}
		response.Body.Close()
		value.Volumes = value.Volumes[:d.volumes]
		data, _ := json.Marshal(value)
		return codingSDKResponse(200, string(data), "application/json"), nil
	}
	if path == "/v1.55/containers/"+d.plan.runtimeName+"/json" && !d.started {
		var observed container.InspectResponse
		if json.NewDecoder(response.Body).Decode(&observed) != nil {
			t.Fatal("runtime fixture")
		}
		response.Body.Close()
		observed.State = &container.State{Status: "created", StartedAt: "0001-01-01T00:00:00Z", FinishedAt: "0001-01-01T00:00:00Z"}
		if d.wrongRuntime {
			observed.HostConfig.Privileged = true
		}
		data, _ := json.Marshal(observed)
		return codingSDKResponse(200, string(data), "application/json"), nil
	}
	return response, nil
}

func (d *codingCreationDaemon) write(t *testing.T, r *http.Request) (*http.Response, error) {
	t.Helper()
	stored, err := readReceiptState(d.ledger.path, d.fixture.observer.binding)
	if err != nil || len(stored.Records) != 1 || stored.Records[0].Status != ReceiptUnknown || stored.Revision != 2 {
		t.Fatal("mutation preceded durable Unknown")
	}
	if r.URL.Host != "docker" || r.URL.Scheme != "http" || r.GetBody != nil || !r.Close {
		t.Fatal("unsafe write route/replay")
	}
	deadline, ok := r.Context().Deadline()
	if !ok || time.Until(deadline) > maxCodingObservationRequestDuration {
		t.Fatal("unbounded mutation")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	step := len(d.writes)
	d.writes = append(d.writes, r.Method+" "+r.URL.RequestURI())
	var response *http.Response
	switch step {
	case 0, 1, 2:
		if r.Method != "POST" || r.URL.Path != "/v1.55/volumes/create" || r.URL.RawQuery != "" || !bytes.Equal(body, d.plan.volumeBodies[step]) {
			t.Fatal("volume authority drift")
		}
		d.volumes++
		role := []CodingResourceRole{CodingInputsRole, CodingWorkspaceRole, CodingOutputsRole}[step]
		name, _ := d.plan.set.VolumeName(role)
		read := r.Clone(r.Context())
		read.Method = "GET"
		read.URL = &url.URL{Path: "/v1.55/volumes/" + name}
		response, err = d.fixture.respond(read)
		if err != nil {
			t.Fatal(err)
		}
		response.StatusCode = 201
	case 3, 6:
		name, expected, id := d.plan.prepName, d.plan.prepBody, strings.Repeat("b", 64)
		if step == 6 {
			name, expected, id = d.plan.runtimeName, d.plan.runtimeBody, strings.Repeat("a", 64)
		}
		if r.Method != "POST" || r.URL.Path != "/v1.55/containers/create" || r.URL.RawQuery != (url.Values{"name": {name}, "platform": {"linux/arm64/v8"}}).Encode() || !bytes.Equal(body, expected) {
			t.Fatal("container authority drift")
		}
		if step == 3 {
			d.prep = true
		} else {
			if d.prep || !d.prepared {
				t.Fatal("runtime before prepared carrier removal")
			}
			d.runtime = true
		}
		response = codingSDKResponse(201, `{"Id":"`+id+`","Warnings":[]}`, "application/json")
	case 4:
		if !d.prep || r.Method != "PUT" || r.URL.Path != "/v1.55/containers/"+strings.Repeat("b", 64)+"/archive" || r.URL.RawQuery != "noOverwriteDirNonDir=true&path=%2F" || !bytes.Equal(body, d.plan.archive) {
			t.Fatal("archive authority drift")
		}
		d.prepared = true
		response = codingSDKResponse(200, "", "")
	case 5:
		if !d.prepared || r.Method != "DELETE" || r.URL.Path != "/v1.55/containers/"+strings.Repeat("b", 64) || r.URL.RawQuery != "" || len(body) != 0 {
			t.Fatal("prep delete drift")
		}
		d.prep = false
		response = codingSDKResponse(204, "", "")
	case 7:
		if !d.runtime || r.Method != "POST" || r.URL.Path != "/v1.55/containers/"+strings.Repeat("a", 64)+"/start" || r.URL.RawQuery != "" || len(body) != 0 {
			t.Fatal("runtime start drift")
		}
		d.started = true
		response = codingSDKResponse(204, "", "")
	default:
		t.Fatal("unexpected extra write")
	}
	if d.failStep == step {
		response.Body.Close()
		return nil, io.ErrUnexpectedEOF
	}
	return response, nil
}

func TestCodingCreationDispatchPersistsBeforeEveryWriteAndCompletes(t *testing.T) {
	d, w := testCodingCreationDaemon(t)
	e := &CodingExecutorV2{ledger: d.ledger}
	if err := e.dispatchCreate(t.Context(), d.fixture.receipt.Authority, d.fixture.observer, w); err != nil {
		t.Fatalf("create: %v, writes=%v, reads=%v", err, d.writes, *d.fixture.calls)
	}
	stored, err := readReceiptState(d.ledger.path, d.fixture.observer.binding)
	if err != nil || stored.Revision != 3 || stored.Records[0].Status != ReceiptCompleted || len(d.writes) != 8 || !d.started {
		t.Fatal("completion not sealed after full chain")
	}
	if _, err := d.ledger.ReadCompletedSnapshot(d.fixture.receipt.Authority.RequestID); err != nil {
		t.Fatal(err)
	}
	if err := e.dispatchCreate(t.Context(), d.fixture.receipt.Authority, d.fixture.observer, w); !errors.Is(err, ErrReceiptReplay) || len(d.writes) != 8 {
		t.Fatal("replayed create performed effects")
	}
}

func TestCodingCreationLostResponseAtEveryStepStaysUnknown(t *testing.T) {
	for step := 0; step < 8; step++ {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			d, w := testCodingCreationDaemon(t)
			d.failStep = step
			e := &CodingExecutorV2{ledger: d.ledger}
			if e.dispatchCreate(t.Context(), d.fixture.receipt.Authority, d.fixture.observer, w) == nil {
				t.Fatal("uncertain response completed")
			}
			stored, err := readReceiptState(d.ledger.path, d.fixture.observer.binding)
			if err != nil || stored.Records[0].Status != ReceiptUnknown || stored.Revision != 2 || len(d.writes) != step+1 {
				t.Fatal("failure retried, cleaned up, or completed")
			}
			if w.next(t.Context()) == nil || len(d.writes) != step+1 {
				t.Fatal("failed finite capability reused")
			}
			if _, err := d.ledger.completeCodingCreate(t.Context(), d.fixture.receipt.Authority.RequestID, d.fixture.observer); err == nil {
				t.Fatal("uncertain create supplemented completion")
			}
		})
	}
}

func TestCodingCreationStopsBeforeUnsafeNextWrite(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*codingCreationDaemon)
		writes int
	}{
		{"missing-image", func(d *codingCreationDaemon) { d.missingImage = true }, 0},
		{"wrong-root-owner", func(d *codingCreationDaemon) { d.wrongRoot = true }, 5},
		{"privileged-runtime", func(d *codingCreationDaemon) { d.wrongRuntime = true }, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, w := testCodingCreationDaemon(t)
			tc.edit(d)
			e := &CodingExecutorV2{ledger: d.ledger}
			if e.dispatchCreate(t.Context(), d.fixture.receipt.Authority, d.fixture.observer, w) == nil || len(d.writes) != tc.writes {
				t.Fatalf("unsafe progression: %v", d.writes)
			}
			receipt, _, _, err := d.ledger.LookupProjection(d.fixture.receipt.Authority.RequestID)
			if err != nil || receipt.Status != ReceiptUnknown {
				t.Fatal("failure did not retain capacity")
			}
		})
	}
}

func TestCodingExecutorV2RetainsAdmissionHoldAndUnknownCleanup(t *testing.T) {
	if _, err := NewCodingExecutorV2(phase6security.ProfileV2{}, "", CodingReceiptBinding{}, nil, phase6security.ImageDescriptorDocuments{}, nil); err == nil {
		t.Fatal("Profile hold bypassed")
	}
	d, w := testCodingCreationDaemon(t)
	d.failStep = 0
	e := &CodingExecutorV2{ledger: d.ledger, binding: d.fixture.observer.binding, gate: make(chan struct{}, 1)}
	e.gate <- struct{}{}
	if e.dispatchCreate(t.Context(), d.fixture.receipt.Authority, d.fixture.observer, w) == nil {
		t.Fatal("fixture must stay Unknown")
	}
	intent := testCodingReleaseIntent(t, d.fixture)
	if e.Cleanup(t.Context(), d.fixture.receipt.Authority, intent) == nil || len(d.writes) != 1 {
		t.Fatal("Unknown cleanup reached Docker")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e.Create(ctx, d.fixture.receipt.Authority) == nil {
		t.Fatal("cancelled admission")
	}
}
