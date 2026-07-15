package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shell-echo/sandbox-runtime/driver/fake"
	"github.com/shell-echo/sandbox-runtime/instance"
	"github.com/shell-echo/sandbox-runtime/instance/memory"
	"github.com/shell-echo/sandbox-runtime/option"
)

type testEnvelope struct {
	Code    string          `json:"code"`
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
}

func TestInstanceLifecycleAPI(t *testing.T) {
	srv := newTestServer(t)

	created := requestInstance(t, srv, http.MethodPost, "/instances", `{"name":"terminal","workload":"shell"}`, http.StatusOK)
	if created.ID == "" || created.State != instance.StateStopped {
		t.Fatalf("created instance = %+v", created)
	}

	got := requestInstance(t, srv, http.MethodGet, "/instances/"+created.ID, "", http.StatusOK)
	if got.ID != created.ID || got.Name != "terminal" {
		t.Fatalf("inspected instance = %+v", got)
	}
	listed := requestInstances(t, srv, "/instances", http.StatusOK)
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("listed instances = %+v", listed)
	}

	running := requestInstance(t, srv, http.MethodPost, "/instances/"+created.ID+"/start", "", http.StatusOK)
	if running.State != instance.StateRunning {
		t.Fatalf("started state = %s, want running", running.State)
	}

	stopped := requestInstance(t, srv, http.MethodPost, "/instances/"+created.ID+"/stop", "", http.StatusOK)
	if stopped.State != instance.StateStopped {
		t.Fatalf("stopped state = %s, want stopped", stopped.State)
	}

	envelope := request(t, srv, http.MethodDelete, "/instances/"+created.ID, "", http.StatusOK)
	if !envelope.Success || envelope.Code != "ok" {
		t.Fatalf("delete envelope = %+v", envelope)
	}
	requestCode(t, srv, http.MethodGet, "/instances/"+created.ID, "", http.StatusNotFound, "instance.not_found")
}

func TestInstanceAPIErrors(t *testing.T) {
	srv := newTestServer(t)

	requestCode(t, srv, http.MethodPost, "/instances", `{"name":"terminal","workload":"desktop"}`, http.StatusBadRequest, "instance.invalid_spec")
	requestCode(t, srv, http.MethodPost, "/instances", `{"name":"`+strings.Repeat("x", instance.MaxNameLength+1)+`","workload":"shell"}`, http.StatusBadRequest, "instance.invalid_spec")
	requestCode(t, srv, http.MethodPost, "/instances", `{`, http.StatusBadRequest, "instance.invalid_spec")
	requestCode(t, srv, http.MethodPost, "/instances", `{"id":"client-id","name":"terminal","workload":"shell"}`, http.StatusBadRequest, "instance.invalid_spec")
	requestCode(t, srv, http.MethodPost, "/instances", `{"name":"terminal","workload":"shell"} {}`, http.StatusBadRequest, "instance.invalid_spec")

	created := requestInstance(t, srv, http.MethodPost, "/instances", `{"name":"terminal","workload":"shell"}`, http.StatusOK)
	requestCode(t, srv, http.MethodPost, "/instances/"+created.ID+"/stop", "", http.StatusConflict, "instance.invalid_state")
	requestCode(t, srv, http.MethodGet, "/instances/missing", "", http.StatusNotFound, "instance.not_found")
}

func TestInstanceRequestBodyLimit(t *testing.T) {
	srv := newTestServer(t)
	body := `{"name":"` + strings.Repeat("x", maxRequestBodyBytes) + `","workload":"shell"}`
	requestCode(t, srv, http.MethodPost, "/instances", body, http.StatusRequestEntityTooLarge, "system.payload_too_large")
}

func TestInstanceLimit(t *testing.T) {
	service, err := instance.NewService(memory.NewRepository(), fake.NewDriver(), instance.WithMaxInstances(1))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	srv, err := NewServer(false, option.HTTP{Host: "127.0.0.1", Port: 8080}, service)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	requestInstance(t, srv, http.MethodPost, "/instances", `{"name":"one","workload":"shell"}`, http.StatusOK)
	requestCode(t, srv, http.MethodPost, "/instances", `{"name":"two","workload":"shell"}`, http.StatusTooManyRequests, "instance.limit_exceeded")
}

func requestInstances(t *testing.T, srv *Server, path string, wantStatus int) []instance.Instance {
	t.Helper()
	envelope := request(t, srv, http.MethodGet, path, "", wantStatus)
	if !envelope.Success || envelope.Code != "ok" {
		t.Fatalf("GET %s envelope = %+v", path, envelope)
	}
	var instances []instance.Instance
	if err := json.Unmarshal(envelope.Data, &instances); err != nil {
		t.Fatalf("decode instances: %v", err)
	}
	return instances
}

func TestNewServerRequiresInstanceService(t *testing.T) {
	if _, err := NewServer(false, option.HTTP{Host: "127.0.0.1", Port: 8080}, nil); err == nil {
		t.Fatal("NewServer with nil instance service should fail")
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(false, option.HTTP{Host: "127.0.0.1", Port: 8080}, newInstanceService(t))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func newInstanceService(t *testing.T) instance.Service {
	t.Helper()
	service, err := instance.NewService(memory.NewRepository(), fake.NewDriver())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func requestInstance(t *testing.T, srv *Server, method, path, body string, wantStatus int) instance.Instance {
	t.Helper()
	envelope := request(t, srv, method, path, body, wantStatus)
	if !envelope.Success || envelope.Code != "ok" {
		t.Fatalf("%s %s envelope = %+v", method, path, envelope)
	}
	var inst instance.Instance
	if err := json.Unmarshal(envelope.Data, &inst); err != nil {
		t.Fatalf("decode instance: %v", err)
	}
	return inst
}

func requestCode(t *testing.T, srv *Server, method, path, body string, wantStatus int, wantCode string) {
	t.Helper()
	envelope := request(t, srv, method, path, body, wantStatus)
	if envelope.Success || envelope.Code != wantCode {
		t.Fatalf("%s %s envelope = %+v, want code %q", method, path, envelope, wantCode)
	}
}

func request(t *testing.T, srv *Server, method, path, body string, wantStatus int) testEnvelope {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.http.Handler.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s %s status = %d, want %d; body=%s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	var envelope testEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode envelope: %v; body=%s", err, rec.Body.String())
	}
	return envelope
}
